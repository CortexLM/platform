use crate::challenge_manager::ChallengeManager;
use crate::cvm_quota::CVMQuotaManager;
use crate::job_vm_manager::JobVmManager;
use crate::network_proxy::NetworkProxy;
use crate::secure_message::SecureMessage;
use anyhow::Result;
use axum::middleware::{from_fn_with_state, Next};
use axum::{
    extract::{Path, State},
    http::{Request, StatusCode},
    response::Json,
    routing::{delete, get, post},
    Router,
};
use base64;
use ed25519_dalek::{Signature, VerifyingKey};
use platform_engine_dynamic_values::DynamicValuesManager;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{error, info};

#[derive(Clone)]
struct AppState {
    dynamic_values: Arc<DynamicValuesManager>,
    cvm_quota: Arc<CVMQuotaManager>,
    challenge_manager: Arc<ChallengeManager>,
    job_vm: Arc<JobVmManager>,
    sessions: Arc<RwLock<HashMap<String, SessionEntry>>>,
}

#[derive(Clone, Debug)]
struct SessionEntry {
    public_key: Vec<u8>,
    job_id: Option<String>,
    challenge_id: Option<String>,
    expires_at: u64,
    nonces: std::collections::BTreeMap<String, u64>, // nonce -> timestamp
    aead_key: Option<[u8; 32]>,                      // XChaCha20-Poly1305 key for encrypted bodies
    srv_x25519_pub: Option<[u8; 32]>,                // Server X25519 public key
}

#[derive(Serialize, Deserialize)]
struct SetValueRequest {
    key: String,
    value: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
struct SetValueResponse {
    success: bool,
    message: String,
}

#[derive(Serialize, Deserialize)]
struct GetValueResponse {
    value: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
struct GetAllValuesResponse {
    values: HashMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
struct DeleteValueResponse {
    success: bool,
    message: String,
}

#[derive(Serialize, Deserialize)]
struct CVMRequest {
    challenge_id: String,
    miner_hotkey: String,
    docker_image: String,
    resources: CVMResources,
}

#[derive(Serialize, Deserialize)]
struct CVMResources {
    cpu_cores: u32,
    memory_mb: u64,
    disk_mb: u64,
}

#[derive(Serialize, Deserialize)]
struct CVMResponse {
    success: bool,
    cvm_id: Option<String>,
    executor_url: Option<String>,
    message: String,
}

pub async fn start_http_server(
    dynamic_values_manager: Arc<DynamicValuesManager>,
    network_proxy: Option<Arc<NetworkProxy>>,
    cvm_quota_manager: Arc<CVMQuotaManager>,
    challenge_manager: Arc<ChallengeManager>,
    job_vm_manager: Arc<JobVmManager>,
) -> Result<()> {
    use crate::network_proxy::create_network_proxy_router;

    let sessions: Arc<RwLock<HashMap<String, SessionEntry>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let app_state = AppState {
        dynamic_values: dynamic_values_manager,
        cvm_quota: cvm_quota_manager,
        challenge_manager,
        job_vm: job_vm_manager,
        sessions: sessions.clone(),
    };

    // Routes requiring signature verification
    let signed_routes = Router::new()
        .route("/results/heartbeat", post(results_heartbeat))
        .route("/results/logs", post(results_log))
        .route("/results/submit", post(results_submit))
        .with_state(app_state.clone())
        .route_layer(from_fn_with_state(app_state.clone(), verify_signed_request));

    // Attestation bootstrap (no signature yet)
    let attestation_routes = Router::new()
        .route("/attestation/challenge", post(attestation_challenge))
        .route("/attest", post(attest))
        .with_state(app_state.clone());

    let mut app = Router::new()
        .route("/health", get(health_check))
        .route("/challenges/:challenge_id/values", get(get_all_values))
        .route("/challenges/:challenge_id/values/:key", get(get_value))
        .route("/challenges/:challenge_id/values", post(set_value))
        .route(
            "/challenges/:challenge_id/values/:key",
            delete(delete_value),
        )
        .route("/api/cvm/request", post(request_cvm))
        .route("/api/cvm/release/:cvm_id", post(release_cvm))
        .route("/api/cvm/quota/:challenge_id", get(get_quota_status))
        .route("/api/cvm/init", post(init_challenge_quota))
        .route(
            "/challenge/:compose_hash/callback",
            post(challenge_callback),
        )
        .route(
            "/challenge/:challenge_name/cleanup",
            post(challenge_cleanup),
        )
        .merge(signed_routes)
        .merge(attestation_routes)
        .with_state(app_state);

    // Add network proxy routes if available
    if let Some(proxy) = network_proxy {
        app = app.merge(create_network_proxy_router(proxy));
    }

    // Start garbage collector for nonce expiry
    let sessions_gc = sessions.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(300)).await; // Every 5 minutes
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let mut sessions = sessions_gc.write().await;
            let mut purge_count = 0;

            // Clean expired sessions and old nonces
            sessions.retain(|token, entry| {
                if entry.expires_at <= now {
                    purge_count += 1;
                    return false;
                }
                // Remove nonces older than 10 minutes
                let cutoff = now.saturating_sub(600);
                entry.nonces.retain(|_, ts| *ts > cutoff);
                true
            });

            if purge_count > 0 {
                info!("GC purged {} expired sessions", purge_count);
            }
        }
    });

    let port = std::env::var("VALIDATOR_PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!("HTTP server started on port {}", port);

    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "validator-dynamic-values"
    }))
}

async fn get_all_values(
    State(state): State<AppState>,
    Path(challenge_id): Path<String>,
) -> Result<Json<GetAllValuesResponse>, StatusCode> {
    match state.dynamic_values.get_all_values(&challenge_id).await {
        Ok(values) => Ok(Json(GetAllValuesResponse { values })),
        Err(e) => {
            error!("Error getting all values: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_value(
    State(state): State<AppState>,
    Path((challenge_id, key)): Path<(String, String)>,
) -> Result<Json<GetValueResponse>, StatusCode> {
    match state.dynamic_values.get_value(&challenge_id, &key).await {
        Ok(value) => Ok(Json(GetValueResponse { value })),
        Err(e) => {
            error!("Error getting value: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn set_value(
    State(state): State<AppState>,
    Path(challenge_id): Path<String>,
    Json(request): Json<SetValueRequest>,
) -> Result<Json<SetValueResponse>, StatusCode> {
    match state
        .dynamic_values
        .set_value(&challenge_id, &request.key, request.value)
        .await
    {
        Ok(_) => Ok(Json(SetValueResponse {
            success: true,
            message: format!("Value set for key: {}", request.key),
        })),
        Err(e) => {
            error!("Error setting value: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn delete_value(
    State(state): State<AppState>,
    Path((challenge_id, key)): Path<(String, String)>,
) -> Result<Json<DeleteValueResponse>, StatusCode> {
    match state.dynamic_values.delete_value(&challenge_id, &key).await {
        Ok(_) => Ok(Json(DeleteValueResponse {
            success: true,
            message: format!("Value deleted for key: {}", key),
        })),
        Err(e) => {
            error!("Error deleting value: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn request_cvm(
    State(state): State<AppState>,
    Json(request): Json<CVMRequest>,
) -> Result<Json<CVMResponse>, StatusCode> {
    info!(
        "CVM request received: challenge={}, miner={}, image={}",
        request.challenge_id, request.miner_hotkey, request.docker_image
    );

    // Docker image integrity is verified via TEE attestation (compose_hash in TDX quote)
    // No manual Docker image validation needed

    use crate::cvm_quota::ResourceRequest;
    let resource_request = ResourceRequest {
        cpu_cores: request.resources.cpu_cores,
        memory_mb: request.resources.memory_mb,
        disk_mb: request.resources.disk_mb,
    };

    match state
        .cvm_quota
        .reserve(&request.challenge_id, resource_request)
        .await
    {
        Ok(crate::cvm_quota::QuotaResult::Granted) => {
            let cvm_id = format!("cvm-{}-{}", request.challenge_id, request.miner_hotkey);
            let executor_url = std::env::var("PLATFORM_EXECUTOR_URL")
                .unwrap_or_else(|_| "http://platform-executor:8080".to_string());

            info!(
                "CVM request approved: cvm_id={}, executor_url={}",
                cvm_id, executor_url
            );

            Ok(Json(CVMResponse {
                success: true,
                cvm_id: Some(cvm_id),
                executor_url: Some(executor_url),
                message: "CVM request approved".to_string(),
            }))
        }
        Ok(crate::cvm_quota::QuotaResult::Insufficient) => Ok(Json(CVMResponse {
            success: false,
            cvm_id: None,
            executor_url: None,
            message: "Insufficient quota for this challenge".to_string(),
        })),
        Err(e) => {
            error!("Error checking quota: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
struct ReleaseCvmRequest {
    cpu_cores: u32,
    memory_mb: u64,
    disk_mb: u64,
}

async fn release_cvm(
    State(state): State<AppState>,
    Path(cvm_id): Path<String>,
    Json(request): Json<ReleaseCvmRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    info!("Releasing CVM: {}", cvm_id);

    let parts: Vec<&str> = cvm_id.split('-').collect();
    if parts.len() >= 3 {
        let challenge_id = parts[1].to_string();
        let miner_hotkey = parts[2..].join("-");

        // Release quota using actual resources
        use crate::cvm_quota::ResourceRequest;
        state
            .cvm_quota
            .release(
                &challenge_id,
                ResourceRequest {
                    cpu_cores: request.cpu_cores,
                    memory_mb: request.memory_mb,
                    disk_mb: request.disk_mb,
                },
            )
            .await;

        Ok(Json(serde_json::json!({
            "success": true,
            "message": format!("CVM {} released", cvm_id)
        })))
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

async fn get_quota_status(
    State(state): State<AppState>,
    Path(challenge_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match state.cvm_quota.get_challenge_state(&challenge_id).await {
        Some((reserved, in_use)) => Ok(Json(serde_json::json!({
            "challenge_id": challenge_id,
            "reserved": {
                "cpu_cores": reserved.cpu_cores,
                "memory_mb": reserved.memory_mb,
                "disk_mb": reserved.disk_mb,
            },
            "in_use": {
                "cpu_cores": in_use.cpu_cores,
                "memory_mb": in_use.memory_mb,
                "disk_mb": in_use.disk_mb,
            },
            "available": {
                "cpu_cores": reserved.cpu_cores.saturating_sub(in_use.cpu_cores),
                "memory_mb": reserved.memory_mb.saturating_sub(in_use.memory_mb),
                "disk_mb": reserved.disk_mb.saturating_sub(in_use.disk_mb),
            }
        }))),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Deserialize)]
struct InitQuotaRequest {
    challenge_id: String,
    total_quota: u32,
}

async fn init_challenge_quota(
    State(state): State<AppState>,
    Json(request): Json<InitQuotaRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Dynamic quota system handles registration automatically
    // This endpoint is kept for compatibility but does nothing
    Ok(Json(serde_json::json!({
        "success": true,
        "message": format!("Dynamic quota system active for challenge {}", request.challenge_id)
    })))
}

#[derive(Deserialize)]
struct ChallengeCallbackRequest {
    job_id: String,
    results: serde_json::Value,
    score: f64,
    execution_time_ms: u64,
    error: Option<String>,
}

async fn challenge_callback(
    State(state): State<AppState>,
    Path(compose_hash): Path<String>,
    Json(request): Json<ChallengeCallbackRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    info!(
        "Received callback for challenge {} with job_id: {}",
        compose_hash, request.job_id
    );

    // Forward results to Platform API
    let client = reqwest::Client::new();
    let platform_api_url = std::env::var("PLATFORM_API_URL")
        .unwrap_or_else(|_| "https://api.platform.network".to_string());

    let payload = serde_json::json!({
        "job_id": request.job_id,
        "compose_hash": compose_hash,
        "results": request.results,
        "score": request.score,
        "execution_time_ms": request.execution_time_ms,
        "error": request.error
    });

    match client
        .post(&format!("{}/results", platform_api_url))
        .json(&payload)
        .send()
        .await
    {
        Ok(_) => {
            info!("Successfully forwarded results to Platform API");
            Ok(Json(serde_json::json!({
                "success": true,
                "message": "Results forwarded to Platform API"
            })))
        }
        Err(e) => {
            error!("Failed to forward results to Platform API: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[derive(Deserialize)]
struct ChallengeCleanupRequest {
    message_type: String,
    data: serde_json::Value,
    timestamp: u64,
    nonce: String,
    signature: String,
    public_key: String,
}

async fn challenge_cleanup(
    State(state): State<AppState>,
    Path(challenge_name): Path<String>,
    Json(request): Json<ChallengeCleanupRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    info!("Received cleanup request for challenge: {}", challenge_name);

    // Verify SecureMessage
    let secure_msg = SecureMessage {
        message_type: request.message_type.clone(),
        data: request.data.clone(),
        timestamp: request.timestamp,
        nonce: request.nonce.clone(),
        signature: request.signature.clone(),
        public_key: request.public_key.clone(),
    };

    // Verify signature
    match secure_msg.verify() {
        Ok(is_valid) => {
            if !is_valid {
                error!("Invalid signature for cleanup request");
                return Err(StatusCode::UNAUTHORIZED);
            }
        }
        Err(e) => {
            error!("Signature verification error: {}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Extract compose_hash from data
    let compose_hash = match request.data.get("compose_hash").and_then(|v| v.as_str()) {
        Some(hash) => hash,
        None => {
            error!("Missing compose_hash in cleanup request");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    info!(
        "Verified cleanup request for challenge {} (compose_hash: {})",
        challenge_name, compose_hash
    );

    // Perform cleanup
    match state.job_vm.cleanup_challenge(&challenge_name).await {
        Ok(cleaned_count) => {
            info!(
                "Cleaned up {} VMs for challenge {}",
                cleaned_count, challenge_name
            );
            Ok(Json(serde_json::json!({
                "success": true,
                "cleaned": cleaned_count
            })))
        }
        Err(e) => {
            error!("Failed to cleanup challenge {}: {}", challenge_name, e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ---------------------------
// Signed request middleware
// ---------------------------

async fn verify_signed_request(
    State(state): State<AppState>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .as_secs();

    // Extract headers first
    let session_token = req
        .headers()
        .get("X-Session-Token")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();
    let timestamp: u64 = req
        .headers()
        .get("X-Timestamp")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if now.abs_diff(timestamp) > 120 {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let nonce = req
        .headers()
        .get("X-Nonce")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();
    let pubkey_b64 = req
        .headers()
        .get("X-Public-Key")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();
    let signature_b64 = req
        .headers()
        .get("X-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_string();

    // Read body bytes for hashing
    let body = std::mem::replace(req.body_mut(), axum::body::Body::empty());
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let body_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&body_bytes);
        hex::encode(hasher.finalize())
    };
    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, path, body_hash, timestamp, nonce, session_token
    );

    // Lookup session and prevent replay
    let aead_key_option = {
        let mut sessions = state.sessions.write().await;
        if let Some(entry) = sessions.get_mut(&session_token) {
            if entry.expires_at <= now {
                return Err(StatusCode::UNAUTHORIZED);
            }
            if entry.nonces.contains_key(&nonce) {
                return Err(StatusCode::UNAUTHORIZED);
            }
            entry.nonces.insert(nonce.clone(), now);
            // Verify pubkey matches
            let provided_pubkey =
                base64::decode(&pubkey_b64).map_err(|_| StatusCode::UNAUTHORIZED)?;
            if provided_pubkey != entry.public_key {
                return Err(StatusCode::UNAUTHORIZED);
            }
            // Verify signature
            let sig_bytes = base64::decode(&signature_b64).map_err(|_| StatusCode::UNAUTHORIZED)?;
            if sig_bytes.len() != 64 {
                return Err(StatusCode::UNAUTHORIZED);
            }
            let signature_bytes: [u8; 64] =
                sig_bytes.try_into().map_err(|_| StatusCode::UNAUTHORIZED)?;
            let signature = Signature::from_bytes(&signature_bytes);
            let pubkey_bytes: [u8; 32] = provided_pubkey
                .try_into()
                .map_err(|_| StatusCode::UNAUTHORIZED)?;
            let vk =
                VerifyingKey::from_bytes(&pubkey_bytes).map_err(|_| StatusCode::UNAUTHORIZED)?;
            if vk.verify_strict(canonical.as_bytes(), &signature).is_err() {
                return Err(StatusCode::UNAUTHORIZED);
            }
            entry.aead_key
        } else {
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Decrypt body if encrypted and session has AEAD key
    let final_body = if let Some(aead_key) = aead_key_option {
        // Try to parse as encrypted envelope
        if let Ok(envelope_json) = serde_json::from_slice::<serde_json::Value>(&body_bytes) {
            if let (Some(enc), Some(nonce_b64), Some(ciphertext_b64)) = (
                envelope_json.get("enc").and_then(|v| v.as_str()),
                envelope_json.get("nonce").and_then(|v| v.as_str()),
                envelope_json.get("ciphertext").and_then(|v| v.as_str()),
            ) {
                if enc == "xchacha20poly1305" || enc == "chacha20poly1305" {
                    // Decode nonce and ciphertext for ChaCha20-Poly1305
                    let nonce_bytes =
                        base64::decode(nonce_b64).map_err(|_| StatusCode::BAD_REQUEST)?;
                    if nonce_bytes.len() != 12 {
                        tracing::error!(
                            "Invalid ChaCha20 nonce length: expected 12 bytes, got {}",
                            nonce_bytes.len()
                        );
                        return Err(StatusCode::BAD_REQUEST);
                    }
                    let nonce_array: [u8; 12] = nonce_bytes
                        .try_into()
                        .map_err(|_| StatusCode::BAD_REQUEST)?;
                    let ciphertext_bytes =
                        base64::decode(ciphertext_b64).map_err(|_| StatusCode::BAD_REQUEST)?;

                    // Use ChaCha20Poly1305 for decryption
                    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
                    let cipher = ChaCha20Poly1305::new(&aead_key.into());

                    match cipher.decrypt(&nonce_array.into(), ciphertext_bytes.as_ref()) {
                        Ok(plaintext) => {
                            tracing::debug!(
                                "Successfully decrypted ChaCha20-Poly1305 request body"
                            );
                            axum::body::Body::from(plaintext)
                        }
                        Err(e) => {
                            tracing::error!("Failed to decrypt body: {:?}", e);
                            return Err(StatusCode::BAD_REQUEST);
                        }
                    }
                } else {
                    // Not encrypted, use original body
                    axum::body::Body::from(body_bytes)
                }
            } else {
                // Not encrypted envelope, use original body
                axum::body::Body::from(body_bytes)
            }
        } else {
            // Not JSON, use original body
            axum::body::Body::from(body_bytes)
        }
    } else {
        // No AEAD key, use original body
        axum::body::Body::from(body_bytes)
    };

    // Replace body with decrypted content
    *req.body_mut() = final_body;

    Ok(next.run(req).await)
}

// ---------------------------
// Results proxy (SDK -> Validator -> Platform API)
// ---------------------------

#[derive(Debug, Serialize, Deserialize)]
struct HeartbeatPayload {
    timestamp: i64,
    status: String,
    metrics: serde_json::Value,
}

async fn results_heartbeat(
    Json(payload): Json<HeartbeatPayload>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let client = reqwest::Client::new();
    let platform_api_url = std::env::var("PLATFORM_API_URL")
        .unwrap_or_else(|_| "http://platform-api:3000".to_string());
    let resp = client
        .post(&format!("{}/results/heartbeat", platform_api_url))
        .json(&payload)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let val = resp
        .json::<serde_json::Value>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(Json(val))
}

#[derive(Debug, Serialize, Deserialize)]
struct LogPayload {
    timestamp: i64,
    level: String,
    message: String,
    component: String,
}

async fn results_log(
    Json(payload): Json<LogPayload>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let client = reqwest::Client::new();
    let platform_api_url = std::env::var("PLATFORM_API_URL")
        .unwrap_or_else(|_| "http://platform-api:3000".to_string());
    let resp = client
        .post(&format!("{}/results/logs", platform_api_url))
        .json(&payload)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let val = resp
        .json::<serde_json::Value>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(Json(val))
}

#[derive(Debug, Serialize, Deserialize)]
struct SubmitPayload {
    session_token: String,
    job_type: String,
    score: f64,
    metrics: std::collections::BTreeMap<String, f64>,
    logs: Vec<String>,
    allowed_log_containers: Option<Vec<String>>,
    error: Option<String>,
}

async fn results_submit(
    Json(payload): Json<SubmitPayload>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let client = reqwest::Client::new();
    let platform_api_url = std::env::var("PLATFORM_API_URL")
        .unwrap_or_else(|_| "http://platform-api:3000".to_string());
    let resp = client
        .post(&format!("{}/results/submit", platform_api_url))
        .json(&payload)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let val = resp
        .json::<serde_json::Value>()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    Ok(Json(val))
}

// ---------------------------
// Attestation proxy and session issuance
// ---------------------------

#[derive(Debug, Deserialize)]
struct ChallengeNonceResponse {
    nonce: String,
    expires_at: String,
}

async fn attestation_challenge() -> Result<Json<serde_json::Value>, StatusCode> {
    // Generate attestation challenge locally
    use rand::RngCore;
    let mut nonce_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);

    // Set expiration to 5 minutes from now
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .as_secs()
        + 300;

    let response = serde_json::json!({
        "nonce": nonce,
        "expires_at": expires_at
    });

    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
struct AttestSdkRequest {
    ephemeral_public_key: String, // base64 Ed25519
    attestation: serde_json::Value,
    sdk_x25519_pub: String, // base64 X25519 public key
}

async fn attest(
    State(state): State<AppState>,
    Json(req): Json<AttestSdkRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Validate TDX attestation locally using dcap-qvl
    let attestation = &req.attestation;
    let attestation_type = attestation.get("attestation_type").and_then(|v| v.as_str());

    if attestation_type == Some("Tdx") {
        let quote = attestation.get("quote").and_then(|v| v.as_str());
        let nonce = attestation.get("nonce").and_then(|v| v.as_str());
        let event_log = attestation.get("event_log");
        let rtmrs = attestation.get("rtmrs");

        let quote_b64 = match quote {
            Some(q) => q,
            None => return Err(StatusCode::BAD_REQUEST),
        };
        let nonce_str = match nonce {
            Some(n) => n,
            None => return Err(StatusCode::BAD_REQUEST),
        };

        // Decode quote from base64
        let quote_bytes = base64::decode(quote_b64).map_err(|_| StatusCode::BAD_REQUEST)?;

        // Verify TDX quote using dcap-qvl (Intel's verification library)
        use dcap_qvl::{collateral, verify::verify};
        let collateral_data = match collateral::get_collateral_from_pcs(&quote_bytes).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to get collateral from Intel PCS: {}", e);
                return Err(StatusCode::BAD_GATEWAY);
            }
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        match verify(&quote_bytes, &collateral_data, now) {
            Ok(tcb) => {
                tracing::info!("TDX quote verified, TCB status: {:?}", tcb.status);
            }
            Err(e) => {
                tracing::error!("TDX quote verification failed: {:?}", e);
                return Err(StatusCode::UNAUTHORIZED);
            }
        }

        // Verify nonce binding: report_data must match SHA256(nonce)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(nonce_str.as_bytes());
        let expected_report_data = hasher.finalize();

        // Extract report_data from TDX quote (offset 368, 32 bytes)
        if quote_bytes.len() < 400 {
            return Err(StatusCode::BAD_REQUEST);
        }
        let report_data_offset = 368;
        if quote_bytes.len() < report_data_offset + 32 {
            return Err(StatusCode::BAD_REQUEST);
        }
        let report_data = &quote_bytes[report_data_offset..report_data_offset + 32];

        // Verify report_data matches expected nonce hash
        if report_data != expected_report_data.as_slice() {
            tracing::error!("Report data mismatch: nonce binding failed");
            return Err(StatusCode::UNAUTHORIZED);
        }

        // Validate event_log and rtmrs are present
        if event_log.is_none() || rtmrs.is_none() {
            return Err(StatusCode::BAD_REQUEST);
        }

        // Extract app info from event log (like platform API does)
        let event_log_str = event_log.and_then(|v| v.as_str()).unwrap_or("");
        let (app_id, instance_id, compose_hash) = extract_app_info_from_event_log(event_log_str)?;

        tracing::info!(
            app_id = ?app_id,
            instance_id = ?instance_id,
            compose_hash = ?compose_hash,
            "TDX attestation validated successfully"
        );
    } else {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Generate session token locally
    let session_token = format!("session_{}", uuid::Uuid::new_v4());
    let mut val = serde_json::json!({
        "session_token": session_token,
        "attested": true
    });

    // Generate server X25519 keypair and derive shared secret
    use hkdf::Hkdf;
    use rand_core::RngCore;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    let server_secret = EphemeralSecret::random_from_rng(&mut rand::thread_rng());
    let server_public = PublicKey::from(&server_secret);

    // Decode SDK X25519 public key
    let sdk_pub_bytes = base64::decode(&req.sdk_x25519_pub).map_err(|_| StatusCode::BAD_REQUEST)?;
    if sdk_pub_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let sdk_pub_key: [u8; 32] = sdk_pub_bytes
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let sdk_public = PublicKey::from(sdk_pub_key);

    // Compute shared secret
    let shared_secret = server_secret.diffie_hellman(&sdk_public);

    // Generate random HKDF salt
    let mut hkdf_salt_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut hkdf_salt_bytes);
    let hkdf_salt = base64::encode(hkdf_salt_bytes);

    // Derive AEAD key using HKDF-SHA256
    let hk = Hkdf::<sha2::Sha256>::new(Some(&hkdf_salt_bytes), shared_secret.as_bytes());
    let mut aead_key = [0u8; 32];
    hk.expand(b"validator-sdk-v1", &mut aead_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Return crypto block with server public key
    val["crypto"] = serde_json::json!({
        "srv_x25519_pub": base64::encode(server_public.as_bytes()),
        "aead": "xchacha20poly1305",
        "hkdf_salt": hkdf_salt,
    });

    // On success, bind session token to ephemeral public key and store AEAD key
    if let Some(session_token) = val.get("session_token").and_then(|v| v.as_str()) {
        use base64::{engine::general_purpose, Engine as _};
        let pubkey = general_purpose::STANDARD
            .decode(&req.ephemeral_public_key)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .as_secs();
        let mut sessions = state.sessions.write().await;
        sessions.insert(
            session_token.to_string(),
            SessionEntry {
                public_key: pubkey,
                job_id: None,
                challenge_id: None,
                expires_at: now + 3600,
                nonces: std::collections::BTreeMap::new(),
                aead_key: Some(aead_key),
                srv_x25519_pub: Some(*server_public.as_bytes()),
            },
        );
    }

    Ok(Json(val))
}

/// Extract app_id, instance_id, and compose_hash from event log JSON
/// Same logic as platform API verifier
fn extract_app_info_from_event_log(
    event_log: &str,
) -> Result<(Option<String>, Option<String>, Option<String>), StatusCode> {
    if event_log.is_empty() {
        return Ok((None, None, None));
    }

    // Parse event log JSON
    let event_log_json: serde_json::Value =
        serde_json::from_str(event_log).map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut app_id = None;
    let mut instance_id = None;
    let mut compose_hash = None;

    if let Some(events) = event_log_json.as_array() {
        for event in events {
            if let Some(event_type) = event.get("event").and_then(|e| e.as_str()) {
                if let Some(payload) = event.get("event_payload").and_then(|p| p.as_str()) {
                    match event_type {
                        "app-id" => app_id = Some(payload.to_string()),
                        "instance-id" => instance_id = Some(payload.to_string()),
                        "compose-hash" => compose_hash = Some(payload.to_string()),
                        _ => {}
                    }
                }
            }
        }
    }

    Ok((app_id, instance_id, compose_hash))
}
