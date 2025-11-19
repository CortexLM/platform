use crate::types::{AppState, AttestSdkRequest};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use base64;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info};
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Generate attestation challenge (nonce)
pub async fn attestation_challenge() -> Result<Json<serde_json::Value>, StatusCode> {
    // Generate attestation challenge locally
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

/// Attest SDK and issue session token
pub async fn attest(
    State(state): State<AppState>,
    Json(req): Json<AttestSdkRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Validate TDX attestation locally
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

        // Verify TDX quote using dcap-qvl
        tracing::info!("Verifying TDX quote with dcap-qvl: {} bytes", quote_bytes.len());

        // Get PCCS URL from environment or use default
        let pccs_url = std::env::var("PCCS_URL")
            .unwrap_or_else(|_| "https://pccs.bittensor.com/sgx/certification/v4/".to_string());
        
        // Get collateral and verify quote
        let collateral = match dcap_qvl::collateral::get_collateral(&pccs_url, &quote_bytes).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to get collateral from PCCS, trying Intel PCS: {}", e);
                dcap_qvl::collateral::get_collateral_from_pcs(&quote_bytes)
                    .await
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            }
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .as_secs();
            
        let verified_report = dcap_qvl::verify::verify(&quote_bytes, &collateral, now)
            .map_err(|e| {
                tracing::error!("Failed to verify TDX quote: {:?}", e);
                StatusCode::BAD_REQUEST
            })?;

        // Check TCB status
        let valid_statuses = ["UpToDate", "SWHardeningNeeded", "ConfigurationNeeded"];
        if !valid_statuses.contains(&verified_report.status.as_str()) {
            tracing::error!("Invalid TCB status: {}", verified_report.status);
            return Err(StatusCode::BAD_REQUEST);
        }

        // Parse quote to get report data
        let quote_struct = dcap_qvl::quote::Quote::parse(&quote_bytes)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
            
        let report_data = match &quote_struct.report {
            dcap_qvl::quote::Report::SgxEnclave(enclave_report) => &enclave_report.report_data,
            dcap_qvl::quote::Report::TD10(td_report) => &td_report.report_data,
            dcap_qvl::quote::Report::TD15(td_report) => &td_report.base.report_data,
        };

        // Verify nonce binding: report_data must match SHA256(nonce)
        let mut hasher = Sha256::new();
        hasher.update(nonce_str.as_bytes());
        let expected_report_data = hasher.finalize();

        // Verify report_data matches expected nonce hash
        if &report_data[..32] != expected_report_data.as_slice() {
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
    hk.expand(b"platform-api-sdk-v1", &mut aead_key)
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
            crate::types::SessionEntry {
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


