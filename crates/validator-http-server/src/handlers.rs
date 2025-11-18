use crate::types::{
    AppState, ChallengeCallbackRequest, ChallengeCleanupRequest, CVMRequest, CVMResponse,
    DeleteValueResponse, GetAllValuesResponse, GetValueResponse, HeartbeatPayload, InitQuotaRequest,
    LogPayload, ReleaseCvmRequest, SetValueRequest, SetValueResponse, SubmitPayload,
};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use platform_validator_quota::ResourceRequest;
use serde_json;
use tracing::{error, info};

/// Health check endpoint
pub async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "validator-dynamic-values"
    }))
}

/// Get all values for a challenge
pub async fn get_all_values(
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

/// Get a specific value for a challenge
pub async fn get_value(
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

/// Set a value for a challenge
pub async fn set_value(
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

/// Delete a value for a challenge
pub async fn delete_value(
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

/// Request a CVM for a challenge
pub async fn request_cvm(
    State(state): State<AppState>,
    Json(request): Json<CVMRequest>,
) -> Result<Json<CVMResponse>, StatusCode> {
    info!(
        "CVM request received: challenge={}, miner={}, image={}",
        request.challenge_id, request.miner_hotkey, request.docker_image
    );

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
        Ok(platform_validator_quota::QuotaResult::Granted) => {
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
        Ok(platform_validator_quota::QuotaResult::Insufficient) => Ok(Json(CVMResponse {
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

/// Release a CVM
pub async fn release_cvm(
    State(state): State<AppState>,
    Path(cvm_id): Path<String>,
    Json(request): Json<ReleaseCvmRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    info!("Releasing CVM: {}", cvm_id);

    let parts: Vec<&str> = cvm_id.split('-').collect();
    if parts.len() >= 3 {
        let challenge_id = parts[1].to_string();

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

/// Get quota status for a challenge
pub async fn get_quota_status(
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

/// Initialize challenge quota (compatibility endpoint)
pub async fn init_challenge_quota(
    State(_state): State<AppState>,
    Json(request): Json<InitQuotaRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Dynamic quota system handles registration automatically
    // This endpoint is kept for compatibility but does nothing
    Ok(Json(serde_json::json!({
        "success": true,
        "message": format!("Dynamic quota system active for challenge {}", request.challenge_id)
    })))
}

/// Challenge callback handler
pub async fn challenge_callback(
    State(_state): State<AppState>,
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

/// Challenge cleanup handler
pub async fn challenge_cleanup(
    State(state): State<AppState>,
    Path(challenge_name): Path<String>,
    Json(request): Json<ChallengeCleanupRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    info!("Received cleanup request for challenge: {}", challenge_name);

    // Verify SecureMessage signature
    // Note: SecureMessage is defined in bins/validator/src/secure_message.rs
    // For now, we'll do basic signature verification here
    // TODO: Extract SecureMessage to a shared crate or pass as trait
    
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

/// Results heartbeat proxy
pub async fn results_heartbeat(
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

/// Results log proxy
pub async fn results_log(
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

/// Results submit proxy
pub async fn results_submit(
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
