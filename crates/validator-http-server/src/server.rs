use crate::attestation::{attest, attestation_challenge};
use crate::handlers::{
    challenge_callback, challenge_cleanup, delete_value, get_all_values, get_quota_status,
    get_value, health_check, init_challenge_quota, release_cvm, request_cvm, results_heartbeat,
    results_log, results_submit, set_value,
};
use crate::middleware::verify_signed_request;
use crate::types::{AppState, JobVmManagerTrait, NetworkProxyTrait};
use anyhow::Result;
use axum::middleware::from_fn_with_state;
use axum::routing::{delete, get, post};
use axum::Router;
use platform_engine_dynamic_values::DynamicValuesManager;
use platform_validator_challenge_manager::ChallengeManager;
use platform_validator_quota::CVMQuotaManager;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::info;

/// Start the HTTP server
pub async fn start_http_server(
    dynamic_values_manager: Arc<DynamicValuesManager>,
    network_proxy: Option<Arc<dyn NetworkProxyTrait + Send + Sync>>,
    cvm_quota_manager: Arc<CVMQuotaManager>,
    challenge_manager: Arc<ChallengeManager>,
    job_vm_manager: Arc<dyn JobVmManagerTrait + Send + Sync>,
) -> Result<()> {
    let sessions: Arc<RwLock<HashMap<String, crate::types::SessionEntry>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let network_proxy_clone = network_proxy.clone();
    
    let app_state = AppState {
        dynamic_values: dynamic_values_manager,
        cvm_quota: cvm_quota_manager,
        challenge_manager,
        job_vm: job_vm_manager,
        network_proxy: network_proxy_clone.clone(),
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
    if let Some(proxy) = network_proxy_clone {
        app = app.merge(proxy.create_router());
    }

    // Start garbage collector for nonce expiry
    let sessions_gc = sessions.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(300)).await; // Every 5 minutes
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
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
