use platform_engine_dynamic_values::DynamicValuesManager;
use platform_validator_challenge_manager::ChallengeManager;
use platform_validator_quota::{CVMQuotaManager, ResourceRequest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// Re-export types that might be needed elsewhere
pub use platform_validator_quota::{QuotaResult, ResourceRequest as QuotaResourceRequest};

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub dynamic_values: Arc<DynamicValuesManager>,
    pub cvm_quota: Arc<CVMQuotaManager>,
    pub challenge_manager: Arc<ChallengeManager>,
    pub job_vm: Arc<dyn JobVmManagerTrait + Send + Sync>,
    pub network_proxy: Option<Arc<dyn NetworkProxyTrait + Send + Sync>>,
    pub sessions: Arc<RwLock<HashMap<String, SessionEntry>>>,
}

/// Session entry for authenticated clients
#[derive(Clone, Debug)]
pub struct SessionEntry {
    pub public_key: Vec<u8>,
    pub job_id: Option<String>,
    pub challenge_id: Option<String>,
    pub expires_at: u64,
    pub nonces: std::collections::BTreeMap<String, u64>, // nonce -> timestamp
    pub aead_key: Option<[u8; 32]>,                      // XChaCha20-Poly1305 key for encrypted bodies
    pub srv_x25519_pub: Option<[u8; 32]>,                // Server X25519 public key
}

// Request/Response types for dynamic values API
#[derive(Serialize, Deserialize)]
pub struct SetValueRequest {
    pub key: String,
    pub value: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
pub struct SetValueResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct GetValueResponse {
    pub value: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
pub struct GetAllValuesResponse {
    pub values: HashMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize)]
pub struct DeleteValueResponse {
    pub success: bool,
    pub message: String,
}

// CVM request/response types
#[derive(Serialize, Deserialize)]
pub struct CVMRequest {
    pub challenge_id: String,
    pub miner_hotkey: String,
    pub docker_image: String,
    pub resources: CVMResources,
}

#[derive(Serialize, Deserialize)]
pub struct CVMResources {
    pub cpu_cores: u32,
    pub memory_mb: u64,
    pub disk_mb: u64,
}

#[derive(Serialize, Deserialize)]
pub struct CVMResponse {
    pub success: bool,
    pub cvm_id: Option<String>,
    pub executor_url: Option<String>,
    pub message: String,
}

#[derive(Deserialize)]
pub struct ReleaseCvmRequest {
    pub cpu_cores: u32,
    pub memory_mb: u64,
    pub disk_mb: u64,
}

#[derive(Deserialize)]
pub struct InitQuotaRequest {
    pub challenge_id: String,
    pub total_quota: u32,
}

#[derive(Deserialize)]
pub struct ChallengeCallbackRequest {
    pub job_id: String,
    pub results: serde_json::Value,
    pub score: f64,
    pub execution_time_ms: u64,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct ChallengeCleanupRequest {
    pub message_type: String,
    pub data: serde_json::Value,
    pub timestamp: u64,
    pub nonce: String,
    pub signature: String,
    pub public_key: String,
}

// Results proxy types
#[derive(Debug, Serialize, Deserialize)]
pub struct HeartbeatPayload {
    pub timestamp: i64,
    pub status: String,
    pub metrics: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogPayload {
    pub timestamp: i64,
    pub level: String,
    pub message: String,
    pub component: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitPayload {
    pub session_token: String,
    pub job_type: String,
    pub score: f64,
    pub metrics: std::collections::BTreeMap<String, f64>,
    pub logs: Vec<String>,
    pub allowed_log_containers: Option<Vec<String>>,
    pub error: Option<String>,
}

// Attestation types
#[derive(Debug, Deserialize)]
pub struct ChallengeNonceResponse {
    pub nonce: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct AttestSdkRequest {
    pub ephemeral_public_key: String, // base64 Ed25519
    pub attestation: serde_json::Value,
    pub sdk_x25519_pub: String, // base64 X25519 public key
}

// Traits for dependency injection
#[async_trait::async_trait]
pub trait JobVmManagerTrait {
    async fn cleanup_challenge(&self, challenge_name: &str) -> anyhow::Result<usize>;
}

#[async_trait::async_trait]
pub trait NetworkProxyTrait {
    fn create_router(&self) -> axum::Router;
}

