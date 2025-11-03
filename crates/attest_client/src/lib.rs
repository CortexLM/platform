use async_trait::async_trait;
use serde::{Deserialize, Serialize};
// BTreeMap import removed as it's not used
use uuid::Uuid;
use chrono::{DateTime, Utc};

pub mod client;
pub mod dstack_client;
pub mod types;

pub use client::*;
pub use dstack_client::*;
pub use types::*;

/// Attestation client trait
#[async_trait]
pub trait AttestationClient: Send + Sync {
    /// Perform attestation
    async fn attest(&self, nonce: &[u8]) -> anyhow::Result<AttestationResult>;
    
    /// Get attestation status
    async fn get_status(&self, session_id: Uuid) -> anyhow::Result<AttestationStatus>;
    
    /// Verify attestation
    async fn verify(&self, result: &AttestationResult) -> anyhow::Result<bool>;
    
    /// Get client metadata
    fn metadata(&self) -> ClientMetadata;
}

/// Attestation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResult {
    pub session_id: Uuid,
    pub nonce: Vec<u8>,
    pub quote: Option<Vec<u8>>,
    pub report: Option<Vec<u8>>,
    pub measurements: Vec<Vec<u8>>,
    pub verified: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Attestation status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationStatus {
    pub session_id: Uuid,
    pub status: Status,
    pub error: Option<String>,
    pub verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Status enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Status {
    Pending,
    InProgress,
    Completed,
    Failed,
    Expired,
}

/// Client metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub supported_types: Vec<AttestationType>,
    pub capabilities: Vec<String>,
}

/// Attestation type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttestationType {
    Dstack,
}

/// Attestation client error
#[derive(Debug, thiserror::Error)]
pub enum AttestationClientError {
    #[error("Attestation failed: {0}")]
    AttestationFailed(String),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Timeout error: {0}")]
    TimeoutError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Initialization error: {0}")]
    InitializationError(String),
}

/// Result type for attestation client operations
pub type AttestationClientResult<T> = Result<T, AttestationClientError>;
