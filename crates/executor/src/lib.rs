use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub mod dstack_executor;
pub mod guest_agent_client;
pub mod standard_executor;
pub mod trusted_executor;
pub mod vmm_client;

pub use dstack_executor::*;
pub use guest_agent_client::*;
pub use standard_executor::*;
pub use trusted_executor::*;
pub use vmm_client::*;

/// Trusted executor trait for TEE execution
#[async_trait]
pub trait TrustedExecutor: Send + Sync {
    /// Perform attestation
    async fn attest(&self, nonce: &[u8]) -> anyhow::Result<AttestationReceipt>;

    /// Execute harness and submission in TEE
    async fn execute(
        &self,
        harness: HarnessBundle,
        submission: SubmissionBundle,
    ) -> anyhow::Result<EvalResult>;

    /// Get executor metadata
    fn metadata(&self) -> ExecutorMetadata;

    /// Check if executor is available
    async fn is_available(&self) -> bool;
}

/// Harness bundle for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessBundle {
    pub id: Uuid,
    pub challenge_id: Uuid,
    pub digest: String,
    pub size: u64,
    pub image_ref: Option<String>,
    pub manifest: Option<String>,
    pub config: HarnessConfig,
    pub created_at: DateTime<Utc>,
}

/// Submission bundle for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionBundle {
    pub id: Uuid,
    pub challenge_id: Uuid,
    pub miner_hotkey: String,
    pub digest: String,
    pub size: u64,
    pub encrypted: bool,
    pub public_key: Option<String>,
    pub metadata: SubmissionMetadata,
    pub created_at: DateTime<Utc>,
}

/// Harness configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessConfig {
    pub runtime: RuntimeType,
    pub resources: ResourceLimits,
    pub timeout: u64,
    pub environment: BTreeMap<String, String>,
    pub network_enabled: bool,
    pub attestation_required: bool,
}

/// Submission metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionMetadata {
    pub version: String,
    pub tags: Vec<String>,
    pub description: Option<String>,
    pub author: Option<String>,
}

/// Runtime type for execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuntimeType {
    Standard,
    Sgx,
    Sev,
    WasmEnclave,
}

/// Resource limits for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_cores: u32,
    pub memory_mb: u64,
    pub disk_mb: u64,
    pub network_bytes: Option<u64>,
}

/// Evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalResult {
    pub id: Uuid,
    pub challenge_id: Uuid,
    pub submission_id: Uuid,
    pub scores: BTreeMap<String, f64>,
    pub metrics: BTreeMap<String, f64>,
    pub logs: Vec<String>,
    pub error: Option<String>,
    pub execution_time: u64,
    pub resource_usage: ResourceUsage,
    pub attestation_receipt: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Resource usage during execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_time: u64,
    pub memory_peak: u64,
    pub disk_usage: u64,
    pub network_bytes: u64,
}

/// Attestation receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReceipt {
    pub id: Uuid,
    pub executor_type: RuntimeType,
    pub nonce: Vec<u8>,
    pub quote: Option<Vec<u8>>,
    pub report: Option<Vec<u8>>,
    pub measurements: Vec<Vec<u8>>,
    pub verified: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Executor metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub supported_runtimes: Vec<RuntimeType>,
    pub capabilities: Vec<String>,
    pub requirements: ExecutorRequirements,
}

/// Executor requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorRequirements {
    pub hardware: Vec<String>,
    pub software: Vec<String>,
    pub configuration: BTreeMap<String, String>,
}

/// Executor error types
#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error("Attestation error: {0}")]
    AttestationError(String),

    #[error("Execution error: {0}")]
    ExecutionError(String),

    #[error("Resource error: {0}")]
    ResourceError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Timeout error: {0}")]
    TimeoutError(String),

    #[error("Unavailable error: {0}")]
    UnavailableError(String),
}

/// Result type for executor operations
pub type ExecutorResult<T> = Result<T, ExecutorError>;

/// Executor factory for creating executors
pub struct ExecutorFactory;

impl ExecutorFactory {
    /// Create executor based on runtime type
    pub async fn create_executor(runtime: RuntimeType) -> ExecutorResult<Box<dyn TrustedExecutor>> {
        match runtime {
            RuntimeType::Standard => {
                let executor = StandardExecutor::new().await?;
                Ok(Box::new(executor))
            }
            RuntimeType::Sgx | RuntimeType::Sev | RuntimeType::WasmEnclave => {
                // All TEE types use dstack
                let executor = DstackExecutor::new().await?;
                Ok(Box::new(executor))
            }
        }
    }

    /// Create all available executors
    pub async fn create_all_executors() -> BTreeMap<RuntimeType, Box<dyn TrustedExecutor>> {
        let mut executors = BTreeMap::new();

        // Try to create each type of executor
        for runtime in [
            RuntimeType::Standard,
            RuntimeType::Sgx,
            RuntimeType::Sev,
            RuntimeType::WasmEnclave,
        ] {
            if let Ok(executor) = Self::create_executor(runtime.clone()).await {
                executors.insert(runtime, executor);
            }
        }

        executors
    }

    /// Get available runtime types
    pub async fn get_available_runtimes() -> Vec<RuntimeType> {
        let mut available = Vec::new();

        // Check standard runtime (always available)
        available.push(RuntimeType::Standard);

        // SGX and SEV executors use dstack framework
        // RuntimeType::Sgx and RuntimeType::Sev are mapped to DstackExecutor

        // Check dstack runtime
        if DstackExecutor::is_dstack_available().await {
            available.push(RuntimeType::WasmEnclave);
        }

        available
    }
}
