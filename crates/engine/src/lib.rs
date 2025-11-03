use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

pub mod adapter;
pub mod evaluator;
pub mod sandbox;
pub mod scoring;
pub mod metrics;

pub use adapter::*;
pub use evaluator::*;
pub use sandbox::*;
pub use scoring::*;
pub use metrics::*;

/// Challenge adapter trait for running evaluations
#[async_trait]
pub trait ChallengeAdapter: Send + Sync {
    /// Prepare the adapter with harness bundle
    async fn prepare(&mut self, harness: &HarnessBundle) -> anyhow::Result<()>;
    
    /// Run evaluation with submission bundle
    async fn run(&mut self, submission: &SubmissionBundle) -> anyhow::Result<EvalResult>;
    
    /// Score the evaluation result
    fn score(&self, result: &EvalResult) -> anyhow::Result<f64>;
    
    /// Get adapter metadata
    fn metadata(&self) -> AdapterMetadata;
}

/// Harness bundle for challenge execution
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

/// Submission bundle for evaluation
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

/// Adapter metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub supported_runtimes: Vec<RuntimeType>,
    pub capabilities: Vec<String>,
}

/// Engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    pub max_concurrent_evaluations: u32,
    pub evaluation_timeout: u64,
    pub resource_limits: ResourceLimits,
    pub sandbox_config: SandboxConfig,
    pub scoring_config: ScoringConfig,
}

/// Sandbox configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    pub isolation_level: IsolationLevel,
    pub network_policy: NetworkPolicy,
    pub filesystem_policy: FilesystemPolicy,
    pub resource_monitoring: bool,
}

/// Isolation level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IsolationLevel {
    None,
    Process,
    Container,
    Vm,
    Tee,
}

/// Network policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub allow_outbound: bool,
    pub allowed_hosts: Vec<String>,
    pub allowed_ports: Vec<u16>,
    pub dns_servers: Vec<String>,
}

/// Filesystem policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    pub read_only: bool,
    pub allowed_paths: Vec<String>,
    pub denied_paths: Vec<String>,
    pub tmpfs_size: Option<u64>,
}

/// Scoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringConfig {
    pub algorithm: ScoringAlgorithm,
    pub weights: BTreeMap<String, f64>,
    pub normalization: NormalizationMethod,
    pub thresholds: BTreeMap<String, f64>,
}

/// Scoring algorithm
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScoringAlgorithm {
    Linear,
    Logarithmic,
    Exponential,
    Custom(String),
}

/// Normalization method
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NormalizationMethod {
    None,
    MinMax,
    ZScore,
    Robust,
}

/// Engine error types
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("Adapter error: {0}")]
    AdapterError(String),
    
    #[error("Sandbox error: {0}")]
    SandboxError(String),
    
    #[error("Scoring error: {0}")]
    ScoringError(String),
    
    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),
    
    #[error("Timeout error: {0}")]
    TimeoutError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for engine operations
pub type EngineResult<T> = Result<T, EngineError>;


