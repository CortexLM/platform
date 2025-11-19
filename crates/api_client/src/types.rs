use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Challenge list response
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeListResponse {
    pub challenges: Vec<ChallengeMetadata>,
    pub total: u64,
    pub page: u32,
    pub per_page: u32,
}

/// Challenge metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeMetadata {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub version: String,
    pub visibility: ChallengeVisibility,
    pub status: ChallengeStatus,
    pub owner: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub tags: Vec<String>,
}

/// Challenge visibility
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum ChallengeVisibility {
    Public,
    Private,
}

/// Challenge status
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum ChallengeStatus {
    Draft,
    Active,
    Paused,
    Archived,
}

/// Challenge detail response
#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeDetailResponse {
    pub metadata: ChallengeMetadata,
    pub emissions: Option<EmissionsSchedule>,
}

// HarnessBundle removed
// HarnessConfig removed
// ResourceLimits removed
// DatasetArtifact removed

/// Emissions schedule
#[derive(Debug, Serialize, Deserialize)]
pub struct EmissionsSchedule {
    pub challenge_id: Uuid,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub emission_rate: f64,
    pub total_emission: Option<f64>,
    pub distribution_curve: DistributionCurve,
}

/// Distribution curve
#[derive(Debug, Serialize, Deserialize)]
pub enum DistributionCurve {
    Linear,
    Exponential { decay_factor: f64 },
    Step { intervals: Vec<(DateTime<Utc>, f64)> },
}

/// Subnet configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct SubnetConfig {
    pub owner_hotkey: String,
    pub rake: f64,
    pub validator_set_hints: Vec<ValidatorHint>,
    pub timing_windows: TimingWindows,
    pub emission_schedule: EmissionSchedule,
    pub updated_at: DateTime<Utc>,
    pub version: u32,
}

/// Validator hint
#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorHint {
    pub hotkey: String,
    pub uid: Option<u32>,
    pub stake: Option<f64>,
    pub performance_score: Option<f64>,
    pub last_seen: Option<DateTime<Utc>>,
}

/// Timing windows
#[derive(Debug, Serialize, Deserialize)]
pub struct TimingWindows {
    pub job_claim_window: u64,
    pub job_execution_timeout: u64,
    pub weight_submission_window: u64,
    pub emission_distribution_window: u64,
    pub attestation_timeout: u64,
}

/// Emission schedule
#[derive(Debug, Serialize, Deserialize)]
pub struct EmissionSchedule {
    pub total_supply: f64,
    pub emission_rate: f64,
    pub distribution_period: u64,
    pub owner_rake_rate: f64,
    pub validator_reward_rate: f64,
    pub miner_reward_rate: f64,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
}

/// Job claim request
#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimJobRequest {
    pub validator_hotkey: String,
    pub runtime: RuntimeType,
    pub capabilities: Vec<String>,
}

/// Job claim response
#[derive(Debug, Serialize, Deserialize)]
pub struct ClaimJobResponse {
    pub job: JobMetadata,
    pub config: JobConfig,
}

/// Job metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct JobMetadata {
    pub id: Uuid,
    pub challenge_id: Uuid,
    pub validator_hotkey: Option<String>,
    pub status: JobStatus,
    pub priority: JobPriority,
    pub runtime: RuntimeType,
    pub created_at: DateTime<Utc>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub timeout_at: Option<DateTime<Utc>>,
    pub retry_count: u32,
    pub max_retries: u32,
}

/// Job status
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum JobStatus {
    Pending,
    Claimed,
    Running,
    Completed,
    Failed,
    Timeout,
}

/// Job priority
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum JobPriority {
    Low,
    Normal,
    High,
    Critical,
}

/// Job configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct JobConfig {
    pub timeout: u64,
    pub environment: BTreeMap<String, String>,
    pub attestation_required: bool,
    pub policy: Option<String>,
}

/// Submit result request
#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitResultRequest {
    pub job_id: Uuid,
    pub result: EvalResult,
    pub receipts: Vec<String>,
}

/// Evaluation result
#[derive(Debug, Serialize, Deserialize)]
pub struct EvalResult {
    pub job_id: Uuid,
    pub submission_id: Uuid,
    pub scores: BTreeMap<String, f64>,
    pub metrics: BTreeMap<String, f64>,
    pub logs: Vec<String>,
    pub error: Option<String>,
    pub execution_time: u64,
    pub resource_usage: ResourceUsage,
    pub attestation_receipt: Option<String>,
}

/// Resource usage
#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_time: u64,
    pub memory_peak: u64,
    pub disk_usage: u64,
    pub network_bytes: u64,
}

/// Attestation request
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationRequest {
    pub attestation_type: AttestationType,
    pub quote: Option<Vec<u8>>,
    pub report: Option<Vec<u8>>,
    pub nonce: Vec<u8>,
    pub measurements: Vec<Vec<u8>>,
    pub capabilities: Vec<String>,
}

/// Attestation type
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum AttestationType {
    SgxDcap,
    SevSnp,
    Tdx,
}

/// Attestation response
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub session_token: String,
    pub status: AttestationStatus,
    pub expires_at: DateTime<Utc>,
    pub verified_measurements: Vec<Vec<u8>>,
    pub policy: String,
    pub error: Option<String>,
}

/// Attestation status
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum AttestationStatus {
    Pending,
    Verified,
    Failed,
    Expired,
}

/// Key release request
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyReleaseRequest {
    pub session_token: String,
    pub policy: String,
    pub harness_digest: String,
    pub measurements: Vec<Vec<u8>>,
    pub nonce: Vec<u8>,
}

/// Key release response
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyReleaseResponse {
    pub sealed_key: Vec<u8>,
    pub key_id: String,
    pub expires_at: DateTime<Utc>,
    pub policy: String,
    pub error: Option<String>,
}

/// Emission aggregate
#[derive(Debug, Serialize, Deserialize)]
pub struct EmissionAggregate {
    pub total_emissions: f64,
    pub challenge_emissions: f64,
    pub validator_emissions: f64,
    pub miner_emissions: f64,
    pub owner_emissions: f64,
    pub network_emissions: f64,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub distributions: Vec<EmissionDistribution>,
}

/// Emission distribution
#[derive(Debug, Serialize, Deserialize)]
pub struct EmissionDistribution {
    pub schedule_id: Uuid,
    pub recipient_hotkey: String,
    pub amount: f64,
    pub percentage: f64,
    pub distributed_at: DateTime<Utc>,
    pub transaction_hash: Option<String>,
    pub receipt: String,
}


