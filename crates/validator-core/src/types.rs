use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Challenge specification structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeSpec {
    pub id: String,
    pub name: String,
    pub compose_hash: String,
    pub compose_yaml: String,
    pub version: String,
    pub images: Vec<String>,
    pub resources: ChallengeResources,
    pub ports: Vec<ChallengePort>,
    pub env: HashMap<String, String>,
    pub emission_share: f64,
    pub mechanism_id: u8,
    pub weight: Option<f64>,
    pub description: Option<String>,
    pub mermaid_chart: Option<String>,
    pub github_repo: Option<String>,
    pub dstack_image: Option<String>,
    pub dstack_config: Option<DstackConfig>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Dstack configuration for CVM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DstackConfig {
    #[serde(default = "default_true")]
    pub gateway_enabled: bool,
    #[serde(default = "default_true")]
    pub kms_enabled: bool,
    #[serde(default = "default_false")]
    pub local_key_provider_enabled: bool,
    #[serde(default = "default_true")]
    pub public_logs: bool,
    #[serde(default = "default_true")]
    pub public_sysinfo: bool,
    #[serde(default = "default_true")]
    pub public_tcbinfo: bool,
    #[serde(default = "default_false")]
    pub secure_time: bool,
    #[serde(default = "default_false")]
    pub no_instance_id: bool,
    pub key_provider_id: Option<String>,
    pub allowed_envs: Option<Vec<String>>,
    pub pre_launch_script: Option<String>,
    #[serde(default = "default_false")]
    pub hugepages: bool,
    #[serde(default = "default_false")]
    pub pin_numa: bool,
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

/// Challenge resources specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResources {
    pub vcpu: u32,
    pub memory: String,
    pub disk: Option<String>,
}

/// Challenge port configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengePort {
    pub container: u16,
    pub protocol: String,
}

/// Validator challenge status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorChallengeStatus {
    pub validator_hotkey: String,
    pub compose_hash: String,
    pub state: String,
    pub last_heartbeat: DateTime<Utc>,
    pub penalty_reason: Option<String>,
}

/// Challenge state lifecycle
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChallengeState {
    Created,
    Provisioning,
    Probing,
    Active,
    Failed,
    Recycling,
    Deprecated,
}

impl ChallengeState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChallengeState::Created => "created",
            ChallengeState::Provisioning => "provisioning",
            ChallengeState::Probing => "probing",
            ChallengeState::Active => "active",
            ChallengeState::Failed => "failed",
            ChallengeState::Recycling => "recycling",
            ChallengeState::Deprecated => "deprecated",
        }
    }
}

