use super::policy::{DstackPolicy, DstackResourceLimits, DstackNetworkPolicy, DstackSecurityPolicy};

/// Dstack configuration
#[derive(Debug, Clone)]
pub struct DstackConfig {
    pub gateway_url: String,
    pub vmm_url: String,
    pub guest_agent_url: String,
    pub api_key: Option<String>,
    pub timeout: u64,
    pub policy: DstackPolicy,
}

