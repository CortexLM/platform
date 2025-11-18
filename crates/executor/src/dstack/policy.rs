/// Dstack policy
#[derive(Debug, Clone)]
pub struct DstackPolicy {
    pub allowed_images: Vec<String>,
    pub resource_limits: DstackResourceLimits,
    pub network_policy: DstackNetworkPolicy,
    pub security_policy: DstackSecurityPolicy,
}

/// Dstack resource limits
#[derive(Debug, Clone)]
pub struct DstackResourceLimits {
    pub cpu_cores: u32,
    pub memory_mb: u64,
    pub disk_mb: u64,
    pub network_mbps: u64,
}

/// Dstack network policy
#[derive(Debug, Clone)]
pub struct DstackNetworkPolicy {
    pub allow_outbound: bool,
    pub allowed_hosts: Vec<String>,
    pub allowed_ports: Vec<u16>,
    pub dns_servers: Vec<String>,
}

/// Dstack security policy
#[derive(Debug, Clone)]
pub struct DstackSecurityPolicy {
    pub require_attestation: bool,
    pub allowed_measurements: Vec<Vec<u8>>,
    pub encryption_required: bool,
    pub audit_logging: bool,
}

