use serde::{Deserialize, Serialize};

/// Resource requirements for a VM
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ResourceRequest {
    pub cpu_cores: u32,
    pub memory_mb: u64,
    pub disk_mb: u64,
}

/// Resource capacity totals
#[derive(Debug, Clone, Copy)]
pub struct ResourceCapacity {
    pub cpu_cores: u32,
    pub memory_mb: u64,
    pub disk_mb: u64,
}

/// Quota reservation result
#[derive(Debug, Clone, PartialEq)]
pub enum QuotaResult {
    Granted,
    Insufficient,
}

