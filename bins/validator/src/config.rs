use crate::hotkey::derive_hotkey_from_mnemonic;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorConfig {
    pub validator_hotkey: String,
    pub hotkey_passphrase: String,
    pub platform_api_url: String,
    pub dstack_vmm_url: String,
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu_cores: u32,
    pub memory_mb: u64,
    pub disk_mb: u64,
    pub gpu_count: u32,
}

impl ValidatorConfig {
    pub fn load() -> Result<Self> {
        // Load from environment variables
        let passphrase = env::var("HOTKEY_PASSPHRASE")
            .context("HOTKEY_PASSPHRASE must be set with 24 mnemonic words")?;

        let validator_hotkey = derive_hotkey_from_mnemonic(&passphrase)
            .context("Failed to derive hotkey from mnemonic passphrase")?;

        let platform_api_url = "https://api.platform.network".to_string();

        let dstack_vmm_url =
            env::var("DSTACK_VMM_URL").unwrap_or_else(|_| "http://localhost:11530".to_string());

        // Get resource limits from environment or use defaults
        // These are the MAX ALLOCABLE resources (not the validator's own resources)
        let cpu_cores = env::var("MAX_ALLOCABLE_VCPU")
            .or_else(|_| env::var("VALIDATOR_CPU_CORES"))
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(20);

        let memory_mb = env::var("MAX_ALLOCABLE_MEMORY_MB")
            .or_else(|_| env::var("VALIDATOR_MEMORY_MB"))
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100000);

        let disk_mb = env::var("MAX_ALLOCABLE_DISK_MB")
            .or_else(|_| env::var("VALIDATOR_DISK_MB"))
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(500000);

        let gpu_count = env::var("VALIDATOR_GPU_COUNT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Ok(Self {
            validator_hotkey,
            hotkey_passphrase: passphrase,
            platform_api_url,
            dstack_vmm_url,
            resource_limits: ResourceLimits {
                cpu_cores,
                memory_mb,
                disk_mb,
                gpu_count,
            },
        })
    }
}
