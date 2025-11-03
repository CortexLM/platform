use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Challenge specification loaded from platform.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeSpec {
    /// Challenge metadata
    pub name: String,
    pub description: String,
    pub version: String,

    /// GitHub repository information
    pub github_repo: String,
    pub github_commit: String,

    /// Resource requirements
    pub resources: ResourceRequirements,

    /// Language configuration
    pub language: LanguageConfig,

    /// Scoring endpoints
    pub endpoints: EndpointConfig,
}

/// Resource requirements for challenge execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    /// CPU cores required
    pub cpu_cores: u32,

    /// RAM in MB
    pub memory_mb: u64,

    /// Disk space in MB
    pub disk_mb: u64,

    /// GPU requirements
    pub gpu: Option<GpuRequirements>,

    /// Network whitelist
    pub network_whitelist: Vec<String>,
}

/// GPU requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuRequirements {
    /// Number of GPUs required
    pub count: u32,

    /// Minimum GPU memory in MB
    pub memory_mb: u64,

    /// GPU model whitelist (e.g., ["NVIDIA A100", "NVIDIA V100"])
    pub models: Vec<String>,
}

/// Language configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanguageConfig {
    /// Primary language
    pub primary: String,

    /// Entry point script
    pub entrypoint: String,

    /// Command arguments
    pub args: Vec<String>,

    /// Environment variables
    pub env: HashMap<String, String>,
}

/// Endpoint configuration for scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointConfig {
    /// Base URL for the challenge API
    pub base_url: String,

    /// Scoring endpoint
    pub score: String,

    /// Validation endpoint
    pub validate: String,

    /// Health check endpoint
    pub health: String,
}

impl Default for ChallengeSpec {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            description: "Default challenge".to_string(),
            version: "1.0.0".to_string(),
            github_repo: "".to_string(),
            github_commit: "".to_string(),
            resources: ResourceRequirements {
                cpu_cores: 2,
                memory_mb: 1024,
                disk_mb: 5120,
                gpu: None,
                network_whitelist: vec![],
            },
            language: LanguageConfig {
                primary: "python".to_string(),
                entrypoint: "main.py".to_string(),
                args: vec![],
                env: HashMap::new(),
            },
            endpoints: EndpointConfig {
                base_url: "http://localhost:8080".to_string(),
                score: "/score".to_string(),
                validate: "/validate".to_string(),
                health: "/health".to_string(),
            },
        }
    }
}
