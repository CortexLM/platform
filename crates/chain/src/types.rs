use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Chain client trait for interacting with blockchain networks
#[async_trait::async_trait]
pub trait ChainClient: Send + Sync {
    /// Submit weights to the chain
    async fn submit_weights(
        &self,
        weights: WeightSubmission,
    ) -> anyhow::Result<WeightSubmissionResult>;

    /// Get weights for a specific validator
    async fn get_weights(
        &self,
        validator_hotkey: &str,
    ) -> anyhow::Result<Option<BTreeMap<String, f64>>>;

    /// Get current validator set
    async fn get_validator_set(&self) -> anyhow::Result<ValidatorSet>;

    /// Get subnet information
    async fn get_subnet_info(&self) -> anyhow::Result<SubnetInfo>;

    /// Get current block number
    async fn get_current_block(&self) -> anyhow::Result<u64>;

    /// Get chain metadata
    fn metadata(&self) -> ChainMetadata;
}

/// Weight submission request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightSubmission {
    pub validator_hotkey: String,
    pub weights: BTreeMap<String, f64>,
    pub nonce: u64,
    pub signature: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub metadata: Option<BTreeMap<String, String>>,
}

/// Weight submission result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightSubmissionResult {
    pub transaction_hash: String,
    pub block_number: u64,
    pub success: bool,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Validator set information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: Vec<ValidatorInfo>,
    pub total_stake: f64,
    pub active_validators: u32,
    pub last_updated: DateTime<Utc>,
}

/// Individual validator information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub hotkey: String,
    pub uid: u32,
    pub stake: f64,
    pub performance_score: f64,
    pub last_seen: DateTime<Utc>,
    pub is_active: bool,
}

/// Subnet information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetInfo {
    pub subnet_id: u32,
    pub owner_hotkey: String,
    pub rake: f64,
    pub total_stake: f64,
    pub validator_count: u32,
    pub emission_rate: f64,
    pub last_updated: DateTime<Utc>,
}

/// Chain metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainMetadata {
    pub name: String,
    pub version: String,
    pub chain_id: String,
    pub rpc_url: String,
    pub ws_url: Option<String>,
    pub supported_features: Vec<String>,
}

/// Chain configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub name: String,
    pub rpc_url: String,
    pub ws_url: Option<String>,
    pub chain_id: String,
    pub timeout: Option<u64>,
    pub retry_attempts: Option<u32>,
    pub retry_delay: Option<u64>,
    pub max_concurrent_requests: Option<u32>,
    pub enable_metrics: Option<bool>,
    pub custom_headers: Option<BTreeMap<String, String>>,
}

/// Chain connection status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConnectionStatus {
    pub connected: bool,
    pub last_connected: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub connection_count: u64,
    pub latency_ms: Option<f64>,
}

/// Chain statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStats {
    pub total_submissions: u64,
    pub successful_submissions: u64,
    pub failed_submissions: u64,
    pub avg_submission_time_ms: f64,
    pub last_submission: Option<DateTime<Utc>>,
    pub current_block: u64,
    pub validator_count: u32,
    pub total_stake: f64,
}

/// Chain event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainEvent {
    WeightSubmitted {
        validator_hotkey: String,
        transaction_hash: String,
        block_number: u64,
    },
    ValidatorSetChanged {
        old_count: u32,
        new_count: u32,
        block_number: u64,
    },
    BlockProduced {
        block_number: u64,
        timestamp: DateTime<Utc>,
    },
    ConnectionLost {
        error: String,
        timestamp: DateTime<Utc>,
    },
    ConnectionRestored {
        timestamp: DateTime<Utc>,
    },
}

/// Chain subscription handle
pub struct ChainSubscription {
    pub id: Uuid,
    pub event_types: Vec<String>,
    pub callback: Box<dyn Fn(ChainEvent) + Send + Sync>,
}

/// Chain subscription manager
pub struct ChainSubscriptionManager {
    subscriptions: std::collections::HashMap<Uuid, ChainSubscription>,
}

impl ChainSubscriptionManager {
    pub fn new() -> Self {
        Self {
            subscriptions: std::collections::HashMap::new(),
        }
    }

    pub fn subscribe<F>(&mut self, event_types: Vec<String>, callback: F) -> Uuid
    where
        F: Fn(ChainEvent) + Send + Sync + 'static,
    {
        let id = Uuid::new_v4();
        let subscription = ChainSubscription {
            id,
            event_types: event_types.clone(),
            callback: Box::new(callback),
        };

        self.subscriptions.insert(id, subscription);
        id
    }

    pub fn unsubscribe(&mut self, id: Uuid) -> bool {
        self.subscriptions.remove(&id).is_some()
    }

    pub fn notify(&self, event: ChainEvent) {
        let event_type = match &event {
            ChainEvent::WeightSubmitted { .. } => "weight_submitted",
            ChainEvent::ValidatorSetChanged { .. } => "validator_set_changed",
            ChainEvent::BlockProduced { .. } => "block_produced",
            ChainEvent::ConnectionLost { .. } => "connection_lost",
            ChainEvent::ConnectionRestored { .. } => "connection_restored",
        };

        for subscription in self.subscriptions.values() {
            if subscription.event_types.contains(&event_type.to_string()) {
                (subscription.callback)(event.clone());
            }
        }
    }
}

/// Chain client builder
pub struct ChainClientBuilder {
    config: ChainConfig,
}

impl ChainClientBuilder {
    pub fn new() -> Self {
        Self {
            config: ChainConfig {
                name: "default".to_string(),
                rpc_url: "http://localhost:9944".to_string(),
                ws_url: None,
                chain_id: "default".to_string(),
                timeout: Some(30),
                retry_attempts: Some(3),
                retry_delay: Some(1000),
                max_concurrent_requests: Some(10),
                enable_metrics: Some(true),
                custom_headers: None,
            },
        }
    }

    pub fn name(mut self, name: String) -> Self {
        self.config.name = name;
        self
    }

    pub fn rpc_url(mut self, url: String) -> Self {
        self.config.rpc_url = url;
        self
    }

    pub fn ws_url(mut self, url: Option<String>) -> Self {
        self.config.ws_url = url;
        self
    }

    pub fn chain_id(mut self, id: String) -> Self {
        self.config.chain_id = id;
        self
    }

    pub fn timeout(mut self, timeout: u64) -> Self {
        self.config.timeout = Some(timeout);
        self
    }

    pub fn retry_attempts(mut self, attempts: u32) -> Self {
        self.config.retry_attempts = Some(attempts);
        self
    }

    pub fn retry_delay(mut self, delay: u64) -> Self {
        self.config.retry_delay = Some(delay);
        self
    }

    pub fn max_concurrent_requests(mut self, max: u32) -> Self {
        self.config.max_concurrent_requests = Some(max);
        self
    }

    pub fn enable_metrics(mut self, enable: bool) -> Self {
        self.config.enable_metrics = Some(enable);
        self
    }

    pub fn custom_headers(mut self, headers: BTreeMap<String, String>) -> Self {
        self.config.custom_headers = Some(headers);
        self
    }

    pub fn build(self) -> ChainConfig {
        self.config
    }
}

/// Chain client error types
#[derive(Debug, thiserror::Error)]
pub enum ChainClientError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Timeout error: {0}")]
    TimeoutError(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitError(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

/// Chain client result type
pub type ChainClientResult<T> = Result<T, ChainClientError>;

/// Chain client metrics collector
pub struct ChainClientMetricsCollector {
    stats: ChainStats,
    start_time: DateTime<Utc>,
}

impl ChainClientMetricsCollector {
    pub fn new() -> Self {
        Self {
            stats: ChainStats {
                total_submissions: 0,
                successful_submissions: 0,
                failed_submissions: 0,
                avg_submission_time_ms: 0.0,
                last_submission: None,
                current_block: 0,
                validator_count: 0,
                total_stake: 0.0,
            },
            start_time: Utc::now(),
        }
    }

    pub fn record_submission(&mut self, success: bool, submission_time_ms: f64) {
        self.stats.total_submissions += 1;
        self.stats.last_submission = Some(Utc::now());

        if success {
            self.stats.successful_submissions += 1;
        } else {
            self.stats.failed_submissions += 1;
        }

        // Update average submission time
        let total_time =
            self.stats.avg_submission_time_ms * (self.stats.total_submissions - 1) as f64;
        self.stats.avg_submission_time_ms =
            (total_time + submission_time_ms) / self.stats.total_submissions as f64;
    }

    pub fn update_block_info(&mut self, block_number: u64) {
        self.stats.current_block = block_number;
    }

    pub fn update_validator_info(&mut self, count: u32, total_stake: f64) {
        self.stats.validator_count = count;
        self.stats.total_stake = total_stake;
    }

    pub fn get_stats(&self) -> &ChainStats {
        &self.stats
    }

    pub fn get_uptime(&self) -> chrono::Duration {
        Utc::now() - self.start_time
    }

    pub fn reset(&mut self) {
        self.stats = ChainStats {
            total_submissions: 0,
            successful_submissions: 0,
            failed_submissions: 0,
            avg_submission_time_ms: 0.0,
            last_submission: None,
            current_block: 0,
            validator_count: 0,
            total_stake: 0.0,
        };
        self.start_time = Utc::now();
    }
}
