use thiserror::Error;

/// Chain client error types
#[derive(Debug, Error)]
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

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Protocol error: {0}")]
    ProtocolError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
}

/// Chain client result type
pub type ChainClientResult<T> = Result<T, ChainClientError>;

/// Error conversion implementations
impl From<std::io::Error> for ChainClientError {
    fn from(err: std::io::Error) -> Self {
        ChainClientError::NetworkError(err.to_string())
    }
}

impl From<serde_json::Error> for ChainClientError {
    fn from(err: serde_json::Error) -> Self {
        ChainClientError::SerializationError(err.to_string())
    }
}

// Reqwest error conversion removed - reqwest not available

impl From<tokio::time::error::Elapsed> for ChainClientError {
    fn from(err: tokio::time::error::Elapsed) -> Self {
        ChainClientError::TimeoutError(err.to_string())
    }
}

impl From<anyhow::Error> for ChainClientError {
    fn from(err: anyhow::Error) -> Self {
        ChainClientError::InternalError(err.to_string())
    }
}

/// Error context extensions
pub trait ChainClientErrorExt<T> {
    fn with_context<F>(self, f: F) -> ChainClientResult<T>
    where
        F: FnOnce() -> String;

    fn with_context_msg(self, msg: &str) -> ChainClientResult<T>;
}

impl<T, E> ChainClientErrorExt<T> for Result<T, E>
where
    E: Into<ChainClientError>,
{
    fn with_context<F>(self, f: F) -> ChainClientResult<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| {
            let mut chain_err: ChainClientError = e.into();
            match &mut chain_err {
                ChainClientError::InternalError(ref mut msg) => {
                    *msg = format!("{}: {}", f(), msg);
                }
                _ => {
                    chain_err = ChainClientError::InternalError(format!("{}: {}", f(), chain_err));
                }
            }
            chain_err
        })
    }

    fn with_context_msg(self, msg: &str) -> ChainClientResult<T> {
        self.with_context(|| msg.to_string())
    }
}

/// Error recovery strategies
pub enum ErrorRecoveryStrategy {
    Retry {
        max_attempts: u32,
        delay_ms: u64,
        backoff_multiplier: f64,
    },
    Fallback {
        fallback_action: Box<dyn Fn() -> ChainClientResult<()> + Send + Sync>,
    },
    Ignore,
    Fail,
}

/// Error recovery manager
pub struct ErrorRecoveryManager {
    strategies: std::collections::HashMap<String, ErrorRecoveryStrategy>,
    default_strategy: ErrorRecoveryStrategy,
}

impl ErrorRecoveryManager {
    pub fn new() -> Self {
        Self {
            strategies: std::collections::HashMap::new(),
            default_strategy: ErrorRecoveryStrategy::Retry {
                max_attempts: 3,
                delay_ms: 1000,
                backoff_multiplier: 2.0,
            },
        }
    }

    pub fn add_strategy(&mut self, error_type: String, strategy: ErrorRecoveryStrategy) {
        self.strategies.insert(error_type, strategy);
    }

    pub fn set_default_strategy(&mut self, strategy: ErrorRecoveryStrategy) {
        self.default_strategy = strategy;
    }

    pub fn get_strategy(&self, error: &ChainClientError) -> &ErrorRecoveryStrategy {
        let error_type = match error {
            ChainClientError::ConnectionError(_) => "connection_error",
            ChainClientError::TimeoutError(_) => "timeout_error",
            ChainClientError::RateLimitError(_) => "rate_limit_error",
            ChainClientError::NetworkError(_) => "network_error",
            _ => "default",
        };

        self.strategies
            .get(error_type)
            .unwrap_or(&self.default_strategy)
    }
}

/// Error metrics collector
pub struct ErrorMetricsCollector {
    error_counts: std::collections::HashMap<String, u64>,
    error_timestamps: std::collections::HashMap<String, Vec<chrono::DateTime<chrono::Utc>>>,
    total_errors: u64,
    start_time: chrono::DateTime<chrono::Utc>,
}

impl ErrorMetricsCollector {
    pub fn new() -> Self {
        Self {
            error_counts: std::collections::HashMap::new(),
            error_timestamps: std::collections::HashMap::new(),
            total_errors: 0,
            start_time: chrono::Utc::now(),
        }
    }

    pub fn record_error(&mut self, error: &ChainClientError) {
        let error_type = self.get_error_type(error);
        let now = chrono::Utc::now();

        // Increment count
        *self.error_counts.entry(error_type.clone()).or_insert(0) += 1;
        self.total_errors += 1;

        // Record timestamp
        self.error_timestamps
            .entry(error_type)
            .or_insert_with(Vec::new)
            .push(now);
    }

    pub fn get_error_stats(&self) -> ErrorStats {
        let uptime = chrono::Utc::now() - self.start_time;
        let error_rate = if uptime.num_seconds() > 0 {
            self.total_errors as f64 / uptime.num_seconds() as f64
        } else {
            0.0
        };

        ErrorStats {
            total_errors: self.total_errors,
            error_rate,
            error_counts: self.error_counts.clone(),
            uptime_seconds: uptime.num_seconds(),
        }
    }

    pub fn get_recent_errors(&self, error_type: &str, last_minutes: i64) -> usize {
        let cutoff = chrono::Utc::now() - chrono::Duration::minutes(last_minutes);

        self.error_timestamps
            .get(error_type)
            .map(|timestamps| timestamps.iter().filter(|&&ts| ts > cutoff).count())
            .unwrap_or(0)
    }

    fn get_error_type(&self, error: &ChainClientError) -> String {
        match error {
            ChainClientError::ConnectionError(_) => "connection_error".to_string(),
            ChainClientError::TimeoutError(_) => "timeout_error".to_string(),
            ChainClientError::InvalidResponse(_) => "invalid_response".to_string(),
            ChainClientError::AuthenticationError(_) => "authentication_error".to_string(),
            ChainClientError::RateLimitError(_) => "rate_limit_error".to_string(),
            ChainClientError::InternalError(_) => "internal_error".to_string(),
            ChainClientError::ConfigurationError(_) => "configuration_error".to_string(),
            ChainClientError::SerializationError(_) => "serialization_error".to_string(),
            ChainClientError::DeserializationError(_) => "deserialization_error".to_string(),
            ChainClientError::NetworkError(_) => "network_error".to_string(),
            ChainClientError::ProtocolError(_) => "protocol_error".to_string(),
            ChainClientError::ValidationError(_) => "validation_error".to_string(),
            ChainClientError::NotFound(_) => "not_found".to_string(),
            ChainClientError::PermissionDenied(_) => "permission_denied".to_string(),
            ChainClientError::ResourceExhausted(_) => "resource_exhausted".to_string(),
            ChainClientError::UnsupportedOperation(_) => "unsupported_operation".to_string(),
        }
    }
}

/// Error statistics
#[derive(Debug, Clone)]
pub struct ErrorStats {
    pub total_errors: u64,
    pub error_rate: f64,
    pub error_counts: std::collections::HashMap<String, u64>,
    pub uptime_seconds: i64,
}

/// Error alerting system
pub struct ErrorAlertingSystem {
    alert_thresholds: std::collections::HashMap<String, u64>,
    alert_cooldown: std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>,
    cooldown_duration: chrono::Duration,
    alert_callbacks:
        std::collections::HashMap<String, Box<dyn Fn(&ChainClientError) + Send + Sync>>,
}

impl ErrorAlertingSystem {
    pub fn new() -> Self {
        Self {
            alert_thresholds: std::collections::HashMap::new(),
            alert_cooldown: std::collections::HashMap::new(),
            cooldown_duration: chrono::Duration::minutes(5),
            alert_callbacks: std::collections::HashMap::new(),
        }
    }

    pub fn set_threshold(&mut self, error_type: String, threshold: u64) {
        self.alert_thresholds.insert(error_type, threshold);
    }

    pub fn set_cooldown_duration(&mut self, duration: chrono::Duration) {
        self.cooldown_duration = duration;
    }

    pub fn register_alert_callback<F>(&mut self, error_type: String, callback: F)
    where
        F: Fn(&ChainClientError) + Send + Sync + 'static,
    {
        self.alert_callbacks.insert(error_type, Box::new(callback));
    }

    pub fn check_and_alert(&mut self, error: &ChainClientError, metrics: &ErrorMetricsCollector) {
        let error_type = self.get_error_type(error);
        let now = chrono::Utc::now();

        // Check if we're in cooldown
        if let Some(last_alert) = self.alert_cooldown.get(&error_type) {
            if now - *last_alert < self.cooldown_duration {
                return;
            }
        }

        // Check threshold
        if let Some(threshold) = self.alert_thresholds.get(&error_type) {
            let recent_errors = metrics.get_recent_errors(&error_type, 1); // Last minute
            if recent_errors >= *threshold as usize {
                // Trigger alert
                if let Some(callback) = self.alert_callbacks.get(&error_type) {
                    callback(error);
                }

                // Update cooldown
                self.alert_cooldown.insert(error_type, now);
            }
        }
    }

    fn get_error_type(&self, error: &ChainClientError) -> String {
        match error {
            ChainClientError::ConnectionError(_) => "connection_error".to_string(),
            ChainClientError::TimeoutError(_) => "timeout_error".to_string(),
            ChainClientError::RateLimitError(_) => "rate_limit_error".to_string(),
            ChainClientError::NetworkError(_) => "network_error".to_string(),
            _ => "other".to_string(),
        }
    }
}
