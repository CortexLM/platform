use thiserror::Error;

/// Platform API client errors
#[derive(Error, Debug)]
pub enum PlatformApiClientError {
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("HTTP error: {status} - {message}")]
    HttpError { status: u16, message: String },
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    
    #[error("Authentication error: {0}")]
    AuthenticationError(String),
    
    #[error("Authorization error: {0}")]
    AuthorizationError(String),
    
    #[error("Rate limit exceeded: {limit}")]
    RateLimitExceeded { limit: u32 },
    
    #[error("Timeout error: {0}")]
    TimeoutError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Resource not found: {resource}")]
    ResourceNotFound { resource: String },
    
    #[error("Service unavailable: {service}")]
    ServiceUnavailable { service: String },
    
    #[error("Internal server error: {0}")]
    InternalError(String),
}

impl PlatformApiClientError {
    /// Get HTTP status code for the error
    pub fn status_code(&self) -> Option<u16> {
        match self {
            PlatformApiClientError::HttpError { status, .. } => Some(*status),
            PlatformApiClientError::AuthenticationError(_) => Some(401),
            PlatformApiClientError::AuthorizationError(_) => Some(403),
            PlatformApiClientError::ResourceNotFound { .. } => Some(404),
            PlatformApiClientError::RateLimitExceeded { .. } => Some(429),
            PlatformApiClientError::TimeoutError(_) => Some(408),
            PlatformApiClientError::ServiceUnavailable { .. } => Some(503),
            PlatformApiClientError::InternalError(_) => Some(500),
            _ => None,
        }
    }
    
    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            PlatformApiClientError::NetworkError(_)
                | PlatformApiClientError::TimeoutError(_)
                | PlatformApiClientError::ServiceUnavailable { .. }
                | PlatformApiClientError::InternalError(_)
        )
    }
    
    /// Get error category
    pub fn category(&self) -> &'static str {
        match self {
            PlatformApiClientError::NetworkError(_) => "network",
            PlatformApiClientError::HttpError { .. } => "http",
            PlatformApiClientError::SerializationError(_) => "serialization",
            PlatformApiClientError::DeserializationError(_) => "deserialization",
            PlatformApiClientError::AuthenticationError(_) => "auth",
            PlatformApiClientError::AuthorizationError(_) => "auth",
            PlatformApiClientError::RateLimitExceeded { .. } => "rate_limit",
            PlatformApiClientError::TimeoutError(_) => "timeout",
            PlatformApiClientError::ConfigError(_) => "config",
            PlatformApiClientError::ValidationError(_) => "validation",
            PlatformApiClientError::ResourceNotFound { .. } => "resource",
            PlatformApiClientError::ServiceUnavailable { .. } => "service",
            PlatformApiClientError::InternalError(_) => "internal",
        }
    }
}

/// Result type alias for Platform API client operations
pub type PlatformApiClientResult<T> = Result<T, PlatformApiClientError>;

/// Error response from API
#[derive(Debug, serde::Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    pub code: u16,
    pub category: String,
    pub retryable: bool,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub request_id: Option<String>,
}

impl From<ErrorResponse> for PlatformApiClientError {
    fn from(response: ErrorResponse) -> Self {
        match response.code {
            401 => PlatformApiClientError::AuthenticationError(response.message),
            403 => PlatformApiClientError::AuthorizationError(response.message),
            404 => PlatformApiClientError::ResourceNotFound { 
                resource: response.message 
            },
            408 => PlatformApiClientError::TimeoutError(response.message),
            429 => PlatformApiClientError::RateLimitExceeded { 
                limit: 100 // Default limit
            },
            503 => PlatformApiClientError::ServiceUnavailable { 
                service: response.message 
            },
            500..=599 => PlatformApiClientError::InternalError(response.message),
            _ => PlatformApiClientError::HttpError { 
                status: response.code, 
                message: response.message 
            },
        }
    }
}

/// Error context for better error handling
#[derive(Debug)]
pub struct ErrorContext {
    pub operation: String,
    pub resource: Option<String>,
    pub request_id: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ErrorContext {
    pub fn new(operation: String) -> Self {
        Self {
            operation,
            resource: None,
            request_id: None,
            timestamp: chrono::Utc::now(),
        }
    }
    
    pub fn with_resource(mut self, resource: String) -> Self {
        self.resource = Some(resource);
        self
    }
    
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }
}

/// Error handler for API client
pub struct ErrorHandler;

impl ErrorHandler {
    /// Handle HTTP response errors
    pub fn handle_http_error(status: u16, body: &str) -> PlatformApiClientError {
        match status {
            400 => PlatformApiClientError::ValidationError(format!("Bad request: {}", body)),
            401 => PlatformApiClientError::AuthenticationError("Unauthorized".to_string()),
            403 => PlatformApiClientError::AuthorizationError("Forbidden".to_string()),
            404 => PlatformApiClientError::ResourceNotFound { 
                resource: "Resource not found".to_string() 
            },
            408 => PlatformApiClientError::TimeoutError("Request timeout".to_string()),
            429 => PlatformApiClientError::RateLimitExceeded { limit: 100 },
            500 => PlatformApiClientError::InternalError("Internal server error".to_string()),
            502 => PlatformApiClientError::ServiceUnavailable { 
                service: "Bad gateway".to_string() 
            },
            503 => PlatformApiClientError::ServiceUnavailable { 
                service: "Service unavailable".to_string() 
            },
            504 => PlatformApiClientError::TimeoutError("Gateway timeout".to_string()),
            _ => PlatformApiClientError::HttpError { 
                status, 
                message: body.to_string() 
            },
        }
    }
    
    /// Handle network errors
    pub fn handle_network_error(error: &reqwest::Error) -> PlatformApiClientError {
        if error.is_timeout() {
            PlatformApiClientError::TimeoutError("Request timeout".to_string())
        } else if error.is_connect() {
            PlatformApiClientError::NetworkError("Connection failed".to_string())
        } else if error.is_request() {
            PlatformApiClientError::NetworkError("Request failed".to_string())
        } else {
            PlatformApiClientError::NetworkError(error.to_string())
        }
    }
    
    /// Handle serialization errors
    pub fn handle_serialization_error(error: &serde_json::Error) -> PlatformApiClientError {
        PlatformApiClientError::SerializationError(error.to_string())
    }
    
    /// Handle deserialization errors
    pub fn handle_deserialization_error(error: &serde_json::Error) -> PlatformApiClientError {
        PlatformApiClientError::DeserializationError(error.to_string())
    }
}


