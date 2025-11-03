use crate::{PlatformApiClient, PlatformApiClientError, ErrorHandler};
use crate::types::*;
use async_trait::async_trait;
use std::time::Duration;

/// HTTP-based platform API client implementation
pub struct HttpPlatformApiClient {
    base_url: String,
    client: reqwest::Client,
    api_key: Option<String>,
    timeout: Duration,
}

impl HttpPlatformApiClient {
    /// Create a new HTTP platform API client
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            client: reqwest::Client::new(),
            api_key: None,
            timeout: Duration::from_secs(30),
        }
    }
    
    /// Set API key for authentication
    pub fn with_api_key(mut self, api_key: String) -> Self {
        self.api_key = Some(api_key);
        self
    }
    
    /// Set custom HTTP client
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }
    
    /// Set request timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    
    /// Build the client with configuration
    pub fn build(self) -> Self {
        self
    }
    
    /// Make a GET request
    async fn get<T>(&self, path: &str) -> Result<T, PlatformApiClientError>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.client
            .get(&url)
            .timeout(self.timeout);
        
        if let Some(ref api_key) = self.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }
        
        let response = request.send().await
            .map_err(|e| ErrorHandler::handle_network_error(&e))?;
        
        let status = response.status();
        let body = response.text().await
            .map_err(|e| PlatformApiClientError::NetworkError(e.to_string()))?;
        
        if status.is_success() {
            serde_json::from_str(&body)
                .map_err(|e| ErrorHandler::handle_deserialization_error(&e))
        } else {
            Err(ErrorHandler::handle_http_error(status.as_u16(), &body))
        }
    }
    
    /// Make a POST request
    async fn post<T, U>(&self, path: &str, body: &T) -> Result<U, PlatformApiClientError>
    where
        T: serde::Serialize,
        U: for<'de> serde::Deserialize<'de>,
    {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.client
            .post(&url)
            .json(body)
            .timeout(self.timeout);
        
        if let Some(ref api_key) = self.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }
        
        let response = request.send().await
            .map_err(|e| ErrorHandler::handle_network_error(&e))?;
        
        let status = response.status();
        let body = response.text().await
            .map_err(|e| PlatformApiClientError::NetworkError(e.to_string()))?;
        
        if status.is_success() {
            serde_json::from_str(&body)
                .map_err(|e| ErrorHandler::handle_deserialization_error(&e))
        } else {
            Err(ErrorHandler::handle_http_error(status.as_u16(), &body))
        }
    }
    
    /// Make a PUT request
    async fn put<T, U>(&self, path: &str, body: &T) -> Result<U, PlatformApiClientError>
    where
        T: serde::Serialize,
        U: for<'de> serde::Deserialize<'de>,
    {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.client
            .put(&url)
            .json(body)
            .timeout(self.timeout);
        
        if let Some(ref api_key) = self.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }
        
        let response = request.send().await
            .map_err(|e| ErrorHandler::handle_network_error(&e))?;
        
        let status = response.status();
        let body = response.text().await
            .map_err(|e| PlatformApiClientError::NetworkError(e.to_string()))?;
        
        if status.is_success() {
            serde_json::from_str(&body)
                .map_err(|e| ErrorHandler::handle_deserialization_error(&e))
        } else {
            Err(ErrorHandler::handle_http_error(status.as_u16(), &body))
        }
    }
    
    /// Make a DELETE request
    async fn delete(&self, path: &str) -> Result<(), PlatformApiClientError> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.client
            .delete(&url)
            .timeout(self.timeout);
        
        if let Some(ref api_key) = self.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }
        
        let response = request.send().await
            .map_err(|e| ErrorHandler::handle_network_error(&e))?;
        
        let status = response.status();
        
        if status.is_success() {
            Ok(())
        } else {
            let body = response.text().await
                .map_err(|e| PlatformApiClientError::NetworkError(e.to_string()))?;
            Err(ErrorHandler::handle_http_error(status.as_u16(), &body))
        }
    }
}

#[async_trait]
impl PlatformApiClient for HttpPlatformApiClient {
    async fn get_challenges(&self, page: u32, per_page: u32) -> Result<ChallengeListResponse, PlatformApiClientError> {
        let path = format!("/challenges?page={}&per_page={}", page, per_page);
        self.get(&path).await
    }
    
    async fn get_challenge(&self, id: uuid::Uuid) -> Result<ChallengeDetailResponse, PlatformApiClientError> {
        let path = format!("/challenges/{}", id);
        self.get(&path).await
    }
    
    async fn get_challenge_emissions(&self, id: uuid::Uuid) -> Result<EmissionsSchedule, PlatformApiClientError> {
        let path = format!("/challenges/{}/emissions", id);
        self.get(&path).await
    }
    
    async fn get_subnet_config(&self) -> Result<SubnetConfig, PlatformApiClientError> {
        self.get("/subnet/config").await
    }
    
    async fn claim_job(&self, request: ClaimJobRequest) -> Result<ClaimJobResponse, PlatformApiClientError> {
        self.post("/jobs/claim", &request).await
    }
    
    async fn get_next_job(&self, validator_hotkey: &str, runtime: Option<&str>) -> Result<Option<ClaimJobResponse>, PlatformApiClientError> {
        let path = if let Some(runtime) = runtime {
            format!("/jobs/next?validator_hotkey={}&runtime={}", validator_hotkey, runtime)
        } else {
            format!("/jobs/next?validator_hotkey={}", validator_hotkey)
        };
        self.get(&path).await
    }
    
    async fn submit_result(&self, request: SubmitResultRequest) -> Result<(), PlatformApiClientError> {
        self.post("/results", &request).await
    }
    
    async fn attest(&self, request: AttestationRequest) -> Result<AttestationResponse, PlatformApiClientError> {
        self.post("/attest", &request).await
    }
    
    async fn release_key(&self, request: KeyReleaseRequest) -> Result<KeyReleaseResponse, PlatformApiClientError> {
        self.post("/keys/release", &request).await
    }
    
    async fn get_emission_aggregate(&self, period_start: chrono::DateTime<chrono::Utc>, period_end: chrono::DateTime<chrono::Utc>) -> Result<EmissionAggregate, PlatformApiClientError> {
        let path = format!("/emissions/aggregate?period_start={}&period_end={}", 
            period_start.to_rfc3339(), period_end.to_rfc3339());
        self.get(&path).await
    }
}

/// Platform API client builder
pub struct PlatformApiClientBuilder {
    base_url: Option<String>,
    api_key: Option<String>,
    timeout: Option<Duration>,
    client: Option<reqwest::Client>,
}

impl PlatformApiClientBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            base_url: None,
            api_key: None,
            timeout: None,
            client: None,
        }
    }
    
    /// Set the base URL
    pub fn base_url(mut self, url: String) -> Self {
        self.base_url = Some(url);
        self
    }
    
    /// Set the API key
    pub fn api_key(mut self, key: String) -> Self {
        self.api_key = Some(key);
        self
    }
    
    /// Set the timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
    
    /// Set a custom HTTP client
    pub fn client(mut self, client: reqwest::Client) -> Self {
        self.client = Some(client);
        self
    }
    
    /// Build the client
    pub fn build(self) -> Result<HttpPlatformApiClient, PlatformApiClientError> {
        let base_url = self.base_url
            .ok_or_else(|| PlatformApiClientError::ConfigError("Base URL is required".to_string()))?;
        
        let mut client = HttpPlatformApiClient::new(base_url);
        
        if let Some(api_key) = self.api_key {
            client = client.with_api_key(api_key);
        }
        
        if let Some(timeout) = self.timeout {
            client = client.with_timeout(timeout);
        }
        
        if let Some(http_client) = self.client {
            client = client.with_client(http_client);
        }
        
        Ok(client.build())
    }
}

impl Default for PlatformApiClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}


