



use anyhow::Result;
use axum::{
    extract::State,
    http::{Method, StatusCode},
    response::Json,
    routing::post,
    Router,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{error, info};

#[derive(Clone)]
pub struct NetworkPolicy {
    enabled: bool,
    whitelist: Vec<String>,
    requests_per_second: f64,
    burst_size: usize,
}

#[derive(Clone)]
pub struct NetworkProxy {
    policy: NetworkPolicy,
    rate_limiters: Arc<RwLock<HashMap<String, RateLimiter>>>,
    client: Client,
}

#[derive(Clone)]
struct RateLimiter {
    tokens: f64,
    last_update: Instant,
    requests_per_second: f64,
    burst_size: usize,
}

impl RateLimiter {
    fn new(requests_per_second: f64, burst_size: usize) -> Self {
        Self {
            tokens: burst_size as f64,
            last_update: Instant::now(),
            requests_per_second,
            burst_size,
        }
    }

    fn acquire(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();

        // Add tokens based on elapsed time
        self.tokens =
            (self.tokens + elapsed * self.requests_per_second).min(self.burst_size as f64);
        self.last_update = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl NetworkProxy {
    pub fn new(policy: NetworkPolicy) -> Self {
        Self {
            policy,
            rate_limiters: Arc::new(RwLock::new(HashMap::new())),
            client: Client::new(),
        }
    }

    fn check_url_allowed(&self, url: &str) -> bool {
        if !self.policy.enabled {
            return true;
        }

        // Parse URL and extract domain
        let domain = match url::Url::parse(url) {
            Ok(parsed) => {
                let host = parsed.host_str().unwrap_or("");
                format!("{}://{}", parsed.scheme(), host)
            }
            Err(_) => return false,
        };

        // Check exact match
        if self.policy.whitelist.contains(&domain) {
            return true;
        }

        // Check wildcard patterns
        for allowed in &self.policy.whitelist {
            if allowed.ends_with("*") {
                let prefix = &allowed[..allowed.len() - 1];
                if domain.starts_with(prefix) {
                    return true;
                }
            }
        }

        false
    }

    async fn check_rate_limit(&self, job_id: &str) -> bool {
        let mut limiters = self.rate_limiters.write().await;

        let limiter = limiters.entry(job_id.to_string()).or_insert_with(|| {
            RateLimiter::new(self.policy.requests_per_second, self.policy.burst_size)
        });

        limiter.acquire()
    }

    pub async fn proxy_request(
        &self,
        method: Method,
        url: String,
        headers: HashMap<String, String>,
        body: Option<Vec<u8>>,
        job_id: String,
    ) -> Result<reqwest::Response> {
        // Check URL whitelist
        if !self.check_url_allowed(&url) {
            anyhow::bail!(
                "Network access denied: {} is not whitelisted. \
                Enabled: {}, Whitelist: {:?}",
                url,
                self.policy.enabled,
                self.policy.whitelist
            );
        }

        // Check rate limit
        if !self.check_rate_limit(&job_id).await {
            anyhow::bail!(
                "Rate limit exceeded for job {}. Max {} requests/second",
                job_id,
                self.policy.requests_per_second
            );
        }

        info!("Proxying request: {} {}", method, url);

        // Build request
        let mut request = match method {
            Method::GET => self.client.get(&url),
            Method::POST => self.client.post(&url),
            Method::PUT => self.client.put(&url),
            Method::DELETE => self.client.delete(&url),
            Method::PATCH => self.client.patch(&url),
            _ => anyhow::bail!("Unsupported method: {}", method),
        };

        // Add headers
        for (key, value) in headers {
            request = request.header(&key, value);
        }

        // Add body
        if let Some(body_data) = body {
            request = request.body(body_data);
        }

        // Execute request
        let response = request.send().await?;

        info!("Proxied request successful: {} {}", method, url);

        Ok(response)
    }
}

#[derive(Serialize, Deserialize)]
struct ProxyRequest {
    method: String,
    url: String,
    headers: HashMap<String, String>,
    body: Option<String>,
    job_id: String,
}

#[derive(Serialize, Deserialize)]
struct ProxyResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

async fn proxy_http_request(
    State(proxy): State<Arc<NetworkProxy>>,
    Json(request): Json<ProxyRequest>,
) -> Result<Json<ProxyResponse>, StatusCode> {
    // Parse method
    let method =
        Method::from_bytes(request.method.as_bytes()).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Get body as bytes
    let body = request.body.map(|b| b.into_bytes());

    // Proxy request
    match proxy
        .proxy_request(method, request.url, request.headers, body, request.job_id)
        .await
    {
        Ok(response) => {
            let status = response.status().as_u16();

            // Extract headers
            let mut headers = HashMap::new();
            for (key, value) in response.headers() {
                headers.insert(key.to_string(), value.to_str().unwrap_or("").to_string());
            }

            // Get body
            let body = response.text().await.unwrap_or_default();

            Ok(Json(ProxyResponse {
                status,
                headers,
                body,
            }))
        }
        Err(e) => {
            error!("Proxy request failed: {}", e);
            Err(StatusCode::FORBIDDEN)
        }
    }
}

pub fn create_network_proxy_router(proxy: Arc<NetworkProxy>) -> Router {
    Router::new()
        .route("/proxy", post(proxy_http_request))
        .with_state(proxy)
}

pub fn create_network_policy(config: &serde_json::Value) -> NetworkPolicy {
    let policy = config.get("network_policy").and_then(|p| p.as_object());

    NetworkPolicy {
        enabled: policy
            .and_then(|p| p.get("enabled"))
            .and_then(|e| e.as_bool())
            .unwrap_or(false),
        whitelist: policy
            .and_then(|p| p.get("whitelist"))
            .and_then(|w| w.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
        requests_per_second: policy
            .and_then(|p| p.get("rate_limit"))
            .and_then(|r| r.get("requests_per_second"))
            .and_then(|v| v.as_f64())
            .unwrap_or(10.0),
        burst_size: policy
            .and_then(|p| p.get("rate_limit"))
            .and_then(|r| r.get("burst_size"))
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(20),
    }
}
