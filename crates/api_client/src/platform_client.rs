use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{error, info, warn};

/// Platform API client for validators
#[derive(Clone)]
pub struct PlatformClient {
    base_url: String,
    pub validator_hotkey: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeInfo {
    pub id: String,
    pub name: String,
    pub status: String,
    pub github_repo: String,
    pub github_commit: String,
    pub resource_requirements: serde_json::Value,
    pub compose_hash: String,
    pub mechanism_id: u8, // Changed from String to u8 to match platform-api
    pub emission_share: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengesResponse {
    pub challenges: Vec<ChallengeInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobInfo {
    pub id: String,
    pub challenge_id: String,
    pub submission_id: String,
    pub miner_hotkey: String,
    pub status: String,
    pub created_at: String,
    #[serde(default)]
    pub payload: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobsResponse {
    pub jobs: Vec<JobInfo>,
}

impl PlatformClient {
    pub fn new(base_url: String, validator_hotkey: String) -> Self {
        Self {
            base_url,
            validator_hotkey,
        }
    }

    /// Get active challenges
    pub async fn get_challenges(&self) -> Result<ChallengesResponse> {
        let url = format!("{}/challenges/active", self.base_url);
        let client = reqwest::Client::new();

        let resp = client
            .get(&url)
            .header("X-Validator-Hotkey", &self.validator_hotkey)
            .send()
            .await?;

        let challenges: ChallengesResponse = resp.json().await?;
        Ok(challenges)
    }

    /// Get full challenge specifications (for validator polling)
    /// Returns the same format as the WebSocket challenges:list message
    pub async fn get_challenge_specs(&self) -> Result<serde_json::Value> {
        let url = format!("{}/challenges/specs", self.base_url);
        let client = reqwest::Client::new();

        let resp = client
            .get(&url)
            .header("X-Validator-Hotkey", &self.validator_hotkey)
            .send()
            .await?;

        let specs: serde_json::Value = resp.json().await?;
        Ok(specs)
    }

    /// Get pending jobs for this validator
    pub async fn get_pending_jobs(&self) -> Result<JobsResponse> {
        let url = format!("{}/api/jobs/pending", self.base_url);
        let client = reqwest::Client::new();

        let resp = client
            .get(&url)
            .header("X-Validator-Hotkey", &self.validator_hotkey)
            .send()
            .await?;

        let jobs: JobsResponse = resp.json().await?;
        Ok(jobs)
    }

    /// Claim a specific job
    pub async fn claim_job(&self, job_id: &str) -> Result<JobInfo> {
        let url = format!("{}/api/jobs/{}/claim", self.base_url, job_id);
        let client = reqwest::Client::new();

        let request_body = json!({
            "validator_hotkey": self.validator_hotkey,
            "runtime": "Docker",
            "capabilities": []
        });

        let resp = client
            .post(&url)
            .header("X-Validator-Hotkey", &self.validator_hotkey)
            .json(&request_body)
            .send()
            .await?;

        // API returns ClaimJobResponse { job: JobMetadata, ... }
        // Extract the job field and convert to JobInfo
        let response: Value = resp.json().await?;
        let job_metadata = response
            .get("job")
            .ok_or_else(|| anyhow::anyhow!("Missing 'job' field in claim response"))?;

        let payload_value = job_metadata.get("payload").cloned();

        // Extract agent_hash from payload for better error reporting
        let agent_hash = payload_value
            .as_ref()
            .and_then(|p| p.get("agent_hash"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                warn!(
                    "No agent_hash in job {} payload - using 'unknown' fallback",
                    job_id
                );
                "unknown".to_string()
            });

        let job = JobInfo {
            id: job_metadata
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or(job_id)
                .to_string(),
            challenge_id: job_metadata
                .get("challenge_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            submission_id: payload_value
                .as_ref()
                .and_then(|p| p.get("session_id"))
                .and_then(|v| v.as_str())
                .unwrap_or(job_id)
                .to_string(),
            miner_hotkey: agent_hash.clone(),
            status: job_metadata
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("claimed")
                .to_string(),
            created_at: job_metadata
                .get("created_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            payload: payload_value,
        };

        Ok(job)
    }

    /// Submit evaluation results
    pub async fn submit_results(&self, job_id: &str, results: SubmissionResults) -> Result<()> {
        let url = format!("{}/api/jobs/{}/results", self.base_url, job_id);
        let client = reqwest::Client::new();

        // Convert SubmissionResults to SubmitResultRequest JSON format expected by platform-api
        let submit_request = json!({
            "job_id": job_id,
            "result": {
                "job_id": job_id,
                "submission_id": job_id, // Use job_id as submission_id fallback
                "scores": results.scores,
                "metrics": {},
                "logs": results.logs,
                "error": results.error,
                "execution_time": results.execution_time_ms,
                "resource_usage": {
                    "cpu_time": 0,
                    "memory_peak": 0,
                    "disk_usage": 0,
                    "network_bytes": 0
                },
                "attestation_receipt": null
            },
            "receipts": []
        });

        client
            .post(&url)
            .header("X-Validator-Hotkey", &self.validator_hotkey)
            .json(&submit_request)
            .send()
            .await?;

        Ok(())
    }

    /// Execute ORM query for a challenge (read-only)
    /// This forwards ORM queries from challenge SDK to platform-api (DEPRECATED: Use WebSocket)
    #[deprecated(note = "Use send_orm_query_via_websocket instead")]
    pub async fn execute_orm_query(
        &self,
        challenge_id: &str,
        query: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let url = format!("{}/challenges/{}/orm/query", self.base_url, challenge_id);
        let client = reqwest::Client::new();

        let resp = client
            .post(&url)
            .header("X-Validator-Hotkey", &self.validator_hotkey)
            .json(&query)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let error_text = resp.text().await.unwrap_or_default();
            return Err(anyhow::anyhow!(
                "ORM query failed with status {}: {}",
                status,
                error_text
            ));
        }

        let result: serde_json::Value = resp.json().await?;
        Ok(result)
    }

    /// Send ORM query via WebSocket connection
    /// This method should be called from within the WebSocket callback
    pub async fn send_orm_query_via_websocket(
        &self,
        ws_sender: &Arc<tokio::sync::mpsc::Sender<String>>,
        challenge_id: &str,
        query: serde_json::Value,
        query_id: &str,
    ) -> Result<()> {
        let message = serde_json::json!({
            "message_type": "orm_query",
            "query": query,
            "challenge_id": challenge_id,
            "query_id": query_id
        });

        ws_sender
            .send(serde_json::to_string(&message)?)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send ORM query via WebSocket: {}", e))?;

        Ok(())
    }

    /// Connect to WebSocket for real-time job updates
    pub async fn connect_websocket<F>(&self, callback: F) -> Result<()>
    where
        F: Fn(String, Arc<tokio::sync::mpsc::Sender<String>>) + Send + 'static,
    {
        let ws_url = format!("{}/validators/{}/ws", self.base_url, self.validator_hotkey);

        info!("Connecting to WebSocket: {}", ws_url);

        // Convert wss:// to ws:// for tokio-tungstenite compatibility
        let url = ws_url
            .replace("https://", "wss://")
            .replace("http://", "ws://");

        let (ws_stream, _) = connect_async(&url).await?;
        let (write, mut read) = ws_stream.split();

        // Wrap write in Arc and Mutex to share between tasks
        let write_handle = Arc::new(tokio::sync::Mutex::new(write));

        // Create a channel for sending messages back
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(100);
        let tx_clone = Arc::new(tx);

        // Clone write handle for the sender task
        let write_clone = write_handle.clone();

        // Spawn task to send messages back
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let mut write = write_clone.lock().await;
                if let Err(e) = write.send(Message::Text(msg)).await {
                    error!("Failed to send WebSocket message: {}", e);
                    break;
                }
            }
        });

        // Send initial handshake
        {
            let mut write = write_handle.lock().await;
            write
                .send(Message::Text(format!(
                    r#"{{"type":"handshake","validator_hotkey":"{}"}}"#,
                    self.validator_hotkey
                )))
                .await?;
        }

        // Listen for messages
        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    callback(text, tx_clone.clone());
                }
                Ok(Message::Close(_)) => {
                    warn!("WebSocket closed");
                    break;
                }
                Err(e) => {
                    error!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Connect to WebSocket with automatic reconnection
    /// This method will continuously retry connecting until successful
    pub async fn connect_websocket_with_reconnect<F>(&self, callback: F)
    where
        F: Fn(String, Arc<tokio::sync::mpsc::Sender<String>>) + Send + 'static + Clone,
    {
        let mut retry_count = 0;
        let max_retry_delay = Duration::from_secs(60); // Max delay of 60 seconds

        loop {
            // Calculate exponential backoff: 1s, 2s, 4s, 8s, ..., max 60s
            let delay = if retry_count == 0 {
                Duration::from_secs(0)
            } else {
                Duration::from_secs(2_u64.pow(retry_count.min(5))) // Cap at 32 seconds
                    .min(max_retry_delay)
            };

            if retry_count > 0 {
                warn!(
                    "Reconnecting in {} seconds (attempt #{})...",
                    delay.as_secs(),
                    retry_count
                );
                sleep(delay).await;
            }

            info!(
                "Attempting WebSocket connection (attempt #{})...",
                retry_count + 1
            );

            match self.connect_websocket(callback.clone()).await {
                Ok(_) => {
                    warn!("WebSocket connection closed normally, reconnecting...");
                    retry_count += 1;
                }
                Err(e) => {
                    error!("WebSocket connection failed: {}", e);
                    retry_count += 1;
                }
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmissionResults {
    pub job_id: String,
    pub scores: HashMap<String, f64>,
    pub logs: Vec<String>,
    pub execution_time_ms: u64,
    pub error: Option<String>,
}
