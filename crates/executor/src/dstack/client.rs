use super::config::DstackConfig;
use anyhow::Result;
use chrono::{DateTime, Utc};

/// Dstack client for communication
#[derive(Debug)]
pub struct DstackClient {
    pub gateway_client: DstackGatewayClient,
    pub vmm_client: DstackVmmClient,
    pub guest_agent_client: DstackGuestAgentClient,
}

/// Dstack HTTP clients
#[derive(Debug)]
pub struct DstackGatewayClient {
    pub url: String,
}

#[derive(Debug)]
pub struct DstackVmmClient {
    pub url: String,
}

#[derive(Debug)]
pub struct DstackGuestAgentClient {
    pub url: String,
}

/// Dstack attestation
#[derive(Debug)]
pub struct DstackAttestation {
    pub nonce: Vec<u8>,
    pub measurement: Vec<u8>,
    pub timestamp: DateTime<Utc>,
}

/// App status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

impl DstackGatewayClient {
    pub async fn new(url: &str) -> Result<Self> {
        Ok(Self {
            url: url.to_string(),
        })
    }
}

impl DstackVmmClient {
    pub async fn new(url: &str) -> Result<Self> {
        Ok(Self {
            url: url.to_string(),
        })
    }
}

impl DstackGuestAgentClient {
    pub async fn new(url: &str) -> Result<Self> {
        Ok(Self {
            url: url.to_string(),
        })
    }
}

impl DstackClient {
    pub async fn new(config: &DstackConfig) -> Result<Self> {
        let gateway_client = DstackGatewayClient::new(&config.gateway_url).await?;
        let vmm_client = DstackVmmClient::new(&config.vmm_url).await?;
        let guest_agent_client = DstackGuestAgentClient::new(&config.guest_agent_url).await?;

        Ok(Self {
            gateway_client,
            vmm_client,
            guest_agent_client,
        })
    }

    pub async fn deploy_app(&self, compose_content: &str) -> Result<String> {
        let client = reqwest::Client::new();
        let request_body = serde_json::json!({
            "compose_content": compose_content
        });

        let response = client
            .post(&format!("{}/deploy", self.vmm_client.url))
            .json(&request_body)
            .send()
            .await?;

        if response.status().is_success() {
            let deploy_data: serde_json::Value = response.json().await?;
            Ok(deploy_data["app_id"]
                .as_str()
                .unwrap_or("unknown")
                .to_string())
        } else {
            Err(anyhow::anyhow!("Failed to deploy app to dstack vmm"))
        }
    }

    pub async fn get_app_status(&self, app_id: &str) -> Result<AppStatus> {
        let client = reqwest::Client::new();
        let response = client
            .get(&format!("{}/status/{}", self.vmm_client.url, app_id))
            .send()
            .await?;

        if response.status().is_success() {
            let status_data: serde_json::Value = response.json().await?;
            Ok(match status_data["status"].as_str().unwrap_or("pending") {
                "running" => AppStatus::Running,
                "completed" => AppStatus::Completed,
                "failed" => AppStatus::Failed,
                _ => AppStatus::Pending,
            })
        } else {
            Err(anyhow::anyhow!("Failed to get app status from dstack vmm"))
        }
    }

    pub async fn get_app_logs(&self, app_id: &str) -> Result<Vec<String>> {
        let client = reqwest::Client::new();
        let response = client
            .get(&format!("{}/logs/{}", self.guest_agent_client.url, app_id))
            .send()
            .await?;

        if response.status().is_success() {
            let logs_data: serde_json::Value = response.json().await?;
            Ok(logs_data["logs"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|log| log.as_str().map(|s| s.to_string()))
                .collect())
        } else {
            Err(anyhow::anyhow!(
                "Failed to get app logs from dstack guest agent"
            ))
        }
    }

    pub async fn destroy_app(&self, app_id: &str) -> Result<()> {
        let client = reqwest::Client::new();
        let response = client
            .delete(&format!("{}/destroy/{}", self.vmm_client.url, app_id))
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to destroy app on dstack vmm"))
        }
    }
}
