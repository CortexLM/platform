use anyhow::{anyhow, Result};
use dstack_guest_agent_rpc::{AppInfo, GetQuoteResponse};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct GuestAgentClient {
    base_url: String,
    client: Client,
    timeout: Duration,
}

#[derive(Debug, Serialize, Deserialize)]
struct RawQuoteRequest {
    pub report_data: Vec<u8>,
}

impl GuestAgentClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: Client::new(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Get a TDX quote from the guest agent
    pub async fn get_quote(&self, report_data: Vec<u8>) -> Result<GetQuoteResponse> {
        let url = format!("{}/prpc/GetQuote?json", self.base_url);

        // Pad report_data to 64 bytes
        let mut padded = vec![0u8; 64];
        let len = report_data.len().min(64);
        padded[..len].copy_from_slice(&report_data[..len]);

        let request = RawQuoteRequest {
            report_data: padded,
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .timeout(self.timeout)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json().await?)
        } else {
            let error_msg = format!("Guest agent GetQuote failed: {}", status);
            Err(anyhow!(error_msg))
        }
    }

    /// Get app info from the guest agent
    pub async fn get_info(&self) -> Result<AppInfo> {
        let url = format!("{}/prpc/Info?json", self.base_url);
        let response = self
            .client
            .post(&url)
            .json(&serde_json::json!({}))
            .timeout(self.timeout)
            .send()
            .await?;

        let status = response.status();
        if status.is_success() {
            Ok(response.json().await?)
        } else {
            let error_msg = format!("Guest agent Info failed: {}", status);
            Err(anyhow!(error_msg))
        }
    }

    /// Verify that the VM is running the expected image
    pub async fn verify_image(&self, expected_os_image_hash: &str) -> Result<bool> {
        let info = self.get_info().await?;

        // Check if os_image_hash matches
        let actual_hash = hex::encode(&info.os_image_hash);
        Ok(actual_hash == expected_os_image_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_guest_agent_client() {
        // Note: This requires a running VM with guest agent
        let client = GuestAgentClient::new("http://localhost:8090".to_string());

        // Test get info
        match client.get_info().await {
            Ok(info) => println!("App ID: {}", hex::encode(&info.app_id)),
            Err(e) => println!("Failed to get info: {}", e),
        }

        // Test get quote
        let report_data = vec![0u8; 32];
        match client.get_quote(report_data).await {
            Ok(quote) => println!("Got quote: {} bytes", quote.quote.len()),
            Err(e) => println!("Failed to get quote: {}", e),
        }
    }
}
