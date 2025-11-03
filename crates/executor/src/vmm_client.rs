use anyhow::{anyhow, Result};
use dstack_vmm_rpc::{Id, StatusRequest, StatusResponse, VmConfiguration, VmInfo};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct VmmClient {
    base_url: String,
    client: Client,
    timeout: Duration,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonRequest<T> {
    #[serde(flatten)]
    inner: T,
}

impl VmmClient {
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

    pub async fn version(&self) -> Result<VersionResponse> {
        let url = format!("{}/prpc/Version?json", self.base_url);
        let response = self.client.post(&url).timeout(self.timeout).send().await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            Err(anyhow!("VMM version request failed: {}", response.status()))
        }
    }

    pub async fn status(&self, request: StatusRequest) -> Result<StatusResponse> {
        let url = format!("{}/prpc/Status?json", self.base_url);
        let response = self
            .client
            .post(&url)
            .json(&request)
            .timeout(self.timeout)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            Err(anyhow!("VMM status request failed: {}", response.status()))
        }
    }

    pub async fn create_vm(&self, config: VmConfiguration) -> Result<Id> {
        let url = format!("{}/prpc/CreateVm?json", self.base_url);
        let response = self
            .client
            .post(&url)
            .json(&config)
            .timeout(self.timeout)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            Err(anyhow!(
                "VMM create VM request failed: {}",
                response.status()
            ))
        }
    }

    pub async fn start_vm(&self, id: Id) -> Result<()> {
        let url = format!("{}/prpc/StartVm?json", self.base_url);
        let response = self
            .client
            .post(&url)
            .json(&id)
            .timeout(self.timeout)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!(
                "VMM start VM request failed: {}",
                response.status()
            ))
        }
    }

    pub async fn stop_vm(&self, id: Id) -> Result<()> {
        let url = format!("{}/prpc/StopVm?json", self.base_url);
        let response = self
            .client
            .post(&url)
            .json(&id)
            .timeout(self.timeout)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!("VMM stop VM request failed: {}", response.status()))
        }
    }

    pub async fn remove_vm(&self, id: Id) -> Result<()> {
        let url = format!("{}/prpc/RemoveVm?json", self.base_url);
        let response = self
            .client
            .post(&url)
            .json(&id)
            .timeout(self.timeout)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!(
                "VMM remove VM request failed: {}",
                response.status()
            ))
        }
    }

    pub async fn get_info(&self, id: Id) -> Result<dstack_vmm_rpc::GetInfoResponse> {
        let url = format!("{}/prpc/GetInfo?json", self.base_url);
        let response = self
            .client
            .post(&url)
            .json(&id)
            .timeout(self.timeout)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            Err(anyhow!(
                "VMM get info request failed: {}",
                response.status()
            ))
        }
    }

    /// Get VM info to extract guest agent URL
    pub async fn get_vm_with_guest_url(&self, vm_id: &str) -> Result<(VmInfo, String)> {
        let info = self
            .get_info(Id {
                id: vm_id.to_string(),
            })
            .await?;

        if let Some(vm_info) = info.info {
            // Extract guest agent URL from app_url
            let guest_url = vm_info
                .app_url
                .as_ref()
                .map(|url| url.replace("https://", "http://").replace(":8090", ":8090"))
                .unwrap_or_else(|| format!("http://localhost:8090"));

            Ok((vm_info, guest_url))
        } else {
            Err(anyhow!("VM not found: {}", vm_id))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VersionResponse {
    pub version: String,
    pub rev: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_vmm_client() {
        let client = VmmClient::new("http://57.128.43.156:11530".to_string());

        // Test version
        match client.version().await {
            Ok(version) => println!("VMM Version: {}", version.version),
            Err(e) => println!("Failed to get version: {}", e),
        }

        // Test status
        let status_req = StatusRequest {
            ids: vec![],
            brief: true,
            keyword: String::new(),
            page: 0,
            page_size: 10,
        };

        match client.status(status_req).await {
            Ok(status) => println!("Found {} VMs", status.total),
            Err(e) => println!("Failed to get status: {}", e),
        }
    }
}
