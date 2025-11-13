use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;
use uuid::Uuid;

// VMM types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfiguration {
    pub name: String,
    pub image: String,
    pub compose_file: String,
    pub vcpu: u32,
    pub memory: u32,
    pub disk_size: u32,
    pub ports: Vec<PortMapping>,
    #[serde(default)]
    pub encrypted_env: Vec<u8>,
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub user_config: String,
    pub hugepages: bool,
    pub pin_numa: bool,
    #[serde(default)]
    pub gpus: Option<GpuConfig>,
    #[serde(default)]
    pub kms_urls: Vec<String>,
    #[serde(default)]
    pub gateway_urls: Vec<String>,
    pub stopped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuConfig {
    #[serde(default)]
    pub gpus: Vec<GpuSpec>,
    #[serde(default)]
    pub attach_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuSpec {
    #[serde(default)]
    pub slot: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub protocol: String,
    pub host_port: u32,
    pub vm_port: u32,
    pub host_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Id {
    pub id: String,
}

/// VMM client for creating and managing CVMs
pub struct VmmClient {
    vmm_url: String,
    client: Client,
    mock_mode: bool,
}

impl VmmClient {
    pub fn new(vmm_url: String) -> Self {
        let mock_mode = std::env::var("VALIDATOR_MOCK_VMM")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase()
            == "true";

        if mock_mode {
            tracing::debug!(
                "MOCK VMM MODE: VMM operations will be mocked (no real CVMs created)"
            );
        }

        Self {
            vmm_url,
            client: Client::new(),
            mock_mode,
        }
    }

    /// Create a CVM with the given configuration
    pub async fn create_vm(&self, config: VmConfiguration) -> Result<String> {
        if self.mock_mode {
            // Mock mode: return fake VM ID without actually creating a VM
            let vm_id = format!(
                "mock-vm-{}",
                Uuid::new_v4().to_string().split('-').next().unwrap()
            );
            return Ok(vm_id);
        }

        info!("Creating VM: {}", config.name);

        let url = format!("{}/prpc/CreateVm?json", self.vmm_url);

        // Encode encrypted_env as hex string (VMM expects hex, not base64)
        let encrypted_env_str = if config.encrypted_env.is_empty() {
            "".to_string()
        } else {
            hex::encode(&config.encrypted_env)
        };

        // Convert to JSON
        let mut payload = json!({
            "name": config.name,
            "image": config.image,
            "compose_file": config.compose_file,
            "vcpu": config.vcpu,
            "memory": config.memory,
            "disk_size": config.disk_size,
            "ports": config.ports.iter().map(|p| json!({
                "protocol": p.protocol,
                "host_port": p.host_port,
                "vm_port": p.vm_port,
                "host_address": p.host_address
            })).collect::<Vec<_>>(),
            "encrypted_env": encrypted_env_str,
            "user_config": config.user_config,
            "hugepages": config.hugepages,
            "pin_numa": config.pin_numa,
            "stopped": config.stopped,
        });

        // Add optional fields if they exist
        if let Some(app_id) = &config.app_id {
            payload["app_id"] = json!(app_id);
        }

        if let Some(gpus) = &config.gpus {
            payload["gpus"] = json!(gpus);
        }

        if !config.kms_urls.is_empty() {
            payload["kms_urls"] = json!(config.kms_urls);
        }

        if !config.gateway_urls.is_empty() {
            payload["gateway_urls"] = json!(config.gateway_urls);
        }

        info!(
            "Sending CreateVm request to VMM: {}",
            serde_json::to_string_pretty(&payload)?
        );

        let response = self.client.post(&url).json(&payload).send().await?;

        let status = response.status();
        info!("VMM response status: {}", status);

        // Check response status
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("VMM API error ({}): {}", status, error_text);
        }

        // Get response body for debugging
        let response_body = response.text().await?;
        info!("VMM response body: {}", response_body);

        // Try to parse as Id struct
        let vm_id: Id = serde_json::from_str(&response_body).map_err(|e| {
            anyhow::anyhow!("Failed to parse VMM response '{}': {}", response_body, e)
        })?;

        info!("Created VM with ID: {}", vm_id.id);

        Ok(vm_id.id)
    }

    /// Get VM info by ID
    pub async fn get_vm_info(&self, vm_id: &str) -> Result<VmInfo> {
        if self.mock_mode {
            // Mock mode: return fake VM info
            return Ok(VmInfo {
                id: vm_id.to_string(),
                name: format!("mock-{}", vm_id),
                status: "Running".to_string(),
                uptime: "0s".to_string(),
                app_url: Some(format!("http://mock-vm-{}:8080", vm_id)),
                app_id: "mock-app-id".to_string(),
                instance_id: Some(format!("mock-instance-{}", vm_id)),
                configuration: serde_json::json!({}),
                exited_at: None,
                boot_progress: "100".to_string(),
                boot_error: "".to_string(),
                shutdown_progress: "".to_string(),
                image_version: "mock".to_string(),
            });
        }

        let url = format!("{}/prpc/GetInfo?json", self.vmm_url);

        let payload = json!({
            "id": vm_id
        });

        let response = self.client.post(&url).json(&payload).send().await?;

        let get_info_response: GetInfoResponse = response.json().await?;

        match get_info_response.info {
            Some(info) => Ok(info),
            None => anyhow::bail!("VM not found: {}", vm_id),
        }
    }

    /// Remove a VM
    pub async fn remove_vm(&self, vm_id: &str) -> Result<()> {
        if self.mock_mode {
            return Ok(());
        }

        info!("Removing VM: {}", vm_id);

        let url = format!("{}/prpc/RemoveVm?json", self.vmm_url);

        let payload = json!({
            "id": vm_id
        });

        self.client.post(&url).json(&payload).send().await?;

        info!("Removed VM: {}", vm_id);

        Ok(())
    }

    /// Start a VM
    pub async fn start_vm(&self, vm_id: &str) -> Result<()> {
        if self.mock_mode {
            return Ok(());
        }

        info!("Starting VM: {}", vm_id);

        let url = format!("{}/prpc/StartVm?json", self.vmm_url);

        let payload = json!({
            "id": vm_id
        });

        self.client.post(&url).json(&payload).send().await?;

        info!("Started VM: {}", vm_id);

        Ok(())
    }

    /// Stop a VM
    pub async fn stop_vm(&self, vm_id: &str) -> Result<()> {
        if self.mock_mode {
            return Ok(());
        }

        info!("Stopping VM: {}", vm_id);

        let url = format!("{}/prpc/StopVm?json", self.vmm_url);

        let payload = json!({
            "id": vm_id
        });

        self.client.post(&url).json(&payload).send().await?;

        info!("Stopped VM: {}", vm_id);

        Ok(())
    }

    /// Kill a VM (force shutdown)
    pub async fn kill_vm(&self, vm_id: &str) -> Result<()> {
        if self.mock_mode {
            return Ok(());
        }

        info!("Killing VM: {}", vm_id);

        let url = format!("{}/prpc/ShutdownVm?json", self.vmm_url);

        let payload = json!({
            "id": vm_id
        });

        self.client.post(&url).json(&payload).send().await?;

        info!("Killed VM: {}", vm_id);

        Ok(())
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct GetInfoResponse {
    pub found: bool,
    pub info: Option<VmInfo>,
}

#[derive(Debug, serde::Deserialize)]
pub struct VmInfo {
    pub id: String,
    pub name: String,
    pub status: String,
    pub uptime: String,
    pub app_url: Option<String>,
    pub app_id: String,
    pub instance_id: Option<String>,
    pub configuration: serde_json::Value,
    pub exited_at: Option<String>,
    pub boot_progress: String,
    pub boot_error: String,
    pub shutdown_progress: String,
    pub image_version: String,
}

/// Get VMM metadata including available resources
impl VmmClient {
    pub async fn get_meta(&self) -> Result<VmmMetadata> {
        if self.mock_mode {
            // Mock mode: return fake metadata
            return Ok(VmmMetadata {
                kms: None,
                gateway: Some(GatewaySettings {
                    url: "http://mock-gateway:8080".to_string(),
                    base_domain: "mock-gateway".to_string(),
                    port: 8080,
                    agent_port: 8081,
                    urls: vec!["http://mock-gateway:8080".to_string()],
                }),
                resources: Some(ResourcesSettings {
                    max_cvm_number: 10,
                    max_allocable_vcpu: 16,
                    max_allocable_memory_in_mb: 32768,
                }),
            });
        }

        let url = format!("{}/prpc/GetMeta?json", self.vmm_url);

        let response = self.client.post(&url).json(&json!({})).send().await?;

        let meta: VmmMetadata = response.json().await?;

        Ok(meta)
    }

    /// List all VMs
    pub async fn list_vms(&self) -> Result<Vec<VmInfo>> {
        if self.mock_mode {
            // Mock mode: return empty list
            return Ok(vec![]);
        }

        let url = format!("{}/prpc/Status?json", self.vmm_url);

        let response = self.client.post(&url).json(&json!({})).send().await?;

        let status: VmmStatus = response.json().await?;

        Ok(status.vms)
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct VmmMetadata {
    pub kms: Option<KmsSettings>,
    pub gateway: Option<GatewaySettings>,
    pub resources: Option<ResourcesSettings>,
}

#[derive(Debug, serde::Deserialize)]
pub struct KmsSettings {
    pub url: String,
    pub urls: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct GatewaySettings {
    pub url: String,
    pub base_domain: String,
    pub port: u32,
    pub agent_port: u32,
    pub urls: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ResourcesSettings {
    pub max_cvm_number: u32,
    pub max_allocable_vcpu: u32,
    pub max_allocable_memory_in_mb: u32,
}

#[derive(Debug, serde::Deserialize)]
pub struct VmmStatus {
    pub vms: Vec<VmInfo>,
}
