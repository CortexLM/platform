use anyhow::Result;
use reqwest::Client;
use serde_json::json;
use tracing::info;
use uuid::Uuid;

use crate::types::*;

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
            tracing::debug!("MOCK VMM MODE: VMM operations will be mocked (no real CVMs created)");
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
            let vm_id = format!(
                "mock-vm-{}",
                Uuid::new_v4().to_string().split('-').next().unwrap()
            );
            return Ok(vm_id);
        }

        info!("Creating VM: {}", config.name);

        let url = format!("{}/prpc/CreateVm?json", self.vmm_url);

        let encrypted_env_str = if config.encrypted_env.is_empty() {
            "".to_string()
        } else {
            hex::encode(&config.encrypted_env)
        };

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

        info!("Sending CreateVm request to VMM: {}", serde_json::to_string_pretty(&payload)?);

        let response = self.client.post(&url).json(&payload).send().await?;

        let status = response.status();
        info!("VMM response status: {}", status);

        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("VMM API error ({}): {}", status, error_text);
        }

        let response_body = response.text().await?;
        info!("VMM response body: {}", response_body);

        let vm_id: Id = serde_json::from_str(&response_body).map_err(|e| {
            anyhow::anyhow!("Failed to parse VMM response '{}': {}", response_body, e)
        })?;

        info!("Created VM with ID: {}", vm_id.id);

        Ok(vm_id.id)
    }

    /// Get VM info by ID
    pub async fn get_vm_info(&self, vm_id: &str) -> Result<VmInfo> {
        if self.mock_mode {
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

    /// Get VMM metadata including available resources
    pub async fn get_meta(&self) -> Result<VmmMetadata> {
        if self.mock_mode {
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
            return Ok(vec![]);
        }

        let url = format!("{}/prpc/Status?json", self.vmm_url);

        let response = self.client.post(&url).json(&json!({})).send().await?;

        let status: VmmStatus = response.json().await?;

        Ok(status.vms)
    }
}

