use serde::{Deserialize, Serialize};

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

