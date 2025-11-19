use platform_validator_vmm::VmmClient;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;
use async_trait::async_trait;

/// Manages VMs created for individual jobs
pub struct JobVmManager {
    vmm_client: VmmClient,
    job_vms: Arc<RwLock<HashMap<String, JobVm>>>,
}

#[derive(Debug, Clone)]
struct JobVm {
    job_id: String,
    challenge_name: String,
    vm_id: String,
    created_at: DateTime<Utc>,
    timeout_seconds: u64,
    vcpu: u32,
    memory_mb: u64,
    disk_mb: u64,
}

impl JobVmManager {
    pub fn new(vmm_client: VmmClient) -> Self {
        Self {
            vmm_client,
            job_vms: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a VM for a job
    pub async fn create_job_vm(
        &self,
        job_id: Uuid,
        challenge_name: &str,
        compose_yaml: &str,
        resources: JobResources,
        timeout_seconds: u64,
    ) -> Result<String> {
        let vm_name = format!("{}-{}", challenge_name, job_id);

        info!("Creating job VM: {} for job {}", vm_name, job_id);

        // Parse memory
        let memory_mb = parse_memory(&resources.memory)?;
        let disk_size = resources
            .disk
            .as_ref()
            .map(|d| parse_disk_size(d))
            .transpose()?
            .unwrap_or(20);
        let disk_mb = disk_size as u64 * 1024;

        // Create AppCompose JSON structure expected by VMM
        // Note: Job VMs use production-safe defaults
        let app_compose_json = serde_json::json!({
            "manifest_version": 2,
            "name": vm_name.clone(),
            "runner": "docker-compose",
            "docker_compose_file": compose_yaml,
            "kms_enabled": false,
            "gateway_enabled": true,
            "public_logs": false,
            "public_sysinfo": false,
            "public_tcbinfo": true,
            "local_key_provider_enabled": false,
            "key_provider_id": "",
            "allowed_envs": [],
            "no_instance_id": false,
            "secure_time": true,
        });
        let app_compose_str = serde_json::to_string(&app_compose_json)
            .map_err(|e| anyhow::anyhow!("Failed to serialize AppCompose JSON: {}", e))?;

        // Create VMM configuration
        use platform_validator_vmm::VmConfiguration;
        let vm_config = VmConfiguration {
            name: vm_name.clone(),
            image: "dstack-dev-0.5.3".to_string(),
            compose_file: app_compose_str,
            vcpu: resources.vcpu,
            memory: memory_mb,
            disk_size,
            ports: vec![],
            encrypted_env: vec![],
            app_id: None,
            user_config: "".to_string(),
            hugepages: false,
            pin_numa: false,
            gpus: None,
            kms_urls: vec![],
            gateway_urls: vec![],
            stopped: false,
        };

        // Create VM
        let vm_id = self.vmm_client.create_vm(vm_config).await?;

        // Store job VM
        let mut job_vms = self.job_vms.write().await;
        job_vms.insert(
            job_id.to_string(),
            JobVm {
                job_id: job_id.to_string(),
                challenge_name: challenge_name.to_string(),
                vm_id: vm_id.clone(),
                created_at: Utc::now(),
                timeout_seconds,
                vcpu: resources.vcpu,
                memory_mb: memory_mb as u64,
                disk_mb,
            },
        );

        info!("Created job VM {} for job {}", vm_id, job_id);

        Ok(vm_id)
    }

    /// Get VM ID for a job
    pub async fn get_job_vm(&self, job_id: &str) -> Option<String> {
        let job_vms = self.job_vms.read().await;
        job_vms.get(job_id).map(|jvm| jvm.vm_id.clone())
    }

    /// Clean up expired job VMs
    pub async fn cleanup_expired_jobs(&self) -> Result<()> {
        let now = Utc::now();
        let job_vms = self.job_vms.write().await;

        let expired_jobs: Vec<(String, String, String, u32, u64, u64)> = job_vms
            .iter()
            .filter(|(_, jvm)| {
                let elapsed = now.signed_duration_since(jvm.created_at).num_seconds() as u64;
                elapsed > jvm.timeout_seconds
            })
            .map(|(job_id, jvm)| {
                (
                    job_id.clone(),
                    jvm.vm_id.clone(),
                    jvm.challenge_name.clone(),
                    jvm.vcpu,
                    jvm.memory_mb,
                    jvm.disk_mb,
                )
            })
            .collect();

        drop(job_vms);

        for (job_id, vm_id, challenge_name, vcpu, memory_mb, disk_mb) in expired_jobs {
            info!("Job {} expired, cleaning up VM {}", job_id, vm_id);

            // Kill and remove VM
            if let Err(e) = self.vmm_client.kill_vm(&vm_id).await {
                warn!("Failed to kill expired job VM {}: {}", vm_id, e);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            if let Err(e) = self.vmm_client.remove_vm(&vm_id).await {
                warn!("Failed to remove expired job VM {}: {}", vm_id, e);
            }

            // Remove from tracking
            let mut job_vms = self.job_vms.write().await;
            job_vms.remove(&job_id);
        }

        Ok(())
    }

    /// Manually cleanup a job VM
    pub async fn cleanup_job(&self, job_id: &str) -> Result<()> {
        let mut job_vms = self.job_vms.write().await;

        if let Some(jvm) = job_vms.remove(job_id) {
            drop(job_vms);

            info!("Cleaning up job VM for job {}", job_id);

            // Kill and remove VM
            if let Err(e) = self.vmm_client.kill_vm(&jvm.vm_id).await {
                warn!("Failed to kill job VM {}: {}", jvm.vm_id, e);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            if let Err(e) = self.vmm_client.remove_vm(&jvm.vm_id).await {
                warn!("Failed to remove job VM {}: {}", jvm.vm_id, e);
            }
        }

        Ok(())
    }

    /// Cleanup all VMs for a challenge (by name prefix)
    pub async fn cleanup_challenge(&self, challenge_name: &str) -> Result<usize> {
        info!("Cleaning up all VMs for challenge: {}", challenge_name);

        // List all VMs from VMM
        let vms = match self.vmm_client.list_vms().await {
            Ok(vms) => vms,
            Err(e) => {
                error!("Failed to list VMs: {}", e);
                return Err(e);
            }
        };

        // Filter VMs by challenge name prefix
        let prefix = format!("{}-", challenge_name);
        let challenge_vms: Vec<(String, String)> = vms
            .iter()
            .filter(|vm| vm.name.starts_with(&prefix))
            .map(|vm| (vm.id.clone(), vm.name.clone()))
            .collect();

        let cleanup_count = challenge_vms.len();
        info!(
            "Found {} VMs to cleanup for challenge {}",
            cleanup_count, challenge_name
        );

        // Kill and remove each VM
        for (vm_id, vm_name) in challenge_vms {
            info!("Cleaning up VM: {} ({})", vm_id, vm_name);

            // Get resources from tracked job VM if exists
            let (vcpu, memory_mb, disk_mb, keys_to_remove) = {
                let job_vms = self.job_vms.read().await;
                let matching_jobs: Vec<(String, u32, u64, u64)> = job_vms
                    .iter()
                    .filter(|(_, jvm)| jvm.vm_id == vm_id)
                    .map(|(job_id, jvm)| (job_id.clone(), jvm.vcpu, jvm.memory_mb, jvm.disk_mb))
                    .collect();

                let (vcpu, memory_mb, disk_mb) = matching_jobs
                    .first()
                    .map(|(_, vcpu, mem, disk)| (*vcpu, *mem, *disk))
                    .unwrap_or((0, 0, 0));
                let keys_to_remove: Vec<String> = matching_jobs
                    .iter()
                    .map(|(job_id, _, _, _)| job_id.clone())
                    .collect();

                (vcpu, memory_mb, disk_mb, keys_to_remove)
            };

            // Kill VM
            if let Err(e) = self.vmm_client.kill_vm(&vm_id).await {
                warn!("Failed to kill VM {}: {}", vm_id, e);
            }

            // Wait for graceful shutdown
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            // Remove VM
            if let Err(e) = self.vmm_client.remove_vm(&vm_id).await {
                warn!("Failed to remove VM {}: {}", vm_id, e);
            }

            // Remove from in-memory tracking
            if !keys_to_remove.is_empty() {
                let mut job_vms = self.job_vms.write().await;
                for job_id in keys_to_remove {
                    job_vms.remove(&job_id);
                }
            }
        }

        Ok(cleanup_count)
    }
}

// Implement JobVmManagerTrait for integration with validator-http-server
#[async_trait::async_trait]
impl platform_validator_http_server::JobVmManagerTrait for JobVmManager {
    async fn cleanup_challenge(&self, challenge_name: &str) -> anyhow::Result<usize> {
        self.cleanup_challenge(challenge_name).await
    }
}

#[derive(Debug, Clone)]
pub struct JobResources {
    pub vcpu: u32,
    pub memory: String,
    pub disk: Option<String>,
}

fn parse_memory(memory: &str) -> Result<u32> {
    let memory = memory.trim().to_lowercase();
    if memory.ends_with("g") {
        Ok(memory.trim_end_matches("g").parse::<u32>()? * 1024)
    } else if memory.ends_with("m") {
        Ok(memory.trim_end_matches("m").parse::<u32>()?)
    } else {
        Ok(memory.parse::<u32>()?)
    }
}

fn parse_disk_size(disk: &str) -> Result<u32> {
    let disk = disk.trim().to_lowercase();
    if disk.ends_with("g") {
        Ok(disk.trim_end_matches("g").parse::<u32>()?)
    } else if disk.ends_with("m") {
        Ok(disk.trim_end_matches("m").parse::<u32>()? / 1024)
    } else {
        Ok(disk.parse::<u32>()?)
    }
}
