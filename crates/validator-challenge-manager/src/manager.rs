use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use platform_engine_api_client::PlatformClient;
use platform_engine_dynamic_values::DynamicValuesManager;
use platform_validator_core::{ChallengeSpec, ChallengeState, ValidatorChallengeStatus};
use platform_validator_docker::{ContainerConfig, DockerClient, PortMapping as DockerPortMapping};
use platform_validator_vmm::{VmmClient, VmConfiguration};
use platform_validator_websocket::ChallengeWsClient;
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

use crate::env::get_or_prompt_env_vars;
use crate::instance::ChallengeInstance;
use crate::probe::probe_health;
use crate::provision::{
    check_docker_provisioning_status, check_provisioning_status, provision_cvm,
    provision_docker_container,
};
use crate::reconcile::{reconcile, recycle_cvm};
use crate::utils::{forward_heartbeat, forward_logs, forward_submit, parse_disk_size, parse_memory};

/// Challenge Manager orchestrates challenge CVMs
pub struct ChallengeManager {
    pub client: PlatformClient,
    vmm_client: VmmClient,
    docker_client: Option<Arc<DockerClient>>,
    docker_network: String,
    use_docker: bool,
    challenges: Arc<RwLock<HashMap<String, ChallengeInstance>>>,
    challenges_by_name: Arc<RwLock<HashMap<String, String>>>,
    pub challenge_specs: Arc<RwLock<HashMap<String, ChallengeSpec>>>,
    status_sender: Arc<Mutex<Option<Arc<mpsc::Sender<String>>>>>,
    validator_base_url: String,
    gateway_url: Option<String>,
    dynamic_values: Arc<DynamicValuesManager>,
    platform_ws_sender: Arc<Mutex<Option<Arc<mpsc::Sender<String>>>>>,
    orm_query_routing: Arc<RwLock<HashMap<String, (String, mpsc::Sender<serde_json::Value>)>>>,
}

impl ChallengeManager {
    pub fn new(
        client: PlatformClient,
        vmm_url: String,
        dynamic_values: Arc<DynamicValuesManager>,
        docker_client: Option<Arc<DockerClient>>,
        docker_network: String,
        use_docker: bool,
    ) -> Self {
        let validator_base_url = std::env::var("VALIDATOR_BASE_URL")
            .unwrap_or_else(|_| "http://10.0.2.2:18080".to_string());

        Self {
            client: client.clone(),
            vmm_client: VmmClient::new(vmm_url),
            docker_client,
            docker_network,
            use_docker,
            challenges: Arc::new(RwLock::new(HashMap::new())),
            challenges_by_name: Arc::new(RwLock::new(HashMap::new())),
            challenge_specs: Arc::new(RwLock::new(HashMap::new())),
            status_sender: Arc::new(Mutex::new(None)),
            validator_base_url,
            gateway_url: None,
            dynamic_values,
            platform_ws_sender: Arc::new(Mutex::new(None)),
            orm_query_routing: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn set_platform_ws_sender(&self, sender: Arc<mpsc::Sender<String>>) {
        let mut guard = self.platform_ws_sender.lock().await;
        *guard = Some(sender);
    }

    pub async fn handle_orm_result(&self, result: serde_json::Value, query_id: Option<String>) {
        if let Some(qid) = query_id {
            let routing_guard = self.orm_query_routing.read().await;
            if let Some((compose_hash, sender)) = routing_guard.get(&qid) {
                let compose_hash = compose_hash.clone();
                let sender = sender.clone();
                drop(routing_guard);

                let mut response = serde_json::json!({
                    "type": "orm_result",
                    "result": result.get("result").unwrap_or(&result).clone()
                });
                response["query_id"] = serde_json::Value::String(qid.clone());

                if let Err(e) = sender.send(response).await {
                    warn!("Failed to forward ORM result to challenge {}: {}", compose_hash, e);
                }

                let mut routing_guard = self.orm_query_routing.write().await;
                routing_guard.remove(&qid);
            } else {
                warn!("No routing found for ORM result with query_id: {}", qid);
            }
        } else {
            warn!("Received ORM result without query_id - cannot route to challenge");
        }
    }

    async fn get_gateway_base_domain(&self) -> Result<String> {
        let meta = self.vmm_client.get_meta().await?;
        if let Some(gateway) = meta.gateway {
            Ok(gateway.base_domain)
        } else {
            anyhow::bail!("No gateway configuration found in VMM metadata")
        }
    }

    async fn get_gateway_port(&self) -> Result<u32> {
        let meta = self.vmm_client.get_meta().await?;
        if let Some(gateway) = meta.gateway {
            Ok(gateway.port)
        } else {
            anyhow::bail!("No gateway configuration found in VMM metadata")
        }
    }

    pub async fn set_status_sender(&self, sender: Arc<mpsc::Sender<String>>) {
        let mut status_sender = self.status_sender.lock().await;
        *status_sender = Some(sender);
    }

    pub async fn report_status(&self) -> Result<()> {
        let statuses = self.get_challenge_statuses().await;

        let resources_msg = match self.vmm_client.get_meta().await {
            Ok(meta) => {
                if let Some(resources) = meta.resources {
                    Some(serde_json::json!({
                        "max_cvm_number": resources.max_cvm_number,
                        "max_allocable_vcpu": resources.max_allocable_vcpu,
                        "max_allocable_memory_mb": resources.max_allocable_memory_in_mb
                    }))
                } else {
                    None
                }
            }
            Err(e) => {
                warn!("Failed to get VMM resources: {}", e);
                None
            }
        };

        let status_sender = self.status_sender.lock().await;
        if let Some(sender) = status_sender.as_ref() {
            let mut msg = serde_json::json!({
                "message_type": "challenge_status",
                "statuses": statuses
            });

            if let Some(resources) = resources_msg {
                msg["resources"] = resources;
            }

            if let Ok(msg_str) = serde_json::to_string(&msg) {
                let _ = sender.send(msg_str).await;
            }
        }

        Ok(())
    }

    pub async fn initialize_challenges(&self, challenge_specs: Vec<ChallengeSpec>) -> Result<()> {
        info!("Initializing {} challenges", challenge_specs.len());

        let mut specs_map = self.challenge_specs.write().await;
        let mut challenges = self.challenges.write().await;

        for spec in challenge_specs {
            let compose_hash = spec.compose_hash.clone();

            let should_recycle = if let Some(old_spec) = specs_map.get(&compose_hash) {
                old_spec.compose_yaml != spec.compose_yaml
            } else {
                false
            };

            specs_map.insert(compose_hash.clone(), spec.clone());

            if !challenges.contains_key(&compose_hash) {
                let instance = ChallengeInstance {
                    compose_hash: compose_hash.clone(),
                    name: spec.name.clone(),
                    state: ChallengeState::Created,
                    created_at: Utc::now(),
                    last_probe: None,
                    probe_attempts: 0,
                    cvm_instance_id: None,
                    challenge_api_url: None,
                    deprecated_at: None,
                    ws_started: false,
                    ws_sender: Arc::new(Mutex::new(None)),
                };

                challenges.insert(compose_hash.clone(), instance);
                info!("Created challenge instance for compose_hash: {}", compose_hash);
            } else if should_recycle {
                if let Some(instance) = challenges.get_mut(&compose_hash) {
                    info!("Docker compose changed for challenge {}, marking for recycling", compose_hash);
                    instance.state = ChallengeState::Recycling;
                }
            }
        }

        Ok(())
    }

    pub async fn update_challenge(&self, spec: ChallengeSpec) -> Result<()> {
        let mut challenges = self.challenges.write().await;

        if let Some(instance) = challenges.get_mut(&spec.compose_hash) {
            if instance.state == ChallengeState::Active {
                info!("Challenge {} updated, marking for recycling", spec.compose_hash);
                instance.state = ChallengeState::Recycling;
            }
        } else {
            let instance = ChallengeInstance {
                compose_hash: spec.compose_hash.clone(),
                name: spec.name.clone(),
                state: ChallengeState::Created,
                created_at: Utc::now(),
                last_probe: None,
                probe_attempts: 0,
                cvm_instance_id: None,
                challenge_api_url: None,
                deprecated_at: None,
                ws_started: false,
                ws_sender: Arc::new(Mutex::new(None)),
            };
            challenges.insert(spec.compose_hash, instance);
        }

        Ok(())
    }

    pub async fn remove_challenge(&self, compose_hash: &str) -> Result<()> {
        let mut challenges = self.challenges.write().await;

        if let Some(instance) = challenges.remove(compose_hash) {
            if let Some(cvm_id) = instance.cvm_instance_id {
                if let Err(e) = self.vmm_client.kill_vm(&cvm_id).await {
                    warn!("Failed to kill CVM during removal: {}", e);
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                if let Err(e) = self.vmm_client.remove_vm(&cvm_id).await {
                    warn!("Failed to remove CVM during removal: {}", e);
                }
            }
            info!("Removed challenge instance: {}", compose_hash);
        }

        Ok(())
    }

    pub async fn get_challenge_statuses(&self) -> Vec<ValidatorChallengeStatus> {
        let challenges = self.challenges.read().await;

        challenges
            .values()
            .map(|instance| ValidatorChallengeStatus {
                validator_hotkey: self.client.validator_hotkey.clone(),
                compose_hash: instance.compose_hash.clone(),
                state: match instance.state {
                    ChallengeState::Active => "Active".to_string(),
                    ChallengeState::Failed => "Failed".to_string(),
                    ChallengeState::Provisioning => "Provisioning".to_string(),
                    ChallengeState::Probing => "Probing".to_string(),
                    ChallengeState::Recycling => "Recycling".to_string(),
                    _ => "Created".to_string(),
                },
                last_heartbeat: instance.last_probe.unwrap_or(instance.created_at),
                penalty_reason: if instance.state == ChallengeState::Failed {
                    Some("Challenge failed health checks".to_string())
                } else {
                    None
                },
            })
            .collect()
    }

    pub async fn get_challenge_api_url(&self, challenge_id: &str) -> Result<Option<String>> {
        let specs = self.challenge_specs.read().await;
        let challenges = self.challenges.read().await;

        let spec = specs
            .values()
            .find(|spec| spec.id == challenge_id || spec.name == challenge_id);

        if let Some(spec) = spec {
            let compose_hash = &spec.compose_hash;

            if let Some(instance) = challenges.get(compose_hash) {
                if instance.state == ChallengeState::Active {
                    return Ok(instance.challenge_api_url.clone());
                } else {
                    warn!("Challenge {} is not in Active state (current: {:?})", challenge_id, instance.state);
                }
            }
        }

        Ok(None)
    }

    pub async fn send_job_execute(
        &self,
        challenge_id: &str,
        job_id: &str,
        job_name: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        let compose_hash = {
            let specs = self.challenge_specs.read().await;
            specs
                .values()
                .find(|spec| spec.id == challenge_id || spec.name == challenge_id)
                .map(|spec| spec.compose_hash.clone())
        };

        let compose_hash = match compose_hash {
            Some(hash) => hash,
            None => {
                return Err(anyhow::anyhow!("Challenge {} not found", challenge_id));
            }
        };

        let ws_sender = {
            let challenges = self.challenges.read().await;
            if let Some(instance) = challenges.get(&compose_hash) {
                if instance.state != ChallengeState::Active {
                    return Err(anyhow::anyhow!("Challenge {} is not in Active state", challenge_id));
                }
                instance.ws_sender.clone()
            } else {
                return Err(anyhow::anyhow!("Challenge instance not found for {}", challenge_id));
            }
        };

        let job_msg = serde_json::json!({
            "type": "job_execute",
            "job_id": job_id,
            "job_name": job_name,
            "payload": payload,
        });

        let max_retries = 10;
        let retry_delay = tokio::time::Duration::from_millis(500);

        for attempt in 0..max_retries {
            let sender_opt = {
                let sender_guard = ws_sender.lock().await;
                sender_guard.as_ref().map(|s| s.clone())
            };

            if let Some(sender) = sender_opt {
                match sender.send(job_msg.clone()).await {
                    Ok(_) => {
                        info!("Sent job_execute message for job {} to challenge {} (attempt {})", job_id, challenge_id, attempt + 1);
                        return Ok(());
                    }
                    Err(e) => {
                        if attempt == max_retries - 1 {
                            return Err(anyhow::anyhow!("Failed to send job_execute after {} attempts: {}", max_retries, e));
                        }
                        warn!("Failed to send job_execute (attempt {}): {}, retrying...", attempt + 1, e);
                    }
                }
            } else {
                if attempt == max_retries - 1 {
                    return Err(anyhow::anyhow!("WebSocket connection not established for challenge {} after {} attempts", challenge_id, max_retries));
                }
                debug!("WebSocket sender not yet available for challenge {} (attempt {}), waiting...", challenge_id, attempt + 1);
            }

            tokio::time::sleep(retry_delay).await;
        }

        Err(anyhow::anyhow!("Failed to send job_execute: max retries exceeded"))
    }

    pub async fn reconcile(&self) -> Result<()> {
        reconcile(self).await
    }

    pub async fn cleanup_docker_containers(&self) -> Result<()> {
        if !self.use_docker {
            return Ok(());
        }

        if let Some(docker_client) = &self.docker_client {
            info!("Cleaning up all Docker containers created by validator...");
            match docker_client.cleanup_containers_by_prefix("challenge-").await {
                Ok(count) => {
                    info!("Cleaned up {} Docker containers", count);
                }
                Err(e) => {
                    warn!("Failed to cleanup Docker containers: {}", e);
                }
            }
        }

        Ok(())
    }

    // Internal methods exposed to modules
    pub(crate) fn vmm_client(&self) -> &VmmClient {
        &self.vmm_client
    }

    pub(crate) fn docker_client(&self) -> Option<&Arc<DockerClient>> {
        self.docker_client.as_ref()
    }

    pub(crate) fn docker_network(&self) -> &str {
        &self.docker_network
    }

    pub(crate) fn use_docker(&self) -> bool {
        self.use_docker
    }

    pub(crate) fn challenges(&self) -> &Arc<RwLock<HashMap<String, ChallengeInstance>>> {
        &self.challenges
    }

    pub(crate) fn challenge_specs(&self) -> &Arc<RwLock<HashMap<String, ChallengeSpec>>> {
        &self.challenge_specs
    }

    pub(crate) fn dynamic_values(&self) -> &Arc<DynamicValuesManager> {
        &self.dynamic_values
    }

    pub(crate) fn platform_client(&self) -> &PlatformClient {
        &self.client
    }

    pub(crate) fn platform_ws_sender(&self) -> &Arc<Mutex<Option<Arc<mpsc::Sender<String>>>>> {
        &self.platform_ws_sender
    }

    pub(crate) fn orm_query_routing(&self) -> &Arc<RwLock<HashMap<String, (String, mpsc::Sender<serde_json::Value>)>>> {
        &self.orm_query_routing
    }

    pub(crate) async fn get_gateway_base_domain_internal(&self) -> Result<String> {
        self.get_gateway_base_domain().await
    }

    pub(crate) async fn get_gateway_port_internal(&self) -> Result<u32> {
        self.get_gateway_port().await
    }
}
