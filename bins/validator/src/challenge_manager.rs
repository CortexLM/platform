use crate::challenge_ws::ChallengeWsClient;
use crate::cvm_quota::CVMQuotaManager;
use crate::docker_client::{ContainerConfig, DockerClient, PortMapping as DockerPortMapping};
use crate::env_prompt::get_or_prompt_env_vars;
use crate::vmm_client::{VmConfiguration, VmmClient};
use anyhow::{Context, Result};
use base64;
use chrono::{DateTime, Utc};
use platform_engine_api_client::PlatformClient;
use platform_engine_dynamic_values::DynamicValuesManager;
use reqwest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

// Re-export ChallengeSpec from platform-api models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeSpec {
    pub id: String,
    pub name: String,
    pub compose_hash: String,
    pub compose_yaml: String,
    pub version: String,
    pub images: Vec<String>,
    pub resources: ChallengeResources,
    pub ports: Vec<ChallengePort>,
    pub env: HashMap<String, String>,
    pub emission_share: f64,
    pub mechanism_id: u8, // Changed from String to u8 to match platform-api
    pub weight: Option<f64>,
    pub description: Option<String>,
    pub mermaid_chart: Option<String>,
    pub github_repo: Option<String>,
    pub dstack_image: Option<String>, // Dstack base image version
    pub dstack_config: Option<DstackConfig>, // Dstack configuration options
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Dstack configuration for CVM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DstackConfig {
    #[serde(default = "default_true")]
    pub gateway_enabled: bool,
    #[serde(default = "default_true")]
    pub kms_enabled: bool, // Enable KMS by default for Update Compose button
    #[serde(default = "default_false")]
    pub local_key_provider_enabled: bool,
    #[serde(default = "default_true")]
    pub public_logs: bool, // Enable logs by default
    #[serde(default = "default_true")]
    pub public_sysinfo: bool, // Enable sysinfo by default
    #[serde(default = "default_true")]
    pub public_tcbinfo: bool,
    #[serde(default = "default_false")]
    pub secure_time: bool,
    #[serde(default = "default_false")]
    pub no_instance_id: bool,
    pub key_provider_id: Option<String>,
    pub allowed_envs: Option<Vec<String>>,
    pub pre_launch_script: Option<String>,
    #[serde(default = "default_false")]
    pub hugepages: bool,
    #[serde(default = "default_false")]
    pub pin_numa: bool,
}

fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResources {
    pub vcpu: u32,
    pub memory: String,
    pub disk: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengePort {
    pub container: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorChallengeStatus {
    pub validator_hotkey: String,
    pub compose_hash: String,
    pub state: String,
    pub last_heartbeat: DateTime<Utc>,
    pub penalty_reason: Option<String>,
}

/// Challenge state lifecycle
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ChallengeState {
    Created,
    Provisioning,
    Probing,
    Active,
    Failed,
    Recycling,
    Deprecated, // Deprecated when compose_hash changes, waiting for jobs to finish
}

/// Challenge instance managed by validator
#[derive(Debug)]
pub struct ChallengeInstance {
    pub compose_hash: String,
    pub name: String, // Challenge name to detect compose_hash changes
    pub state: ChallengeState,
    pub created_at: DateTime<Utc>,
    pub last_probe: Option<DateTime<Utc>>,
    pub probe_attempts: u32,
    pub cvm_instance_id: Option<String>,
    pub challenge_api_url: Option<String>,
    pub deprecated_at: Option<DateTime<Utc>>, // Timestamp when deprecated for timeout tracking
    pub ws_started: bool,
    pub ws_sender: Arc<tokio::sync::Mutex<Option<tokio::sync::mpsc::Sender<serde_json::Value>>>>, // WebSocket sender for sending messages
}

/// Challenge Manager orchestrates challenge CVMs
pub struct ChallengeManager {
    client: PlatformClient,
    vmm_client: VmmClient,
    docker_client: Option<Arc<DockerClient>>, // Docker client for dev mode
    docker_network: String,                   // Docker network name
    use_docker: bool,                         // Whether to use Docker instead of VMM
    challenges: Arc<RwLock<HashMap<String, ChallengeInstance>>>, // Key: compose_hash
    challenges_by_name: Arc<RwLock<HashMap<String, String>>>, // Key: name, Value: current compose_hash
    pub challenge_specs: Arc<RwLock<HashMap<String, ChallengeSpec>>>, // Key: compose_hash
    status_sender: Arc<tokio::sync::Mutex<Option<Arc<tokio::sync::mpsc::Sender<String>>>>>,
    quota_manager: Arc<CVMQuotaManager>,
    validator_base_url: String, // URL for challenge CVMs to connect to validator
    gateway_url: Option<String>, // Gateway URL for CVM-to-CVM communication
    dynamic_values: Arc<DynamicValuesManager>, // For storing private environment variables
    platform_ws_sender: Arc<tokio::sync::Mutex<Option<Arc<tokio::sync::mpsc::Sender<String>>>>>, // Platform API WebSocket sender
    orm_query_routing: Arc<RwLock<HashMap<String, (String, tokio::sync::mpsc::Sender<serde_json::Value>)>>>, // Key: query_id, Value: (compose_hash, challenge_ws_sender)
}

impl ChallengeManager {
    pub fn new(
        client: PlatformClient,
        vmm_url: String,
        quota_manager: Arc<CVMQuotaManager>,
        dynamic_values: Arc<DynamicValuesManager>,
        docker_client: Option<Arc<DockerClient>>,
        docker_network: String,
        use_docker: bool,
    ) -> Self {
        // Get validator base URL from environment or use default
        let validator_base_url = std::env::var("VALIDATOR_BASE_URL")
            .unwrap_or_else(|_| "http://10.0.2.2:18080".to_string());

        Self {
            client,
            vmm_client: VmmClient::new(vmm_url),
            docker_client,
            docker_network,
            use_docker,
            challenges: Arc::new(RwLock::new(HashMap::new())),
            challenges_by_name: Arc::new(RwLock::new(HashMap::new())),
            challenge_specs: Arc::new(RwLock::new(HashMap::new())),
            status_sender: Arc::new(tokio::sync::Mutex::new(None)),
            quota_manager,
            validator_base_url,
            gateway_url: None, // Will be populated from VMM metadata
            dynamic_values,
            platform_ws_sender: Arc::new(tokio::sync::Mutex::new(None)),
            orm_query_routing: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set the platform WebSocket sender for ORM queries
    pub async fn set_platform_ws_sender(&self, sender: Arc<tokio::sync::mpsc::Sender<String>>) {
        let mut guard = self.platform_ws_sender.lock().await;
        *guard = Some(sender);
    }
    
    /// Handle ORM result from platform API and forward to the appropriate challenge
    pub async fn handle_orm_result(&self, result: serde_json::Value, query_id: Option<String>) {
        if let Some(qid) = query_id {
            // Look up the routing information
            let routing_guard = self.orm_query_routing.read().await;
            if let Some((compose_hash, sender)) = routing_guard.get(&qid) {
                let compose_hash = compose_hash.clone();
                let sender = sender.clone();
                drop(routing_guard); // Release the lock early
                
                // Create response message
                let mut response = serde_json::json!({
                    "type": "orm_result",
                    "result": result.get("result").unwrap_or(&result).clone()
                });
                response["query_id"] = serde_json::Value::String(qid.clone());
                
                // Send response to challenge
                if let Err(e) = sender.send(response).await {
                    warn!("Failed to forward ORM result to challenge {}: {}", compose_hash, e);
                }
                
                // Clean up routing entry
                let mut routing_guard = self.orm_query_routing.write().await;
                routing_guard.remove(&qid);
            } else {
                warn!("No routing found for ORM result with query_id: {}", qid);
            }
        } else {
            warn!("Received ORM result without query_id - cannot route to challenge");
        }
    }

    /// Get gateway base domain from VMM metadata
    async fn get_gateway_base_domain(&self) -> Result<String> {
        let meta = self.vmm_client.get_meta().await?;
        if let Some(gateway) = meta.gateway {
            // Use base_domain instead of url
            Ok(gateway.base_domain)
        } else {
            anyhow::bail!("No gateway configuration found in VMM metadata")
        }
    }

    /// Get gateway port from VMM metadata
    async fn get_gateway_port(&self) -> Result<u32> {
        let meta = self.vmm_client.get_meta().await?;
        if let Some(gateway) = meta.gateway {
            Ok(gateway.port)
        } else {
            anyhow::bail!("No gateway configuration found in VMM metadata")
        }
    }

    /// Set the WebSocket sender for status reporting
    pub async fn set_status_sender(&self, sender: Arc<tokio::sync::mpsc::Sender<String>>) {
        let mut status_sender = self.status_sender.lock().await;
        *status_sender = Some(sender);
    }

    /// Report challenge status to Platform API
    pub async fn report_status(&self) -> Result<()> {
        let statuses = self.get_challenge_statuses().await;

        // Get available resources from VMM
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

        // Send via WebSocket if available
        let status_sender = self.status_sender.lock().await;
        if let Some(sender) = status_sender.as_ref() {
            let mut msg = serde_json::json!({
                "message_type": "challenge_status",
                "statuses": statuses
            });

            // Add resources if available
            if let Some(resources) = resources_msg {
                msg["resources"] = resources;
            }

            if let Ok(msg_str) = serde_json::to_string(&msg) {
                let _ = sender.send(msg_str).await;
            }
        }

        Ok(())
    }

    /// Initialize challenges from list received from Platform API
    pub async fn initialize_challenges(&self, challenge_specs: Vec<ChallengeSpec>) -> Result<()> {
        info!("Initializing {} challenges", challenge_specs.len());

        let mut specs_map = self.challenge_specs.write().await;
        let mut challenges = self.challenges.write().await;

        for spec in challenge_specs {
            let compose_hash = spec.compose_hash.clone();

            // Check if compose_yaml changed for existing challenge
            let should_recycle = if let Some(old_spec) = specs_map.get(&compose_hash) {
                old_spec.compose_yaml != spec.compose_yaml
            } else {
                false
            };

            // Store the spec (always update to latest from platform-api)
            specs_map.insert(compose_hash.clone(), spec.clone());

            // Register challenge with quota manager
            self.quota_manager
                .register_or_update_challenge(compose_hash.clone(), spec.emission_share)
                .await;

            if !challenges.contains_key(&compose_hash) {
                // Create new challenge instance
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
                    ws_sender: Arc::new(tokio::sync::Mutex::new(None)),
                };

                challenges.insert(compose_hash.clone(), instance);
                info!(
                    "Created challenge instance for compose_hash: {}",
                    compose_hash
                );
            } else if should_recycle {
                // Docker compose changed, mark for recycling
                if let Some(instance) = challenges.get_mut(&compose_hash) {
                    info!(
                        "Docker compose changed for challenge {}, marking for recycling",
                        compose_hash
                    );
                    instance.state = ChallengeState::Recycling;
                }
            }
        }

        Ok(())
    }

    /// Update a challenge (redeploy if compose hash changed)
    pub async fn update_challenge(&self, spec: ChallengeSpec) -> Result<()> {
        let mut challenges = self.challenges.write().await;

        if let Some(instance) = challenges.get_mut(&spec.compose_hash) {
            // If this is an update, mark for recycling if needed
            if instance.state == ChallengeState::Active {
                info!(
                    "Challenge {} updated, marking for recycling",
                    spec.compose_hash
                );
                instance.state = ChallengeState::Recycling;
            }
        } else {
            // New challenge
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
                ws_sender: Arc::new(tokio::sync::Mutex::new(None)),
            };
            challenges.insert(spec.compose_hash, instance);
        }

        Ok(())
    }

    /// Remove a challenge
    pub async fn remove_challenge(&self, compose_hash: &str) -> Result<()> {
        let mut challenges = self.challenges.write().await;

        if let Some(instance) = challenges.remove(compose_hash) {
            // Clean up CVM instance if it exists
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

    /// Get challenge status for all challenges
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

    /// Get challenge API URL by challenge_id (UUID or name)
    /// Returns None if challenge is not found or not in Active state
    pub async fn get_challenge_api_url(&self, challenge_id: &str) -> Result<Option<String>> {
        let specs = self.challenge_specs.read().await;
        let challenges = self.challenges.read().await;

        // Find the challenge spec by id or name
        let spec = specs
            .values()
            .find(|spec| spec.id == challenge_id || spec.name == challenge_id);

        if let Some(spec) = spec {
            let compose_hash = &spec.compose_hash;

            // Find the challenge instance
            if let Some(instance) = challenges.get(compose_hash) {
                // Only return URL if challenge is Active
                if instance.state == ChallengeState::Active {
                    return Ok(instance.challenge_api_url.clone());
                } else {
                    warn!(
                        "Challenge {} is not in Active state (current: {:?})",
                        challenge_id, instance.state
                    );
                }
            }
        }

        Ok(None)
    }

    /// Send job_execute message to challenge via WebSocket
    /// Retries if WebSocket connection is not yet established
    pub async fn send_job_execute(
        &self,
        challenge_id: &str,
        job_id: &str,
        job_name: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        // Find challenge by id or name
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

        // Get WebSocket sender
        let ws_sender = {
            let challenges = self.challenges.read().await;
            if let Some(instance) = challenges.get(&compose_hash) {
                if instance.state != ChallengeState::Active {
                    return Err(anyhow::anyhow!(
                        "Challenge {} is not in Active state",
                        challenge_id
                    ));
                }
                instance.ws_sender.clone()
            } else {
                return Err(anyhow::anyhow!(
                    "Challenge instance not found for {}",
                    challenge_id
                ));
            }
        };

        // Send job_execute message with retry logic
        let job_msg = serde_json::json!({
            "type": "job_execute",
            "job_id": job_id,
            "job_name": job_name,
            "payload": payload,
        });

        // Retry up to 10 times with 500ms delay between attempts
        // This gives the WebSocket connection time to establish and complete attestation
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
                        info!(
                            "Sent job_execute message for job {} to challenge {} (attempt {})",
                            job_id,
                            challenge_id,
                            attempt + 1
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        if attempt == max_retries - 1 {
                            return Err(anyhow::anyhow!(
                                "Failed to send job_execute after {} attempts: {}",
                                max_retries,
                                e
                            ));
                        }
                        warn!(
                            "Failed to send job_execute (attempt {}): {}, retrying...",
                            attempt + 1,
                            e
                        );
                    }
                }
            } else {
                if attempt == max_retries - 1 {
                    return Err(anyhow::anyhow!(
                        "WebSocket connection not established for challenge {} after {} attempts",
                        challenge_id,
                        max_retries
                    ));
                }
                debug!(
                    "WebSocket sender not yet available for challenge {} (attempt {}), waiting...",
                    challenge_id,
                    attempt + 1
                );
            }

            tokio::time::sleep(retry_delay).await;
        }

        Err(anyhow::anyhow!(
            "Failed to send job_execute: max retries exceeded"
        ))
    }

    /// Reconcile loop - ensures exactly one CVM per compose_hash
    pub async fn reconcile(&self) -> Result<()> {
        let challenges = self.challenges.read().await;
        let specs = self.challenge_specs.read().await;

        // Debug: log reconcile execution
        if !challenges.is_empty() {
            let states: Vec<(String, String)> = challenges
                .iter()
                .map(|(hash, inst)| (hash.clone(), format!("{:?}", inst.state)))
                .collect();
            debug!("Reconciling challenges: {:?}", states);
        }

        for (compose_hash, instance) in challenges.iter() {
            debug!(
                "Processing challenge {} in state {:?}",
                compose_hash, instance.state
            );
            match instance.state {
                ChallengeState::Created => {
                    // Provision new CVM or Docker container (only if not already being provisioned)
                    if let Some(spec) = specs.get(compose_hash) {
                        // Check if CVM/container already exists
                        if let Some(cvm_id) = &instance.cvm_instance_id {
                            warn!(
                                "Challenge {} already has CVM/container {}, skipping provisioning",
                                compose_hash, cvm_id
                            );
                            drop(challenges);
                            drop(specs);
                            return Ok(());
                        }

                        let spec_clone = spec.clone();
                        let compose_hash_clone = compose_hash.clone();
                        drop(challenges);
                        drop(specs);

                        // Use Docker in dev mode, VMM in production
                        if self.use_docker {
                            self.provision_docker_container(spec_clone).await?;
                        } else {
                            self.provision_cvm(spec_clone).await?;
                        }
                        return Ok(()); // Return after one operation to avoid deadlock
                    }
                }
                ChallengeState::Provisioning => {
                    // Check provisioning status
                    if let Some(cvm_id) = &instance.cvm_instance_id {
                        let compose_hash_clone = compose_hash.clone();
                        let cvm_id_clone = cvm_id.clone();
                        drop(challenges);
                        drop(specs);

                        // Use Docker check in dev mode, VMM check in production
                        if self.use_docker {
                            self.check_docker_provisioning_status(
                                &compose_hash_clone,
                                &cvm_id_clone,
                            )
                            .await?;
                        } else {
                            self.check_provisioning_status(&compose_hash_clone, &cvm_id_clone)
                                .await?;
                        }
                        return Ok(());
                    }
                }
                ChallengeState::Probing => {
                    // Probe health
                    if let Some(api_url) = &instance.challenge_api_url {
                        let compose_hash_clone = compose_hash.clone();
                        let api_url_clone = api_url.clone();
                        drop(challenges);
                        drop(specs);
                        debug!(
                            "Starting health probe for challenge {} at {}",
                            compose_hash_clone, api_url_clone
                        );
                        self.probe_health(&compose_hash_clone, &api_url_clone)
                            .await?;
                        return Ok(());
                    } else {
                        warn!(
                            "Challenge {} in Probing state but no api_url set",
                            compose_hash
                        );
                    }
                }
                ChallengeState::Active => {
                    // Ensure WS dialer is started once; also do periodic health check
                    if let Some(api_url) = &instance.challenge_api_url {
                        let compose_hash_clone = compose_hash.clone();
                        let api_url_clone = api_url.clone();
                        let need_ws = !instance.ws_started;
                        drop(challenges);
                        drop(specs);

                        if need_ws {
                            // Get challenge_id from spec for ORM forwarding
                            let challenge_id_opt = {
                                let specs = self.challenge_specs.read().await;
                                specs.get(&compose_hash_clone).map(|s| s.id.clone())
                            };

                            // Get ws_sender from instance to store it
                            let ws_sender_arc = {
                                let challenges = self.challenges.read().await;
                                if let Some(instance) = challenges.get(&compose_hash_clone) {
                                    instance.ws_sender.clone()
                                } else {
                                    return Ok(());
                                }
                            };

                            // Turn https://host:port into wss://host:port/sdk/ws
                            let ws_url = api_url_clone
                                .replace("https://", "wss://")
                                .replace("http://", "ws://")
                                + "/sdk/ws";
                            let client = ChallengeWsClient::new(
                                ws_url.clone(),
                                self.client.validator_hotkey.clone(),
                            );
                            let compose_hash_for_log = compose_hash_clone.clone();
                            let compose_hash_for_spawn = compose_hash_clone.clone();
                            let platform_client = self.client.clone();
                            let challenge_id_for_orm = challenge_id_opt.clone();
                            let ws_sender_for_store = ws_sender_arc.clone();
                            let platform_ws_sender_spawn = self.platform_ws_sender.clone();
                            let orm_query_routing_spawn = self.orm_query_routing.clone();
                            
                            tokio::spawn(async move {
                                // on_ready callback: store sender and initialize ORM bridge
                                let ws_sender_for_ready = ws_sender_for_store.clone();
                                let compose_hash_for_ready = compose_hash_for_log.clone();
                                let on_ready_cb = move |sender: tokio::sync::mpsc::Sender<
                                    serde_json::Value,
                                >| {
                                    let sender_clone = sender.clone();
                                    let ws_sender_store = ws_sender_for_ready.clone();
                                    let compose_hash_log = compose_hash_for_ready.clone();
                                    
                                    // Store sender asynchronously (non-blocking)
                                    tokio::spawn(async move {
                                        let mut guard = ws_sender_store.lock().await;
                                        // Always update the sender, even if one already exists (in case of reconnection with new keys)
                                        *guard = Some(sender_clone.clone());
                                        info!("✅ WebSocket sender stored/updated for challenge {} (ready for job_execute)", compose_hash_log);
                                        
                                        // Initialize ORM bridge: send orm_ready without schema
                                        // Platform API will resolve the correct schema when processing ORM queries
                                        let orm_ready_msg = serde_json::json!({
                                            "type": "orm_ready"
                                        });
                                        
                                        if let Err(e) = sender_clone.send(orm_ready_msg).await {
                                            error!("Failed to send orm_ready to challenge {}: {}", compose_hash_log, e);
                                        } else {
                                            info!("✅ Sent orm_ready signal to challenge {} (schema will be resolved by platform-api)", compose_hash_log);
                                        }
                                    });
                                };

                                let ws_sender_for_cleanup = ws_sender_for_store.clone();
                                let compose_hash_for_cleanup = compose_hash_for_spawn.clone();

                                // Clean up ws_sender before each reconnection attempt
                                {
                                    let mut guard = ws_sender_for_cleanup.lock().await;
                                    if guard.is_some() {
                                        *guard = None;
                                        info!("🔄 Cleared old WebSocket sender for challenge {} (preparing for reconnection)", compose_hash_for_cleanup);
                                    }
                                }

                                let ws_sender_for_disconnect_loop = ws_sender_for_store.clone();
                                let compose_hash_for_disconnect =
                                    Arc::new(compose_hash_for_spawn.clone());
                                let on_disconnect_cb = {
                                    let compose_hash_for_disconnect =
                                        compose_hash_for_disconnect.clone();
                                    move || {
                                        let ws_sender_cleanup =
                                            ws_sender_for_disconnect_loop.clone();
                                        let compose_hash_log = compose_hash_for_disconnect.clone();
                                        tokio::spawn(async move {
                                            let mut guard = ws_sender_cleanup.lock().await;
                                            if guard.is_some() {
                                                *guard = None;
                                                info!(
                                                    "🔌 Cleared WebSocket sender for challenge {} (connection closed)",
                                                    compose_hash_log.as_str()
                                                );
                                            }
                                        });
                                    }
                                };
                                
                                // Use the cloned versions from outside the tokio::spawn
                                let platform_ws_sender_for_orm = platform_ws_sender_spawn.clone();
                                let orm_query_routing_for_orm = orm_query_routing_spawn.clone();

                                client.connect_with_reconnect_and_ready(
                                    move |json, sender| {
                                        // Forward known types to Platform API via HTTP
                                    if let Some(typ) = json.get("type").and_then(|t| t.as_str()) {
                                        match typ {
                                            "heartbeat" => {
                                                if let Some(payload) = json.get("payload") {
                                                    if let Err(e) = forward_heartbeat(payload.clone()) {
                                                        warn!("forward heartbeat error: {}", e);
                                                    }
                                                }
                                            }
                                            "logs" => {
                                                if let Some(payload) = json.get("payload") {
                                                    if let Err(e) = forward_logs(payload.clone()) {
                                                        warn!("forward logs error: {}", e);
                                                    }
                                                }
                                            }
                                            "submit" => {
                                                if let Some(payload) = json.get("payload") {
                                                    if let Err(e) = forward_submit(payload.clone()) {
                                                        warn!("forward submit error: {}", e);
                                                    }
                                                }
                                            }
                                            "orm_query" => {
                                                // Forward ORM query to platform-api (read-only)
                                                // The message structure from challenge SDK is:
                                                // { "type": "orm_query", "payload": { "query": { ... ORMQuery ... }, "query_id": "..." } }
                                                if let Some(query_payload) = json.get("payload").and_then(|p| p.get("query")) {
                                                    let query_clone = query_payload.clone();
                                                    let client_clone = platform_client.clone();
                                                    let challenge_id_clone = challenge_id_for_orm.clone();
                                                    let sender_clone = sender.clone();

                                                    // Extract query_id if present for response matching
                                                    // Check both payload.query_id and top-level query_id
                                                    let query_id = json.get("payload")
                                                        .and_then(|p| p.get("query_id"))
                                                        .and_then(|q| q.as_str())
                                                        .or_else(|| json.get("query_id").and_then(|q| q.as_str()))
                                                        .map(|s| s.to_string());

                                                    // Clone compose_hash for spawn (it's captured in Fn closure)
                                                    let compose_hash_spawn_clone = compose_hash_for_spawn.clone();

                                                    // Use the cloned versions from outside the closure
                                                    let platform_ws_sender = platform_ws_sender_for_orm.clone();
                                                    let orm_query_routing = orm_query_routing_for_orm.clone();
                                                    
                                                    tokio::spawn(async move {
                                                        if let Some(challenge_id) = challenge_id_clone {
                                                            info!("Forwarding ORM query to platform-api via WebSocket for challenge {}", challenge_id);
                                                            
                                                            // Get platform WebSocket sender
                                                            let ws_sender_guard = platform_ws_sender.lock().await;
                                                            if let Some(ref ws_sender) = *ws_sender_guard {
                                                                // Generate a unique query_id if not present
                                                                let final_query_id = query_id.clone()
                                                                    .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
                                                                
                                                                // Store routing information
                                                                {
                                                                    let mut routing_guard = orm_query_routing.write().await;
                                                                    routing_guard.insert(
                                                                        final_query_id.clone(),
                                                                        (compose_hash_spawn_clone.clone(), sender_clone.clone())
                                                                    );
                                                                }
                                                                
                                                                // Send ORM query via WebSocket
                                                                match client_clone.send_orm_query_via_websocket(
                                                                    ws_sender,
                                                                    &challenge_id,
                                                                    query_clone,
                                                                    &final_query_id
                                                                ).await {
                                                                    Ok(_) => {
                                                                        // Note: The response will come back through the WebSocket message handler
                                                                        // and will be routed back to the challenge based on query_id
                                                                    }
                                                                    Err(e) => {
                                                                        error!("Failed to send ORM query via WebSocket: {}", e);
                                                                        
                                                                        // Clean up routing entry
                                                                        {
                                                                            let mut routing_guard = orm_query_routing.write().await;
                                                                            routing_guard.remove(&final_query_id);
                                                                        }

                                                                        // Send error response to challenge
                                                                        let mut error_response = serde_json::json!({
                                                                            "type": "error",
                                                                            "message": format!("ORM query failed: {}", e)
                                                                        });

                                                                        error_response["query_id"] = serde_json::Value::String(final_query_id.clone());

                                                                        if let Err(send_err) = sender_clone.send(error_response).await {
                                                                            warn!("Failed to send ORM error to challenge: {}", send_err);
                                                                        }
                                                                    }
                                                                }
                                                            } else {
                                                                error!("Platform WebSocket not connected - cannot forward ORM query");
                                                                
                                                                // Send error response to challenge
                                                                let mut error_response = serde_json::json!({
                                                                    "type": "error",
                                                                    "message": "Platform WebSocket not connected"
                                                                });

                                                                if let Some(ref qid) = query_id {
                                                                    error_response["query_id"] = serde_json::Value::String(qid.clone());
                                                                }

                                                                if let Err(send_err) = sender_clone.send(error_response).await {
                                                                    warn!("Failed to send ORM error to challenge: {}", send_err);
                                                                }
                                                            }
                                                        } else {
                                                            warn!("Cannot forward ORM query: challenge_id not available for compose_hash {}", compose_hash_spawn_clone);

                                                            // Send error response
                                                            let mut error_response = serde_json::json!({
                                                                "type": "error",
                                                                "message": "Challenge ID not available for ORM query"
                                                            });

                                                            if let Some(ref qid) = query_id {
                                                                error_response["query_id"] = serde_json::Value::String(qid.clone());
                                                            }

                                                            if let Err(e) = sender_clone.send(error_response).await {
                                                                warn!("Failed to send ORM error to challenge: {}", e);
                                                            }
                                                        }
                                                    });
                                                } else {
                                                    warn!("Received orm_query without query payload");
                                                }
                                            }
                                            _ => {
                                                info!("WS[{}] message type: {}", compose_hash_for_log, typ);
                                            }
                                        }
                                    }
                                },
                                Some(on_ready_cb),
                                Some(on_disconnect_cb)
                            ).await;
                            });

                            // Mark ws_started
                            let mut challenges2 = self.challenges.write().await;
                            if let Some(inst) = challenges2.get_mut(&compose_hash_clone) {
                                inst.ws_started = true;
                            }
                        }

                        self.probe_health(&compose_hash_clone, &api_url_clone)
                            .await?;
                        return Ok(());
                    }
                }
                ChallengeState::Recycling => {
                    // Clean up and recreate
                    if let Some(cvm_id) = &instance.cvm_instance_id {
                        let compose_hash_clone = compose_hash.clone();
                        let cvm_id_clone = cvm_id.clone();
                        drop(challenges);
                        drop(specs);
                        self.recycle_cvm(&compose_hash_clone, &cvm_id_clone).await?;
                        return Ok(());
                    }
                }
                ChallengeState::Failed => {
                    // Attempt to recover
                    if let Some(cvm_id) = &instance.cvm_instance_id {
                        let compose_hash_clone = compose_hash.clone();
                        let cvm_id_clone = cvm_id.clone();
                        drop(challenges);
                        drop(specs);
                        self.recycle_cvm(&compose_hash_clone, &cvm_id_clone).await?;
                        return Ok(());
                    }
                }
                ChallengeState::Deprecated => {
                    // Check if timeout reached (10 minutes)
                    if let Some(deprecated_at) = instance.deprecated_at {
                        let elapsed = Utc::now().signed_duration_since(deprecated_at);
                        if elapsed.num_seconds() > 600 {
                            // Timeout reached, force recycle
                            info!(
                                "Deprecated challenge {} timeout reached, forcing recycle",
                                compose_hash
                            );
                            if let Some(cvm_id) = &instance.cvm_instance_id {
                                let compose_hash_clone = compose_hash.clone();
                                let cvm_id_clone = cvm_id.clone();
                                drop(challenges);
                                drop(specs);
                                self.recycle_cvm(&compose_hash_clone, &cvm_id_clone).await?;
                                return Ok(());
                            }
                        }
                    }
                    // Check if all jobs for this challenge are finished when implementing job tracking
                    // For now, just wait for timeout
                }
            }
        }

        Ok(())
    }

    /// Provision a CVM for a challenge
    async fn provision_cvm(&self, spec: ChallengeSpec) -> Result<()> {
        info!("Provisioning CVM for challenge: {}", spec.compose_hash);

        let mut challenges = self.challenges.write().await;

        if let Some(instance) = challenges.get_mut(&spec.compose_hash) {
            instance.state = ChallengeState::Provisioning;

            let compose_hash_clone = spec.compose_hash.clone();
            drop(challenges);

            // Parse resources
            let memory_mb = parse_memory(&spec.resources.memory)?;
            let disk_mb = spec
                .resources
                .disk
                .as_ref()
                .map(|d| parse_disk_size(d))
                .transpose()?
                .unwrap_or(20) as u64
                * 1024;

            // Create resource request
            use crate::cvm_quota::ResourceRequest;
            let resource_request = ResourceRequest {
                cpu_cores: spec.resources.vcpu,
                memory_mb: memory_mb as u64,
                disk_mb,
            };

            // Check and reserve quota using new dynamic system
            match self
                .quota_manager
                .reserve(&compose_hash_clone, resource_request)
                .await
            {
                Ok(crate::cvm_quota::QuotaResult::Granted) => {
                    info!("Quota granted for challenge {}", compose_hash_clone);
                }
                Ok(crate::cvm_quota::QuotaResult::Insufficient) => {
                    warn!(
                        "Insufficient quota for challenge {}, backing off",
                        compose_hash_clone
                    );
                    let mut challenges = self.challenges.write().await;
                    if let Some(instance) = challenges.get_mut(&compose_hash_clone) {
                        instance.state = ChallengeState::Failed;
                    }
                    return Err(anyhow::anyhow!("Insufficient quota for challenge"));
                }
                Err(e) => {
                    error!("Quota check failed: {}", e);
                    let mut challenges = self.challenges.write().await;
                    if let Some(instance) = challenges.get_mut(&compose_hash_clone) {
                        instance.state = ChallengeState::Failed;
                    }
                    return Err(e);
                }
            }

            // Decode base64 docker-compose.yaml
            let compose_yaml = base64::decode(&spec.compose_yaml)
                .map_err(|e| anyhow::anyhow!("Failed to decode compose_yaml from base64: {}", e))?;
            let compose_yaml_str = String::from_utf8(compose_yaml)
                .map_err(|e| anyhow::anyhow!("Failed to convert compose_yaml to string: {}", e))?;

            info!(
                "Decoded docker-compose.yaml for challenge {}",
                compose_hash_clone
            );

            // Parse memory
            let memory_mb = parse_memory(&spec.resources.memory)?;

            // Get dstack config or use defaults
            let dstack_config = spec.dstack_config.as_ref();

            // Parse docker-compose YAML
            let mut compose_doc: serde_yaml::Value = serde_yaml::from_str(&compose_yaml_str)
                .context("Failed to parse docker-compose YAML")?;

            // No longer inject VALIDATOR_BASE_URL; WS is validator-initiated

            // Convert back to YAML string (no injection)
            let modified_compose_yaml = serde_yaml::to_string(&compose_doc)
                .context("Failed to serialize modified docker-compose YAML")?;

            // Create AppCompose JSON structure expected by VMM
            // Use production-ready defaults matching VMM console expectations
            // Use compose_hash as name to ensure uniqueness per compose version
            let mut app_compose = serde_json::json!({
                "manifest_version": 2,
                "name": compose_hash_clone.clone(),
                "runner": "docker-compose",
                "docker_compose_file": modified_compose_yaml,
                "docker_config": {}, // Empty docker config by default
                "kms_enabled": dstack_config.map(|c| c.kms_enabled).unwrap_or(true), // Enable KMS by default for Update Compose button
                "gateway_enabled": dstack_config.map(|c| c.gateway_enabled).unwrap_or(true),
                "public_logs": dstack_config.map(|c| c.public_logs).unwrap_or(true), // Enable logs by default
                "public_sysinfo": dstack_config.map(|c| c.public_sysinfo).unwrap_or(true), // Enable sysinfo by default
                "public_tcbinfo": dstack_config.map(|c| c.public_tcbinfo).unwrap_or(true),
                "local_key_provider_enabled": dstack_config.map(|c| c.local_key_provider_enabled).unwrap_or(false),
                "key_provider_id": dstack_config.and_then(|c| c.key_provider_id.clone()).unwrap_or_else(|| "".to_string()),
                "allowed_envs": dstack_config.and_then(|c| c.allowed_envs.clone()).unwrap_or_default(),
                "no_instance_id": dstack_config.map(|c| c.no_instance_id).unwrap_or(false),
                "secure_time": dstack_config.map(|c| c.secure_time).unwrap_or(false), // Default to false for production
            });

            // Add pre_launch_script if provided
            if let Some(script) = dstack_config.and_then(|c| c.pre_launch_script.clone()) {
                app_compose["pre_launch_script"] = serde_json::Value::String(script);
            }

            let app_compose_json = app_compose;
            let app_compose_str = serde_json::to_string(&app_compose_json)
                .map_err(|e| anyhow::anyhow!("Failed to serialize AppCompose JSON: {}", e))?;

            // Create VMM configuration
            // CVMs access validator via gateway host (10.0.2.2) on configured port
            let dstack_image = spec.dstack_image.as_deref().unwrap_or("dstack-0.5.2");

            // No validator URL injection required for WS
            let user_config = String::new();

            // No port forwarding needed - gateway handles routing via instance_id
            let ports = vec![];

            // Get or prompt for private environment variables
            // Pass github_repo to load platform.toml
            let private_env_vars = get_or_prompt_env_vars(
                &self.dynamic_values,
                &compose_hash_clone,
                &spec.name,
                spec.github_repo.as_ref(),
            )
            .await
            .context("Failed to get or prompt for private environment variables")?;

            // Convert env vars to encrypted_env format (Vec<u8> as JSON)
            // Serialize as JSON array of "KEY=VALUE" strings
            let env_var_strings: Vec<String> = private_env_vars
                .iter()
                .map(|(key, value)| format!("{}={}", key, value))
                .collect();
            let encrypted_env = serde_json::to_vec(&env_var_strings)
                .context("Failed to serialize environment variables as JSON")?;

            info!(
                "Prepared {} private environment variables for challenge {}",
                private_env_vars.len(),
                compose_hash_clone
            );

            // Check if CVM with this compose_hash already exists
            let existing_vm = self.vmm_client.list_vms().await.ok().and_then(|vms| {
                vms.iter()
                    .find(|vm| vm.name == compose_hash_clone)
                    .map(|vm| vm.id.clone())
            });

            let vm_result = if let Some(existing_vm_id) = existing_vm {
                info!(
                    compose_hash = &compose_hash_clone,
                    existing_vm_id = &existing_vm_id,
                    "CVM with compose_hash already exists, reusing"
                );
                // Verify the existing CVM matches our compose_hash (it should since name matches)
                Ok(existing_vm_id)
            } else {
                // Create new VM with compose_hash as name
                let vm_config = VmConfiguration {
                    name: compose_hash_clone.clone(),
                    image: dstack_image.to_string(),
                    compose_file: app_compose_str,
                    vcpu: spec.resources.vcpu,
                    memory: memory_mb,
                    disk_size: spec
                        .resources
                        .disk
                        .as_ref()
                        .map(|d| parse_disk_size(d))
                        .transpose()?
                        .unwrap_or(20),
                    ports,
                    encrypted_env, // Private environment variables from validator DB
                    app_id: None,  // No app_id for new challenges
                    user_config,   // Empty user config - WS is validator-initiated
                    hugepages: dstack_config.map(|c| c.hugepages).unwrap_or(false),
                    pin_numa: dstack_config.map(|c| c.pin_numa).unwrap_or(false),
                    gpus: None,           // No GPU by default
                    kms_urls: vec![],     // Empty KMS URLs by default
                    gateway_urls: vec![], // Empty gateway URLs by default
                    stopped: false,
                };

                // Create VM
                self.vmm_client.create_vm(vm_config).await
            };

            let mut challenges = self.challenges.write().await;
            if let Some(instance) = challenges.get_mut(&compose_hash_clone) {
                match vm_result {
                    Ok(vm_id) => {
                        instance.cvm_instance_id = Some(vm_id.clone());

                        // Get gateway base domain and port - REQUIRED
                        let base_domain = self
                            .get_gateway_base_domain()
                            .await
                            .context("Failed to get gateway base_domain from VMM")?;
                        let gateway_port = self
                            .get_gateway_port()
                            .await
                            .context("Failed to get gateway port from VMM")?;

                        // Get VM info to try to retrieve instance_id immediately
                        let mut instance_id = None;
                        if let Ok(vm_info) = self.vmm_client.get_vm_info(&vm_id).await {
                            instance_id = vm_info.instance_id;
                        }

                        // Build base hostname first
                        // Format: {instance_id}-10000.{base_domain}:{gateway_port}
                        // where 10000 is the port the challenge serves on, and gateway_port is for gateway access
                        let host = if let Some(id) = &instance_id {
                            if !id.trim().is_empty() {
                                format!("{}-10000.{}:{}", id, base_domain, gateway_port)
                            } else {
                                format!("-10000.{}:{}", base_domain, gateway_port)
                            }
                        } else {
                            format!("-10000.{}:{}", base_domain, gateway_port)
                        };

                        // Store HTTP base URL for health checks
                        let http_url = format!("https://{}", host);
                        instance.challenge_api_url = Some(http_url.clone());
                        info!("CVM provisioned: {} with gateway host: {}", vm_id, host);
                        // Quota already allocated above, no need to refresh
                    }
                    Err(e) => {
                        error!("Failed to provision CVM: {}", e);
                        instance.state = ChallengeState::Failed;
                        // Release quota on failure
                        drop(challenges);
                        use crate::cvm_quota::ResourceRequest;
                        let _ = self
                            .quota_manager
                            .release(
                                &compose_hash_clone,
                                ResourceRequest {
                                    cpu_cores: spec.resources.vcpu,
                                    memory_mb: memory_mb as u64,
                                    disk_mb,
                                },
                            )
                            .await;
                    }
                }
            }
        }

        Ok(())
    }

    /// Provision a Docker container for a challenge (dev mode)
    async fn provision_docker_container(&self, spec: ChallengeSpec) -> Result<()> {
        let compose_hash_clone = spec.compose_hash.clone();

        info!("Attempting to provision Docker container for challenge {} (use_docker: {}, docker_client available: {})", 
            compose_hash_clone, self.use_docker, self.docker_client.is_some());

        // Check if Docker client is available
        let docker_client = match &self.docker_client {
            Some(client) => {
                info!(
                    "Docker client is available for challenge {}",
                    compose_hash_clone
                );
                client
            }
            None => {
                error!(
                    "Docker client not available for challenge {} (use_docker: {})",
                    compose_hash_clone, self.use_docker
                );
                let mut challenges = self.challenges.write().await;
                if let Some(instance) = challenges.get_mut(&compose_hash_clone) {
                    instance.state = ChallengeState::Failed;
                }
                return Err(anyhow::anyhow!(
                    "Docker client not available (use_docker: {}, client initialized: {})",
                    self.use_docker,
                    false
                ));
            }
        };

        // Update state to Provisioning
        {
            let mut challenges = self.challenges.write().await;
            if let Some(instance) = challenges.get_mut(&compose_hash_clone) {
                instance.state = ChallengeState::Provisioning;
            }
        }

        // Get image from spec (first image in the list)
        let image = spec
            .images
            .first()
            .ok_or_else(|| anyhow::anyhow!("No image specified in challenge spec"))?
            .clone();

        info!(
            "Provisioning Docker container for challenge {} with image: {}",
            compose_hash_clone, image
        );

        // Ensure Docker network exists (lazy initialization)
        if let Err(e) = docker_client.ensure_network().await {
            error!("Failed to ensure Docker network exists: {}", e);
            return Err(anyhow::anyhow!("Failed to ensure Docker network: {}", e));
        }

        // Build environment variables
        let mut env_vars = HashMap::new();

        // Add spec environment variables
        for (key, value) in &spec.env {
            env_vars.insert(key.clone(), value.clone());
        }

        // Add required system environment variables
        env_vars.insert("ENVIRONMENT_MODE".to_string(), "dev".to_string());
        env_vars.insert("CHALLENGE_ID".to_string(), spec.name.clone());
        env_vars.insert(
            "PLATFORM_API_URL".to_string(),
            std::env::var("PLATFORM_BASE_API")
                .unwrap_or_else(|_| "http://platform-api:15000".to_string()),
        );

        // Add dev mode environment variables for challenge SDK
        // These are required for the challenge SDK to use mock quotes instead of trying dstack SDK
        let validator_mock_vmm =
            std::env::var("VALIDATOR_MOCK_VMM").unwrap_or_else(|_| "false".to_string()) == "true";

        if validator_mock_vmm {
            // Validator is in dev mode, so challenge should also use dev mode
            env_vars.insert("SDK_DEV_MODE".to_string(), "true".to_string());
            env_vars.insert("TEE_ENFORCED".to_string(), "false".to_string());

            // Pass TDX_SIMULATION_MODE from validator to challenge
            // This controls whether mock TDX attestation is used (encryption is always enabled)
            let tdx_simulation_mode =
                std::env::var("TDX_SIMULATION_MODE").unwrap_or_else(|_| "true".to_string()); // Default to true in dev mode

            env_vars.insert(
                "TDX_SIMULATION_MODE".to_string(),
                tdx_simulation_mode.clone(),
            );

            info!("Setting dev mode environment variables for challenge container (SDK_DEV_MODE=true, TEE_ENFORCED=false, TDX_SIMULATION_MODE={})", 
                tdx_simulation_mode);
        }

        // Get or prompt for private environment variables
        let private_env_vars = get_or_prompt_env_vars(
            &self.dynamic_values,
            &compose_hash_clone,
            &spec.name,
            spec.github_repo.as_ref(),
        )
        .await
        .context("Failed to get or prompt for private environment variables")?;

        // Add private environment variables
        for (key, value) in private_env_vars {
            env_vars.insert(key, value);
        }

        // Build port mappings
        let mut port_mappings = Vec::new();
        for port in &spec.ports {
            port_mappings.push(DockerPortMapping {
                container_port: port.container,
                host_port: None, // Let Docker assign random port
                protocol: port.protocol.clone(),
            });
        }

        // Default port if none specified (challenge SDK typically uses 10000)
        if port_mappings.is_empty() {
            port_mappings.push(DockerPortMapping {
                container_port: 10000,
                host_port: None,
                protocol: "tcp".to_string(),
            });
        }

        // Create container configuration
        let container_name = format!("challenge-{}", compose_hash_clone);
        let container_config = ContainerConfig {
            name: container_name.clone(),
            image,
            env: env_vars,
            ports: port_mappings,
            network: self.docker_network.clone(),
            restart_policy: "unless-stopped".to_string(),
        };

        // Create and start container
        match docker_client
            .create_and_start_container(container_config)
            .await
        {
            Ok(container_id) => {
                info!("✅ Docker container {} created and started", container_name);

                // Wait a bit for container to initialize
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                // Get container IP address
                let container_ip = docker_client
                    .get_container_ip(&container_name)
                    .await
                    .context("Failed to get container IP")?;

                let http_url = if let Some(ip) = container_ip {
                    // Use container IP and default port
                    format!("http://{}:10000", ip)
                } else {
                    // Fallback: use container name in network
                    format!("http://{}:10000", container_name)
                };

                // Update challenge instance
                let mut challenges = self.challenges.write().await;
                if let Some(instance) = challenges.get_mut(&compose_hash_clone) {
                    instance.cvm_instance_id = Some(container_id);
                    instance.challenge_api_url = Some(http_url.clone());
                    instance.state = ChallengeState::Probing;
                }

                info!("Docker container {} ready at {}", container_name, http_url);
            }
            Err(e) => {
                error!("Failed to provision Docker container: {}", e);
                let mut challenges = self.challenges.write().await;
                if let Some(instance) = challenges.get_mut(&compose_hash_clone) {
                    instance.state = ChallengeState::Failed;
                }
                return Err(e);
            }
        }

        Ok(())
    }

    /// Check provisioning status (VMM)
    async fn check_provisioning_status(&self, compose_hash: &str, cvm_id: &str) -> Result<()> {
        match self.vmm_client.get_vm_info(cvm_id).await {
            Ok(info) => {
                if info.status == "running" {
                    let mut challenges = self.challenges.write().await;
                    if let Some(instance) = challenges.get_mut(compose_hash) {
                        instance.state = ChallengeState::Probing;
                        info!("CVM is running, starting health probe");
                    }
                }
            }
            Err(e) => {
                error!("Failed to get VM info: {}", e);
            }
        }

        Ok(())
    }

    /// Check Docker container provisioning status
    async fn check_docker_provisioning_status(
        &self,
        compose_hash: &str,
        container_id: &str,
    ) -> Result<()> {
        let docker_client = match &self.docker_client {
            Some(client) => client,
            None => {
                error!("Docker client not available");
                return Err(anyhow::anyhow!("Docker client not available"));
            }
        };

        let container_name = format!("challenge-{}", compose_hash);
        match docker_client.is_container_running(&container_name).await {
            Ok(true) => {
                let mut challenges = self.challenges.write().await;
                if let Some(instance) = challenges.get_mut(compose_hash) {
                    instance.state = ChallengeState::Probing;
                    info!(
                        "Docker container {} is running, starting health probe",
                        container_name
                    );
                }
            }
            Ok(false) => {
                warn!("Docker container {} is not running", container_name);
            }
            Err(e) => {
                error!("Failed to check Docker container status: {}", e);
            }
        }

        Ok(())
    }

    /// Probe health of challenge CVM
    async fn probe_health(&self, compose_hash: &str, api_url: &str) -> Result<()> {
        // Detect if this is a Docker container (HTTP URL) or VMM CVM (HTTPS URL)
        let is_docker = api_url.starts_with("http://") && !api_url.starts_with("https://");

        if is_docker {
            // Docker container: simple HTTP health check without instance_id logic
            info!(
                "Probing Docker container health for challenge {} at {}",
                compose_hash, api_url
            );

            let mut challenges = self.challenges.write().await;
            if let Some(instance) = challenges.get_mut(compose_hash) {
                instance.last_probe = Some(Utc::now());
                instance.probe_attempts += 1;
            }
            drop(challenges);

            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(3))
                .build()?;

            let probe_start = std::time::Instant::now();
            let probe_timeout = std::time::Duration::from_secs(30); // Shorter timeout for Docker
            let mut healthy = false;

            while !healthy && probe_start.elapsed() < probe_timeout {
                match client.get(&format!("{}/sdk/health", api_url)).send().await {
                    Ok(response) => {
                        if response.status().is_success() {
                            healthy = true;
                            let mut challenges = self.challenges.write().await;
                            if let Some(instance) = challenges.get_mut(compose_hash) {
                                instance.state = ChallengeState::Active;
                                instance.probe_attempts = 0;
                                info!("Challenge {} is healthy (Docker)", compose_hash);
                                info!("✅ Challenge {} is ready", compose_hash);
                            }
                            break;
                        } else {
                            debug!(
                                "Health check returned status {} for {}",
                                response.status(),
                                api_url
                            );
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        }
                    }
                    Err(e) => {
                        debug!("Health check error for {}: {}", api_url, e);
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                }
            }

            if !healthy {
                let mut challenges = self.challenges.write().await;
                if let Some(instance) = challenges.get_mut(compose_hash) {
                    warn!("Challenge {} health probe failed after 30s: error sending request for url ({}/sdk/health)", compose_hash, api_url);
                    instance.state = ChallengeState::Failed;
                }
            }

            return Ok(());
        }

        // VMM CVM: original logic with instance_id handling
        let mut challenges = self.challenges.write().await;

        // Check if instance_id is empty (URL starts with - after https://)
        // Pattern: https://-10000.domain:port vs https://abc123-10000.domain:port
        let has_empty_instance_id = api_url.contains("https://-")
            || api_url.contains("wss://-")
            || api_url.contains("ws://-");
        if has_empty_instance_id {
            // Try to get instance_id from VMM (poll with 60s timeout)
            let cvm_id = {
                let instance = challenges.get(compose_hash);
                instance.and_then(|i| i.cvm_instance_id.clone())
            };
            drop(challenges);

            if let Some(cvm_id_clone) = cvm_id {
                // Poll VMM for instance_id
                let start = std::time::Instant::now();
                let timeout = std::time::Duration::from_secs(60);
                let mut instance_id = None;

                while instance_id.is_none() && start.elapsed() < timeout {
                    match self.vmm_client.get_vm_info(&cvm_id_clone).await {
                        Ok(vm_info) => {
                            if let Some(id) = vm_info.instance_id {
                                // Treat empty string as missing
                                if !id.trim().is_empty() {
                                    instance_id = Some(id);
                                    break;
                                } else {
                                    info!("Waiting for challenge {} instance_id...", compose_hash);
                                }
                            } else {
                                info!("Waiting for challenge {} instance_id...", compose_hash);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to get VM info for {}: {}", cvm_id_clone, e);
                        }
                    }

                    // Wait 1 second before retrying
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }

                // Re-acquire write lock
                let mut challenges = self.challenges.write().await;
                if let Some(instance) = challenges.get_mut(compose_hash) {
                    if let Some(id) = instance_id {
                        // Build base hostname with instance_id
                        let base_domain = self
                            .get_gateway_base_domain()
                            .await
                            .context("Failed to get gateway base_domain")?;
                        let gateway_port = self
                            .get_gateway_port()
                            .await
                            .context("Failed to get gateway port")?;
                        // Format: {instance_id}-10000.{base_domain}:{gateway_port}
                        // where 10000 is the port the challenge serves on
                        let host = format!("{}-10000.{}:{}", id, base_domain, gateway_port);

                        // Store HTTP base URL for health checks
                        let http_url = format!("https://{}", host);
                        instance.challenge_api_url = Some(http_url.clone());
                        info!(
                            "Updated challenge {} URL with instance_id: https://{}",
                            compose_hash, host
                        );
                        drop(challenges);

                        // Perform health probe with retry loop: 120s total, 3s timeout per request
                        let client = reqwest::Client::builder()
                            .danger_accept_invalid_certs(true)
                            .timeout(std::time::Duration::from_secs(3))
                            .build()?;

                        let probe_start = std::time::Instant::now();
                        let probe_timeout = std::time::Duration::from_secs(120);
                        let mut healthy = false;

                        while !healthy && probe_start.elapsed() < probe_timeout {
                            match client.get(&format!("{}/sdk/health", http_url)).send().await {
                                Ok(response) => {
                                    if response.status().is_success() {
                                        healthy = true;
                                        let mut challenges = self.challenges.write().await;
                                        if let Some(instance) = challenges.get_mut(compose_hash) {
                                            instance.state = ChallengeState::Active;
                                            instance.probe_attempts = 0;
                                            info!("Challenge {} is healthy", compose_hash);
                                            info!("✅ Challenge {} is ready", compose_hash);
                                        }
                                        break;
                                    } else {
                                        // Wait a bit before retrying
                                        tokio::time::sleep(std::time::Duration::from_millis(500))
                                            .await;
                                    }
                                }
                                Err(_) => {
                                    // Wait a bit before retrying
                                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                }
                            }
                        }

                        if !healthy {
                            let mut challenges = self.challenges.write().await;
                            if let Some(instance) = challenges.get_mut(compose_hash) {
                                warn!("Challenge {} health probe failed after 120s: error sending request for url ({}/sdk/health)", compose_hash, http_url);
                            }
                        }

                        return Ok(());
                    } else {
                        let mut challenges = self.challenges.write().await;
                        if let Some(instance) = challenges.get_mut(compose_hash) {
                            error!(
                                "Challenge {} instance_id not available after 60s timeout",
                                compose_hash
                            );
                            instance.state = ChallengeState::Failed;
                        }
                        return Ok(());
                    }
                }
            } else {
                let mut challenges = self.challenges.write().await;
                if let Some(instance) = challenges.get_mut(compose_hash) {
                    error!("Challenge {} has invalid URL and no CVM ID", compose_hash);
                    instance.state = ChallengeState::Failed;
                }
                return Ok(());
            }
        }

        // Re-acquire lock for health check (if not already dropped above)
        let mut challenges = self.challenges.write().await;

        // Perform health check with retry loop: 120s total, 3s timeout per request
        if let Some(instance) = challenges.get_mut(compose_hash) {
            instance.last_probe = Some(Utc::now());
            instance.probe_attempts += 1;

            let api_url_clone = api_url.to_string();
            drop(challenges); // Release lock during network I/O

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true) // RA-TLS certificates
                .timeout(std::time::Duration::from_secs(3)) // 3s timeout per request
                .build()?;

            let probe_start = std::time::Instant::now();
            let probe_timeout = std::time::Duration::from_secs(120);
            let mut healthy = false;

            while !healthy && probe_start.elapsed() < probe_timeout {
                match client
                    .get(&format!("{}/sdk/health", api_url_clone))
                    .send()
                    .await
                {
                    Ok(response) => {
                        if response.status().is_success() {
                            healthy = true;
                            let mut challenges = self.challenges.write().await;
                            if let Some(instance) = challenges.get_mut(compose_hash) {
                                instance.state = ChallengeState::Active;
                                instance.probe_attempts = 0;
                                info!("Challenge {} is healthy", compose_hash);
                                info!("✅ Challenge {} is ready", compose_hash);
                            }
                            break;
                        } else {
                            // Wait a bit before retrying
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        }
                    }
                    Err(_) => {
                        // Wait a bit before retrying
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                }
            }

            if !healthy {
                let mut challenges = self.challenges.write().await;
                if let Some(instance) = challenges.get_mut(compose_hash) {
                    warn!("Challenge {} health probe failed after 120s: error sending request for url ({}/sdk/health)", compose_hash, api_url_clone);
                    // Mark as failed after 120s of retries
                    instance.state = ChallengeState::Failed;
                }
            }
        }

        Ok(())
    }

    /// Cleanup all Docker containers created by this validator
    pub async fn cleanup_docker_containers(&self) -> Result<()> {
        if !self.use_docker {
            return Ok(());
        }

        if let Some(docker_client) = &self.docker_client {
            info!("Cleaning up all Docker containers created by validator...");
            match docker_client
                .cleanup_containers_by_prefix("challenge-")
                .await
            {
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

    /// Recycle a CVM (stop, kill, remove, recreate)
    async fn recycle_cvm(&self, compose_hash: &str, cvm_id: &str) -> Result<()> {
        info!("Recycling CVM: {}", cvm_id);

        // Get VM info to extract resources before removing
        let resources = match self.vmm_client.get_vm_info(cvm_id).await {
            Ok(info) => {
                let vcpu = info
                    .configuration
                    .get("vcpu")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;
                let memory = info
                    .configuration
                    .get("memory")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let disk = info
                    .configuration
                    .get("disk_size")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                (vcpu, memory, disk)
            }
            Err(_) => (0, 0, 0),
        };

        // Step 1: Stop the VM gracefully first
        if let Err(e) = self.vmm_client.stop_vm(cvm_id).await {
            warn!("Failed to stop CVM {}: {}", cvm_id, e);
        }

        // Wait for stop to complete
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Step 2: Kill CVM if still running (force shutdown)
        if let Err(e) = self.vmm_client.kill_vm(cvm_id).await {
            warn!("Failed to kill CVM {}: {}", cvm_id, e);
        }

        // Wait a bit more for cleanup
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Step 3: Remove the CVM
        if let Err(e) = self.vmm_client.remove_vm(cvm_id).await {
            warn!("Failed to remove CVM {}: {}", cvm_id, e);
        }

        // Release quota
        if resources.0 > 0 {
            use crate::cvm_quota::ResourceRequest;
            let _ = self
                .quota_manager
                .release(
                    compose_hash,
                    ResourceRequest {
                        cpu_cores: resources.0,
                        memory_mb: resources.1,
                        disk_mb: resources.2,
                    },
                )
                .await;
        }

        // Reset state to Created to trigger provisioning
        let mut challenges = self.challenges.write().await;
        if let Some(instance) = challenges.get_mut(compose_hash) {
            // Don't recreate if deprecated
            if instance.state != ChallengeState::Deprecated {
                instance.state = ChallengeState::Created;
                instance.cvm_instance_id = None;
                instance.challenge_api_url = None;
                instance.probe_attempts = 0;
                info!("CVM {} recycled, will be recreated", cvm_id);
            } else {
                // If deprecated, just clear the CVM ID but don't recreate
                instance.cvm_instance_id = None;
                instance.challenge_api_url = None;
                info!("CVM {} removed for deprecated challenge", cvm_id);
            }
        }

        Ok(())
    }
}

fn forward_heartbeat(payload: serde_json::Value) -> Result<()> {
    let platform_api_url = std::env::var("PLATFORM_API_URL")
        .unwrap_or_else(|_| "http://platform-api:3000".to_string());
    let client = reqwest::blocking::Client::new();
    let _ = client
        .post(format!("{}/results/heartbeat", platform_api_url))
        .json(&payload)
        .send();
    Ok(())
}

fn forward_logs(payload: serde_json::Value) -> Result<()> {
    let platform_api_url = std::env::var("PLATFORM_API_URL")
        .unwrap_or_else(|_| "http://platform-api:3000".to_string());
    let client = reqwest::blocking::Client::new();
    let _ = client
        .post(format!("{}/results/logs", platform_api_url))
        .json(&payload)
        .send();
    Ok(())
}

fn forward_submit(payload: serde_json::Value) -> Result<()> {
    let platform_api_url = std::env::var("PLATFORM_API_URL")
        .unwrap_or_else(|_| "http://platform-api:3000".to_string());
    let client = reqwest::blocking::Client::new();
    let _ = client
        .post(format!("{}/results/submit", platform_api_url))
        .json(&payload)
        .send();
    Ok(())
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
