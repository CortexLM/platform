use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine as _};
use dstack_sdk::dstack_client::DstackClient;
use hex;
use platform_engine_api_client::PlatformClient;
use rand::RngCore;
use serde_json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

mod challenge_manager;
mod challenge_ws;
mod config;
mod cvm_quota;
mod docker_client;
mod dstack_provisioner;
mod env_prompt;
mod epoch_manager;
mod executor;
mod hotkey;
mod http_server;
mod job_manager;
mod job_vm_manager;
mod network_proxy;
mod platform_verifier;
mod secure_message;
mod vmm_client;

use challenge_manager::ChallengeManager;
use config::ValidatorConfig;
use cvm_quota::CVMQuotaManager;
use executor::DstackExecutor;
use hotkey::get_keypair_from_mnemonic;
use job_manager::JobManager;
use network_proxy::{create_network_policy, NetworkProxy};
use platform_engine_chain::{BlockSyncManager, SubtensorClient};
use platform_engine_dynamic_values::DynamicValuesManager;
use platform_verifier::PlatformVerifier;
use secure_message::SecureMessage;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Starting Platform Validator");

    // Load configuration
    let config = ValidatorConfig::load()?;
    info!(
        "Configuration loaded: validator={}",
        config.validator_hotkey
    );

    // Get keypair for signing messages
    let keypair = get_keypair_from_mnemonic(&config.hotkey_passphrase)?;

    // Initialize platform client
    let client = PlatformClient::new(
        config.platform_api_url.clone(),
        config.validator_hotkey.clone(),
    );

    // Initialize dynamic values manager
    let db_path =
        std::env::var("VALIDATOR_DB_PATH").unwrap_or_else(|_| "./validator.db".to_string());
    let dynamic_values_manager = Arc::new(DynamicValuesManager::new(&db_path)?);

    // Initialize job manager
    let job_manager = Arc::new(RwLock::new(JobManager::new(client.clone(), config.clone())));

    // Executor will be initialized after challenge_manager is created

    // Initialize CVM quota manager with capacity from config
    let capacity = crate::cvm_quota::ResourceCapacity {
        cpu_cores: config.resource_limits.cpu_cores,
        memory_mb: config.resource_limits.memory_mb,
        disk_mb: config.resource_limits.disk_mb,
    };
    let cvm_quota_manager = Arc::new(CVMQuotaManager::with_capacity(capacity));

    // Initialize VMM client
    let vmm_url = config.dstack_vmm_url.clone();
    // Note: vmm_client is created inside ChallengeManager, not needed here

    // Initialize Docker client if in dev mode
    info!(
        "Checking Docker mode: use_docker={}, VALIDATOR_MOCK_VMM={:?}, ENVIRONMENT_MODE={:?}",
        config.use_docker,
        std::env::var("VALIDATOR_MOCK_VMM").ok(),
        std::env::var("ENVIRONMENT_MODE").ok()
    );

    let docker_client = if config.use_docker {
        info!(
            "Initializing Docker client for dev mode (socket: {:?}, network: {})",
            config.docker_socket_path, config.docker_network
        );
        match crate::docker_client::DockerClient::new(
            config.docker_socket_path.clone(),
            config.docker_network.clone(),
        )
        .await
        {
            Ok(client) => {
                info!("✅ Docker client initialized successfully");
                Some(Arc::new(client))
            }
            Err(e) => {
                error!(
                    "Failed to initialize Docker client: {}. Continuing without Docker support.",
                    e
                );
                None
            }
        }
    } else {
        warn!("Docker mode is disabled. Set VALIDATOR_MOCK_VMM=true or ENVIRONMENT_MODE=dev to enable.");
        None
    };

    // Initialize challenge manager
    let challenge_manager = Arc::new(ChallengeManager::new(
        client.clone(),
        vmm_url.clone(),
        cvm_quota_manager.clone(),
        dynamic_values_manager.clone(),
        docker_client,
        config.docker_network.clone(),
        config.use_docker,
    ));

    // Initialize executor with challenge_manager
    let executor = Arc::new(RwLock::new(DstackExecutor::new(
        config.clone(),
        challenge_manager.clone(),
    )?));

    // Initialize chain components for epoch-based weight setting
    let epoch_config = epoch_manager::EpochConfig::default();
    info!(
        "Epoch manager configured with {} block intervals",
        epoch_config.block_interval
    );

    // Initialize SubtensorClient (using default endpoint for now)
    let subtensor_endpoint = std::env::var("SUBTENSOR_ENDPOINT")
        .unwrap_or_else(|_| "wss://entrypoint-finney.opentensor.ai:443".to_string());
    let subtensor_network =
        std::env::var("SUBTENSOR_NETWORK").unwrap_or_else(|_| "finney".to_string());
    let subtensor_client = Arc::new(SubtensorClient::new(
        subtensor_endpoint.clone(),
        subtensor_network.clone(),
    ));

    // Initialize BlockSyncManager
    let block_sync_manager = Arc::new(RwLock::new(BlockSyncManager::new(subtensor_client.clone())));

    // Get netuid from environment or use default
    let netuid: u16 = std::env::var("NETUID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    // Initialize EpochManager
    let validator_config_for_epoch = config.clone();
    let epoch_manager = Arc::new(epoch_manager::EpochManager::new(
        epoch_config,
        validator_config_for_epoch,
        block_sync_manager.clone(),
        challenge_manager.clone(),
        subtensor_client.clone(),
        client.clone(),
        netuid,
    ));

    // Start block listener (connects to blockchain and listens for new blocks)
    if let Err(e) = subtensor_client.start_block_listener().await {
        warn!(
            "Failed to start block listener: {}. Will use simulated blocks.",
            e
        );
    } else {
        info!("✅ Block listener started - listening to blockchain for new blocks");
    }

    // Start block sync task (syncs BlockSyncManager with SubtensorClient every 12 seconds)
    let block_sync_manager_for_sync = block_sync_manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(12));
        loop {
            interval.tick().await;

            let mut block_sync = block_sync_manager_for_sync.write().await;
            if let Err(e) = block_sync.sync_block_from_client().await {
                warn!("Failed to sync block from client: {}", e);
            }
        }
    });
    info!("✅ Block sync task started - syncing with blockchain every 12s");

    // Start epoch manager monitoring loop
    epoch_manager::spawn_epoch_manager(epoch_manager);
    info!("✅ Epoch manager started and monitoring for weight submission");

    // Start background task to recompute quota reservations every 5s
    let challenge_manager_for_quota = challenge_manager.clone();
    let cvm_quota_manager_for_quota = cvm_quota_manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;

            // Gather active challenges with their emission_share
            let specs = challenge_manager_for_quota.challenge_specs.read().await;
            let active_challenges: Vec<(String, f64)> = specs
                .values()
                .map(|spec| (spec.compose_hash.clone(), spec.emission_share))
                .collect();
            drop(specs);

            // Recompute reservations
            cvm_quota_manager_for_quota
                .recompute_reservations(&active_challenges)
                .await;

            // Decay demand EMA
            cvm_quota_manager_for_quota.decay_demand().await;
        }
    });

    // Initialize job VM manager
    let job_vm_manager = Arc::new(job_vm_manager::JobVmManager::new(
        crate::vmm_client::VmmClient::new(vmm_url.clone()),
        cvm_quota_manager.clone(),
    ));

    // Start WebSocket listener
    let job_manager_clone = job_manager.clone();
    let executor_clone = executor.clone();
    let keypair_clone = Arc::new(keypair);
    let challenge_manager_clone = challenge_manager.clone();

    // Clone client for polling loop before moving it to WebSocket
    let client_poll = client.clone();

    tokio::spawn(async move {
        client
            .connect_websocket_with_reconnect(move |message, sender| {
                let job_manager = job_manager_clone.clone();
                let executor = executor_clone.clone();
                let keypair = keypair_clone.clone();
                let challenge_manager = challenge_manager_clone.clone();

                // Set status sender and platform WebSocket sender on first message
                tokio::spawn({
                    let challenge_manager = challenge_manager.clone();
                    let sender = sender.clone();
                    async move {
                        challenge_manager.set_status_sender(sender.clone()).await;
                        challenge_manager.set_platform_ws_sender(sender).await;
                    }
                });

                tokio::spawn(async move {
                    if let Err(e) = handle_websocket_message(
                        message,
                        sender,
                        job_manager,
                        executor,
                        keypair,
                        challenge_manager,
                    )
                    .await
                    {
                        error!("Error handling WebSocket message: {}", e);
                    }
                });
            })
            .await;
    });

    // Start job polling loop
    let job_manager_poll = job_manager.clone();
    let executor_poll = executor.clone();

    tokio::spawn(async move {
        loop {
            if let Err(e) =
                poll_and_execute_jobs(job_manager_poll.clone(), executor_poll.clone()).await
            {
                error!("Error polling jobs: {}", e);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    });

    // Start challenge monitoring loop
    let job_manager_monitor = job_manager.clone();

    tokio::spawn(async move {
        loop {
            if let Err(e) = monitor_challenges(job_manager_monitor.clone()).await {
                error!("Error monitoring challenges: {}", e);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
    });

    // Start challenge reconcile loop
    let challenge_manager_reconcile = challenge_manager.clone();

    tokio::spawn(async move {
        loop {
            if let Err(e) = challenge_manager_reconcile.reconcile().await {
                error!("Error reconciling challenges: {}", e);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    });

    // Start challenge polling loop to detect new challenges
    let challenge_manager_poll = challenge_manager.clone();

    tokio::spawn(async move {
        loop {
            // Poll for new challenges every 30 seconds
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

            if let Err(e) =
                poll_for_new_challenges(client_poll.clone(), challenge_manager_poll.clone()).await
            {
                error!("Error polling for new challenges: {}", e);
            }
        }
    });

    // Start challenge status reporting loop
    let challenge_manager_status = challenge_manager.clone();

    tokio::spawn(async move {
        loop {
            if let Err(e) = challenge_manager_status.report_status().await {
                error!("Error reporting challenge status: {}", e);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    });

    // Start job VM cleanup loop
    let job_vm_manager_cleanup = job_vm_manager.clone();

    tokio::spawn(async move {
        loop {
            if let Err(e) = job_vm_manager_cleanup.cleanup_expired_jobs().await {
                error!("Error cleaning up expired job VMs: {}", e);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
        }
    });

    // Start quota reconciliation loop (every 60s)
    // Old quota reconciliation removed - dynamic system handles this automatically

    // Start platform-api verification loop
    let platform_api_url = config.platform_api_url.clone();
    tokio::spawn(async move {
        let mut verifier = PlatformVerifier::new(platform_api_url);

        // Optionally add allowed commits from environment variable
        if let Ok(allowed_commits) = std::env::var("ALLOWED_PLATFORM_API_COMMITS") {
            for commit in allowed_commits.split(',') {
                verifier.add_allowed_commit(commit.trim().to_string());
            }
        }

        loop {
            if let Err(e) = verifier.verify_platform_api().await {
                error!("Error verifying platform-api: {}", e);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        }
    });

    // Initialize CVM quota manager
    let cvm_quota_manager = Arc::new(CVMQuotaManager::new());

    // Initialize network proxy from config
    let policy = create_network_policy(&serde_json::json!({}));
    let network_proxy = Arc::new(NetworkProxy::new(policy));

    // Start HTTP server for dynamic values, network proxy, and CVM quota API
    let dynamic_values_clone = dynamic_values_manager.clone();
    let network_proxy_clone = network_proxy.clone();
    let cvm_quota_clone = cvm_quota_manager.clone();
    let challenge_manager_http = challenge_manager.clone();
    let job_vm_clone = job_vm_manager.clone();
    tokio::spawn(async move {
        if let Err(e) = http_server::start_http_server(
            dynamic_values_clone,
            Some(network_proxy_clone),
            cvm_quota_clone,
            challenge_manager_http,
            job_vm_clone,
        )
        .await
        {
            error!("Error starting HTTP server: {}", e);
        }
    });

    // Keep main thread alive and handle shutdown signals
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

    tokio::select! {
        _ = sigterm.recv() => {
            info!("Received SIGTERM, shutting down validator");
        }
        _ = sigint.recv() => {
            info!("Received SIGINT (Ctrl+C), shutting down validator");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received Ctrl+C, shutting down validator");
        }
    }

    info!("Shutting down validator");

    // Cleanup Docker containers before exiting
    if config.use_docker {
        info!("Cleaning up Docker containers...");
        if let Err(e) = challenge_manager.cleanup_docker_containers().await {
            warn!("Error cleaning up Docker containers: {}", e);
        }
    }

    Ok(())
}

async fn handle_websocket_message(
    message: String,
    sender: Arc<tokio::sync::mpsc::Sender<String>>,
    _job_manager: Arc<RwLock<JobManager>>,
    _executor: Arc<RwLock<DstackExecutor>>,
    keypair: Arc<sp_core::sr25519::Pair>,
    challenge_manager: Arc<ChallengeManager>,
) -> Result<()> {
    // (Logging removed for verbosity)

    // Parse message JSON
    let msg_json: serde_json::Value = serde_json::from_str(&message)?;
    let msg_type = msg_json["type"].as_str().unwrap_or("");

    match msg_type {
        "challenges:list" => {
            info!("Received challenge list from Platform API");
            if let Some(challenges_array) = msg_json["challenges"].as_array() {
                let challenge_specs: Vec<challenge_manager::ChallengeSpec> = challenges_array
                    .iter()
                    .filter_map(|c| serde_json::from_value(c.clone()).ok())
                    .collect();

                if let Err(e) = challenge_manager
                    .initialize_challenges(challenge_specs)
                    .await
                {
                    error!("Failed to initialize challenges: {}", e);
                } else {
                    info!("Initialized challenges successfully");
                }
            }
        }
        "request_attestation" => {
            info!("Platform API requesting TDX attestation");

            // Extract challenge from the message
            let challenge = msg_json["challenge"].as_str().unwrap_or("");
            if challenge.is_empty() {
                error!("No challenge provided in request_attestation message");
                return Ok(());
            }

            // Check if we're in dev mode
            let dev_mode = msg_json["dev_mode"].as_bool().unwrap_or(false);

            info!(
                "Received challenge from platform-api: {} (dev_mode: {})",
                challenge, dev_mode
            );

            // Derive report_data from challenge (always bind using SHA256)
            let report_data = derive_report_data_from_challenge(challenge);
            let report_data_vec = report_data.to_vec();
            let report_data_hash_hex = hex::encode(&report_data[..32]);
            info!(
                "Derived challenge-bound report_data (sha256): {}",
                report_data_hash_hex
            );

            if dev_mode {
                // Dev mode: Generate mock attestation with compose_hash from challenge
                info!("DEV MODE: Generating mock TDX attestation");

                // Get compose_hash from environment or use default for term-challenge
                let compose_hash = std::env::var("CHALLENGE_COMPOSE_HASH")
                    .unwrap_or_else(|_| "term-challenge-dev-001".to_string());

                info!("Using compose_hash for mock attestation: {}", compose_hash);

                // Generate mock quote with report_data embedded
                let mut mock_quote = vec![0u8; 1024];
                rand::thread_rng().fill_bytes(&mut mock_quote);

                // Embed report_data at known offsets (must match platform-api verification offsets)
                // Platform-api checks: [568, 576, 584]
                let report_offsets: [usize; 3] = [568, 576, 584];
                for offset in &report_offsets {
                    if mock_quote.len() >= *offset + 32 {
                        mock_quote[*offset..*offset + 32].copy_from_slice(&report_data[..32]);
                        break;
                    }
                }

                // Convert quote to base64
                let quote_b64 = base64_engine.encode(&mock_quote);

                // Generate app_id and instance_id
                // Use the hotkey (ss58 address) for app_id
                use sp_core::crypto::{Pair, Ss58Codec};
                let hotkey = Pair::public(keypair.as_ref()).to_ss58check();
                let app_id = format!("validator-{}", &hotkey[..16.min(hotkey.len())]);
                let instance_id = format!("instance-{}", &Uuid::new_v4().to_string()[..8]);

                // Create event log with compose_hash
                let event_log = serde_json::json!([
                    {
                        "imr": 3,
                        "event_type": 1,
                        "event": "app-id",
                        "event_payload": app_id,
                    },
                    {
                        "imr": 3,
                        "event_type": 2,
                        "event": "instance-id",
                        "event_payload": instance_id,
                    },
                    {
                        "imr": 3,
                        "event_type": 3,
                        "event": "compose-hash",
                        "event_payload": compose_hash,
                    },
                    {
                        "imr": 3,
                        "event_type": 4,
                        "event": "dev-mode",
                        "event_payload": "true",
                    }
                ])
                .to_string();

                // Convert report_data to hex string
                info!(
                    "Generated mock TDX attestation with compose_hash: {}",
                    compose_hash
                );

                // Send mock attestation back via WebSocket to platform-api (SIGNED)
                match SecureMessage::attestation_response(
                    quote_b64,
                    event_log,
                    report_data_hash_hex,
                    "{}".to_string(), // vm_config (empty JSON for mock)
                    challenge.to_string(),
                    &keypair,
                ) {
                    Ok(secure_msg) => {
                        if let Ok(msg_str) = serde_json::to_string(&secure_msg) {
                            if let Err(e) = sender.send(msg_str).await {
                                error!("Failed to send mock attestation via WebSocket: {}", e);
                            } else {
                                info!(
                                    "Mock attestation sent successfully to platform-api (signed)"
                                );
                            }
                        } else {
                            error!("Failed to serialize mock attestation message");
                        }
                    }
                    Err(e) => {
                        error!("Failed to create secure mock attestation message: {}", e);
                    }
                }
            } else {
                // Production mode: Get real TDX attestation from dstack guest agent
                // Using official dstack SDK client (dstack_sdk::dstack_client::DstackClient)
                // Creates client with default endpoint (/var/run/dstack.sock) or from DSTACK_SIMULATOR_ENDPOINT env var
                let dstack_client = DstackClient::new(None);

                match dstack_client.get_quote(report_data_vec.clone()).await {
                    Ok(quote_response) => {
                        info!("Generated TDX quote successfully");
                        info!("Quote: {} chars", quote_response.quote.len());
                        info!("Event log: {} chars", quote_response.event_log.len());

                        // Verify that the report_data in the quote matches the challenge
                        // Note: report_data is already hex-encoded from dstack SDK
                        info!(
                            "Received report_data from TDX quote: {}",
                            quote_response.report_data
                        );
                        info!("Expected challenge: {}", challenge);

                        // Convert hex quote to base64 for consistency with platform-api expectations
                        // Use the official decode_quote() method from GetQuoteResponse
                        let quote_bytes = match quote_response.decode_quote() {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                error!("Failed to decode hex quote from dstack: {}", e);
                                
                                // Send error response (SIGNED)
                                if let Ok(error_msg) = SecureMessage::error(format!("Failed to decode quote: {}", e), &keypair) {
                                    if let Ok(msg_str) = serde_json::to_string(&error_msg) {
                                        let _ = sender.send(msg_str).await;
                                    }
                                }
                                return Ok(());
                            }
                        };
                        let quote_b64 = base64_engine.encode(&quote_bytes);
                        
                        // Send attestation back via WebSocket to platform-api (SIGNED)
                        match SecureMessage::attestation_response(
                            quote_b64,
                            quote_response.event_log,
                            quote_response.report_data,
                            quote_response.vm_config,
                            challenge.to_string(),
                            &keypair,
                        ) {
                            Ok(secure_msg) => {
                                if let Ok(msg_str) = serde_json::to_string(&secure_msg) {
                                    if let Err(e) = sender.send(msg_str).await {
                                        error!("Failed to send attestation via WebSocket: {}", e);
                                    } else {
                                        info!("Attestation sent successfully to platform-api (signed)");
                                    }
                                } else {
                                    error!("Failed to serialize attestation message");
                                }
                            }
                            Err(e) => {
                                error!("Failed to create secure attestation message: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to generate TDX attestation: {}", e);

                        // Send error response (SIGNED)
                        if let Ok(error_msg) = SecureMessage::error(e.to_string(), &keypair) {
                            if let Ok(msg_str) = serde_json::to_string(&error_msg) {
                                let _ = sender.send(msg_str).await;
                            }
                        }
                    }
                }
            }
        }
        "orm_result" => {
            // (Logging removed for verbosity)
            let query_id = msg_json["query_id"].as_str().map(|s| s.to_string());
            challenge_manager
                .handle_orm_result(msg_json.clone(), query_id)
                .await;
        }
        _ => {
            // Handle other message types
            // (Logging removed for verbosity)
        }
    }

    Ok(())
}

fn derive_report_data_from_challenge(challenge: &str) -> [u8; 64] {
    let mut hasher = Sha256::new();
    hasher.update(challenge.as_bytes());
    let digest = hasher.finalize();
    let mut report_data = [0u8; 64];
    report_data[..digest.len()].copy_from_slice(&digest);
    report_data
}

async fn poll_and_execute_jobs(
    job_manager: Arc<RwLock<JobManager>>,
    executor: Arc<RwLock<DstackExecutor>>,
) -> Result<()> {
    let mut manager = job_manager.write().await;

    // Check for new jobs
    let pending_jobs = manager.fetch_pending_jobs().await?;

    for job in pending_jobs {
        // Check if we have capacity
        if !manager.has_capacity(&job).await? {
            continue;
        }

        // Claim the job
        if let Ok(claimed_job) = manager.claim_job(&job.id).await {
            info!("Claimed job: {}", claimed_job.id);

            // Execute the job
            let mut exec = executor.write().await;
            if let Err(e) = exec.execute_job(claimed_job).await {
                error!("Error executing job: {}", e);
            }
        }
    }

    Ok(())
}

async fn monitor_challenges(job_manager: Arc<RwLock<JobManager>>) -> Result<()> {
    let mut manager = job_manager.write().await;
    manager.check_challenge_updates().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn derive_report_data_hashes_and_pads_challenge() {
        let challenge = "08a22649887872d3739d3ec4da80ecaa826f51705656d1b0a0c9a2aff6ab3371";
        let expected = Sha256::digest(challenge.as_bytes());
        let report_data = derive_report_data_from_challenge(challenge);
        assert_eq!(&report_data[..expected.len()], expected.as_slice());
        assert!(report_data[expected.len()..].iter().all(|b| *b == 0));
    }
}

async fn poll_for_new_challenges(
    client: PlatformClient,
    challenge_manager: Arc<ChallengeManager>,
) -> Result<()> {
    // Get full challenge specifications from platform-api
    match client.get_challenge_specs().await {
        Ok(specs_response) => {
            // Extract challenges array from response
            if let Some(challenges_array) = specs_response["challenges"].as_array() {
                // Convert to ChallengeSpec vector
                let challenge_specs: Vec<challenge_manager::ChallengeSpec> = challenges_array
                    .iter()
                    .filter_map(|c| serde_json::from_value(c.clone()).ok())
                    .collect();

                if !challenge_specs.is_empty() {
                    info!(
                        "Polled {} challenges from platform-api, initializing new ones",
                        challenge_specs.len()
                    );

                    // Initialize challenges - this will only create new ones, not affect existing
                    if let Err(e) = challenge_manager
                        .initialize_challenges(challenge_specs)
                        .await
                    {
                        error!("Failed to initialize polled challenges: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            // Don't log errors too frequently to avoid spam
            debug!("Failed to poll for new challenges: {}", e);
        }
    }

    Ok(())
}

// Old reconcile_quotas function removed - dynamic quota system handles this automatically
