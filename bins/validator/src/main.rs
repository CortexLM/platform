use anyhow::Result;
use dstack_sdk::dstack_client::DstackClient;
use platform_engine_api_client::PlatformClient;
use serde_json;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

mod challenge_manager;
mod challenge_ws;
mod config;
mod cvm_quota;
mod dstack_provisioner;
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

    // Initialize executor
    let executor = Arc::new(RwLock::new(DstackExecutor::new(config.clone())?));

    // Initialize CVM quota manager with capacity from config
    let capacity = crate::cvm_quota::ResourceCapacity {
        cpu_cores: config.resource_limits.cpu_cores,
        memory_mb: config.resource_limits.memory_mb,
        disk_mb: config.resource_limits.disk_mb,
    };
    let cvm_quota_manager = Arc::new(CVMQuotaManager::with_capacity(capacity));

    // Initialize VMM client
    let vmm_url = config.dstack_vmm_url.clone();
    let vmm_client = Arc::new(crate::vmm_client::VmmClient::new(vmm_url.clone()));

    // Initialize challenge manager
    let challenge_manager = Arc::new(ChallengeManager::new(
        client.clone(),
        vmm_url.clone(),
        cvm_quota_manager.clone(),
    ));

    // Initialize chain components (stub for now - will be fully integrated later)
    // Initialize SubtensorClient and BlockSyncManager for epoch-based weight setting
    let epoch_config = epoch_manager::EpochConfig::default();
    info!(
        "Epoch manager configured with {} block intervals",
        epoch_config.block_interval
    );

    // Note: Full epoch manager initialization will be added when chain integration is complete
    // For now, we have the structure in place for weight collection and submission

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

    tokio::spawn(async move {
        client
            .connect_websocket_with_reconnect(move |message, sender| {
                let job_manager = job_manager_clone.clone();
                let executor = executor_clone.clone();
                let keypair = keypair_clone.clone();
                let challenge_manager = challenge_manager_clone.clone();

                // Set status sender on first message
                tokio::spawn({
                    let challenge_manager = challenge_manager.clone();
                    let sender = sender.clone();
                    async move {
                        challenge_manager.set_status_sender(sender).await;
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

    // Keep main thread alive
    tokio::signal::ctrl_c().await?;
    info!("Shutting down validator");

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
    info!("Handling WebSocket message: {}", message);

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

            info!("Received challenge from platform-api: {}", challenge);

            // Get TDX attestation from dstack guest agent
            // The validator is running in a TDX CVM, so we can get the quote
            // Use Unix socket if mounted, otherwise try HTTP
            let dstack_client = DstackClient::new(None); // Uses /var/run/dstack.sock by default

            // Use the challenge as report_data to bind attestation to the challenge
            let challenge_bytes =
                hex::decode(challenge).unwrap_or_else(|_| challenge.as_bytes().to_vec());
            let report_data = if challenge_bytes.len() <= 64 {
                challenge_bytes
            } else {
                // Hash if too long
                let mut hasher = Sha256::new();
                hasher.update(challenge_bytes);
                hasher.finalize().to_vec()
            };

            match dstack_client.get_quote(report_data).await {
                Ok(quote_response) => {
                    info!("Generated TDX quote successfully");
                    info!("Quote: {} chars", quote_response.quote.len());
                    info!("Event log: {} chars", quote_response.event_log.len());

                    // Verify that the report_data in the quote matches the challenge
                    let received_report_data = hex::encode(&quote_response.report_data);
                    info!(
                        "Received report_data from TDX quote: {}",
                        received_report_data
                    );
                    info!("Expected challenge: {}", challenge);

                    // Send attestation back via WebSocket to platform-api (SIGNED)
                    match SecureMessage::attestation_response(
                        quote_response.quote,
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
        _ => {
            // Handle other message types
            info!("Received message type: {}", msg_type);
        }
    }

    Ok(())
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

// Old reconcile_quotas function removed - dynamic quota system handles this automatically
