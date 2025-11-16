use crate::challenge_manager::ChallengeManager;
use crate::challenge_ws::ChallengeWsClient;
use crate::config::ValidatorConfig;
use anyhow::Result;
use platform_engine_api_client::PlatformClient;
use platform_engine_chain::{
    BlockSyncManager, BlockchainMonitor, ChallengeWeight, CommitWeightsConfig,
    CommitWeightsService, HotkeyMapper, MechanismWeightAggregator, NetworkHyperparameters,
    SubtensorClient,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

/// Cached weights for a specific epoch (sync_block)
#[derive(Debug, Clone)]
struct CachedEpochWeights {
    /// The sync_block for which these weights were calculated
    epoch_sync_block: u64,
    /// Chain-formatted weights by mechanism ID
    chain_weights_by_mechanism: HashMap<u8, Vec<(u64, u16)>>,
    /// Block number where weights were calculated
    calculated_at_block: u64,
}

/// Configuration for epoch-based weight setting
#[derive(Debug, Clone)]
pub struct EpochConfig {
    pub block_interval: u64,                  // Every N blocks (default 360)
    pub weight_query_timeout: u64,            // Timeout for weight queries in seconds
    pub weight_submission_retries: u32,       // Number of retries for chain submission
    pub commit_block_offset: u64,             // Block offset for commit (before sync block)
    pub reveal_block_offset: u64,             // Block offset for reveal (after sync block)
    pub use_commit_reveal: bool, // Activate commit-reveal instead of direct set_weights
    pub epoch_interval_blocks: u64, // Interval in blocks to define an epoch
    pub weight_submission_safety_margin: u64, // Blocks before epoch to submit (default: 10)
    pub weight_submission_jitter_max: u64, // Maximum random delay (default: 10)
    pub weight_retry_backoff_multiplier: f64, // Exponential backoff factor (default: 2.0)
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self {
            block_interval: 360,
            weight_query_timeout: 30,
            weight_submission_retries: 3,
            commit_block_offset: 5,     // Commit 5 blocks before sync block
            reveal_block_offset: 1,     // Reveal 1 block after sync block
            use_commit_reveal: false,   // Default to direct set_weights for backward compatibility
            epoch_interval_blocks: 360, // Same as block_interval by default
            weight_submission_safety_margin: 10, // Submit 10 blocks before epoch end
            weight_submission_jitter_max: 10, // Max 10 blocks jitter
            weight_retry_backoff_multiplier: 2.0, // Exponential backoff multiplier
        }
    }
}

/// Manages epoch-based weight collection and submission
pub struct EpochManager {
    config: EpochConfig,
    validator_config: ValidatorConfig,
    block_sync_manager: Arc<RwLock<BlockSyncManager>>,
    challenge_manager: Arc<ChallengeManager>,
    subtensor_client: Arc<SubtensorClient>,
    platform_client: PlatformClient,
    commit_weights_service: Option<Arc<CommitWeightsService>>,
    blockchain_monitor: Arc<BlockchainMonitor>,
    netuid: u16,                // Network UID for Bittensor subnet
    validator_uid: Option<u16>, // Validator UID (cached)
    /// Cached weights for the current epoch (sync_block)
    cached_weights: Arc<RwLock<Option<CachedEpochWeights>>>,
}

impl EpochManager {
    pub fn new(
        config: EpochConfig,
        validator_config: ValidatorConfig,
        block_sync_manager: Arc<RwLock<BlockSyncManager>>,
        challenge_manager: Arc<ChallengeManager>,
        subtensor_client: Arc<SubtensorClient>,
        platform_client: PlatformClient,
        netuid: u16,
    ) -> Self {
        // Initialize commit weights service if commit-reveal is enabled
        let commit_weights_service = if config.use_commit_reveal {
            let version_key = std::env::var("COMMIT_WEIGHTS_VERSION_KEY")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1); // Default to 1 if not set or invalid

            let commit_config = CommitWeightsConfig {
                max_retries: config.weight_submission_retries,
                retry_delay_secs: 5,
                version_key,
            };
            Some(Arc::new(CommitWeightsService::new(commit_config)))
        } else {
            None
        };

        // Initialize blockchain monitor
        let blockchain_monitor = Arc::new(BlockchainMonitor::new(subtensor_client.clone(), netuid));

        Self {
            config,
            validator_config,
            block_sync_manager,
            challenge_manager,
            subtensor_client,
            platform_client,
            commit_weights_service,
            blockchain_monitor,
            netuid,
            validator_uid: None,
            cached_weights: Arc::new(RwLock::new(None)),
        }
    }

    /// Get current sync block
    async fn get_current_sync_block(&self) -> u64 {
        let block_sync = self.block_sync_manager.read().await;
        block_sync.get_sync_block()
    }

    /// Start the epoch monitoring loop
    pub async fn start_monitoring(&self) {
        info!(
            "Starting epoch manager with {} block intervals",
            self.config.block_interval
        );

        // Check every 12 seconds (Bittensor block time)
        let mut check_interval = interval(Duration::from_secs(12));

        loop {
            check_interval.tick().await;

            // Check for pending commits that need to be revealed
            if let Some(commit_service) = &self.commit_weights_service {
                let current_block = {
                    let block_sync = self.block_sync_manager.read().await;
                    block_sync.get_sync_info().current_block
                };

                // Check if there's a pending commit that should be revealed at current block
                if let Some(commit_block) = commit_service
                    .get_pending_commit_for_reveal(current_block)
                    .await
                {
                    info!(
                        "🔓 Auto-revealing weights committed at block {} (current: {})",
                        commit_block, current_block
                    );
                    match commit_service
                        .reveal_weights_with_retry(self.netuid, commit_block)
                        .await
                    {
                        Ok(tx_hash) => {
                            info!("✅ Successfully auto-revealed weights: {}", tx_hash);
                        }
                        Err(e) => {
                            error!("Failed to auto-reveal weights: {}", e);
                        }
                    }
                }
            }

            match self.check_and_process_epoch().await {
                Ok(processed) => {
                    if processed {
                        info!("Epoch processing completed successfully");
                    }
                }
                Err(e) => {
                    error!("Error processing epoch: {}", e);
                }
            }
        }
    }

    /// Check if we need to process weights and do so if needed
    /// Called at every check interval. Retries with cached weights if submission failed previously.
    async fn check_and_process_epoch(&self) -> Result<bool> {
        let block_sync = self.block_sync_manager.read().await;
        let sync_info = block_sync.get_sync_info();
        let current_block = sync_info.current_block;
        let blocks_until_sync = sync_info.blocks_until_sync;
        let current_sync_block = sync_info.sync_block;
        drop(block_sync); // Release read lock before processing

        // Get network hyperparameters for optimal timing calculation
        let hyperparams = match self.blockchain_monitor.get_hyperparameters().await {
            Ok(params) => params,
            Err(e) => {
                warn!("Failed to get hyperparameters: {}. Using defaults.", e);
                NetworkHyperparameters::default()
            }
        };

        // Check admin freeze window
        if self.blockchain_monitor.is_in_admin_freeze_window(
            hyperparams.tempo,
            current_block,
            hyperparams.admin_freeze_window,
        ) {
            warn!(
                "Admin freeze window active at block {}. Skipping weight submission.",
                current_block
            );
            return Ok(false);
        }

        // Check rate limit
        if let Some(validator_uid) = self.validator_uid {
            match self
                .blockchain_monitor
                .can_submit_weights(validator_uid, current_block)
                .await
            {
                Ok(can_submit) => {
                    if !can_submit {
                        info!(
                            "Rate limit active at block {}. Waiting for next opportunity.",
                            current_block
                        );
                        return Ok(false);
                    }
                }
                Err(e) => {
                    warn!("Failed to check rate limit: {}. Proceeding anyway.", e);
                }
            }
        }

        // Calculate optimal submission block
        let optimal_block = self.blockchain_monitor.calculate_optimal_submission_block(
            hyperparams.tempo,
            hyperparams.weights_set_rate_limit,
            current_block,
            self.config.weight_submission_safety_margin,
            self.config.weight_submission_jitter_max,
        );

        // Check if we have cached weights for a previous epoch that needs to be retried
        let has_cached_weights = {
            let cache = self.cached_weights.read().await;
            cache.is_some()
        };

        // If we have cached weights, check if they're for the current sync_block
        let should_retry_with_cache = if has_cached_weights {
            let cache = self.cached_weights.read().await;
            if let Some(ref cached) = *cache {
                // If cached sync_block matches current sync_block, we should retry
                // (meaning previous submission might have failed)
                cached.epoch_sync_block == current_sync_block
            } else {
                false
            }
        } else {
            false
        };

        // Check if we've reached a new sync_block (need to invalidate cache and calculate new weights)
        let reached_new_sync_block = {
            let cache = self.cached_weights.read().await;
            if let Some(ref cached) = *cache {
                cached.epoch_sync_block < current_sync_block
            } else {
                false
            }
        };

        if reached_new_sync_block {
            // Invalidate cache for old sync_block
            info!(
                "🔄 New sync_block {} reached, invalidating cache for old sync_block",
                current_sync_block
            );
            let mut cache = self.cached_weights.write().await;
            *cache = None;
        }

        // Process weights in these scenarios:
        // 1. We're at or past the optimal submission block
        // 2. We have cached weights for current sync_block (retry after failure)
        // 3. We've reached a new sync_block (calculate new weights)
        let should_process =
            current_block >= optimal_block || should_retry_with_cache || reached_new_sync_block;

        if should_process {
            if current_block >= optimal_block && !should_retry_with_cache && !reached_new_sync_block
            {
                info!(
                    "⚡ Optimal submission block {} reached (current: {}), collecting weights",
                    optimal_block, current_block
                );
            } else if should_retry_with_cache {
                info!(
                    "🔄 Retrying weight submission with cached weights (block {}, sync_block {})",
                    current_block, current_sync_block
                );
            } else if reached_new_sync_block {
                info!(
                    "🔄 New sync_block {} reached, calculating new weights at block {}",
                    current_sync_block, current_block
                );
            }

            self.collect_and_submit_weights(current_block).await?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Collect weights from all challenges and submit to chain
    /// Uses cached weights if available for the current sync_block, otherwise calculates new weights
    async fn collect_and_submit_weights(&self, block: u64) -> Result<()> {
        let current_sync_block = self.get_current_sync_block().await;

        // Check if we have cached weights for the current sync_block
        let cached = {
            let cache = self.cached_weights.read().await;
            cache.clone()
        };

        // Check if cached weights are valid for current sync_block
        let cached_weights_valid = if let Some(ref cached) = cached {
            cached.epoch_sync_block == current_sync_block
        } else {
            false
        };

        // Use cached weights if available and valid, otherwise calculate new ones
        let chain_weights_by_mechanism = if cached_weights_valid {
            if let Some(ref cached) = cached {
                info!(
                    "💾 Using cached weights for sync_block {} (calculated at block {})",
                    current_sync_block, cached.calculated_at_block
                );
                cached.chain_weights_by_mechanism.clone()
            } else {
                // Should never reach here due to cached_weights_valid check, but compiler needs this
                HashMap::new()
            }
        } else {
            if cached.is_some() {
                info!("🔄 Cache invalid - cached sync_block {} != current sync_block {}, recalculating",
                      cached.as_ref().unwrap().epoch_sync_block, current_sync_block);
            }
            info!(
                "🔄 Collecting weights from challenges for block {} (sync_block: {})",
                block, current_sync_block
            );

            // Get all active challenges
            let challenges_response = self.platform_client.get_challenges().await?;
            if challenges_response.challenges.is_empty() {
                warn!("No active challenges found");
                return Ok(());
            }

            let mut challenge_weights = Vec::new();

            // Query each challenge for weights
            for challenge in &challenges_response.challenges {
                let compose_hash = challenge.compose_hash.clone();
                let mechanism_id = challenge.mechanism_id; // Already u8, no need to clone
                let emission_share = challenge.emission_share;

                match self.query_challenge_weights(&compose_hash, block).await {
                    Ok(Some(weights)) => {
                        challenge_weights.push(ChallengeWeight {
                            compose_hash: compose_hash.clone(),
                            mechanism_id, // u8 value, not String
                            emission_share,
                            raw_weights: weights,
                        });
                    }
                    Ok(None) => {
                        warn!("Challenge {} did not provide weights", compose_hash);
                    }
                    Err(e) => {
                        error!(
                            "Failed to query weights from challenge {}: {}",
                            compose_hash, e
                        );
                    }
                }
            }

            if challenge_weights.is_empty() {
                warn!("No weights collected from any challenge");
                return Ok(());
            }

            // Group challenges by mechanism_id to submit weights separately for each mechanism
            let mut mechanism_groups: HashMap<u8, Vec<ChallengeWeight>> = HashMap::new();
            for challenge in challenge_weights {
                mechanism_groups
                    .entry(challenge.mechanism_id)
                    .or_insert_with(Vec::new)
                    .push(challenge);
            }

            info!(
                "📊 Processing weights for {} mechanism(s)",
                mechanism_groups.len()
            );

            // Convert hotkeys to UIDs using metagraph (once, shared across all mechanisms)
            let hotkey_to_uid = self
                .subtensor_client
                .get_hotkey_to_uid_map(self.netuid)
                .await?;

            // Process weights for each mechanism separately
            let mut calculated_weights: HashMap<u8, Vec<(u64, u16)>> = HashMap::new();

            for (mechanism_id, mechanism_challenges) in mechanism_groups {
                // Aggregate weights for this specific mechanism
                let mechanism_result = MechanismWeightAggregator::process_mechanism(
                    mechanism_id,
                    mechanism_challenges,
                )?;

                info!(
                    "📊 Mechanism {}: {} hotkeys",
                    mechanism_id,
                    mechanism_result.normalized_weights.len()
                );

                // Convert hotkeys to UIDs for this mechanism
                let uid_weights = HotkeyMapper::convert_weights_to_uids(
                    &mechanism_result.normalized_weights,
                    &hotkey_to_uid,
                );
                info!(
                    "📊 Mechanism {}: {} UID weights",
                    mechanism_id,
                    uid_weights.len()
                );

                // Normalize with UID 0 fallback to ensure sum = 1.0
                let uid_weights_str: HashMap<String, f64> = uid_weights
                    .iter()
                    .map(|(uid, weight)| (uid.to_string(), *weight))
                    .collect();

                let (normalized_weights, used_uid0) =
                    MechanismWeightAggregator::normalize_with_uid0_fallback(&uid_weights_str);

                if used_uid0 {
                    info!(
                        "⚠️ Mechanism {}: UID 0 was used for remaining weight",
                        mechanism_id
                    );
                }

                // Convert to chain format (u16 weights)
                let chain_weights =
                    MechanismWeightAggregator::normalize_for_chain(&normalized_weights, 65535);

                calculated_weights.insert(mechanism_id, chain_weights);
            }

            // Cache the calculated weights
            {
                let mut cache = self.cached_weights.write().await;
                *cache = Some(CachedEpochWeights {
                    epoch_sync_block: current_sync_block,
                    chain_weights_by_mechanism: calculated_weights.clone(),
                    calculated_at_block: block,
                });
                info!(
                    "💾 Cached weights for sync_block {} (calculated at block {})",
                    current_sync_block, block
                );
            }

            calculated_weights
        };

        // Submit weights for each mechanism
        for (mechanism_id, chain_weights) in chain_weights_by_mechanism {
            let mechanism_id_u8: Option<u8> = Some(mechanism_id);

            // Submit to chain with retries (separate submission per mechanism)
            if self.config.use_commit_reveal {
                self.submit_weights_with_commit_reveal(chain_weights, block, mechanism_id_u8)
                    .await?;
            } else {
                // For direct set_weights, we would need mechanism support too
                // For now, fall back to submit_weights_with_retry which uses default mechanism
                warn!(
                    "Direct set_weights does not support mechanism_id, using default mechanism (0)"
                );
                self.submit_weights_with_retry(chain_weights).await?;
            }
        }

        Ok(())
    }

    /// Query a challenge for its weight recommendations
    async fn query_challenge_weights(
        &self,
        compose_hash: &str,
        block: u64,
    ) -> Result<Option<std::collections::HashMap<String, f64>>> {
        // Get challenge instance to find its API URL
        let challenge_specs = self.challenge_manager.challenge_specs.read().await;
        let spec = challenge_specs.get(compose_hash);

        if spec.is_none() {
            return Ok(None);
        }

        // Get challenge status to find active instance
        let challenge_statuses = self.challenge_manager.get_challenge_statuses().await;
        let status = challenge_statuses
            .iter()
            .find(|s| &s.compose_hash == compose_hash);

        if let Some(status) = status {
            // For now, we'll need to construct the API URL from the compose hash
            // Use compose_hash to construct the challenge API URL
            let api_url = format!("http://challenge-{}", compose_hash);

            // Convert HTTP URL to WebSocket URL
            let ws_url = api_url
                .replace("http://", "ws://")
                .replace("https://", "wss://");
            let ws_url = format!("{}/sdk/ws", ws_url.trim_end_matches('/'));

            // Create WebSocket client and request weights
            let ws_client =
                ChallengeWsClient::new(ws_url, self.validator_config.validator_hotkey.clone());

            match ws_client
                .request_weights(block, self.config.weight_query_timeout)
                .await
            {
                Ok(weights) => {
                    info!(
                        "Received {} weights from challenge {}",
                        weights.len(),
                        compose_hash
                    );
                    Ok(Some(weights))
                }
                Err(e) => {
                    warn!(
                        "Failed to get weights from challenge {}: {}",
                        compose_hash, e
                    );
                    Ok(None)
                }
            }
        } else {
            warn!("Challenge {} not found in active instances", compose_hash);
            Ok(None)
        }
    }

    /// Submit weights to chain with intelligent retry logic
    async fn submit_weights_with_retry(&self, weights: Vec<(u64, u16)>) -> Result<()> {
        let mut retries = 0;
        let mut last_error: Option<String> = None;

        while retries < self.config.weight_submission_retries {
            match self.submit_weights_to_chain(weights.clone()).await {
                Ok(_) => {
                    info!("✅ Successfully submitted weights to chain");
                    return Ok(());
                }
                Err(e) => {
                    retries += 1;
                    let error_str = e.to_string();
                    last_error = Some(error_str.clone());

                    // Try to parse error to determine if retryable
                    let is_retryable = if error_str.contains("WeightAlreadySet") {
                        // Weights already set - skip, don't retry
                        info!("Weights already set for this epoch. Skipping submission.");
                        return Ok(()); // Not an error, just skip
                    } else if error_str.contains("TooManyUnrevealedCommits") {
                        // Need to reveal pending commits first
                        warn!("Too many unrevealed commits. Attempting to reveal pending commits.");

                        if let Some(commit_service) = &self.commit_weights_service {
                            let current_block = {
                                let block_sync = self.block_sync_manager.read().await;
                                block_sync.get_sync_info().current_block
                            };

                            // Get all pending commits that need to be revealed
                            let pending_commits =
                                commit_service.get_all_pending_commits(current_block).await;

                            if let Some(oldest_commit_block) = pending_commits.iter().min() {
                                info!(
                                    "Revealing oldest pending commit from block {}",
                                    oldest_commit_block
                                );
                                match commit_service
                                    .reveal_weights_with_retry(self.netuid, *oldest_commit_block)
                                    .await
                                {
                                    Ok(tx_hash) => {
                                        info!(
                                            "✅ Successfully revealed pending commit: {}",
                                            tx_hash
                                        );
                                        // After revealing, we can retry the commit
                                        return Ok(());
                                    }
                                    Err(reveal_err) => {
                                        error!("Failed to reveal pending commit: {}", reveal_err);
                                        // Still non-retryable until reveals are done
                                        return Err(anyhow::anyhow!(
                                            "Cannot proceed: need to reveal pending commits first: {}",
                                            reveal_err
                                        ));
                                    }
                                }
                            } else {
                                warn!("No pending commits found to reveal");
                            }
                        }

                        false // Don't retry set_weights, need to reveal first
                    } else if error_str.contains("CommittingWeightsTooFast")
                        || error_str.contains("RateLimitExceeded")
                    {
                        // Rate limit - calculate wait time
                        info!("Rate limit exceeded. Will retry after appropriate delay.");
                        true // Retryable, but need proper delay
                    } else if error_str.contains("AdminFreezeWindowActive") {
                        // Admin freeze - skip, don't retry
                        warn!("Admin freeze window active. Skipping submission.");
                        return Ok(()); // Not an error, just skip
                    } else {
                        // Other errors - retryable
                        true
                    };

                    if !is_retryable {
                        // Non-retryable error or skip condition
                        return Err(anyhow::anyhow!("Non-retryable error: {}", error_str));
                    }

                    if retries < self.config.weight_submission_retries {
                        // Calculate exponential backoff delay
                        let base_delay_secs = 5;
                        let delay_secs = (base_delay_secs as f64
                            * self
                                .config
                                .weight_retry_backoff_multiplier
                                .powi(retries as i32 - 1))
                            as u64;

                        error!(
                            "Failed to submit weights (attempt {}/{}): {}. Retrying in {} seconds...",
                            retries, self.config.weight_submission_retries, error_str, delay_secs
                        );

                        tokio::time::sleep(Duration::from_secs(delay_secs)).await;
                    }
                }
            }
        }

        Err(anyhow::anyhow!(
            "Failed to submit weights after {} retries: {}",
            self.config.weight_submission_retries,
            last_error.unwrap_or_else(|| "Unknown error".to_string())
        ))
    }

    /// Submit weights to the blockchain
    async fn submit_weights_to_chain(&self, weights: Vec<(u64, u16)>) -> Result<()> {
        // Update weights in block sync manager
        let mut block_sync = self.block_sync_manager.write().await;

        // Convert to BTreeMap format expected by block sync
        let mut weight_map = std::collections::BTreeMap::new();
        for (uid, weight) in &weights {
            weight_map.insert(uid.to_string(), *weight as f64);
        }

        // Set weights (will be submitted on next sync block)
        block_sync.set_weights(weight_map)?;

        info!("📤 Weights prepared for submission at next sync block");
        Ok(())
    }

    /// Submit weights using commit-reveal scheme
    ///
    /// mechanism_id: None = default mechanism (0), Some(id) = specific mechanism ID
    async fn submit_weights_with_commit_reveal(
        &self,
        weights: Vec<(u64, u16)>,
        block: u64,
        mechanism_id: Option<u8>,
    ) -> Result<()> {
        let commit_service = self
            .commit_weights_service
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Commit weights service not initialized"))?;

        let sync_block = {
            let block_sync = self.block_sync_manager.read().await;
            block_sync.get_sync_block()
        };

        // Check if we should commit (commit_block_offset blocks before sync)
        let commit_block = sync_block.saturating_sub(self.config.commit_block_offset);
        let reveal_block = sync_block + self.config.reveal_block_offset;

        let mech_info = match mechanism_id {
            Some(id) => format!("mechanism {}", id),
            None => "default mechanism (0)".to_string(),
        };

        if block == commit_block {
            // Extract uids and weights
            let uids: Vec<u64> = weights.iter().map(|(uid, _)| *uid).collect();
            let weight_vals: Vec<u16> = weights.iter().map(|(_, weight)| *weight).collect();

            // Commit weights with mechanism_id
            let commit_hash = commit_service
                .commit_weights_with_retry(self.netuid, uids, weight_vals, block, mechanism_id)
                .await?;

            info!(
                "✅ Committed weights ({}) at block {} (hash: {})",
                mech_info, block, commit_hash
            );
        } else if block == reveal_block {
            // Reveal weights committed at commit_block
            let commit_block_to_reveal = block
                .saturating_sub(self.config.reveal_block_offset)
                .saturating_sub(self.config.commit_block_offset);

            let reveal_tx = commit_service
                .reveal_weights_with_retry(self.netuid, commit_block_to_reveal)
                .await?;

            info!(
                "✅ Revealed weights ({}) at block {} (tx: {})",
                mech_info, block, reveal_tx
            );
        } else {
            info!(
                "Block {} is not a commit/reveal block (commit: {}, reveal: {}, sync: {})",
                block, commit_block, reveal_block, sync_block
            );
        }

        Ok(())
    }
}

/// Start epoch management in a background task
pub fn spawn_epoch_manager(epoch_manager: Arc<EpochManager>) {
    tokio::spawn(async move {
        epoch_manager.start_monitoring().await;
    });
}
