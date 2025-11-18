// Re-export from commit_weights.rs (moved here)
// This file contains the commit-reveal weight submission logic

use anyhow::Result;
use hex;
use rand::RngCore;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Configuration for commit-reveal weight submission
#[derive(Debug, Clone)]
pub struct CommitWeightsConfig {
    pub max_retries: u32,
    pub retry_delay_secs: u64,
    pub version_key: u64,
}

impl Default for CommitWeightsConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            retry_delay_secs: 5,
            version_key: 1,
        }
    }
}

/// Pending commit information stored between commit and reveal phases
#[derive(Debug, Clone)]
struct PendingCommit {
    pub uids: Vec<u64>,
    pub weights: Vec<u16>,
    pub salt: Vec<u8>,
    pub commit_block: u64,
    pub commit_hash: String,
    pub mechanism_id: Option<u8>, // None = default mechanism (0), Some(id) = specific mechanism
}

/// Service for managing commit-reveal weight submission
pub struct CommitWeightsService {
    config: CommitWeightsConfig,
    pending_commits: RwLock<HashMap<u64, PendingCommit>>, // Key: commit_block
    // Optional bittensor client and signer for actual blockchain submission
    bittensor_client: Option<Arc<bittensor_rs::chain::BittensorClient>>,
    bittensor_signer: Option<Arc<bittensor_rs::chain::BittensorSigner>>,
}

impl CommitWeightsService {
    /// Create a new CommitWeightsService without bittensor client (logging only)
    pub fn new(config: CommitWeightsConfig) -> Self {
        Self {
            config,
            pending_commits: RwLock::new(HashMap::new()),
            bittensor_client: None,
            bittensor_signer: None,
        }
    }

    /// Create a new CommitWeightsService with bittensor client and signer for real blockchain submission
    pub fn new_with_client(
        config: CommitWeightsConfig,
        client: Arc<bittensor_rs::chain::BittensorClient>,
        signer: Arc<bittensor_rs::chain::BittensorSigner>,
    ) -> Self {
        Self {
            config,
            pending_commits: RwLock::new(HashMap::new()),
            bittensor_client: Some(client),
            bittensor_signer: Some(signer),
        }
    }

    /// Generate random salt for commit-reveal
    fn generate_salt(&self, length: usize) -> Vec<u8> {
        let mut salt = vec![0u8; length];
        let mut rng = rand::rng();
        rng.fill_bytes(&mut salt);
        salt
    }

    /// Generate commit hash from weights and salt
    fn generate_commit_hash(&self, uids: &[u64], weights: &[u16], salt: &[u8]) -> Result<String> {
        use bittensor_rs::utils::commit_weights_hash;
        let hash = commit_weights_hash(uids, weights, salt);
        Ok(hex::encode(hash))
    }

    /// Commit weights (phase 1 of commit-reveal)
    pub async fn commit_weights(
        &self,
        netuid: u16,
        uids: Vec<u64>,
        weights: Vec<u16>,
        block_number: u64,
        mechanism_id: Option<u8>,
    ) -> Result<String> {
        if uids.len() != weights.len() {
            return Err(anyhow::anyhow!(
                "UIDS and weights must have the same length (got {} uids, {} weights)",
                uids.len(),
                weights.len()
            ));
        }

        if uids.is_empty() {
            return Err(anyhow::anyhow!("Cannot commit empty weights"));
        }

        // Generate salt for this commit
        let salt = self.generate_salt(32); // 32 bytes salt

        // Generate commit hash
        let commit_hash = self.generate_commit_hash(&uids, &weights, &salt)?;

        let mech_info = match mechanism_id {
            Some(id) => format!("mechanism {}", id),
            None => "default mechanism (0)".to_string(),
        };

        info!(
            "Committing weights for netuid {} at block {} ({}): {} UIDs, hash: {}",
            netuid,
            block_number,
            mech_info,
            uids.len(),
            commit_hash
        );

        // Store pending commit for reveal phase
        let pending = PendingCommit {
            uids: uids.clone(),
            weights: weights.clone(),
            salt,
            commit_block: block_number,
            commit_hash: commit_hash.clone(),
            mechanism_id,
        };

        {
            let mut pending_map = self.pending_commits.write().await;
            pending_map.insert(block_number, pending);
        }

        // Call bittensor_rs if client and signer are available
        if let (Some(client), Some(signer)) = (&self.bittensor_client, &self.bittensor_signer) {
            use bittensor_rs::chain::ExtrinsicWait;
            use bittensor_rs::validator::weights::commit_weights;

            match commit_weights(
                client.as_ref(),
                signer.as_ref(),
                netuid,
                &commit_hash,
                ExtrinsicWait::Included,
            )
            .await
            {
                Ok(tx_hash) => {
                    info!(
                        "✅ Weight commit submitted to blockchain (hash: {}, tx: {}, {} UIDs). Reveal should happen at block {}",
                        commit_hash, tx_hash, uids.len(), block_number + 1
                    );
                    return Ok(tx_hash);
                }
                Err(e) => {
                    error!(
                        "Failed to commit weights to blockchain: {}. Storing locally only.",
                        e
                    );
                }
            }
        }

        // Log and store locally (fallback or when no client/signer)
        info!(
            "✅ Weight commit prepared (hash: {}, {} UIDs). Reveal should happen at block {}",
            commit_hash,
            uids.len(),
            block_number + 1
        );

        Ok(commit_hash)
    }

    /// Reveal weights (phase 2 of commit-reveal)
    pub async fn reveal_weights(&self, netuid: u16, commit_block: u64) -> Result<String> {
        // Get pending commit
        let pending = {
            let pending_map = self.pending_commits.read().await;
            pending_map.get(&commit_block).cloned()
        };

        let pending = pending
            .ok_or_else(|| anyhow::anyhow!("No pending commit found for block {}", commit_block))?;

        let mech_info = match pending.mechanism_id {
            Some(id) => format!("mechanism {}", id),
            None => "default mechanism (0)".to_string(),
        };

        info!(
            "Revealing weights for netuid {} committed at block {} ({}): {} UIDs",
            netuid,
            commit_block,
            mech_info,
            pending.uids.len()
        );

        // Call bittensor_rs if client and signer are available
        if let (Some(client), Some(signer)) = (&self.bittensor_client, &self.bittensor_signer) {
            use bittensor_rs::chain::ExtrinsicWait;

            // For mechanism-specific reveals
            if let Some(mech_id) = pending.mechanism_id {
                use bittensor_rs::validator::mechanism::reveal_mechanism_weights;
                match reveal_mechanism_weights(
                    client.as_ref(),
                    signer.as_ref(),
                    netuid,
                    mech_id,
                    &pending.uids,
                    &pending.weights,
                    &pending.salt,
                    self.config.version_key,
                    ExtrinsicWait::Included,
                )
                .await
                {
                    Ok(tx_hash) => {
                        info!(
                            "✅ Weight reveal submitted to blockchain ({}): commit hash: {}, tx: {}, {} UIDs, version_key: {}",
                            mech_info, pending.commit_hash, tx_hash, pending.uids.len(), self.config.version_key
                        );
                        {
                            let mut pending_map = self.pending_commits.write().await;
                            pending_map.remove(&commit_block);
                        }
                        return Ok(tx_hash);
                    }
                    Err(e) => {
                        error!("Failed to reveal mechanism weights to blockchain: {}. Trying standard reveal.", e);
                    }
                }
            }

            // Standard reveal_weights
            use bittensor_rs::validator::weights::reveal_weights;
            match reveal_weights(
                client.as_ref(),
                signer.as_ref(),
                netuid,
                &pending.uids,
                &pending.weights,
                &pending.salt,
                self.config.version_key,
                ExtrinsicWait::Included,
            )
            .await
            {
                Ok(tx_hash) => {
                    info!(
                        "✅ Weight reveal submitted to blockchain ({}): commit hash: {}, tx: {}, {} UIDs, version_key: {}",
                        mech_info, pending.commit_hash, tx_hash, pending.uids.len(), self.config.version_key
                    );
                    {
                        let mut pending_map = self.pending_commits.write().await;
                        pending_map.remove(&commit_block);
                    }
                    return Ok(tx_hash);
                }
                Err(e) => {
                    error!(
                        "Failed to reveal weights to blockchain: {}. Storing locally only.",
                        e
                    );
                }
            }
        }

        // Log and cleanup locally (fallback or when no client/signer)
        info!(
            "✅ Weight reveal prepared ({}): commit hash: {}, {} UIDs, version_key: {}",
            mech_info,
            pending.commit_hash,
            pending.uids.len(),
            self.config.version_key
        );

        // Remove pending commit after reveal
        {
            let mut pending_map = self.pending_commits.write().await;
            pending_map.remove(&commit_block);
        }

        Ok(format!("revealed_at_block_{}", commit_block + 1))
    }

    /// Reveal weights with retry logic
    pub async fn reveal_weights_with_retry(
        &self,
        netuid: u16,
        commit_block: u64,
    ) -> Result<String> {
        let mut retries = 0;

        while retries < self.config.max_retries {
            match self.reveal_weights(netuid, commit_block).await {
                Ok(tx_hash) => {
                    info!(
                        "✅ Successfully revealed weights (attempt {}/{})",
                        retries + 1,
                        self.config.max_retries
                    );
                    return Ok(tx_hash);
                }
                Err(e) => {
                    retries += 1;
                    error!(
                        "Failed to reveal weights (attempt {}/{}): {}",
                        retries, self.config.max_retries, e
                    );

                    if retries < self.config.max_retries {
                        let delay = self.config.retry_delay_secs * retries as u64;
                        warn!("Retrying reveal in {} seconds...", delay);
                        tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;
                    }
                }
            }
        }

        Err(anyhow::anyhow!(
            "Failed to reveal weights after {} retries",
            self.config.max_retries
        ))
    }

    /// Commit weights with retry logic
    pub async fn commit_weights_with_retry(
        &self,
        netuid: u16,
        uids: Vec<u64>,
        weights: Vec<u16>,
        block_number: u64,
        mechanism_id: Option<u8>,
    ) -> Result<String> {
        let mut retries = 0;

        while retries < self.config.max_retries {
            match self
                .commit_weights(
                    netuid,
                    uids.clone(),
                    weights.clone(),
                    block_number,
                    mechanism_id,
                )
                .await
            {
                Ok(hash) => {
                    info!(
                        "✅ Successfully committed weights (attempt {}/{})",
                        retries + 1,
                        self.config.max_retries
                    );
                    return Ok(hash);
                }
                Err(e) => {
                    retries += 1;
                    error!(
                        "Failed to commit weights (attempt {}/{}): {}",
                        retries, self.config.max_retries, e
                    );

                    if retries < self.config.max_retries {
                        let delay = self.config.retry_delay_secs * retries as u64;
                        warn!("Retrying commit in {} seconds...", delay);
                        tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;
                    }
                }
            }
        }

        Err(anyhow::anyhow!(
            "Failed to commit weights after {} retries",
            self.config.max_retries
        ))
    }

    /// Check if there's a pending commit that should be revealed at current block
    pub async fn get_pending_commit_for_reveal(&self, current_block: u64) -> Option<u64> {
        let pending_map = self.pending_commits.read().await;
        // Reveal should happen at commit_block + 1 (or later, within reveal window)
        // Find the oldest commit that should be revealed (commit_block + 1 <= current_block)
        pending_map
            .keys()
            .filter(|&&commit_block| commit_block + 1 <= current_block)
            .min()
            .copied()
    }

    /// Get all pending commits that need to be revealed
    pub async fn get_all_pending_commits(&self, current_block: u64) -> Vec<u64> {
        let pending_map = self.pending_commits.read().await;
        // Return all commits that should be revealed (commit_block + 1 <= current_block)
        pending_map
            .keys()
            .filter(|&&commit_block| commit_block + 1 <= current_block)
            .copied()
            .collect()
    }
}
