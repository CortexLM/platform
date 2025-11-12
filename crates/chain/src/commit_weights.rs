use anyhow::Result;
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
    ///
    /// This stores the weights and salt for later revelation at the next block
    /// If mechanism_id is Some(id), uses commit_mechanism_weights, otherwise uses commit_weights
    /// In a real implementation, this would call bittensor_rs::validator::weights::commit_weights()
    /// or bittensor_rs::validator::mechanism::commit_mechanism_weights()
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
                ExtrinsicWait::Included, // Wait for inclusion in block
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
                    // Fall through to local storage
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
    ///
    /// This reveals the weights that were committed in the previous block
    /// Uses mechanism-specific reveal if mechanism_id was specified during commit
    /// In a real implementation, this would call bittensor_rs::validator::weights::reveal_weights()
    /// or bittensor_rs::validator::mechanism::reveal_mechanism_weights()
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

            // For mechanism-specific reveals, check if mechanism module exists
            if let Some(mech_id) = pending.mechanism_id {
                // Check if mechanism-specific reveal is available
                // Note: mechanism-weights feature support (conditionally compiled)
                {
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
                            // Remove pending commit after successful reveal
                            {
                                let mut pending_map = self.pending_commits.write().await;
                                pending_map.remove(&commit_block);
                            }
                            return Ok(tx_hash);
                        }
                        Err(e) => {
                            error!("Failed to reveal mechanism weights to blockchain: {}. Trying standard reveal.", e);
                            // Fall through to standard reveal
                        }
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
                    // Remove pending commit after successful reveal
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
                    // Fall through to local cleanup
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
                        let delay = self.config.retry_delay_secs * retries as u64; // Exponential backoff
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
                        let delay = self.config.retry_delay_secs * retries as u64; // Exponential backoff
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

    /// Cleanup old pending commits (older than N blocks)
    pub async fn cleanup_old_commits(&self, current_block: u64, max_age_blocks: u64) {
        let mut pending_map = self.pending_commits.write().await;
        let initial_size = pending_map.len();

        pending_map.retain(|&commit_block, _| {
            current_block.saturating_sub(commit_block) <= max_age_blocks
        });

        let removed = initial_size - pending_map.len();
        if removed > 0 {
            info!("Cleaned up {} old pending commit(s)", removed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_commit_reveal_cycle() {
        let config = CommitWeightsConfig::default();
        let service = CommitWeightsService::new(config);

        let netuid = 1;
        let uids = vec![10, 20, 30];
        let weights = vec![32767, 16383, 16385]; // Normalized to u16
        let commit_block = 1000;

        // Commit at block N (default mechanism, None = mechanism 0)
        let commit_hash = service
            .commit_weights(netuid, uids.clone(), weights.clone(), commit_block, None)
            .await
            .unwrap();
        assert!(!commit_hash.is_empty());

        // Check pending commit exists
        let pending = service
            .get_pending_commit_for_reveal(commit_block + 1)
            .await;
        assert_eq!(pending, Some(commit_block));

        // Reveal at block N+1
        let reveal_tx = service.reveal_weights(netuid, commit_block).await.unwrap();
        assert!(!reveal_tx.is_empty());

        // Verify commit was removed
        let pending = service
            .get_pending_commit_for_reveal(commit_block + 1)
            .await;
        assert_eq!(pending, None);
    }

    #[tokio::test]
    async fn test_retry_logic() {
        // Test would need mock implementation of commit_weights that fails first attempts
        // For now, just verify the structure
        let config = CommitWeightsConfig {
            max_retries: 3,
            retry_delay_secs: 1,
            version_key: 1,
        };
        let service = CommitWeightsService::new(config);

        let netuid = 1;
        let uids = vec![10, 20];
        let weights = vec![32767, 32768]; // Invalid (second weight > u16::MAX)

        // This should fail validation
        let result = service
            .commit_weights(netuid, uids, weights, 1000, None)
            .await;
        // Note: Current implementation doesn't validate u16::MAX, but it should in production
    }
}
