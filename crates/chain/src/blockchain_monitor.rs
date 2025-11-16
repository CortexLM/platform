use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use super::subtensor_client::SubtensorClient;
use super::types::ChainClient;

/// Network hyperparameters retrieved from blockchain
#[derive(Debug, Clone)]
pub struct NetworkHyperparameters {
    pub tempo: u16,
    pub weights_set_rate_limit: u64,
    pub current_block: u64,
    pub last_update: Option<u64>, // Last block when this validator set weights
    pub admin_freeze_window: u16,
}

impl Default for NetworkHyperparameters {
    fn default() -> Self {
        Self {
            tempo: 360,                  // Default tempo
            weights_set_rate_limit: 100, // Default rate limit
            current_block: 0,
            last_update: None,
            admin_freeze_window: 0,
        }
    }
}

/// Blockchain state monitor for weight synchronization
pub struct BlockchainMonitor {
    client: Arc<SubtensorClient>,
    netuid: u16,
    cached_hyperparams: Arc<RwLock<Option<NetworkHyperparameters>>>,
    cache_ttl_blocks: u64,
    last_cache_block: Arc<RwLock<u64>>,
}

impl BlockchainMonitor {
    pub fn new(client: Arc<SubtensorClient>, netuid: u16) -> Self {
        Self {
            client,
            netuid,
            cached_hyperparams: Arc::new(RwLock::new(None)),
            cache_ttl_blocks: 10, // Cache for 10 blocks
            last_cache_block: Arc::new(RwLock::new(0)),
        }
    }

    /// Get network hyperparameters (cached)
    pub async fn get_hyperparameters(&self) -> Result<NetworkHyperparameters> {
        let current_block = ChainClient::get_current_block(&*self.client).await?;

        // Check if cache is still valid
        let cache_valid = {
            let last_block = self.last_cache_block.read().await;
            current_block.saturating_sub(*last_block) < self.cache_ttl_blocks
        };

        if cache_valid {
            let cached = self.cached_hyperparams.read().await;
            if let Some(ref params) = *cached {
                return Ok(params.clone());
            }
        }

        // Fetch fresh hyperparameters
        let hyperparams = self.fetch_hyperparameters(current_block).await?;

        // Update cache
        {
            let mut cached = self.cached_hyperparams.write().await;
            *cached = Some(hyperparams.clone());
        }
        {
            let mut last_block = self.last_cache_block.write().await;
            *last_block = current_block;
        }

        Ok(hyperparams)
    }

    /// Fetch hyperparameters from blockchain
    async fn fetch_hyperparameters(&self, current_block: u64) -> Result<NetworkHyperparameters> {
        info!(
            "Fetching hyperparameters for netuid {} at block {}",
            self.netuid, current_block
        );

        // Query blockchain for tempo and weights_set_rate_limit
        // Try to use bittensor-rs queries if available, otherwise use defaults
        let tempo = self.query_tempo().await.unwrap_or(360);
        let weights_set_rate_limit = self.query_weights_set_rate_limit().await.unwrap_or(100);

        let hyperparams = NetworkHyperparameters {
            tempo,
            weights_set_rate_limit,
            current_block,
            last_update: None,
            admin_freeze_window: 0, // TODO: Query AdminFreezeWindow if available
        };

        info!(
            "Retrieved hyperparameters: tempo={}, weights_set_rate_limit={}",
            tempo, weights_set_rate_limit
        );

        Ok(hyperparams)
    }

    /// Query tempo from blockchain
    async fn query_tempo(&self) -> Result<u16> {
        // Try to query using bittensor-rs if available
        // For now, return default - in production this should query SubtensorModule::Tempo(netuid)
        // Example implementation:
        // use bittensor_rs::queries::subnets::tempo;
        // if let Ok(Some(tempo_val)) = tempo(&bittensor_client, self.netuid).await {
        //     return Ok(tempo_val as u16);
        // }
        Ok(360) // Default tempo
    }

    /// Query weights_set_rate_limit from blockchain
    async fn query_weights_set_rate_limit(&self) -> Result<u64> {
        // Try to query using bittensor-rs if available
        // For now, return default - in production this should query SubtensorModule::WeightsSetRateLimit(netuid)
        // Example implementation:
        // use bittensor_rs::queries::subnets::weights_rate_limit;
        // if let Ok(Some(rate_limit)) = weights_rate_limit(&bittensor_client, self.netuid).await {
        //     return Ok(rate_limit);
        // }
        Ok(100) // Default rate limit
    }

    /// Calculate blocks until next epoch
    /// Formula: tempo - (current_block % tempo)
    pub fn blocks_until_next_epoch(&self, tempo: u16, current_block: u64) -> u64 {
        if tempo == 0 {
            return u64::MAX; // No epoch defined
        }

        let tempo_u64 = tempo as u64;
        let remainder = current_block % tempo_u64;
        tempo_u64 - remainder
    }

    /// Check if we're in admin freeze window
    /// Admin freeze window is typically the last N blocks before epoch end
    pub fn is_in_admin_freeze_window(
        &self,
        tempo: u16,
        current_block: u64,
        freeze_window: u16,
    ) -> bool {
        if tempo == 0 || freeze_window == 0 {
            return false;
        }

        let blocks_until_epoch = self.blocks_until_next_epoch(tempo, current_block);
        blocks_until_epoch < freeze_window as u64
    }

    /// Calculate optimal block for weight submission
    /// Returns the block number when weights should be submitted
    pub fn calculate_optimal_submission_block(
        &self,
        tempo: u16,
        rate_limit: u64,
        current_block: u64,
        safety_margin: u64,
        jitter_max: u64,
    ) -> u64 {
        let blocks_until_epoch = self.blocks_until_next_epoch(tempo, current_block);

        // Calculate optimal block: submit before epoch ends, respecting rate limit
        let optimal_block = if blocks_until_epoch < rate_limit {
            // If epoch is ending soon, submit with safety margin
            current_block + blocks_until_epoch.saturating_sub(safety_margin)
        } else {
            // Otherwise, submit at halfway point or rate limit, whichever is smaller
            let half_epoch = blocks_until_epoch / 2;
            current_block + half_epoch.min(rate_limit)
        };

        // Add jitter to prevent validator collision
        // Jitter is random between 0 and jitter_max
        let jitter = if jitter_max > 0 {
            use rand::Rng;
            let mut rng = rand::rng();
            rng.random_range(0..=jitter_max.min(tempo as u64 / 10))
        } else {
            0
        };

        optimal_block + jitter
    }

    /// Get last update block for validator
    /// This queries the blockchain for when this validator last set weights
    pub async fn get_last_update_block(&self, validator_uid: u16) -> Result<Option<u64>> {
        // Query blockchain for LastUpdate[netuid_index][validator_uid]
        // In production, this should query SubtensorModule::LastUpdate storage
        // Example implementation:
        // use bittensor_rs::queries::subnets::last_update_for_uid;
        // if let Ok(Some(last_update)) = last_update_for_uid(&bittensor_client, self.netuid, validator_uid).await {
        //     return Ok(Some(last_update));
        // }

        // For now, try to get from cached hyperparameters or return None
        // This indicates no previous update, which allows first submission
        Ok(None)
    }

    /// Check if rate limit allows weight submission
    pub async fn can_submit_weights(&self, validator_uid: u16, current_block: u64) -> Result<bool> {
        let hyperparams = self.get_hyperparameters().await?;

        if let Some(last_update) = self.get_last_update_block(validator_uid).await? {
            let blocks_since_update = current_block.saturating_sub(last_update);
            let can_submit = blocks_since_update >= hyperparams.weights_set_rate_limit;

            if !can_submit {
                info!(
                    "Rate limit active: {} blocks since last update, need {} blocks",
                    blocks_since_update, hyperparams.weights_set_rate_limit
                );
            }

            return Ok(can_submit);
        }

        // No previous update, can submit
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocks_until_next_epoch() {
        let monitor = BlockchainMonitor::new(
            Arc::new(SubtensorClient::new(
                "http://localhost".to_string(),
                "test".to_string(),
            )),
            1,
        );

        // Test with tempo = 10, current_block = 5
        assert_eq!(monitor.blocks_until_next_epoch(10, 5), 5);

        // Test with tempo = 10, current_block = 10 (at epoch boundary)
        assert_eq!(monitor.blocks_until_next_epoch(10, 10), 10);

        // Test with tempo = 10, current_block = 9
        assert_eq!(monitor.blocks_until_next_epoch(10, 9), 1);

        // Test with tempo = 0 (no epoch)
        assert_eq!(monitor.blocks_until_next_epoch(0, 5), u64::MAX);
    }

    #[test]
    fn test_is_in_admin_freeze_window() {
        let monitor = BlockchainMonitor::new(
            Arc::new(SubtensorClient::new(
                "http://localhost".to_string(),
                "test".to_string(),
            )),
            1,
        );

        // At block 8 with tempo 10, freeze window 2: blocks_until_epoch = 2, should be in freeze
        assert!(monitor.is_in_admin_freeze_window(10, 8, 2));

        // At block 7 with tempo 10, freeze window 2: blocks_until_epoch = 3, should NOT be in freeze
        assert!(!monitor.is_in_admin_freeze_window(10, 7, 2));

        // At block 0 with tempo 10, freeze window 2: blocks_until_epoch = 10, should NOT be in freeze
        assert!(!monitor.is_in_admin_freeze_window(10, 0, 2));
    }

    #[test]
    fn test_calculate_optimal_submission_block() {
        let monitor = BlockchainMonitor::new(
            Arc::new(SubtensorClient::new(
                "http://localhost".to_string(),
                "test".to_string(),
            )),
            1,
        );

        // With tempo 10, current_block 5, rate_limit 100, safety_margin 2, jitter_max 0
        // blocks_until_epoch = 5, optimal = 5 + 5 - 2 = 8
        let optimal = monitor.calculate_optimal_submission_block(10, 100, 5, 2, 0);
        assert_eq!(optimal, 8);

        // With tempo 10, current_block 1, rate_limit 3, safety_margin 2, jitter_max 0
        // blocks_until_epoch = 9, optimal = 1 + min(9/2, 3) = 1 + 3 = 4
        let optimal = monitor.calculate_optimal_submission_block(10, 3, 1, 2, 0);
        assert_eq!(optimal, 4);
    }
}
