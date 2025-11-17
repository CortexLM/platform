use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tracing::{info, warn};

use super::subtensor_client::{MetagraphState, SubtensorClient};

/// Block synchronization manager for 360-block cycles
pub struct BlockSyncManager {
    client: Arc<SubtensorClient>,
    current_block: u64,
    block_modulus: u64,
    last_sync_block: u64,
    weights: BTreeMap<String, f64>,
    weights_locked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncBlockInfo {
    pub sync_block: u64,
    pub current_block: u64,
    pub blocks_until_sync: u64,
    pub weights_locked: bool,
}

impl BlockSyncManager {
    pub fn new(client: Arc<SubtensorClient>) -> Self {
        Self {
            client,
            current_block: 0,
            block_modulus: 360,
            last_sync_block: 0,
            weights: BTreeMap::new(),
            weights_locked: false,
        }
    }

    /// Update current block and check if sync is needed
    pub async fn update_block(&mut self, block_number: u64) -> Result<SyncBlockInfo> {
        self.current_block = block_number;
        self.client.set_block(block_number).await;

        let sync_block = self.get_sync_block();
        let blocks_until_sync = self.modulus_distance_to_sync();

        // Lock weights during sync period (blocks n*360 to (n+1)*360)
        if blocks_until_sync == 0 {
            info!(
                "🔒 SYNC BLOCK {} - Weights are LOCKED for next 360 blocks",
                sync_block
            );
            self.weights_locked = true;
            self.last_sync_block = sync_block;
        } else if blocks_until_sync == 1 {
            info!(
                "🔓 BLOCK {} - Weights unlock at next block (sync block {})",
                block_number, sync_block
            );
            self.weights_locked = false;
        }

        Ok(SyncBlockInfo {
            sync_block,
            current_block: block_number,
            blocks_until_sync,
            weights_locked: self.weights_locked,
        })
    }

    /// Get the sync block for current position
    pub fn get_sync_block(&self) -> u64 {
        (self.current_block / self.block_modulus) * self.block_modulus
    }

    /// Get next sync block
    pub fn get_next_sync_block(&self) -> u64 {
        self.get_sync_block() + self.block_modulus
    }

    /// Check if current block is a sync block
    pub fn is_sync_block(&self) -> bool {
        self.current_block % self.block_modulus == 0
    }

    /// Get distance to next sync block
    pub fn modulus_distance_to_sync(&self) -> u64 {
        self.block_modulus - (self.current_block % self.block_modulus)
    }

    /// Check if weights can be updated
    pub fn can_update_weights(&self) -> bool {
        !self.weights_locked && !self.is_sync_block()
    }

    /// Set weights (only if not locked)
    pub fn set_weights(&mut self, weights: BTreeMap<String, f64>) -> Result<()> {
        if self.weights_locked {
            return Err(anyhow::anyhow!(
                "Weights are locked. Wait until next sync block (block {})",
                self.get_next_sync_block()
            ));
        }

        if self.is_sync_block() {
            return Err(anyhow::anyhow!(
                "Cannot update weights on sync block. Set weights before sync block."
            ));
        }

        info!("Setting weights for {} miners", weights.len());
        self.weights = weights;
        Ok(())
    }

    /// Get current weights
    pub fn get_weights(&self) -> &BTreeMap<String, f64> {
        &self.weights
    }

    /// Submit weights to Subtensor on sync block
    pub async fn submit_weights_to_chain(&mut self) -> Result<()> {
        if !self.is_sync_block() {
            return Err(anyhow::anyhow!("Not a sync block"));
        }

        if self.weights.is_empty() {
            warn!("No weights to submit on sync block");
            return Ok(());
        }

        info!(
            "✅ SYNC BLOCK {} - Submitting weights to Subtensor",
            self.current_block
        );
        info!("   Submitting {} weight pairs", self.weights.len());

        // Submit weights via SubtensorClient
        self.client
            .update_weights_on_sync_block(self.weights.clone())
            .await?;

        info!(
            "✅ Weights submitted successfully to Subtensor at block {}",
            self.current_block
        );

        Ok(())
    }

    /// Get synchronization info
    pub fn get_sync_info(&self) -> SyncBlockInfo {
        SyncBlockInfo {
            sync_block: self.get_sync_block(),
            current_block: self.current_block,
            blocks_until_sync: self.modulus_distance_to_sync(),
            weights_locked: self.weights_locked,
        }
    }

    /// Sync current block from SubtensorClient
    /// This should be called periodically to keep BlockSyncManager in sync with the blockchain
    pub async fn sync_block_from_client(&mut self) -> Result<SyncBlockInfo> {
        use crate::types::ChainClient;
        let client_block = self.client.get_current_block().await?;
        self.update_block(client_block).await
    }
}

/// Metagraph synchronization manager
pub struct MetagraphSyncManager {
    block_sync: BlockSyncManager,
    metagraph: Option<MetagraphState>,
    last_metagraph_update: Option<DateTime<Utc>>,
}

impl MetagraphSyncManager {
    pub fn new(client: Arc<SubtensorClient>) -> Self {
        Self {
            block_sync: BlockSyncManager::new(client),
            metagraph: None,
            last_metagraph_update: None,
        }
    }

    /// Update metagraph on sync blocks
    pub async fn update_metagraph(&mut self, netuid: u16) -> Result<()> {
        if !self.block_sync.is_sync_block() {
            return Ok(()); // Only update on sync blocks
        }

        info!(
            "📊 Updating metagraph for subnet {} at sync block {}",
            netuid, self.block_sync.current_block
        );

        // Fetch metagraph from Subtensor
        let metagraph = self.block_sync.client.get_metagraph(netuid).await?;
        self.metagraph = Some(metagraph);
        self.last_metagraph_update = Some(Utc::now());

        info!(
            "✅ Metagraph updated with {} validators",
            self.metagraph
                .as_ref()
                .map(|m| m.validators.len())
                .unwrap_or(0)
        );

        Ok(())
    }

    /// Get metagraph state
    pub fn get_metagraph(&self) -> Option<&MetagraphState> {
        self.metagraph.as_ref()
    }

    /// Get block sync manager
    pub fn block_sync(&self) -> &BlockSyncManager {
        &self.block_sync
    }

    /// Get mutable block sync manager
    pub fn block_sync_mut(&mut self) -> &mut BlockSyncManager {
        &mut self.block_sync
    }
}
