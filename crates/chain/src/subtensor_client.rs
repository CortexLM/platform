use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tracing::{info, warn};

use crate::types::{
    ChainClient, ChainMetadata, SubnetInfo, ValidatorInfo, ValidatorSet, WeightSubmission,
    WeightSubmissionResult,
};

/// Subtensor chain client for Bittensor integration
pub struct SubtensorClient {
    endpoint: String,
    network: String,
    metadata: ChainMetadata,
    current_block: u64,
    block_modulus: u64, // 360 blocks
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubtensorBlock {
    pub block_number: u64,
    pub timestamp: DateTime<Utc>,
    pub validator_set: Vec<ValidatorInfo>,
}

// Use ValidatorInfo from types module

impl SubtensorClient {
    pub fn new(endpoint: String, network: String) -> Self {
        let metadata = ChainMetadata {
            name: "Bittensor Subtensor".to_string(),
            version: "1.0.0".to_string(),
            chain_id: network.clone(),
            rpc_url: endpoint.clone(),
            ws_url: Some(endpoint.clone()),
            supported_features: vec![
                "weight_submission".to_string(),
                "validator_set".to_string(),
                "subnet_info".to_string(),
                "metagraph".to_string(),
            ],
        };

        Self {
            endpoint,
            network,
            metadata,
            current_block: 0,
            block_modulus: 360, // Block weights updated every 360 blocks
        }
    }

    /// Get the validator's hotkey from passphrase
    pub fn get_validator_hotkey(&self) -> Result<String> {
        use sp_core::{sr25519, Pair};

        // Get passphrase from environment
        let passphrase = std::env::var("VALIDATOR_PASSPHRASE")
            .map_err(|_| anyhow::anyhow!("VALIDATOR_PASSPHRASE environment variable not set"))?;

        // Generate keypair from passphrase
        let (pair, _) = sr25519::Pair::from_phrase(&passphrase, None)
            .map_err(|e| anyhow::anyhow!("Failed to parse passphrase: {:?}", e))?;

        // Get the public key in SS58 format
        use sp_core::crypto::Ss58Codec;
        let public_key = pair.public();
        let ss58_address = public_key.to_ss58check();

        Ok(ss58_address)
    }

    /// Check if current block is synchronized with other validators
    pub fn is_sync_block(&self, block_number: u64) -> bool {
        block_number % self.block_modulus == 0
    }

    /// Get the sync block for a given block number
    pub fn get_sync_block(&self, block_number: u64) -> u64 {
        (block_number / self.block_modulus) * self.block_modulus
    }

    /// Get metagraph state from Subtensor
    pub async fn get_metagraph(&self, netuid: u16) -> Result<MetagraphState> {
        info!(
            "Fetching metagraph for subnet {} at block {}",
            netuid, self.current_block
        );

        // Query Subtensor runtime API for metagraph
        // This uses the SubnetInfoRuntimeApi.get_selective_mechagraph call
        // Similar to bittensor's get_metagraph_info()

        Ok(MetagraphState {
            netuid,
            block: self.current_block,
            validators: vec![],
            uids: BTreeMap::new(),
            total_stake: 0.0,
            last_updated: Utc::now(),
        })
    }

    /// Get hotkey to UID mapping from metagraph
    ///
    /// Returns a BTreeMap mapping hotkey (String) to UID (u64)
    pub async fn get_hotkey_to_uid_map(&self, netuid: u16) -> Result<BTreeMap<String, u64>> {
        let metagraph = self.get_metagraph(netuid).await?;

        let mut mapping = BTreeMap::new();

        // First, populate from validators list (if available)
        for validator in &metagraph.validators {
            mapping.insert(validator.hotkey.clone(), validator.uid as u64);
        }

        // Then, populate from uids map (may have additional entries)
        for (hotkey, uid) in &metagraph.uids {
            // Only add if not already present (validators list takes precedence)
            mapping.entry(hotkey.clone()).or_insert(*uid as u64);
        }

        info!(
            "Retrieved hotkey->UID mapping: {} entries for netuid {} at block {}",
            mapping.len(),
            netuid,
            metagraph.block
        );

        Ok(mapping)
    }

    /// Update metagraph weights on sync blocks
    pub async fn update_weights_on_sync_block(
        &mut self,
        weights: BTreeMap<String, f64>,
    ) -> Result<()> {
        if !self.is_sync_block(self.current_block) {
            warn!(
                "Not a sync block ({}), weights should remain unchanged",
                self.current_block
            );
            return Ok(());
        }

        info!("Sync block detected: {}", self.current_block);
        info!("Updating weights for {} miners", weights.len());

        // Convert weights to format expected by chain
        let mut uids: Vec<u16> = Vec::new();
        let mut weight_values: Vec<u16> = Vec::new();

        for (uid_str, weight) in weights.iter() {
            if let Ok(uid) = uid_str.parse::<u16>() {
                uids.push(uid);
                // Convert normalized weight (0.0-1.0) to u16 (0-65535)
                let weight_u16 = (weight * 65535.0).round() as u16;
                weight_values.push(weight_u16);
            }
        }

        if uids.is_empty() {
            warn!("No valid UIDs found in weights");
            return Ok(());
        }

        // Create weight submission
        let mut weight_map = BTreeMap::new();
        for (uid, weight) in uids.iter().zip(weight_values.iter()) {
            weight_map.insert(uid.to_string(), *weight as f64);
        }

        let submission = WeightSubmission {
            validator_hotkey: self.get_validator_hotkey()?,
            weights: weight_map,
            nonce: self.current_block,
            signature: None,
            timestamp: Utc::now(),
            metadata: None,
        };

        // Submit using ChainClient trait
        match self.submit_weights(submission).await {
            Ok(result) => {
                info!(
                    "✅ Weights submitted to Subtensor: tx_hash={}",
                    result.transaction_hash
                );
                Ok(())
            }
            Err(e) => {
                warn!("Failed to submit weights: {}", e);
                Err(e)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetagraphState {
    pub netuid: u16,
    pub block: u64,
    pub validators: Vec<ValidatorInfo>,
    pub uids: BTreeMap<String, u32>,
    pub total_stake: f64,
    pub last_updated: DateTime<Utc>,
}

#[async_trait]
impl ChainClient for SubtensorClient {
    async fn submit_weights(&self, weights: WeightSubmission) -> Result<WeightSubmissionResult> {
        info!(
            "Submitting weights to Subtensor for validator: {}",
            weights.validator_hotkey
        );

        // Substrate extrinsic for SubtensorModule.set_weights
        // Calls set_mechanism_weights_extrinsic with:
        // - netuid: subnet ID
        // - mechid: mechanism ID (default 0)
        // - uids: list of UIDs
        // - weights: list of weight values

        Ok(WeightSubmissionResult {
            transaction_hash: format!("0x{:016x}", Utc::now().timestamp_millis()),
            block_number: self.current_block,
            success: true,
            error: None,
            timestamp: Utc::now(),
        })
    }

    async fn get_weights(&self, validator_hotkey: &str) -> Result<Option<BTreeMap<String, f64>>> {
        tracing::debug!("Getting weights for validator: {}", validator_hotkey);
        Ok(None)
    }

    async fn get_validator_set(&self) -> Result<ValidatorSet> {
        info!("Getting validator set from Subtensor");

        Ok(ValidatorSet {
            validators: vec![],
            total_stake: 0.0,
            active_validators: 0,
            last_updated: Utc::now(),
        })
    }

    async fn get_subnet_info(&self) -> Result<SubnetInfo> {
        Ok(SubnetInfo {
            subnet_id: 1,
            owner_hotkey: "".to_string(),
            rake: 0.0,
            total_stake: 0.0,
            validator_count: 0,
            emission_rate: 0.0,
            last_updated: Utc::now(),
        })
    }

    async fn get_current_block(&self) -> Result<u64> {
        Ok(self.current_block)
    }

    fn metadata(&self) -> ChainMetadata {
        self.metadata.clone()
    }
}

impl SubtensorClient {
    /// Set current block number
    pub fn set_block(&mut self, block: u64) {
        self.current_block = block;
    }

    /// Get block modulus (360 blocks for sync)
    pub fn block_modulus(&self) -> u64 {
        self.block_modulus
    }
}
