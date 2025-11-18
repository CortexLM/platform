use std::collections::HashMap;

/// Cached weights for a specific epoch (sync_block)
#[derive(Debug, Clone)]
pub struct CachedEpochWeights {
    /// The sync_block for which these weights were calculated
    pub epoch_sync_block: u64,
    /// Chain-formatted weights by mechanism ID
    pub chain_weights_by_mechanism: HashMap<u8, Vec<(u64, u16)>>,
    /// Block number where weights were calculated
    pub calculated_at_block: u64,
}

