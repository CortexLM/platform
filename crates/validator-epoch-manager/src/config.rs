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
