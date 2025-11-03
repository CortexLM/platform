use crate::{ChainClient, WeightSubmission, WeightSubmissionResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Weight submission manager
pub struct WeightSubmissionManager {
    submissions: BTreeMap<String, WeightSubmission>,
    results: BTreeMap<String, WeightSubmissionResult>,
    pending_submissions: BTreeMap<String, DateTime<Utc>>,
}

/// Weight submission error
#[derive(Debug, Error)]
pub enum WeightSubmissionError {
    #[error("Submission timeout")]
    Timeout,

    #[error("Invalid weights: {0}")]
    InvalidWeights(String),

    #[error("Duplicate submission")]
    DuplicateSubmission,

    #[error("Chain error: {0}")]
    ChainError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),
}

/// Weight submission status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WeightSubmissionStatus {
    Pending,
    Submitted,
    Confirmed,
    Failed,
    Timeout,
}

/// Weight submission tracker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightSubmissionTracker {
    pub submission_id: String,
    pub validator_hotkey: String,
    pub status: WeightSubmissionStatus,
    pub created_at: DateTime<Utc>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub failed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub transaction_hash: Option<String>,
    pub block_number: Option<u64>,
}

impl WeightSubmissionManager {
    pub fn new() -> Self {
        Self {
            submissions: BTreeMap::new(),
            results: BTreeMap::new(),
            pending_submissions: BTreeMap::new(),
        }
    }

    /// Submit weights to chain
    pub async fn submit_weights(
        &mut self,
        chain_client: &dyn ChainClient,
        weights: WeightSubmission,
    ) -> Result<WeightSubmissionResult, WeightSubmissionError> {
        // Validate weights
        self.validate_weights(&weights)?;

        // Check for duplicate submission
        let submission_key = format!("{}_{}", weights.validator_hotkey, weights.nonce);
        if self.submissions.contains_key(&submission_key) {
            return Err(WeightSubmissionError::DuplicateSubmission);
        }

        // Store submission
        self.submissions
            .insert(submission_key.clone(), weights.clone());
        self.pending_submissions
            .insert(submission_key.clone(), Utc::now());

        // Submit to chain
        let result = chain_client
            .submit_weights(weights)
            .await
            .map_err(|e| WeightSubmissionError::ChainError(e.to_string()))?;

        // Store result
        self.results.insert(submission_key, result.clone());

        Ok(result)
    }

    /// Get submission result
    pub fn get_submission_result(
        &self,
        validator_hotkey: &str,
        nonce: u64,
    ) -> Option<&WeightSubmissionResult> {
        let submission_key = format!("{}_{}", validator_hotkey, nonce);
        self.results.get(&submission_key)
    }

    /// Get all submissions for a validator
    pub fn get_validator_submissions(&self, validator_hotkey: &str) -> Vec<&WeightSubmission> {
        self.submissions
            .iter()
            .filter(|(key, _)| key.starts_with(validator_hotkey))
            .map(|(_, submission)| submission)
            .collect()
    }

    /// Get pending submissions
    pub fn get_pending_submissions(&self) -> Vec<&WeightSubmission> {
        self.pending_submissions
            .iter()
            .filter_map(|(key, _)| self.submissions.get(key))
            .collect()
    }

    /// Clean up old submissions
    pub fn cleanup_old_submissions(&mut self, max_age_hours: i64) {
        let cutoff = Utc::now() - chrono::Duration::hours(max_age_hours);

        // Remove old submissions
        self.submissions
            .retain(|_key, submission| submission.timestamp > cutoff);

        // Remove old results
        self.results
            .retain(|_key, result| result.timestamp > cutoff);

        // Remove old pending submissions
        self.pending_submissions
            .retain(|_key, timestamp| *timestamp > cutoff);
    }

    /// Validate weights
    fn validate_weights(&self, weights: &WeightSubmission) -> Result<(), WeightSubmissionError> {
        // Check if weights are empty
        if weights.weights.is_empty() {
            return Err(WeightSubmissionError::InvalidWeights(
                "Weights cannot be empty".to_string(),
            ));
        }

        // Check if all weights are positive
        for (key, weight) in &weights.weights {
            if *weight < 0.0 {
                return Err(WeightSubmissionError::InvalidWeights(format!(
                    "Weight for {} is negative: {}",
                    key, weight
                )));
            }
        }

        // Check if weights sum to reasonable range (not required to be 1.0)
        let total_weight: f64 = weights.weights.values().sum();
        if total_weight > 1000.0 {
            return Err(WeightSubmissionError::InvalidWeights(format!(
                "Total weight too large: {}",
                total_weight
            )));
        }

        Ok(())
    }
}

/// Weight submission batch processor
pub struct WeightSubmissionBatchProcessor {
    batch_size: usize,
    batch_timeout: chrono::Duration,
    pending_batch: Vec<WeightSubmission>,
    last_batch_time: DateTime<Utc>,
}

impl WeightSubmissionBatchProcessor {
    pub fn new(batch_size: usize, batch_timeout_seconds: i64) -> Self {
        Self {
            batch_size,
            batch_timeout: chrono::Duration::seconds(batch_timeout_seconds),
            pending_batch: Vec::new(),
            last_batch_time: Utc::now(),
        }
    }

    /// Add submission to batch
    pub fn add_submission(&mut self, submission: WeightSubmission) -> bool {
        self.pending_batch.push(submission);

        // Check if batch is ready
        self.is_batch_ready()
    }

    /// Check if batch is ready to process
    pub fn is_batch_ready(&self) -> bool {
        self.pending_batch.len() >= self.batch_size
            || (self.pending_batch.len() > 0
                && Utc::now() - self.last_batch_time > self.batch_timeout)
    }

    /// Process batch
    pub async fn process_batch(
        &mut self,
        chain_client: &dyn ChainClient,
    ) -> Result<Vec<WeightSubmissionResult>, WeightSubmissionError> {
        if self.pending_batch.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        let mut submission_manager = WeightSubmissionManager::new();

        // Process each submission in the batch
        for submission in self.pending_batch.drain(..) {
            match submission_manager
                .submit_weights(chain_client, submission)
                .await
            {
                Ok(result) => results.push(result),
                Err(e) => {
                    tracing::error!("Failed to submit weights: {}", e);
                    // Continue with other submissions
                }
            }
        }

        self.last_batch_time = Utc::now();
        Ok(results)
    }

    /// Get pending batch size
    pub fn pending_batch_size(&self) -> usize {
        self.pending_batch.len()
    }

    /// Clear pending batch
    pub fn clear_pending_batch(&mut self) {
        self.pending_batch.clear();
    }
}

/// Weight submission retry manager
pub struct WeightSubmissionRetryManager {
    max_retries: u32,
    retry_delay: chrono::Duration,
    retry_backoff_multiplier: f64,
    failed_submissions: BTreeMap<String, WeightSubmissionRetryInfo>,
}

/// Weight submission retry information
#[derive(Debug, Clone)]
pub struct WeightSubmissionRetryInfo {
    pub submission: WeightSubmission,
    pub attempt_count: u32,
    pub last_attempt: DateTime<Utc>,
    pub next_retry: DateTime<Utc>,
    pub error: String,
}

impl WeightSubmissionRetryManager {
    pub fn new(max_retries: u32, retry_delay_seconds: i64, backoff_multiplier: f64) -> Self {
        Self {
            max_retries,
            retry_delay: chrono::Duration::seconds(retry_delay_seconds),
            retry_backoff_multiplier: backoff_multiplier,
            failed_submissions: BTreeMap::new(),
        }
    }

    /// Add failed submission for retry
    pub fn add_failed_submission(&mut self, submission: WeightSubmission, error: String) {
        let submission_key = format!("{}_{}", submission.validator_hotkey, submission.nonce);
        let retry_info = WeightSubmissionRetryInfo {
            submission,
            attempt_count: 1,
            last_attempt: Utc::now(),
            next_retry: Utc::now() + self.retry_delay,
            error,
        };

        self.failed_submissions.insert(submission_key, retry_info);
    }

    /// Get submissions ready for retry
    pub fn get_ready_for_retry(&self) -> Vec<WeightSubmission> {
        let now = Utc::now();
        self.failed_submissions
            .values()
            .filter(|info| info.next_retry <= now && info.attempt_count <= self.max_retries)
            .map(|info| info.submission.clone())
            .collect()
    }

    /// Update retry attempt
    pub fn update_retry_attempt(
        &mut self,
        submission: &WeightSubmission,
        success: bool,
        error: Option<String>,
    ) {
        let submission_key = format!("{}_{}", submission.validator_hotkey, submission.nonce);

        if let Some(retry_info) = self.failed_submissions.get_mut(&submission_key) {
            if success {
                // Remove from retry list
                self.failed_submissions.remove(&submission_key);
            } else {
                // Update retry info
                retry_info.attempt_count += 1;
                retry_info.last_attempt = Utc::now();

                // Calculate next retry time with exponential backoff
                let delay_seconds = self.retry_delay.num_seconds() as f64
                    * self
                        .retry_backoff_multiplier
                        .powi(retry_info.attempt_count as i32 - 1);
                retry_info.next_retry =
                    Utc::now() + chrono::Duration::seconds(delay_seconds as i64);

                if let Some(err) = error {
                    retry_info.error = err;
                }
            }
        }
    }

    /// Get retry statistics
    pub fn get_retry_stats(&self) -> WeightSubmissionRetryStats {
        let total_failed = self.failed_submissions.len();
        let ready_for_retry = self.get_ready_for_retry().len();
        let max_attempts_reached = self
            .failed_submissions
            .values()
            .filter(|info| info.attempt_count > self.max_retries)
            .count();

        WeightSubmissionRetryStats {
            total_failed,
            ready_for_retry,
            max_attempts_reached,
            avg_attempts: if total_failed > 0 {
                self.failed_submissions
                    .values()
                    .map(|info| info.attempt_count)
                    .sum::<u32>() as f64
                    / total_failed as f64
            } else {
                0.0
            },
        }
    }

    /// Clean up old failed submissions
    pub fn cleanup_old_failed_submissions(&mut self, max_age_hours: i64) {
        let cutoff = Utc::now() - chrono::Duration::hours(max_age_hours);

        self.failed_submissions
            .retain(|_, info| info.last_attempt > cutoff);
    }
}

/// Weight submission retry statistics
#[derive(Debug, Clone)]
pub struct WeightSubmissionRetryStats {
    pub total_failed: usize,
    pub ready_for_retry: usize,
    pub max_attempts_reached: usize,
    pub avg_attempts: f64,
}

/// Weight submission validator
pub struct WeightSubmissionValidator {
    min_weight: f64,
    max_weight: f64,
    max_total_weight: f64,
    required_keys: Vec<String>,
    forbidden_keys: Vec<String>,
}

impl WeightSubmissionValidator {
    pub fn new() -> Self {
        Self {
            min_weight: 0.0,
            max_weight: 1000.0,
            max_total_weight: 1000.0,
            required_keys: Vec::new(),
            forbidden_keys: Vec::new(),
        }
    }

    pub fn with_min_weight(mut self, min_weight: f64) -> Self {
        self.min_weight = min_weight;
        self
    }

    pub fn with_max_weight(mut self, max_weight: f64) -> Self {
        self.max_weight = max_weight;
        self
    }

    pub fn with_max_total_weight(mut self, max_total_weight: f64) -> Self {
        self.max_total_weight = max_total_weight;
        self
    }

    pub fn with_required_keys(mut self, required_keys: Vec<String>) -> Self {
        self.required_keys = required_keys;
        self
    }

    pub fn with_forbidden_keys(mut self, forbidden_keys: Vec<String>) -> Self {
        self.forbidden_keys = forbidden_keys;
        self
    }

    /// Validate weight submission
    pub fn validate(&self, submission: &WeightSubmission) -> Result<(), WeightSubmissionError> {
        // Check required keys
        for required_key in &self.required_keys {
            if !submission.weights.contains_key(required_key) {
                return Err(WeightSubmissionError::ValidationError(format!(
                    "Required key missing: {}",
                    required_key
                )));
            }
        }

        // Check forbidden keys
        for forbidden_key in &self.forbidden_keys {
            if submission.weights.contains_key(forbidden_key) {
                return Err(WeightSubmissionError::ValidationError(format!(
                    "Forbidden key present: {}",
                    forbidden_key
                )));
            }
        }

        // Check individual weights
        for (key, weight) in &submission.weights {
            if *weight < self.min_weight {
                return Err(WeightSubmissionError::ValidationError(format!(
                    "Weight for {} below minimum: {}",
                    key, weight
                )));
            }

            if *weight > self.max_weight {
                return Err(WeightSubmissionError::ValidationError(format!(
                    "Weight for {} above maximum: {}",
                    key, weight
                )));
            }
        }

        // Check total weight
        let total_weight: f64 = submission.weights.values().sum();
        if total_weight > self.max_total_weight {
            return Err(WeightSubmissionError::ValidationError(format!(
                "Total weight exceeds maximum: {}",
                total_weight
            )));
        }

        Ok(())
    }
}
