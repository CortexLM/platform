use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Metrics for weight submission synchronization
#[derive(Debug, Clone, Default)]
pub struct WeightSyncMetrics {
    /// Total weight submission attempts
    pub submission_attempts: u64,
    /// Successful submissions
    pub successful_submissions: u64,
    /// Failed submissions
    pub failed_submissions: u64,
    /// Retry attempts
    pub retry_attempts: u64,
    /// Average blocks until successful submission
    pub avg_blocks_until_submission: f64,
    /// Coordination efficiency (validators not conflicting)
    pub coordination_efficiency: f64,
    /// Error type distribution
    pub error_distribution: HashMap<String, u64>,
    /// Last successful submission block
    pub last_successful_block: Option<u64>,
    /// Last failed submission block
    pub last_failed_block: Option<u64>,
}

/// Metrics collector for weight synchronization
pub struct WeightSyncMetricsCollector {
    metrics: Arc<RwLock<WeightSyncMetrics>>,
    submission_history: Arc<RwLock<Vec<SubmissionRecord>>>,
}

#[derive(Debug, Clone)]
struct SubmissionRecord {
    block: u64,
    success: bool,
    retry_count: u32,
    error_type: Option<String>,
    timestamp: chrono::DateTime<chrono::Utc>,
}

impl WeightSyncMetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(WeightSyncMetrics::default())),
            submission_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Record a weight submission attempt
    pub async fn record_submission_attempt(&self, block: u64) {
        let mut metrics = self.metrics.write().await;
        metrics.submission_attempts += 1;

        let mut history = self.submission_history.write().await;
        history.push(SubmissionRecord {
            block,
            success: false,
            retry_count: 0,
            error_type: None,
            timestamp: chrono::Utc::now(),
        });
    }

    /// Record a successful submission
    pub async fn record_success(&self, block: u64, retry_count: u32) {
        let mut metrics = self.metrics.write().await;
        metrics.successful_submissions += 1;
        metrics.last_successful_block = Some(block);

        // Update retry attempts
        if retry_count > 0 {
            metrics.retry_attempts += retry_count as u64;
        }

        // Update history
        let mut history = self.submission_history.write().await;
        if let Some(last) = history.last_mut() {
            last.success = true;
            last.retry_count = retry_count;
        }

        // Calculate average blocks until submission
        Self::update_avg_blocks_until_submission(&mut metrics, &history);
    }

    /// Record a failed submission
    pub async fn record_failure(&self, block: u64, error_type: &str, retry_count: u32) {
        let mut metrics = self.metrics.write().await;
        metrics.failed_submissions += 1;
        metrics.last_failed_block = Some(block);

        if retry_count > 0 {
            metrics.retry_attempts += retry_count as u64;
        }

        // Update error distribution
        *metrics
            .error_distribution
            .entry(error_type.to_string())
            .or_insert(0) += 1;

        // Update history
        let mut history = self.submission_history.write().await;
        if let Some(last) = history.last_mut() {
            last.success = false;
            last.retry_count = retry_count;
            last.error_type = Some(error_type.to_string());
        }
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> WeightSyncMetrics {
        self.metrics.read().await.clone()
    }

    /// Calculate coordination efficiency
    /// This is a placeholder - in production, this would analyze validator submission patterns
    pub async fn calculate_coordination_efficiency(&self) -> f64 {
        let history = self.submission_history.read().await;
        if history.len() < 2 {
            return 1.0; // Perfect efficiency if no history
        }

        // Simple heuristic: efficiency decreases with retries
        let total_attempts = history.len() as u64;
        let successful_without_retry: u64 = history
            .iter()
            .filter(|r| r.success && r.retry_count == 0)
            .count() as u64;

        if total_attempts > 0 {
            successful_without_retry as f64 / total_attempts as f64
        } else {
            1.0
        }
    }

    /// Update average blocks until submission
    fn update_avg_blocks_until_submission(
        metrics: &mut WeightSyncMetrics,
        history: &[SubmissionRecord],
    ) {
        let successful: Vec<_> = history.iter().filter(|r| r.success).collect();

        if successful.len() >= 2 {
            let mut block_diffs = Vec::new();
            for i in 1..successful.len() {
                let diff = successful[i].block.saturating_sub(successful[i - 1].block);
                block_diffs.push(diff);
            }

            if !block_diffs.is_empty() {
                let sum: u64 = block_diffs.iter().sum();
                metrics.avg_blocks_until_submission = sum as f64 / block_diffs.len() as f64;
            }
        }
    }

    /// Clean up old history
    pub async fn cleanup_old_history(&self, max_age_hours: i64) {
        let cutoff = chrono::Utc::now() - chrono::Duration::hours(max_age_hours);
        let mut history = self.submission_history.write().await;
        history.retain(|r| r.timestamp > cutoff);
    }

    /// Log metrics summary
    pub async fn log_summary(&self) {
        let metrics = self.get_metrics().await;
        let efficiency = self.calculate_coordination_efficiency().await;

        info!(
            "Weight Sync Metrics: attempts={}, success={}, failed={}, retries={}, avg_blocks={:.2}, efficiency={:.2}%",
            metrics.submission_attempts,
            metrics.successful_submissions,
            metrics.failed_submissions,
            metrics.retry_attempts,
            metrics.avg_blocks_until_submission,
            efficiency * 100.0
        );

        if !metrics.error_distribution.is_empty() {
            info!("Error distribution: {:?}", metrics.error_distribution);
        }
    }
}

impl Default for WeightSyncMetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
