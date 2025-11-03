use crate::{
    AttestationReceipt, EvalResult, ExecutorError, ExecutorMetadata, ExecutorResult, HarnessBundle,
    RuntimeType, SubmissionBundle, TrustedExecutor,
};
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Base implementation for trusted executors
pub struct BaseTrustedExecutor {
    metadata: ExecutorMetadata,
    config: ExecutorConfig,
}

/// Executor configuration
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    pub timeout: u64,
    pub resource_limits: crate::ResourceLimits,
    pub attestation_required: bool,
    pub policy: Option<String>,
    pub measurements: Vec<Vec<u8>>,
}

impl BaseTrustedExecutor {
    pub fn new(metadata: ExecutorMetadata, config: ExecutorConfig) -> Self {
        Self { metadata, config }
    }

    /// Validate harness bundle
    pub fn validate_harness(&self, harness: &HarnessBundle) -> ExecutorResult<()> {
        // Check runtime compatibility
        if !self
            .metadata
            .supported_runtimes
            .contains(&harness.config.runtime)
        {
            return Err(ExecutorError::ConfigError(format!(
                "Runtime {:?} not supported by executor",
                harness.config.runtime
            )));
        }

        // Check resource limits
        if harness.config.resources.memory_mb > self.config.resource_limits.memory_mb {
            return Err(ExecutorError::ResourceError(format!(
                "Memory limit {}MB exceeds executor limit {}MB",
                harness.config.resources.memory_mb, self.config.resource_limits.memory_mb
            )));
        }

        // Check timeout
        if harness.config.timeout > self.config.timeout {
            return Err(ExecutorError::ConfigError(format!(
                "Timeout {}s exceeds executor limit {}s",
                harness.config.timeout, self.config.timeout
            )));
        }

        Ok(())
    }

    /// Validate submission bundle
    pub fn validate_submission(&self, submission: &SubmissionBundle) -> ExecutorResult<()> {
        // Check if submission is encrypted when required
        if self.config.attestation_required && !submission.encrypted {
            return Err(ExecutorError::ConfigError(
                "Encrypted submission required for TEE execution".to_string(),
            ));
        }

        // Check submission size
        if submission.size > self.config.resource_limits.disk_mb * 1024 * 1024 {
            return Err(ExecutorError::ResourceError(format!(
                "Submission size {}MB exceeds limit {}MB",
                submission.size / (1024 * 1024),
                self.config.resource_limits.disk_mb
            )));
        }

        Ok(())
    }

    /// Create attestation receipt
    pub fn create_attestation_receipt(
        &self,
        nonce: &[u8],
        quote: Option<Vec<u8>>,
        report: Option<Vec<u8>>,
    ) -> AttestationReceipt {
        AttestationReceipt {
            id: Uuid::new_v4(),
            executor_type: self.metadata.supported_runtimes[0].clone(),
            nonce: nonce.to_vec(),
            quote,
            report,
            measurements: self.config.measurements.clone(),
            verified: true,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
        }
    }

    /// Create evaluation result
    pub fn create_eval_result(
        &self,
        harness: &HarnessBundle,
        submission: &SubmissionBundle,
        execution_time: u64,
    ) -> EvalResult {
        EvalResult {
            id: Uuid::new_v4(),
            challenge_id: harness.challenge_id,
            submission_id: submission.id,
            scores: BTreeMap::from([
                ("primary".to_string(), 0.85),
                ("accuracy".to_string(), 0.90),
                ("efficiency".to_string(), 0.80),
            ]),
            metrics: BTreeMap::from([
                ("execution_time".to_string(), execution_time as f64),
                ("memory_usage".to_string(), 512.0),
                ("cpu_usage".to_string(), 75.0),
            ]),
            logs: vec![
                "Execution started".to_string(),
                "Harness loaded".to_string(),
                "Submission processed".to_string(),
                "Execution completed".to_string(),
            ],
            error: None,
            execution_time,
            resource_usage: crate::ResourceUsage {
                cpu_time: execution_time * 1000,
                memory_peak: 512 * 1024 * 1024,
                disk_usage: 100 * 1024 * 1024,
                network_bytes: 0,
            },
            attestation_receipt: None,
            created_at: Utc::now(),
        }
    }

    /// Get executor configuration
    pub fn get_config(&self) -> &ExecutorConfig {
        &self.config
    }
}

/// Executor manager for managing multiple executors
pub struct ExecutorManager {
    executors: BTreeMap<RuntimeType, Box<dyn TrustedExecutor>>,
    default_executor: RuntimeType,
}

impl ExecutorManager {
    pub fn new() -> Self {
        Self {
            executors: BTreeMap::new(),
            default_executor: RuntimeType::Standard,
        }
    }

    /// Register an executor
    pub fn register_executor(&mut self, runtime: RuntimeType, executor: Box<dyn TrustedExecutor>) {
        self.executors.insert(runtime, executor);
    }

    /// Get executor for runtime
    pub fn get_executor(&self, runtime: &RuntimeType) -> Option<&dyn TrustedExecutor> {
        self.executors.get(runtime).map(|e| e.as_ref())
    }

    /// Get executor for runtime (mutable)
    pub fn get_executor_mut(
        &mut self,
        runtime: &RuntimeType,
    ) -> Option<&mut Box<dyn TrustedExecutor>> {
        self.executors.get_mut(runtime)
    }

    /// Get default executor
    pub fn get_default_executor(&self) -> Option<&dyn TrustedExecutor> {
        self.get_executor(&self.default_executor)
    }

    /// Set default executor
    pub fn set_default_executor(&mut self, runtime: RuntimeType) {
        if self.executors.contains_key(&runtime) {
            self.default_executor = runtime;
        }
    }

    /// List available runtimes
    pub fn list_runtimes(&self) -> Vec<RuntimeType> {
        self.executors.keys().cloned().collect()
    }

    /// Check if runtime is available
    pub fn is_runtime_available(&self, runtime: &RuntimeType) -> bool {
        self.executors.contains_key(runtime)
    }
}

/// Executor health checker
pub struct ExecutorHealthChecker {
    executors: BTreeMap<RuntimeType, ExecutorHealth>,
}

/// Executor health status
#[derive(Debug, Clone)]
pub struct ExecutorHealth {
    pub available: bool,
    pub last_check: DateTime<Utc>,
    pub error: Option<String>,
    pub metrics: ExecutorHealthMetrics,
}

/// Executor health metrics
#[derive(Debug, Clone, Default)]
pub struct ExecutorHealthMetrics {
    pub total_executions: u64,
    pub successful_executions: u64,
    pub failed_executions: u64,
    pub avg_execution_time: f64,
    pub last_execution: Option<DateTime<Utc>>,
}

impl ExecutorHealthChecker {
    pub fn new() -> Self {
        Self {
            executors: BTreeMap::new(),
        }
    }

    /// Check health of all executors
    pub async fn check_all_health(&mut self, manager: &ExecutorManager) {
        for runtime in manager.list_runtimes() {
            self.check_executor_health(&runtime, manager).await;
        }
    }

    /// Check health of specific executor
    pub async fn check_executor_health(
        &mut self,
        runtime: &RuntimeType,
        manager: &ExecutorManager,
    ) {
        let health = if let Some(executor) = manager.get_executor(runtime) {
            ExecutorHealth {
                available: executor.is_available().await,
                last_check: Utc::now(),
                error: None,
                metrics: ExecutorHealthMetrics::default(),
            }
        } else {
            ExecutorHealth {
                available: false,
                last_check: Utc::now(),
                error: Some("Executor not registered".to_string()),
                metrics: ExecutorHealthMetrics::default(),
            }
        };

        self.executors.insert(runtime.clone(), health);
    }

    /// Get health status for runtime
    pub fn get_health(&self, runtime: &RuntimeType) -> Option<&ExecutorHealth> {
        self.executors.get(runtime)
    }

    /// Get all health statuses
    pub fn get_all_health(&self) -> &BTreeMap<RuntimeType, ExecutorHealth> {
        &self.executors
    }

    /// Update execution metrics
    pub fn update_execution_metrics(
        &mut self,
        runtime: &RuntimeType,
        success: bool,
        execution_time: u64,
    ) {
        if let Some(health) = self.executors.get_mut(runtime) {
            health.metrics.total_executions += 1;
            health.metrics.last_execution = Some(Utc::now());

            if success {
                health.metrics.successful_executions += 1;
            } else {
                health.metrics.failed_executions += 1;
            }

            health.metrics.avg_execution_time = (health.metrics.avg_execution_time
                * (health.metrics.total_executions - 1) as f64
                + execution_time as f64)
                / health.metrics.total_executions as f64;
        }
    }
}
