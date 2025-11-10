// async_trait import removed as it's not used
use crate::{ChallengeAdapter, HarnessBundle, SubmissionBundle, EvalResult, EngineConfig, EngineResult, EngineError};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Main evaluation engine
pub struct Evaluator {
    config: EngineConfig,
    adapters: BTreeMap<String, Box<dyn ChallengeAdapter>>,
    metrics: EvaluatorMetrics,
}

/// Evaluator metrics
#[derive(Debug, Default, Clone)]
pub struct EvaluatorMetrics {
    pub total_evaluations: u64,
    pub successful_evaluations: u64,
    pub failed_evaluations: u64,
    pub total_execution_time: u64,
    pub avg_execution_time: f64,
}

impl Evaluator {
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            adapters: BTreeMap::new(),
            metrics: EvaluatorMetrics::default(),
        }
    }

    /// Register a challenge adapter
    pub fn register_adapter(&mut self, name: String, adapter: Box<dyn ChallengeAdapter>) {
        self.adapters.insert(name, adapter);
    }

    /// Evaluate a submission using the appropriate adapter
    pub async fn evaluate(
        &mut self,
        harness: &HarnessBundle,
        submission: &SubmissionBundle,
    ) -> EngineResult<EvalResult> {
        let start_time = std::time::Instant::now();
        
        tracing::info!(
            "Starting evaluation: harness={}, submission={}",
            harness.id,
            submission.id
        );

        // Select appropriate adapter based on harness runtime
        let adapter_name = self.select_adapter(&harness.config.runtime)?;
        let adapter = self.adapters.get_mut(&adapter_name)
            .ok_or_else(|| crate::EngineError::AdapterError(format!("Adapter not found: {}", adapter_name)))?;

        // Prepare adapter
        adapter.prepare(harness).await
            .map_err(|e| crate::EngineError::AdapterError(format!("Adapter preparation failed: {}", e)))?;

        // Run evaluation
        let result = adapter.run(submission).await
            .map_err(|e| crate::EngineError::AdapterError(format!("Evaluation failed: {}", e)))?;

        // Score the result
        let score = adapter.score(&result)
            .map_err(|e| crate::EngineError::ScoringError(format!("Scoring failed: {}", e)))?;

        let execution_time = start_time.elapsed().as_secs();
        
        // Update metrics
        self.update_metrics(execution_time, true);

        tracing::info!(
            "Evaluation completed: score={}, execution_time={}s",
            score,
            execution_time
        );

        Ok(result)
    }

    /// Get evaluator metrics
    pub fn get_metrics(&self) -> &EvaluatorMetrics {
        &self.metrics
    }

    /// Reset metrics
    pub fn reset_metrics(&mut self) {
        self.metrics = EvaluatorMetrics::default();
    }

    fn select_adapter(&self, runtime: &crate::RuntimeType) -> EngineResult<String> {
        match runtime {
            crate::RuntimeType::Standard => Ok("standard".to_string()),
            crate::RuntimeType::Sgx => Ok("tee".to_string()),
            crate::RuntimeType::Sev => Ok("tee".to_string()),
            crate::RuntimeType::WasmEnclave => Ok("tee".to_string()),
        }
    }

    fn update_metrics(&mut self, execution_time: u64, success: bool) {
        self.metrics.total_evaluations += 1;
        self.metrics.total_execution_time += execution_time;
        
        if success {
            self.metrics.successful_evaluations += 1;
        } else {
            self.metrics.failed_evaluations += 1;
        }
        
        self.metrics.avg_execution_time = 
            self.metrics.total_execution_time as f64 / self.metrics.total_evaluations as f64;
    }
}

/// Batch evaluator for multiple submissions
pub struct BatchEvaluator {
    evaluator: Arc<RwLock<Evaluator>>,
    max_concurrent: u32,
    semaphore: Arc<tokio::sync::Semaphore>,
}

impl BatchEvaluator {
    pub fn new(config: EngineConfig, max_concurrent: u32) -> Self {
        Self {
            evaluator: Arc::new(RwLock::new(Evaluator::new(config))),
            max_concurrent,
            semaphore: Arc::new(tokio::sync::Semaphore::new(max_concurrent as usize)),
        }
    }

    /// Register a challenge adapter
    pub async fn register_adapter(&self, name: String, adapter: Box<dyn ChallengeAdapter>) {
        let mut evaluator = self.evaluator.write().await;
        evaluator.register_adapter(name, adapter);
    }

    /// Evaluate multiple submissions concurrently
    pub async fn evaluate_batch(
        &self,
        harness: &HarnessBundle,
        submissions: Vec<SubmissionBundle>,
    ) -> EngineResult<Vec<EvalResult>> {
        let mut handles = Vec::new();
        
        for submission in submissions {
            let harness = harness.clone();
            let semaphore = self.semaphore.clone();
            let evaluator = self.evaluator.clone();
            
            let handle = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                
                // Get write lock for evaluation
                let mut eval_guard = evaluator.write().await;
                let result = eval_guard.evaluate(&harness, &submission).await;
                
                result
            });
            
            handles.push(handle);
        }
        
        let mut results = Vec::new();
        for handle in handles {
            let result = handle.await
                .map_err(|e| crate::EngineError::AdapterError(format!("Task failed: {}", e)))?;
            results.push(result?);
        }
        
        Ok(results)
    }

    /// Get evaluator metrics
    pub async fn get_metrics(&self) -> EvaluatorMetrics {
        let evaluator = self.evaluator.read().await;
        evaluator.get_metrics().clone()
    }
}

/// Evaluation context for tracking evaluation state
#[derive(Debug, Clone)]
pub struct EvaluationContext {
    pub id: Uuid,
    pub harness_id: Uuid,
    pub submission_id: Uuid,
    pub start_time: DateTime<Utc>,
    pub status: EvaluationStatus,
    pub progress: f64,
    pub current_step: String,
}

/// Evaluation status
#[derive(Debug, Clone, PartialEq)]
pub enum EvaluationStatus {
    Pending,
    Preparing,
    Running,
    Scoring,
    Completed,
    Failed,
    Timeout,
}

impl EvaluationContext {
    pub fn new(harness_id: Uuid, submission_id: Uuid) -> Self {
        Self {
            id: Uuid::new_v4(),
            harness_id,
            submission_id,
            start_time: Utc::now(),
            status: EvaluationStatus::Pending,
            progress: 0.0,
            current_step: "Initializing".to_string(),
        }
    }

    pub fn update_status(&mut self, status: EvaluationStatus, step: String, progress: f64) {
        self.status = status;
        self.current_step = step;
        self.progress = progress;
    }
}

/// Evaluation progress tracker
pub struct ProgressTracker {
    contexts: BTreeMap<Uuid, EvaluationContext>,
}

impl ProgressTracker {
    pub fn new() -> Self {
        Self {
            contexts: BTreeMap::new(),
        }
    }

    pub fn start_evaluation(&mut self, harness_id: Uuid, submission_id: Uuid) -> Uuid {
        let context = EvaluationContext::new(harness_id, submission_id);
        let id = context.id;
        self.contexts.insert(id, context);
        id
    }

    pub fn update_progress(&mut self, id: Uuid, status: EvaluationStatus, step: String, progress: f64) {
        if let Some(context) = self.contexts.get_mut(&id) {
            context.update_status(status, step, progress);
        }
    }

    pub fn get_context(&self, id: Uuid) -> Option<&EvaluationContext> {
        self.contexts.get(&id)
    }

    pub fn finish_evaluation(&mut self, id: Uuid) {
        self.contexts.remove(&id);
    }
}
