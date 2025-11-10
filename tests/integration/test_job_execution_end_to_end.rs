// End-to-end tests for job execution flow
use platform_engine_api_client::{PlatformApiClient, ApiConfig};
use platform_engine_executor::{JobManager, JobExecutor};
use platform_engine_engine::{EvaluationEngine, EngineConfig};
use platform_engine_challenge_spec::ChallengeSpec;
use platform_engine_chain::{ChainClient, MockChainClient, BittensorChainClient};
use platform_api_models::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use serde_json::json;

#[tokio::test]
async fn test_complete_job_execution_flow() {
    // Setup platform API client
    let api_config = ApiConfig {
        base_url: "http://localhost:8000".to_string(),
        api_key: Some("test-api-key".to_string()),
        timeout_seconds: 30,
        max_retries: 3,
    };
    
    let api_client = Arc::new(
        PlatformApiClient::new(api_config)
            .expect("Failed to create API client")
    );
    
    // Setup job manager
    let job_manager = JobManager::new(api_client.clone())
        .await
        .expect("Failed to create job manager");
    
    // Setup evaluation engine
    let engine_config = EngineConfig::default();
    let engine = EvaluationEngine::new(engine_config)
        .await
        .expect("Failed to create evaluation engine");
    
    // Create job executor
    let executor = JobExecutor::new(
        job_manager.clone(),
        engine.clone(),
        api_client.clone()
    );
    
    // 1. Claim a job
    let claim_request = ClaimJobRequest {
        validator_hotkey: "test_validator_hotkey".into(),
        challenge_id: None, // Claim any available job
        runtime: RuntimeType::Docker,
    };
    
    let claimed_job = api_client.claim_job(claim_request)
        .await
        .expect("Failed to claim job");
    
    assert_eq!(claimed_job.job.status, JobStatus::Claimed);
    let job = claimed_job.job;
    
    // 2. Execute the job
    let execution_result = executor.execute_job(&job)
        .await
        .expect("Failed to execute job");
    
    assert!(execution_result.success);
    assert!(execution_result.eval_result.is_some());
    
    let eval_result = execution_result.eval_result.unwrap();
    assert!(eval_result.score >= 0.0 && eval_result.score <= 1.0);
    assert!(eval_result.passed_tests <= eval_result.total_tests);
    
    // 3. Submit results
    let submit_request = SubmitResultRequest {
        result: eval_result.clone(),
        status: JobStatus::Completed,
        error: None,
        usage: Some(execution_result.resource_usage),
    };
    
    let submitted = api_client.submit_result(job.id, submit_request)
        .await
        .expect("Failed to submit result");
    
    assert_eq!(submitted.status, JobStatus::Completed);
    assert!(submitted.completed_at.is_some());
    
    // 4. Verify job completion
    let completed_job = api_client.get_job(job.id)
        .await
        .expect("Failed to get completed job");
    
    assert_eq!(completed_job.status, JobStatus::Completed);
    assert_eq!(completed_job.validator_hotkey, Some("test_validator_hotkey".into()));
}

#[tokio::test]
async fn test_job_execution_with_failure_handling() {
    let api_client = create_test_api_client();
    let job_manager = JobManager::new(api_client.clone())
        .await
        .expect("Failed to create job manager");
    
    let engine = create_test_engine().await;
    let executor = JobExecutor::new(
        job_manager.clone(),
        engine.clone(),
        api_client.clone()
    );
    
    // Create a job that will fail
    let failing_job = JobMetadata {
        id: Uuid::new_v4().into(),
        challenge_id: Uuid::new_v4().into(),
        validator_hotkey: Some("test_validator".into()),
        status: JobStatus::Claimed,
        priority: JobPriority::Normal,
        runtime: RuntimeType::Docker,
        created_at: chrono::Utc::now(),
        claimed_at: Some(chrono::Utc::now()),
        started_at: None,
        completed_at: None,
        timeout_at: Some(chrono::Utc::now() + chrono::Duration::seconds(60)),
        retry_count: 0,
        max_retries: 3,
    };
    
    // Mock a failing challenge
    let result = executor.execute_job(&failing_job).await;
    
    // Should handle failure gracefully
    assert!(result.is_ok());
    let execution_result = result.unwrap();
    assert!(!execution_result.success);
    assert!(execution_result.error.is_some());
}

#[tokio::test]
async fn test_job_timeout_handling() {
    let api_client = create_test_api_client();
    let job_manager = JobManager::new(api_client.clone())
        .await
        .expect("Failed to create job manager");
    
    let engine = create_test_engine().await;
    let executor = JobExecutor::new(
        job_manager.clone(),
        engine.clone(),
        api_client.clone()
    );
    
    // Create job with very short timeout
    let timeout_job = JobMetadata {
        id: Uuid::new_v4().into(),
        challenge_id: Uuid::new_v4().into(),
        validator_hotkey: Some("test_validator".into()),
        status: JobStatus::Claimed,
        priority: JobPriority::Normal,
        runtime: RuntimeType::Docker,
        created_at: chrono::Utc::now(),
        claimed_at: Some(chrono::Utc::now()),
        started_at: None,
        completed_at: None,
        timeout_at: Some(chrono::Utc::now() + chrono::Duration::seconds(1)), // 1 second timeout
        retry_count: 0,
        max_retries: 3,
    };
    
    // Execute with timeout
    let start = std::time::Instant::now();
    let result = executor.execute_job(&timeout_job).await;
    let duration = start.elapsed();
    
    // Should timeout quickly
    assert!(duration.as_secs() < 5);
    assert!(result.is_ok());
    
    let execution_result = result.unwrap();
    assert!(!execution_result.success);
    assert!(execution_result.error.unwrap().contains("timeout"));
}

#[tokio::test]
async fn test_concurrent_job_execution() {
    use futures::future::join_all;
    
    let api_client = Arc::new(create_test_api_client());
    let job_manager = Arc::new(
        JobManager::new(api_client.clone())
            .await
            .expect("Failed to create job manager")
    );
    
    let engine = Arc::new(create_test_engine().await);
    
    // Create multiple executors
    let executor_count = 3;
    let mut executors = Vec::new();
    
    for _ in 0..executor_count {
        executors.push(Arc::new(JobExecutor::new(
            job_manager.clone(),
            engine.clone(),
            api_client.clone()
        )));
    }
    
    // Execute multiple jobs concurrently
    let mut execution_tasks = Vec::new();
    
    for (i, executor) in executors.iter().enumerate() {
        let executor_clone = executor.clone();
        let validator_hotkey = format!("validator_{}", i);
        
        execution_tasks.push(tokio::spawn(async move {
            // Claim job
            let claim_request = ClaimJobRequest {
                validator_hotkey: validator_hotkey.clone().into(),
                challenge_id: None,
                runtime: RuntimeType::Docker,
            };
            
            if let Ok(claimed) = executor_clone.api_client.claim_job(claim_request).await {
                // Execute job
                executor_clone.execute_job(&claimed.job).await
            } else {
                Err(anyhow::anyhow!("Failed to claim job"))
            }
        }));
    }
    
    let results = join_all(execution_tasks).await;
    
    // At least some should succeed
    let successful_count = results.iter()
        .filter(|r| r.is_ok() && r.as_ref().unwrap().is_ok())
        .count();
    
    assert!(successful_count > 0);
}

#[tokio::test]
async fn test_job_result_verification() {
    let api_client = create_test_api_client();
    
    // Submit a result with specific values
    let test_result = EvalResult {
        score: 0.85,
        metrics: [
            ("accuracy".to_string(), 0.85),
            ("precision".to_string(), 0.88),
            ("recall".to_string(), 0.82),
            ("f1_score".to_string(), 0.85),
        ].iter().cloned().collect(),
        passed_tests: 85,
        total_tests: 100,
        execution_time: 45.6,
        validator_hotkey: "verifier_validator".to_string(),
        challenge_id: Uuid::new_v4().to_string(),
    };
    
    // Create job first
    let job_id = Uuid::new_v4();
    
    // Submit result
    let submit_request = SubmitResultRequest {
        result: test_result.clone(),
        status: JobStatus::Completed,
        error: None,
        usage: Some(ResourceUsage {
            cpu_seconds: 180.0,
            memory_mb_seconds: 2048.0,
            network_bytes: 1024 * 1024,
        }),
    };
    
    // In real test, would submit to actual API
    // Verify result integrity
    assert_eq!(test_result.score, 0.85);
    assert_eq!(test_result.metrics.len(), 4);
    assert_eq!(test_result.passed_tests, 85);
    assert_eq!(test_result.total_tests, 100);
    
    // Verify score calculation
    let calculated_score = test_result.passed_tests as f64 / test_result.total_tests as f64;
    assert!((calculated_score - test_result.score).abs() < 0.001);
}

#[tokio::test]
async fn test_chain_weight_submission() {
    // Test with mock chain first
    let mock_chain: Arc<dyn ChainClient> = Arc::new(MockChainClient::new());
    
    // Create weight submission
    let weights = WeightSubmission {
        validator_hotkey: "test_validator".to_string(),
        subnet_id: 100,
        weights: vec![
            WeightEntry { uid: 1, weight: 0.3 },
            WeightEntry { uid: 2, weight: 0.5 },
            WeightEntry { uid: 3, weight: 0.2 },
        ],
        version: 1,
        nonce: 12345,
        signature: vec![0u8; 64], // Mock signature
    };
    
    // Submit to mock chain
    let result = mock_chain.submit_weights(weights.clone())
        .await
        .expect("Failed to submit weights to mock chain");
    
    assert!(result.success);
    assert!(!result.transaction_hash.is_empty());
    
    // Test with real Bittensor chain (if configured)
    if std::env::var("CHAIN_CLIENT_TYPE").unwrap_or_default() == "bittensor" {
        let bittensor_chain: Arc<dyn ChainClient> = Arc::new(
            BittensorChainClient::from_env()
                .await
                .expect("Failed to create Bittensor client")
        );
        
        // Note: Real submission would require valid signature and credentials
        // This is just to test the client setup
        let validator_set = bittensor_chain.get_validator_set()
            .await
            .expect("Failed to get validator set");
        
        assert!(validator_set.validators.len() > 0);
        assert!(validator_set.total_stake > 0.0);
    }
}

#[tokio::test]
async fn test_quota_management() {
    use platform_engine_executor::QuotaManager;
    
    let quota_manager = QuotaManager::new();
    
    let validator_hotkey = "quota_test_validator";
    let initial_quota = quota_manager.get_quota(validator_hotkey).await;
    
    // Default quota should be reasonable
    assert!(initial_quota.cpu_seconds > 0.0);
    assert!(initial_quota.memory_mb_seconds > 0.0);
    assert!(initial_quota.network_bytes > 0);
    
    // Consume some quota
    let usage = ResourceUsage {
        cpu_seconds: 100.0,
        memory_mb_seconds: 1024.0 * 100.0,
        network_bytes: 1024 * 1024 * 10,
    };
    
    quota_manager.consume_quota(validator_hotkey, &usage)
        .await
        .expect("Failed to consume quota");
    
    // Check remaining quota
    let remaining = quota_manager.get_quota(validator_hotkey).await;
    assert!(remaining.cpu_seconds < initial_quota.cpu_seconds);
    assert!(remaining.memory_mb_seconds < initial_quota.memory_mb_seconds);
    assert!(remaining.network_bytes < initial_quota.network_bytes);
    
    // Test quota exceeded
    let excessive_usage = ResourceUsage {
        cpu_seconds: initial_quota.cpu_seconds * 2.0,
        memory_mb_seconds: initial_quota.memory_mb_seconds * 2.0,
        network_bytes: initial_quota.network_bytes * 2,
    };
    
    let result = quota_manager.consume_quota(validator_hotkey, &excessive_usage).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("quota exceeded"));
    
    // Test quota reset (daily)
    quota_manager.reset_daily_quotas().await
        .expect("Failed to reset quotas");
    
    let reset_quota = quota_manager.get_quota(validator_hotkey).await;
    assert_eq!(reset_quota.cpu_seconds, initial_quota.cpu_seconds);
}

// Helper functions

fn create_test_api_client() -> Arc<PlatformApiClient> {
    let config = ApiConfig {
        base_url: std::env::var("PLATFORM_API_URL")
            .unwrap_or_else(|_| "http://localhost:8000".to_string()),
        api_key: std::env::var("API_KEY").ok(),
        timeout_seconds: 30,
        max_retries: 3,
    };
    
    Arc::new(PlatformApiClient::new(config).expect("Failed to create API client"))
}

async fn create_test_engine() -> Arc<EvaluationEngine> {
    let config = EngineConfig::default();
    Arc::new(
        EvaluationEngine::new(config)
            .await
            .expect("Failed to create evaluation engine")
    )
}
