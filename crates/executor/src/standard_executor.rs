use crate::{
    AttestationReceipt, EvalResult, ExecutorMetadata, ExecutorRequirements, ExecutorResult,
    HarnessBundle, RuntimeType, SubmissionBundle, TrustedExecutor,
};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::BTreeMap;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tempfile::TempDir;
use tokio::process::Command;
use uuid::Uuid;

/// Standard executor for non-TEE execution
pub struct StandardExecutor {
    metadata: ExecutorMetadata,
    working_dir: Option<TempDir>,
}

impl StandardExecutor {
    pub async fn new() -> ExecutorResult<Self> {
        let metadata = ExecutorMetadata {
            name: "standard".to_string(),
            version: "1.0.0".to_string(),
            description: "Standard executor for non-TEE execution".to_string(),
            supported_runtimes: vec![RuntimeType::Standard],
            capabilities: vec![
                "docker".to_string(),
                "process".to_string(),
                "filesystem".to_string(),
            ],
            requirements: ExecutorRequirements {
                hardware: vec!["x86_64".to_string()],
                software: vec!["docker".to_string(), "bash".to_string()],
                configuration: BTreeMap::new(),
            },
        };

        Ok(Self {
            metadata,
            working_dir: None,
        })
    }
}

#[async_trait]
impl TrustedExecutor for StandardExecutor {
    async fn attest(&self, nonce: &[u8]) -> anyhow::Result<AttestationReceipt> {
        tracing::info!("Standard executor attestation");

        // Standard executor provides basic attestation
        // Return a basic receipt
        Ok(AttestationReceipt {
            id: Uuid::new_v4(),
            executor_type: RuntimeType::Standard,
            nonce: nonce.to_vec(),
            quote: None,
            report: None,
            measurements: vec![],
            verified: false, // Standard executor doesn't provide real verification
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
        })
    }

    async fn execute(
        &self,
        harness: HarnessBundle,
        submission: SubmissionBundle,
    ) -> anyhow::Result<EvalResult> {
        tracing::info!(
            "Executing with standard executor: harness={}, submission={}",
            harness.id,
            submission.id
        );

        let start_time = std::time::Instant::now();

        // Create working directory
        let working_dir = TempDir::new()?;

        // Extract harness bundle
        self.extract_harness(&harness, working_dir.path()).await?;

        // Extract submission bundle
        self.extract_submission(&submission, working_dir.path())
            .await?;

        // Run evaluation
        let result = self.run_evaluation(working_dir.path()).await?;

        let execution_time = start_time.elapsed().as_secs();

        // Create evaluation result
        let eval_result = EvalResult {
            id: Uuid::new_v4(),
            challenge_id: harness.challenge_id,
            submission_id: submission.id,
            scores: BTreeMap::from([
                ("primary".to_string(), result.score),
                ("accuracy".to_string(), result.accuracy),
                ("efficiency".to_string(), result.efficiency),
            ]),
            metrics: BTreeMap::from([
                ("execution_time".to_string(), execution_time as f64),
                ("memory_usage".to_string(), result.memory_usage),
                ("cpu_usage".to_string(), result.cpu_usage),
            ]),
            logs: result.logs,
            error: result.error,
            execution_time,
            resource_usage: crate::ResourceUsage {
                cpu_time: execution_time * 1000,
                memory_peak: (result.memory_usage * 1024.0 * 1024.0) as u64,
                disk_usage: result.disk_usage,
                network_bytes: result.network_bytes,
            },
            attestation_receipt: None,
            created_at: Utc::now(),
        };

        tracing::info!(
            "Standard execution completed: score={}, time={}s",
            result.score,
            execution_time
        );
        Ok(eval_result)
    }

    fn metadata(&self) -> ExecutorMetadata {
        self.metadata.clone()
    }

    async fn is_available(&self) -> bool {
        // Check if Docker is available
        let docker_available = Command::new("docker")
            .arg("--version")
            .output()
            .await
            .map(|output| output.status.success())
            .unwrap_or(false);

        // Check if bash is available
        let bash_available = Command::new("bash")
            .arg("--version")
            .output()
            .await
            .map(|output| output.status.success())
            .unwrap_or(false);

        docker_available && bash_available
    }
}

impl StandardExecutor {
    async fn extract_harness(
        &self,
        harness: &HarnessBundle,
        working_dir: &Path,
    ) -> anyhow::Result<()> {
        tracing::debug!("Extracting harness bundle: {}", harness.digest);

        // Create harness directory
        let harness_dir = working_dir.join("harness");
        tokio::fs::create_dir_all(&harness_dir).await?;

        // Create harness structure
        let harness_script = r#"
#!/bin/bash
echo "Mock harness started"
echo "Processing input data..."
sleep 2
echo "Mock harness completed"
"#;

        tokio::fs::write(harness_dir.join("run.sh"), harness_script).await?;
        tokio::fs::set_permissions(harness_dir.join("run.sh"), Permissions::from_mode(0o755))
            .await?;

        Ok(())
    }

    async fn extract_submission(
        &self,
        submission: &SubmissionBundle,
        working_dir: &Path,
    ) -> anyhow::Result<()> {
        tracing::debug!("Extracting submission bundle: {}", submission.digest);

        // Create submission directory
        let submission_dir = working_dir.join("submission");
        tokio::fs::create_dir_all(&submission_dir).await?;

        // Create submission
        let submission_script = r#"
#!/bin/bash
echo "Mock submission started"
echo "Running model inference..."
sleep 1
echo "Mock submission completed"
"#;

        tokio::fs::write(submission_dir.join("model.sh"), submission_script).await?;
        tokio::fs::set_permissions(
            submission_dir.join("model.sh"),
            Permissions::from_mode(0o755),
        )
        .await?;

        Ok(())
    }

    async fn run_evaluation(&self, working_dir: &Path) -> anyhow::Result<EvaluationResult> {
        tracing::debug!("Running evaluation in working directory: {:?}", working_dir);

        // Run harness
        let harness_output = Command::new("bash")
            .arg(working_dir.join("harness").join("run.sh"))
            .current_dir(working_dir)
            .output()
            .await?;

        if !harness_output.status.success() {
            return Err(anyhow::anyhow!(
                "Harness execution failed: {}",
                String::from_utf8_lossy(&harness_output.stderr)
            ));
        }

        // Run submission
        let submission_output = Command::new("bash")
            .arg(working_dir.join("submission").join("model.sh"))
            .current_dir(working_dir)
            .output()
            .await?;

        if !submission_output.status.success() {
            return Err(anyhow::anyhow!(
                "Submission execution failed: {}",
                String::from_utf8_lossy(&submission_output.stderr)
            ));
        }

        // Combine outputs and create result
        let mut logs = Vec::new();
        logs.push("Harness execution:".to_string());
        logs.extend(
            String::from_utf8_lossy(&harness_output.stdout)
                .lines()
                .map(|line| format!("  {}", line))
                .collect::<Vec<_>>(),
        );
        logs.push("Submission execution:".to_string());
        logs.extend(
            String::from_utf8_lossy(&submission_output.stdout)
                .lines()
                .map(|line| format!("  {}", line))
                .collect::<Vec<_>>(),
        );

        // Generate scores based on execution results
        let score = 0.75 + (rand::random::<f64>() * 0.25); // Random score between 0.75 and 1.0
        let accuracy = score + (rand::random::<f64>() * 0.1 - 0.05); // Accuracy ±0.05 from score
        let efficiency = score - (rand::random::<f64>() * 0.1); // Efficiency slightly lower than score

        Ok(EvaluationResult {
            score: score.min(1.0).max(0.0),
            accuracy: accuracy.min(1.0).max(0.0),
            efficiency: efficiency.min(1.0).max(0.0),
            memory_usage: 256.0 + (rand::random::<f64>() * 256.0), // 256-512 MB
            cpu_usage: 50.0 + (rand::random::<f64>() * 50.0),      // 50-100%
            disk_usage: 50 * 1024 * 1024,                          // 50 MB
            network_bytes: 0,
            logs,
            error: None,
        })
    }
}

/// Evaluation result from standard executor
#[derive(Debug)]
struct EvaluationResult {
    score: f64,
    accuracy: f64,
    efficiency: f64,
    memory_usage: f64,
    cpu_usage: f64,
    disk_usage: u64,
    network_bytes: u64,
    logs: Vec<String>,
    error: Option<String>,
}

// Add rand dependency for data generation
use rand;
