use crate::challenge_manager::ChallengeManager;
use crate::config::ValidatorConfig;
use anyhow::{Context, Result};
use platform_engine_api_client::JobInfo;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

pub struct DstackExecutor {
    config: ValidatorConfig,
    challenge_manager: Arc<ChallengeManager>,
}

impl DstackExecutor {
    pub fn new(config: ValidatorConfig, challenge_manager: Arc<ChallengeManager>) -> Result<Self> {
        Ok(Self {
            config,
            challenge_manager,
        })
    }

    /// Forward job to challenge container for execution via WebSocket
    /// The challenge will handle execution and store results via ORM
    pub async fn execute_job(&mut self, job: JobInfo) -> Result<()> {
        info!(
            "Forwarding job {} to challenge {} via WebSocket",
            job.id, job.challenge_id
        );

        // Forward job to challenge container via WebSocket
        // The challenge will execute the job and store results via ORM
        // Extract job_name from payload or use default
        let job_payload = serde_json::json!({
            "session_id": job.submission_id,
            "agent_hash": job.miner_hotkey,
        });

        // Default job name for term-challenge is "evaluate_agent"
        // This can be extracted from job metadata if available
        let job_name = "evaluate_agent";

        // Send job_execute message via WebSocket
        match self
            .challenge_manager
            .send_job_execute(&job.challenge_id, &job.id, job_name, job_payload)
            .await
        {
            Ok(_) => {
                info!(
                    "Successfully sent job_execute for job {} to challenge {}",
                    job.id, job.challenge_id
                );
                Ok(())
            }
            Err(e) => {
                error!("Failed to send job_execute for job {}: {}", job.id, e);
                Err(e)
            }
        }
    }
}
