use platform_validator_challenge_manager::ChallengeManager;
use crate::config::ValidatorConfig;
use anyhow::Result;
use platform_engine_api_client::JobInfo;
use serde_json::Value;
use std::sync::Arc;
use tracing::{error, info};

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
        // Ensure payload includes required fields
        let job_payload_value = job.payload.clone().unwrap_or_else(|| serde_json::json!({}));

        let mut payload_map: serde_json::Map<String, Value> = match job_payload_value {
            Value::Object(map) => map,
            _ => serde_json::Map::new(),
        };

        if payload_map
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false)
            == false
        {
            payload_map.insert(
                "session_id".to_string(),
                Value::String(job.submission_id.clone()),
            );
        }

        if payload_map
            .get("agent_hash")
            .and_then(|v| v.as_str())
            .map(|s| !s.is_empty())
            .unwrap_or(false)
            == false
        {
            // Use miner_hotkey (which should contain agent_hash from the payload)
            // If it's "unknown", log an error as this will cause evaluation to fail
            if job.miner_hotkey == "unknown" {
                error!(
                    "Job {} has no agent_hash in payload - evaluation will fail. \
                    This likely means the job was created without the required agent_hash field.",
                    job.id
                );
            }
            payload_map.insert(
                "agent_hash".to_string(),
                Value::String(job.miner_hotkey.clone()),
            );
        }

        let job_payload = Value::Object(payload_map);

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
