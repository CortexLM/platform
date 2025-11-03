use crate::config::ValidatorConfig;
use anyhow::Result;
use platform_engine_api_client::{JobInfo, PlatformClient};
use platform_engine_challenge_spec::ChallengeSpec;
use std::collections::HashMap;
use tracing::info;

pub struct JobManager {
    client: PlatformClient,
    config: ValidatorConfig,
    active_jobs: HashMap<String, JobInfo>,
    challenge_specs: HashMap<String, ChallengeSpec>,
}

impl JobManager {
    pub fn new(client: PlatformClient, config: ValidatorConfig) -> Self {
        Self {
            client,
            config,
            active_jobs: HashMap::new(),
            challenge_specs: HashMap::new(),
        }
    }

    pub async fn fetch_pending_jobs(&mut self) -> Result<Vec<JobInfo>> {
        let response = self.client.get_pending_jobs().await?;
        Ok(response.jobs)
    }

    pub async fn claim_job(&mut self, job_id: &str) -> Result<JobInfo> {
        let job = self.client.claim_job(job_id).await?;
        self.active_jobs.insert(job.id.clone(), job.clone());
        Ok(job)
    }

    pub async fn has_capacity(&self, _job: &JobInfo) -> Result<bool> {
        // Check if we have enough resources for this job
        // For now, simple check based on active jobs count
        Ok(self.active_jobs.len() < 10)
    }

    pub async fn check_challenge_updates(&mut self) -> Result<()> {
        let challenges = self.client.get_challenges().await?;

        for challenge in challenges.challenges {
            // Check if GitHub commit has changed
            if let Some(spec) = self.challenge_specs.get(&challenge.id) {
                if spec.github_commit != challenge.github_commit {
                    info!("Challenge {} commit changed, restarting", challenge.id);
                    // Restart challenge execution
                    self.restart_challenge(&challenge.id).await?;
                }
            } else {
                // New challenge, load spec
                self.load_challenge_spec(&challenge.id).await?;
            }
        }

        Ok(())
    }

    async fn load_challenge_spec(&mut self, challenge_id: &str) -> Result<()> {
        // Load platform.toml from GitHub repository
        // For now, use default spec
        let spec = ChallengeSpec::default();
        self.challenge_specs.insert(challenge_id.to_string(), spec);
        Ok(())
    }

    async fn restart_challenge(&mut self, challenge_id: &str) -> Result<()> {
        info!("Restarting challenge: {}", challenge_id);
        // Implement restart logic
        Ok(())
    }
}
