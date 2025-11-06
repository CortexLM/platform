// Mock Platform API client for testing
// Used for platform validator tests

use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;

/// Mock Platform API client for testing
pub struct MockPlatformApiClient {
    pub mock_jobs: Vec<MockJob>,
    pub mock_challenges: Vec<MockChallenge>,
}

#[derive(Clone)]
pub struct MockJob {
    pub id: String,
    pub challenge_id: String,
    pub status: String,
    pub payload: Value,
}

#[derive(Clone)]
pub struct MockChallenge {
    pub id: String,
    pub compose_hash: String,
    pub github_commit: String,
}

impl MockPlatformApiClient {
    pub fn new() -> Self {
        Self {
            mock_jobs: Vec::new(),
            mock_challenges: Vec::new(),
        }
    }

    pub fn with_job(mut self, job: MockJob) -> Self {
        self.mock_jobs.push(job);
        self
    }

    pub fn with_challenge(mut self, challenge: MockChallenge) -> Self {
        self.mock_challenges.push(challenge);
        self
    }

    /// Mock getting pending jobs
    pub async fn get_pending_jobs(&self) -> Result<MockJobListResponse> {
        let pending_jobs: Vec<MockJob> = self.mock_jobs
            .iter()
            .filter(|j| j.status == "pending")
            .cloned()
            .collect();
        
        Ok(MockJobListResponse {
            jobs: pending_jobs,
        })
    }

    /// Mock claiming a job
    pub async fn claim_job(&self, job_id: &str) -> Result<MockJob> {
        self.mock_jobs
            .iter()
            .find(|j| j.id == job_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Job not found: {}", job_id))
    }

    /// Mock getting challenges
    pub async fn get_challenges(&self) -> Result<MockChallengeListResponse> {
        Ok(MockChallengeListResponse {
            challenges: self.mock_challenges.clone(),
        })
    }
}

#[derive(Clone)]
pub struct MockJobListResponse {
    pub jobs: Vec<MockJob>,
}

#[derive(Clone)]
pub struct MockChallengeListResponse {
    pub challenges: Vec<MockChallenge>,
}

impl Default for MockPlatformApiClient {
    fn default() -> Self {
        Self::new()
    }
}

