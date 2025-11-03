use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Challenge definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub version: String,
    pub owner: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub spec: ChallengeSpec,
    pub status: ChallengeStatus,
    pub visibility: ChallengeVisibility,
}

/// Challenge status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChallengeStatus {
    Draft,
    Active,
    Paused,
    Archived,
}

/// Challenge visibility
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChallengeVisibility {
    Public,
    Private,
}

/// Challenge specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeSpec {
    pub runtime: super::RuntimeType,
    pub resources: super::ResourceSpec,
    pub timeout: u64,
    pub environment: BTreeMap<String, String>,
    pub network_enabled: bool,
    pub attestation_required: bool,
    pub datasets: Vec<super::DatasetSpec>,
    pub evaluation: super::EvaluationSpec,
}

impl Challenge {
    pub fn new(
        name: String,
        description: String,
        version: String,
        owner: String,
        spec: ChallengeSpec,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            description,
            version,
            owner,
            created_at: now,
            updated_at: now,
            spec,
            status: ChallengeStatus::Draft,
            visibility: ChallengeVisibility::Public,
        }
    }
    
    pub fn activate(&mut self) {
        self.status = ChallengeStatus::Active;
        self.updated_at = Utc::now();
    }
    
    pub fn pause(&mut self) {
        self.status = ChallengeStatus::Paused;
        self.updated_at = Utc::now();
    }
    
    pub fn archive(&mut self) {
        self.status = ChallengeStatus::Archived;
        self.updated_at = Utc::now();
    }
    
    pub fn make_private(&mut self) {
        self.visibility = ChallengeVisibility::Private;
        self.updated_at = Utc::now();
    }
    
    pub fn make_public(&mut self) {
        self.visibility = ChallengeVisibility::Public;
        self.updated_at = Utc::now();
    }
    
    pub fn is_active(&self) -> bool {
        self.status == ChallengeStatus::Active
    }
    
    pub fn is_public(&self) -> bool {
        self.visibility == ChallengeVisibility::Public
    }
    
    pub fn requires_attestation(&self) -> bool {
        self.spec.attestation_required
    }
    
    pub fn supports_network(&self) -> bool {
        self.spec.network_enabled
    }
}


