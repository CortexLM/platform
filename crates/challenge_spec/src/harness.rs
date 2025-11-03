use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Harness bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessBundle {
    pub id: Uuid,
    pub challenge_id: Uuid,
    pub digest: String,
    pub size: u64,
    pub image_ref: Option<String>,
    pub manifest: Option<String>,
    pub config: HarnessConfig,
    pub created_at: DateTime<Utc>,
}

/// Harness configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessConfig {
    pub runtime: super::RuntimeType,
    pub resources: super::ResourceSpec,
    pub timeout: u64,
    pub environment: BTreeMap<String, String>,
    pub network_enabled: bool,
    pub attestation_required: bool,
}

impl HarnessBundle {
    pub fn new(
        challenge_id: Uuid,
        digest: String,
        size: u64,
        config: HarnessConfig,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            challenge_id,
            digest,
            size,
            image_ref: None,
            manifest: None,
            config,
            created_at: Utc::now(),
        }
    }
    
    pub fn with_image_ref(mut self, image_ref: String) -> Self {
        self.image_ref = Some(image_ref);
        self
    }
    
    pub fn with_manifest(mut self, manifest: String) -> Self {
        self.manifest = Some(manifest);
        self
    }
    
    pub fn get_image_ref(&self) -> Option<&String> {
        self.image_ref.as_ref()
    }
    
    pub fn get_manifest(&self) -> Option<&String> {
        self.manifest.as_ref()
    }
    
    pub fn is_docker_image(&self) -> bool {
        self.image_ref.is_some()
    }
    
    pub fn is_manifest_bundle(&self) -> bool {
        self.manifest.is_some()
    }
    
    pub fn requires_attestation(&self) -> bool {
        self.config.attestation_required
    }
    
    pub fn supports_network(&self) -> bool {
        self.config.network_enabled
    }
    
    pub fn get_timeout(&self) -> u64 {
        self.config.timeout
    }
    
    pub fn get_resource_limits(&self) -> &super::ResourceSpec {
        &self.config.resources
    }
}


