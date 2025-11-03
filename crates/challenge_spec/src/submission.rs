use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Submission bundle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionBundle {
    pub id: Uuid,
    pub challenge_id: Uuid,
    pub miner_hotkey: String,
    pub digest: String,
    pub size: u64,
    pub encrypted: bool,
    pub public_key: Option<String>,
    pub metadata: SubmissionMetadata,
    pub created_at: DateTime<Utc>,
}

/// Submission metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionMetadata {
    pub version: String,
    pub tags: Vec<String>,
    pub description: Option<String>,
    pub author: Option<String>,
    pub algorithm: Option<String>,
    pub model_type: Option<String>,
    pub parameters: BTreeMap<String, String>,
}

impl SubmissionBundle {
    pub fn new(
        challenge_id: Uuid,
        miner_hotkey: String,
        digest: String,
        size: u64,
        metadata: SubmissionMetadata,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            challenge_id,
            miner_hotkey,
            digest,
            size,
            encrypted: false,
            public_key: None,
            metadata,
            created_at: Utc::now(),
        }
    }
    
    pub fn with_encryption(mut self, public_key: String) -> Self {
        self.encrypted = true;
        self.public_key = Some(public_key);
        self
    }
    
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }
    
    pub fn get_public_key(&self) -> Option<&String> {
        self.public_key.as_ref()
    }
    
    pub fn get_miner_hotkey(&self) -> &String {
        &self.miner_hotkey
    }
    
    pub fn get_digest(&self) -> &String {
        &self.digest
    }
    
    pub fn get_size(&self) -> u64 {
        self.size
    }
    
    pub fn get_version(&self) -> &String {
        &self.metadata.version
    }
    
    pub fn get_tags(&self) -> &Vec<String> {
        &self.metadata.tags
    }
    
    pub fn get_description(&self) -> Option<&String> {
        self.metadata.description.as_ref()
    }
    
    pub fn get_author(&self) -> Option<&String> {
        self.metadata.author.as_ref()
    }
    
    pub fn get_algorithm(&self) -> Option<&String> {
        self.metadata.algorithm.as_ref()
    }
    
    pub fn get_model_type(&self) -> Option<&String> {
        self.metadata.model_type.as_ref()
    }
    
    pub fn get_parameters(&self) -> &BTreeMap<String, String> {
        &self.metadata.parameters
    }
    
    pub fn add_tag(&mut self, tag: String) {
        self.metadata.tags.push(tag);
    }
    
    pub fn set_description(&mut self, description: String) {
        self.metadata.description = Some(description);
    }
    
    pub fn set_author(&mut self, author: String) {
        self.metadata.author = Some(author);
    }
    
    pub fn set_algorithm(&mut self, algorithm: String) {
        self.metadata.algorithm = Some(algorithm);
    }
    
    pub fn set_model_type(&mut self, model_type: String) {
        self.metadata.model_type = Some(model_type);
    }
    
    pub fn set_parameter(&mut self, key: String, value: String) {
        self.metadata.parameters.insert(key, value);
    }
}

impl SubmissionMetadata {
    pub fn new(version: String) -> Self {
        Self {
            version,
            tags: Vec::new(),
            description: None,
            author: None,
            algorithm: None,
            model_type: None,
            parameters: BTreeMap::new(),
        }
    }
    
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }
    
    pub fn with_author(mut self, author: String) -> Self {
        self.author = Some(author);
        self
    }
    
    pub fn with_algorithm(mut self, algorithm: String) -> Self {
        self.algorithm = Some(algorithm);
        self
    }
    
    pub fn with_model_type(mut self, model_type: String) -> Self {
        self.model_type = Some(model_type);
        self
    }
    
    pub fn with_tag(mut self, tag: String) -> Self {
        self.tags.push(tag);
        self
    }
    
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags.extend(tags);
        self
    }
    
    pub fn with_parameter(mut self, key: String, value: String) -> Self {
        self.parameters.insert(key, value);
        self
    }
    
    pub fn with_parameters(mut self, parameters: BTreeMap<String, String>) -> Self {
        self.parameters.extend(parameters);
        self
    }
}


