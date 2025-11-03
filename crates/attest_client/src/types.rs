use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Attestation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationPolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub attestation_type: crate::AttestationType,
    pub allowed_measurements: Vec<Vec<u8>>,
    pub allowed_digests: Vec<String>,
    pub tcb_requirements: TcbRequirements,
    pub nonce_freshness: u64,
    pub key_derivation: KeyDerivationPolicy,
}

/// TCB (Trusted Computing Base) requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcbRequirements {
    pub min_svn: Option<u32>,
    pub max_svn: Option<u32>,
    pub allowed_svns: Vec<u32>,
    pub min_tcb_version: Option<String>,
    pub max_tcb_version: Option<String>,
}

/// Key derivation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationPolicy {
    pub algorithm: String,
    pub key_size: u32,
    pub derivation_context: String,
    pub usage_count: Option<u32>,
    pub time_bound: Option<u64>,
}

/// Attestation verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationVerificationResult {
    pub is_valid: bool,
    pub measurements_match: bool,
    pub tcb_valid: bool,
    pub nonce_fresh: bool,
    pub error: Option<String>,
    pub details: AttestationDetails,
}

/// Attestation verification details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDetails {
    pub quote_valid: bool,
    pub signature_valid: bool,
    pub certificate_chain_valid: bool,
    pub measurements: Vec<Vec<u8>>,
    pub tcb_info: Option<TcbInfo>,
    pub timestamp: DateTime<Utc>,
}

/// TCB information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcbInfo {
    pub version: String,
    pub svn: u32,
    pub components: Vec<TcbComponent>,
    pub status: String,
}

/// TCB component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcbComponent {
    pub component_id: u8,
    pub svn: u32,
    pub category: String,
}

/// Attestation request
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationRequest {
    pub attestation_type: crate::AttestationType,
    pub nonce: Vec<u8>,
    pub measurements: Vec<Vec<u8>>,
    pub capabilities: Vec<String>,
    pub policy: Option<String>,
}

/// Attestation response
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationResponse {
    pub session_id: Uuid,
    pub status: crate::Status,
    pub expires_at: DateTime<Utc>,
    pub verified_measurements: Vec<Vec<u8>>,
    pub policy: String,
    pub error: Option<String>,
}

/// Key release request
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyReleaseRequest {
    pub session_id: Uuid,
    pub policy: String,
    pub harness_digest: String,
    pub measurements: Vec<Vec<u8>>,
    pub nonce: Vec<u8>,
}

/// Key release response
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyReleaseResponse {
    pub key_id: String,
    pub sealed_key: Vec<u8>,
    pub expires_at: DateTime<Utc>,
    pub policy: String,
    pub error: Option<String>,
}

/// Attestation session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationSession {
    pub id: Uuid,
    pub session_id: Uuid,
    pub attestation_type: crate::AttestationType,
    pub status: crate::Status,
    pub validator_hotkey: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub verified_measurements: Vec<Vec<u8>>,
    pub policy: String,
    pub key_releases: Vec<KeyRelease>,
}

/// Key release record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRelease {
    pub id: Uuid,
    pub session_id: Uuid,
    pub key_id: String,
    pub harness_digest: String,
    pub released_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub policy: String,
    pub receipt: String,
}

/// Attestation audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationAuditLog {
    pub id: Uuid,
    pub session_id: Option<Uuid>,
    pub event_type: AttestationEventType,
    pub validator_hotkey: String,
    pub timestamp: DateTime<Utc>,
    pub details: BTreeMap<String, String>,
    pub receipt: String,
}

/// Attestation event type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttestationEventType {
    AttestationRequested,
    AttestationVerified,
    AttestationFailed,
    KeyReleased,
    KeyExpired,
    PolicyViolation,
    SessionExpired,
}

/// Attestation metrics
#[derive(Debug, Default)]
pub struct AttestationMetrics {
    pub total_attestations: u64,
    pub successful_attestations: u64,
    pub failed_attestations: u64,
    pub avg_attestation_time: f64,
    pub attestation_distribution: BTreeMap<String, u64>,
}

impl AttestationMetrics {
    pub fn record_attestation(&mut self, success: bool, attestation_time: u64, client_type: &str) {
        self.total_attestations += 1;
        
        if success {
            self.successful_attestations += 1;
        } else {
            self.failed_attestations += 1;
        }
        
        self.avg_attestation_time = 
            (self.avg_attestation_time * (self.total_attestations - 1) as f64 + attestation_time as f64) / 
            self.total_attestations as f64;
        
        *self.attestation_distribution.entry(client_type.to_string()).or_insert(0) += 1;
    }
    
    pub fn get_success_rate(&self) -> f64 {
        if self.total_attestations == 0 {
            0.0
        } else {
            self.successful_attestations as f64 / self.total_attestations as f64
        }
    }
    
    pub fn get_failure_rate(&self) -> f64 {
        if self.total_attestations == 0 {
            0.0
        } else {
            self.failed_attestations as f64 / self.total_attestations as f64
        }
    }
}


