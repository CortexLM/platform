use chrono::{DateTime, Utc};
use platform_validator_core::ChallengeState;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// Challenge instance managed by validator
#[derive(Debug)]
pub struct ChallengeInstance {
    pub compose_hash: String,
    pub name: String, // Challenge name to detect compose_hash changes
    pub state: ChallengeState,
    pub created_at: DateTime<Utc>,
    pub last_probe: Option<DateTime<Utc>>,
    pub probe_attempts: u32,
    pub cvm_instance_id: Option<String>,
    pub challenge_api_url: Option<String>,
    pub deprecated_at: Option<DateTime<Utc>>, // Timestamp when deprecated for timeout tracking
    pub ws_started: bool,
    pub ws_sender: Arc<Mutex<Option<mpsc::Sender<Value>>>>, // WebSocket sender for sending messages
}

impl ChallengeInstance {
    pub fn new(compose_hash: String, name: String) -> Self {
        Self {
            compose_hash,
            name,
            state: ChallengeState::Created,
            created_at: Utc::now(),
            last_probe: None,
            probe_attempts: 0,
            cvm_instance_id: None,
            challenge_api_url: None,
            deprecated_at: None,
            ws_started: false,
            ws_sender: Arc::new(Mutex::new(None)),
        }
    }
}

