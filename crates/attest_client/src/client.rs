use crate::{AttestationClient, AttestationStatus, ClientMetadata, AttestationType, Status};
use std::collections::BTreeMap;
use uuid::Uuid;
use chrono::Utc;

/// Base attestation client implementation
pub struct BaseAttestationClient {
    metadata: ClientMetadata,
    config: ClientConfig,
    sessions: BTreeMap<Uuid, AttestationStatus>,
}

/// Client configuration
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub timeout: u64,
    pub retry_attempts: u32,
    pub retry_delay: u64,
    pub verification_required: bool,
    pub policy: Option<String>,
}

impl BaseAttestationClient {
    pub fn new(metadata: ClientMetadata, config: ClientConfig) -> Self {
        Self {
            metadata,
            config,
            sessions: BTreeMap::new(),
        }
    }

    /// Create a new attestation session
    pub fn create_session(&mut self, _nonce: &[u8]) -> Uuid {
        let session_id = Uuid::new_v4();
        let status = AttestationStatus {
            session_id,
            status: Status::Pending,
            error: None,
            verified: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        self.sessions.insert(session_id, status);
        session_id
    }

    /// Update session status
    pub fn update_session(&mut self, session_id: Uuid, status: Status, error: Option<String>) {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.status = status;
            session.error = error;
            session.updated_at = Utc::now();
        }
    }

    /// Mark session as verified
    pub fn mark_verified(&mut self, session_id: Uuid) {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            session.verified = true;
            session.status = Status::Completed;
            session.updated_at = Utc::now();
        }
    }

    /// Get session status
    pub fn get_session_status(&self, session_id: Uuid) -> Option<&AttestationStatus> {
        self.sessions.get(&session_id)
    }

    /// Clean up expired sessions
    pub fn cleanup_expired_sessions(&mut self) {
        let now = Utc::now();
        self.sessions.retain(|_, session| {
            now.signed_duration_since(session.created_at).num_hours() < 24
        });
    }

    /// Get client configuration
    pub fn get_config(&self) -> &ClientConfig {
        &self.config
    }
}

/// Attestation client manager
pub struct AttestationClientManager {
    clients: BTreeMap<AttestationType, Box<dyn AttestationClient>>,
    default_client: Option<AttestationType>,
}

impl AttestationClientManager {
    pub fn new() -> Self {
        Self {
            clients: BTreeMap::new(),
            default_client: None,
        }
    }

    /// Register an attestation client
    pub fn register_client(&mut self, client_type: AttestationType, client: Box<dyn AttestationClient>) {
        self.clients.insert(client_type.clone(), client);
        
        // Set as default if it's the first client
        if self.default_client.is_none() {
            self.default_client = Some(client_type);
        }
    }

    /// Get client for specific type
    pub fn get_client(&self, client_type: &AttestationType) -> Option<&dyn AttestationClient> {
        self.clients.get(client_type).map(|c| c.as_ref())
    }

    /// Get default client
    pub fn get_default_client(&self) -> Option<&dyn AttestationClient> {
        self.default_client.as_ref().and_then(|t| self.get_client(t))
    }

    /// Set default client
    pub fn set_default_client(&mut self, client_type: AttestationType) {
        if self.clients.contains_key(&client_type) {
            self.default_client = Some(client_type);
        }
    }

    /// List available client types
    pub fn list_client_types(&self) -> Vec<AttestationType> {
        self.clients.keys().cloned().collect()
    }

    /// Check if client type is available
    pub fn is_client_available(&self, client_type: &AttestationType) -> bool {
        self.clients.contains_key(client_type)
    }
}

/// Attestation client factory
pub struct AttestationClientFactory;

impl AttestationClientFactory {
    /// Create attestation client based on type
    pub async fn create_client(client_type: AttestationType) -> anyhow::Result<Box<dyn AttestationClient>> {
        match client_type {
            AttestationType::Dstack => {
                let client = crate::dstack_client::DstackAttestationClient::new().await?;
                Ok(Box::new(client))
            }
        }
    }

    /// Create all available clients
    pub async fn create_all_clients() -> BTreeMap<AttestationType, Box<dyn AttestationClient>> {
        let mut clients = BTreeMap::new();
        
        for client_type in [AttestationType::Dstack] {
            if let Ok(client) = Self::create_client(client_type.clone()).await {
                clients.insert(client_type, client);
            }
        }
        
        clients
    }

    /// Get available client types
    pub async fn get_available_client_types() -> Vec<AttestationType> {
        let mut available = Vec::new();
        
        // Check dstack client
        if crate::dstack_client::DstackAttestationClient::is_available().await {
            available.push(AttestationType::Dstack);
        }
        
        available
    }
}
