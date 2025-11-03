use crate::types::{
    ChainClient, ChainMetadata, SubnetInfo, ValidatorSet, WeightSubmission, WeightSubmissionResult,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

/// Mock chain client for testing
pub struct MockChainClient {
    metadata: ChainMetadata,
    weights: BTreeMap<String, BTreeMap<String, f64>>,
    validators: Vec<ValidatorInfo>,
    subnet_info: SubnetInfo,
    current_block: u64,
}

/// Validator information
#[derive(Debug, Clone)]
pub struct ValidatorInfo {
    pub hotkey: String,
    pub uid: u32,
    pub stake: f64,
    pub performance_score: f64,
    pub last_seen: DateTime<Utc>,
    pub is_active: bool,
}

impl MockChainClient {
    pub fn new() -> Self {
        let metadata = ChainMetadata {
            name: "Platform Chain".to_string(),
            version: "1.0.0".to_string(),
            chain_id: "platform-chain".to_string(),
            rpc_url: "http://localhost:9944".to_string(),
            ws_url: Some("ws://localhost:9944".to_string()),
            supported_features: vec![
                "weight_submission".to_string(),
                "validator_set".to_string(),
                "subnet_info".to_string(),
            ],
        };

        let subnet_info = SubnetInfo {
            subnet_id: 1,
            owner_hotkey: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
            rake: 0.1,
            total_stake: 10000.0,
            validator_count: 5,
            emission_rate: 100.0,
            last_updated: Utc::now(),
        };

        let validators = vec![
            ValidatorInfo {
                hotkey: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
                uid: 1,
                stake: 2000.0,
                performance_score: 0.85,
                last_seen: Utc::now(),
                is_active: true,
            },
            ValidatorInfo {
                hotkey: "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty".to_string(),
                uid: 2,
                stake: 3000.0,
                performance_score: 0.92,
                last_seen: Utc::now(),
                is_active: true,
            },
            ValidatorInfo {
                hotkey: "5DAAnrj7VHTznn2AWBemMuyBwZWs6FNFjdyVXUeYum3PTXFy".to_string(),
                uid: 3,
                stake: 2500.0,
                performance_score: 0.78,
                last_seen: Utc::now(),
                is_active: true,
            },
            ValidatorInfo {
                hotkey: "5HGjWAeFDfFCWPsjFQdVV2Msvz2XtMktvgocEYSj4ZR6Efg".to_string(),
                uid: 4,
                stake: 1500.0,
                performance_score: 0.88,
                last_seen: Utc::now(),
                is_active: true,
            },
            ValidatorInfo {
                hotkey: "5CiPPseXPECbkjWCa6MnjNokrgYjMqmKndv2rSnekmSK2Dj".to_string(),
                uid: 5,
                stake: 1000.0,
                performance_score: 0.95,
                last_seen: Utc::now(),
                is_active: true,
            },
        ];

        Self {
            metadata,
            weights: BTreeMap::new(),
            validators,
            subnet_info,
            current_block: 12345,
        }
    }

    /// Add weights for a validator
    pub fn add_weights(&mut self, validator_hotkey: &str, weights: BTreeMap<String, f64>) {
        self.weights.insert(validator_hotkey.to_string(), weights);
    }

    /// Update validator performance
    pub fn update_validator_performance(&mut self, hotkey: &str, performance_score: f64) {
        if let Some(validator) = self.validators.iter_mut().find(|v| v.hotkey == hotkey) {
            validator.performance_score = performance_score;
            validator.last_seen = Utc::now();
        }
    }

    /// Increment block number
    pub fn increment_block(&mut self) {
        self.current_block += 1;
    }
}

#[async_trait]
impl ChainClient for MockChainClient {
    async fn submit_weights(
        &self,
        weights: WeightSubmission,
    ) -> anyhow::Result<WeightSubmissionResult> {
        tracing::info!(
            "Mock: Submitting weights for validator: {}",
            weights.validator_hotkey
        );

        // Simulate some processing time
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Generate a transaction hash
        let transaction_hash = format!("0x{:064x}", rand::random::<u64>());

        Ok(WeightSubmissionResult {
            transaction_hash,
            block_number: self.current_block + 1,
            success: true,
            error: None,
            timestamp: Utc::now(),
        })
    }

    async fn get_weights(
        &self,
        validator_hotkey: &str,
    ) -> anyhow::Result<Option<BTreeMap<String, f64>>> {
        tracing::debug!("Mock: Getting weights for validator: {}", validator_hotkey);

        Ok(self.weights.get(validator_hotkey).cloned())
    }

    async fn get_validator_set(&self) -> anyhow::Result<ValidatorSet> {
        tracing::debug!("Mock: Getting validator set");

        let total_stake: f64 = self.validators.iter().map(|v| v.stake).sum();
        let active_validators = self.validators.iter().filter(|v| v.is_active).count() as u32;

        Ok(ValidatorSet {
            validators: self
                .validators
                .iter()
                .map(|v| crate::types::ValidatorInfo {
                    hotkey: v.hotkey.clone(),
                    uid: v.uid,
                    stake: v.stake,
                    performance_score: v.performance_score,
                    last_seen: v.last_seen,
                    is_active: v.is_active,
                })
                .collect(),
            total_stake,
            active_validators,
            last_updated: Utc::now(),
        })
    }

    async fn get_subnet_info(&self) -> anyhow::Result<SubnetInfo> {
        tracing::debug!("Mock: Getting subnet information");

        Ok(self.subnet_info.clone())
    }

    async fn get_current_block(&self) -> anyhow::Result<u64> {
        tracing::debug!("Mock: Getting current block number");

        Ok(self.current_block)
    }

    fn metadata(&self) -> ChainMetadata {
        self.metadata.clone()
    }
}

/// Chain client manager for managing multiple clients
pub struct ChainClientManager {
    clients: BTreeMap<String, Box<dyn ChainClient>>,
    default_client: Option<String>,
}

impl ChainClientManager {
    pub fn new() -> Self {
        Self {
            clients: BTreeMap::new(),
            default_client: None,
        }
    }

    /// Register a chain client
    pub fn register_client(&mut self, name: String, client: Box<dyn ChainClient>) {
        self.clients.insert(name.clone(), client);

        // Set as default if it's the first client
        if self.default_client.is_none() {
            self.default_client = Some(name);
        }
    }

    /// Get client by name
    pub fn get_client(&self, name: &str) -> Option<&dyn ChainClient> {
        self.clients.get(name).map(|c| c.as_ref())
    }

    /// Get default client
    pub fn get_default_client(&self) -> Option<&dyn ChainClient> {
        self.default_client
            .as_ref()
            .and_then(|name| self.get_client(name))
    }

    /// Set default client
    pub fn set_default_client(&mut self, name: String) {
        if self.clients.contains_key(&name) {
            self.default_client = Some(name);
        }
    }

    /// List available clients
    pub fn list_clients(&self) -> Vec<String> {
        self.clients.keys().cloned().collect()
    }

    /// Check if client exists
    pub fn has_client(&self, name: &str) -> bool {
        self.clients.contains_key(name)
    }
}

/// Chain client health checker
pub struct ChainClientHealthChecker {
    clients: BTreeMap<String, ChainClientHealth>,
}

/// Chain client health status
#[derive(Debug, Clone)]
pub struct ChainClientHealth {
    pub available: bool,
    pub last_check: DateTime<Utc>,
    pub error: Option<String>,
    pub metrics: ChainClientMetrics,
}

/// Chain client metrics
#[derive(Debug, Clone, Default)]
pub struct ChainClientMetrics {
    pub total_submissions: u64,
    pub successful_submissions: u64,
    pub failed_submissions: u64,
    pub avg_submission_time: f64,
    pub last_submission: Option<DateTime<Utc>>,
}

impl ChainClientHealthChecker {
    pub fn new() -> Self {
        Self {
            clients: BTreeMap::new(),
        }
    }

    /// Check health of all clients
    pub async fn check_all_health(&mut self, manager: &ChainClientManager) {
        for client_name in manager.list_clients() {
            self.check_client_health(&client_name, manager).await;
        }
    }

    /// Check health of specific client
    pub async fn check_client_health(&mut self, client_name: &str, manager: &ChainClientManager) {
        let health = if let Some(client) = manager.get_client(client_name) {
            // Try to get current block as a health check
            match client.get_current_block().await {
                Ok(_) => ChainClientHealth {
                    available: true,
                    last_check: Utc::now(),
                    error: None,
                    metrics: ChainClientMetrics::default(),
                },
                Err(e) => ChainClientHealth {
                    available: false,
                    last_check: Utc::now(),
                    error: Some(e.to_string()),
                    metrics: ChainClientMetrics::default(),
                },
            }
        } else {
            ChainClientHealth {
                available: false,
                last_check: Utc::now(),
                error: Some("Client not registered".to_string()),
                metrics: ChainClientMetrics::default(),
            }
        };

        self.clients.insert(client_name.to_string(), health);
    }

    /// Get health status for client
    pub fn get_health(&self, client_name: &str) -> Option<&ChainClientHealth> {
        self.clients.get(client_name)
    }

    /// Get all health statuses
    pub fn get_all_health(&self) -> &BTreeMap<String, ChainClientHealth> {
        &self.clients
    }

    /// Update submission metrics
    pub fn update_submission_metrics(
        &mut self,
        client_name: &str,
        success: bool,
        submission_time: u64,
    ) {
        if let Some(health) = self.clients.get_mut(client_name) {
            health.metrics.total_submissions += 1;
            health.metrics.last_submission = Some(Utc::now());

            if success {
                health.metrics.successful_submissions += 1;
            } else {
                health.metrics.failed_submissions += 1;
            }

            health.metrics.avg_submission_time = (health.metrics.avg_submission_time
                * (health.metrics.total_submissions - 1) as f64
                + submission_time as f64)
                / health.metrics.total_submissions as f64;
        }
    }
}

// Add rand dependency for data generation
use rand;
