use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Resource requirements for a VM
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ResourceRequest {
    pub cpu_cores: u32,
    pub memory_mb: u64,
    pub disk_mb: u64,
}

/// Resource capacity totals
#[derive(Debug, Clone, Copy)]
pub struct ResourceCapacity {
    pub cpu_cores: u32,
    pub memory_mb: u64,
    pub disk_mb: u64,
}

/// Quota reservation result
#[derive(Debug, Clone, PartialEq)]
pub enum QuotaResult {
    Granted,
    Insufficient,
}

/// Per-challenge state tracking
#[derive(Debug, Clone)]
struct ChallengeQuotaState {
    compose_hash: String,
    emission_share: f64,
    demand_ema: f64, // Exponential moving average of demand
    reserved: ResourceRequest,
    in_use: ResourceRequest,
    last_reservation_time: Instant,
}

impl ChallengeQuotaState {
    fn new(compose_hash: String, emission_share: f64) -> Self {
        Self {
            compose_hash,
            emission_share,
            demand_ema: 0.0,
            reserved: ResourceRequest {
                cpu_cores: 0,
                memory_mb: 0,
                disk_mb: 0,
            },
            in_use: ResourceRequest {
                cpu_cores: 0,
                memory_mb: 0,
                disk_mb: 0,
            },
            last_reservation_time: Instant::now(),
        }
    }
}

/// Configuration parameters for quota manager
#[derive(Debug, Clone)]
pub struct QuotaParams {
    pub recompute_interval_ms: u64,
    pub alpha: f64,           // EMA smoothing factor
    pub demand_weight_k: f64, // Weight multiplier for demand
    pub min_floor: f64,       // Minimum share per active challenge
}

impl Default for QuotaParams {
    fn default() -> Self {
        Self {
            recompute_interval_ms: 5000,
            alpha: 0.3,
            demand_weight_k: 0.5,
            min_floor: 0.05,
        }
    }
}

/// Dynamic quota manager that allocates resources based on emission_share and demand
pub struct CVMQuotaManager {
    capacity: ResourceCapacity,
    challenges: Arc<RwLock<HashMap<String, ChallengeQuotaState>>>,
    params: QuotaParams,
}

impl CVMQuotaManager {
    pub fn new() -> Self {
        Self::with_params(
            ResourceCapacity {
                cpu_cores: 4,
                memory_mb: 2048,
                disk_mb: 10240,
            },
            QuotaParams::default(),
        )
    }

    pub fn with_capacity(capacity: ResourceCapacity) -> Self {
        Self::with_params(capacity, QuotaParams::default())
    }

    pub fn with_params(capacity: ResourceCapacity, params: QuotaParams) -> Self {
        info!(
            "Initializing CVMQuotaManager with capacity: {} CPU, {} MB RAM, {} MB disk",
            capacity.cpu_cores, capacity.memory_mb, capacity.disk_mb
        );
        Self {
            capacity,
            challenges: Arc::new(RwLock::new(HashMap::new())),
            params,
        }
    }

    /// Register or update a challenge with its emission_share
    pub async fn register_or_update_challenge(&self, compose_hash: String, emission_share: f64) {
        let mut challenges = self.challenges.write().await;

        if let Some(state) = challenges.get_mut(&compose_hash) {
            // Update emission_share
            state.emission_share = emission_share;
            info!(
                "Updated challenge {} with emission_share: {}",
                compose_hash, emission_share
            );
        } else {
            // Register new challenge
            challenges.insert(
                compose_hash.clone(),
                ChallengeQuotaState::new(compose_hash.clone(), emission_share),
            );
            info!(
                "Registered challenge {} with emission_share: {}",
                compose_hash, emission_share
            );
        }
    }

    /// Reserve resources for a challenge (increments demand tracking)
    pub async fn reserve(
        &self,
        compose_hash: &str,
        request: ResourceRequest,
    ) -> Result<QuotaResult> {
        let mut challenges = self.challenges.write().await;

        if let Some(state) = challenges.get_mut(compose_hash) {
            // Update demand EMA (treat each reservation attempt as demand signal)
            state.demand_ema =
                self.params.alpha * 1.0 + (1.0 - self.params.alpha) * state.demand_ema;
            state.last_reservation_time = Instant::now();

            // Check if we have enough reserved capacity minus what's in use
            let available = ResourceRequest {
                cpu_cores: state
                    .reserved
                    .cpu_cores
                    .saturating_sub(state.in_use.cpu_cores),
                memory_mb: state
                    .reserved
                    .memory_mb
                    .saturating_sub(state.in_use.memory_mb),
                disk_mb: state.reserved.disk_mb.saturating_sub(state.in_use.disk_mb),
            };

            if request.cpu_cores <= available.cpu_cores
                && request.memory_mb <= available.memory_mb
                && request.disk_mb <= available.disk_mb
            {
                // Grant reservation
                state.in_use.cpu_cores += request.cpu_cores;
                state.in_use.memory_mb += request.memory_mb;
                state.in_use.disk_mb += request.disk_mb;

                info!(
                    "Granted reservation for {}: {} CPU, {} MB RAM, {} MB disk",
                    compose_hash, request.cpu_cores, request.memory_mb, request.disk_mb
                );
                Ok(QuotaResult::Granted)
            } else {
                warn!(
                    "Insufficient quota for {}: requested {} CPU, {} MB RAM, {} MB disk; available {} CPU, {} MB RAM, {} MB disk",
                    compose_hash, request.cpu_cores, request.memory_mb, request.disk_mb,
                    available.cpu_cores, available.memory_mb, available.disk_mb
                );
                Ok(QuotaResult::Insufficient)
            }
        } else {
            error!("Challenge {} not registered", compose_hash);
            Ok(QuotaResult::Insufficient)
        }
    }

    /// Release resources that were in use
    pub async fn release(&self, compose_hash: &str, released: ResourceRequest) {
        let mut challenges = self.challenges.write().await;

        if let Some(state) = challenges.get_mut(compose_hash) {
            state.in_use.cpu_cores = state.in_use.cpu_cores.saturating_sub(released.cpu_cores);
            state.in_use.memory_mb = state.in_use.memory_mb.saturating_sub(released.memory_mb);
            state.in_use.disk_mb = state.in_use.disk_mb.saturating_sub(released.disk_mb);

            info!(
                "Released resources for {}: {} CPU, {} MB RAM, {} MB disk",
                compose_hash, released.cpu_cores, released.memory_mb, released.disk_mb
            );
        }
    }

    /// Recompute reservations based on emission_share and demand
    pub async fn recompute_reservations(&self, active_challenges: &[(String, f64)]) {
        let mut challenges = self.challenges.write().await;

        if active_challenges.is_empty() {
            for state in challenges.values_mut() {
                state.reserved = ResourceRequest {
                    cpu_cores: 0,
                    memory_mb: 0,
                    disk_mb: 0,
                };
            }
            return;
        }

        // Calculate total demand EMA for normalization
        let total_demand: f64 = active_challenges
            .iter()
            .filter_map(|(hash, _)| challenges.get(hash))
            .map(|state| state.demand_ema)
            .sum();

        let demand_norm_factor = if total_demand > 0.0 {
            1.0 / total_demand
        } else {
            0.0
        };

        // Calculate weights for each challenge
        let mut weights: Vec<(String, f64)> = Vec::new();
        for (compose_hash, emission_share) in active_challenges {
            if let Some(state) = challenges.get(compose_hash) {
                let demand_norm = state.demand_ema * demand_norm_factor;
                let weight = emission_share * (1.0 + self.params.demand_weight_k * demand_norm);
                weights.push((compose_hash.clone(), weight));
            }
        }

        // Normalize weights to sum to 1.0
        let total_weight: f64 = weights.iter().map(|(_, w)| w).sum();
        if total_weight > 0.0 {
            for (_, w) in weights.iter_mut() {
                *w /= total_weight;
            }
        }

        // Apply minimum floor per challenge
        let floor_per_challenge = self.params.min_floor;
        let floor_total = floor_per_challenge * active_challenges.len() as f64;

        if floor_total < 1.0 {
            // Re-distribute the remaining capacity after floor
            let remaining = 1.0 - floor_total;
            let floor_adjusted_weight: f64 = weights
                .iter()
                .map(|(_, w)| (*w).max(floor_per_challenge))
                .sum();

            if floor_adjusted_weight > 0.0 {
                for (_, w) in weights.iter_mut() {
                    let floor_scaled = (*w).max(floor_per_challenge);
                    *w = floor_per_challenge
                        + (floor_scaled - floor_per_challenge)
                            * (remaining / floor_adjusted_weight);
                }
            }
        }

        // Allocate resources proportionally
        for (compose_hash, weight) in weights {
            if let Some(state) = challenges.get_mut(&compose_hash) {
                // Water-filling allocation per resource
                state.reserved.cpu_cores =
                    ((self.capacity.cpu_cores as f64) * weight).ceil() as u32;
                state.reserved.memory_mb =
                    ((self.capacity.memory_mb as f64) * weight).ceil() as u64;
                state.reserved.disk_mb = ((self.capacity.disk_mb as f64) * weight).ceil() as u64;

                debug!(
                    "Allocated to {} (weight={:.3}, emission={:.3}): {} CPU, {} MB RAM, {} MB disk",
                    compose_hash,
                    weight,
                    state.emission_share,
                    state.reserved.cpu_cores,
                    state.reserved.memory_mb,
                    state.reserved.disk_mb
                );
            }
        }

        // Log totals (only if changed)
        let total_reserved_cpu: u32 = challenges.values().map(|s| s.reserved.cpu_cores).sum();
        let total_reserved_mem: u64 = challenges.values().map(|s| s.reserved.memory_mb).sum();
        let total_reserved_disk: u64 = challenges.values().map(|s| s.reserved.disk_mb).sum();

        debug!(
            "Total reservations: {} CPU, {} MB RAM, {} MB disk (capacity: {} CPU, {} MB RAM, {} MB disk)",
            total_reserved_cpu, total_reserved_mem, total_reserved_disk,
            self.capacity.cpu_cores, self.capacity.memory_mb, self.capacity.disk_mb
        );
    }

    /// Get current state for a challenge
    pub async fn get_challenge_state(
        &self,
        compose_hash: &str,
    ) -> Option<(ResourceRequest, ResourceRequest)> {
        let challenges = self.challenges.read().await;
        challenges
            .get(compose_hash)
            .map(|state| (state.reserved, state.in_use))
    }

    /// Decay demand EMA (call periodically to decay old demand)
    pub async fn decay_demand(&self) {
        let mut challenges = self.challenges.write().await;
        let decay_factor = 0.95; // Slight decay

        for state in challenges.values_mut() {
            state.demand_ema *= decay_factor;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proportional_allocation() {
        let capacity = ResourceCapacity {
            cpu_cores: 10,
            memory_mb: 4096,
            disk_mb: 20480,
        };

        let manager = CVMQuotaManager::with_capacity(capacity);

        // Register two challenges with different emission shares
        manager
            .register_or_update_challenge("challenge1".to_string(), 0.7)
            .await;
        manager
            .register_or_update_challenge("challenge2".to_string(), 0.3)
            .await;

        // Recompute reservations
        let active = vec![
            ("challenge1".to_string(), 0.7),
            ("challenge2".to_string(), 0.3),
        ];
        manager.recompute_reservations(&active).await;

        // Check allocations
        let (reserved1, _) = manager.get_challenge_state("challenge1").await.unwrap();
        let (reserved2, _) = manager.get_challenge_state("challenge2").await.unwrap();

        // Challenge 1 should get more resources due to higher emission_share
        assert!(reserved1.cpu_cores > reserved2.cpu_cores);
        assert!(reserved1.memory_mb > reserved2.memory_mb);
        assert!(reserved1.disk_mb > reserved2.disk_mb);
    }

    #[tokio::test]
    async fn test_quota_enforcement() {
        let capacity = ResourceCapacity {
            cpu_cores: 4,
            memory_mb: 2048,
            disk_mb: 10240,
        };

        let manager = CVMQuotaManager::with_capacity(capacity);

        manager
            .register_or_update_challenge("challenge1".to_string(), 1.0)
            .await;

        let active = vec![("challenge1".to_string(), 1.0)];
        manager.recompute_reservations(&active).await;

        // Should be able to reserve within capacity
        let request = ResourceRequest {
            cpu_cores: 2,
            memory_mb: 1024,
            disk_mb: 5120,
        };

        let result = manager.reserve("challenge1", request).await.unwrap();
        assert_eq!(result, QuotaResult::Granted);

        // Should be able to release
        manager.release("challenge1", request).await;
    }
}
