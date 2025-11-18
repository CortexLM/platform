// Re-export from mechanism_weights.rs (moved here)
// This file contains the mechanism weight aggregation logic

use anyhow::Result;
use std::collections::HashMap;
use tracing::{info, warn};

/// Challenge weight information
#[derive(Debug, Clone)]
pub struct ChallengeWeight {
    pub compose_hash: String,
    pub mechanism_id: u8, // Changed from String to u8 to match platform-api
    pub emission_share: f64,
    pub raw_weights: HashMap<String, f64>, // uid -> weight from challenge
}

/// Aggregated weights for a mechanism
#[derive(Debug, Clone)]
pub struct MechanismWeights {
    pub mechanism_id: String,
    pub total_emission_share: f64,
    pub normalized_weights: HashMap<String, f64>, // uid -> aggregated weight
}

/// Final aggregated weights across all mechanisms
#[derive(Debug, Clone)]
pub struct AggregatedWeights {
    pub weights: HashMap<String, f64>, // uid -> final weight
    pub block: u64,
    pub timestamp: i64,
}

/// Weight aggregator that groups challenges by mechanism and normalizes
pub struct MechanismWeightAggregator;

impl MechanismWeightAggregator {
    /// Aggregate weights from multiple challenges grouped by mechanism
    pub fn aggregate_weights(
        challenge_weights: Vec<ChallengeWeight>,
        block: u64,
    ) -> Result<AggregatedWeights> {
        // Group challenges by mechanism
        let mut mechanisms: HashMap<u8, Vec<ChallengeWeight>> = HashMap::new();

        for challenge in challenge_weights {
            mechanisms
                .entry(challenge.mechanism_id)
                .or_insert_with(Vec::new)
                .push(challenge);
        }

        info!("Aggregating weights from {} mechanisms", mechanisms.len());

        // Process each mechanism
        let mut mechanism_results: Vec<MechanismWeights> = Vec::new();

        for (mechanism_id, challenges) in mechanisms {
            let mechanism_weights = Self::process_mechanism(mechanism_id, challenges)?;
            mechanism_results.push(mechanism_weights);
        }

        // Combine all mechanism weights
        let final_weights = Self::combine_mechanisms(mechanism_results)?;

        Ok(AggregatedWeights {
            weights: final_weights,
            block,
            timestamp: chrono::Utc::now().timestamp(),
        })
    }

    /// Check if a challenge is term-challenge based on compose_hash or name
    fn is_term_challenge(compose_hash: &str) -> bool {
        compose_hash.contains("term") || compose_hash.contains("terminal")
    }

    /// Apply winner-takes-all logic for term-challenge
    fn apply_winner_takes_all(raw_weights: &HashMap<String, f64>) -> HashMap<String, f64> {
        if raw_weights.is_empty() {
            return HashMap::new();
        }

        let best_miner = raw_weights
            .iter()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        if let Some((best_uid, _best_weight)) = best_miner {
            let mut winner_takes_all = HashMap::new();
            winner_takes_all.insert(best_uid.clone(), 1.0);
            info!(
                "Term-challenge winner-takes-all: {} gets 100% weight (accuracy: {:.4})",
                best_uid, raw_weights[best_uid]
            );
            winner_takes_all
        } else {
            warn!("No best miner found for term-challenge winner-takes-all");
            HashMap::new()
        }
    }

    /// Process weights for a single mechanism
    pub fn process_mechanism(
        mechanism_id: u8,
        challenges: Vec<ChallengeWeight>,
    ) -> Result<MechanismWeights> {
        let total_emission_share: f64 = challenges.iter().map(|c| c.emission_share).sum();

        if total_emission_share == 0.0 {
            warn!("Mechanism {} has zero total emission share", mechanism_id);
            return Ok(MechanismWeights {
                mechanism_id: mechanism_id.to_string(),
                total_emission_share: 0.0,
                normalized_weights: HashMap::new(),
            });
        }

        // Check if any challenge is term-challenge (winner-takes-all)
        let has_term_challenge = challenges
            .iter()
            .any(|c| Self::is_term_challenge(&c.compose_hash));

        let aggregated = if has_term_challenge {
            // For term-challenge: winner-takes-all (100% to best accuracy agent)
            info!(
                "Mechanism {} contains term-challenge, applying winner-takes-all logic",
                mechanism_id
            );

            // Find the term-challenge challenge
            let term_challenge = challenges
                .iter()
                .find(|c| Self::is_term_challenge(&c.compose_hash));

            if let Some(term_challenge) = term_challenge {
                // Apply winner-takes-all to term-challenge weights
                let winner_weights = Self::apply_winner_takes_all(&term_challenge.raw_weights);

                // If there are other challenges in the mechanism, aggregate them normally
                let other_challenges: Vec<_> = challenges
                    .iter()
                    .filter(|c| !Self::is_term_challenge(&c.compose_hash))
                    .collect();

                if !other_challenges.is_empty() {
                    // Aggregate other challenges weighted by emission share
                    let mut other_aggregated: HashMap<String, f64> = HashMap::new();
                    let other_emission: f64 =
                        other_challenges.iter().map(|c| c.emission_share).sum();
                    let term_emission = term_challenge.emission_share;
                    let total_emission = other_emission + term_emission;

                    for challenge in other_challenges {
                        let weight_factor = challenge.emission_share / total_emission;
                        for (uid, weight) in &challenge.raw_weights {
                            *other_aggregated.entry(uid.clone()).or_insert(0.0) +=
                                weight * weight_factor;
                        }
                    }

                    // Combine: term-challenge gets term_emission/total_emission share
                    let mut combined = HashMap::new();
                    let term_factor = term_emission / total_emission;
                    let other_factor = other_emission / total_emission;

                    // Add term-challenge winner weights
                    for (uid, weight) in &winner_weights {
                        combined.insert(uid.clone(), weight * term_factor);
                    }

                    // Add other challenge weights
                    for (uid, weight) in &other_aggregated {
                        *combined.entry(uid.clone()).or_insert(0.0) += weight * other_factor;
                    }

                    // Normalize
                    let total: f64 = combined.values().sum();
                    if total > 0.0 {
                        for weight in combined.values_mut() {
                            *weight /= total;
                        }
                    }

                    combined
                } else {
                    // Only term-challenge in mechanism - winner gets 100% of mechanism emission
                    winner_weights
                }
            } else {
                // Fallback: shouldn't happen, but aggregate normally
                warn!("Term-challenge flag set but no term-challenge found");
                let mut aggregated: HashMap<String, f64> = HashMap::new();
                for challenge in &challenges {
                    let weight_factor = challenge.emission_share / total_emission_share;
                    for (uid, weight) in &challenge.raw_weights {
                        *aggregated.entry(uid.clone()).or_insert(0.0) += weight * weight_factor;
                    }
                }
                let total_weight: f64 = aggregated.values().sum();
                if total_weight > 0.0 {
                    for weight in aggregated.values_mut() {
                        *weight /= total_weight;
                    }
                }
                aggregated
            }
        } else {
            // Normal aggregation: weighted by emission share
            let mut aggregated: HashMap<String, f64> = HashMap::new();

            for challenge in &challenges {
                let weight_factor = challenge.emission_share / total_emission_share;

                for (uid, weight) in &challenge.raw_weights {
                    *aggregated.entry(uid.clone()).or_insert(0.0) += weight * weight_factor;
                }
            }

            // Normalize within mechanism
            let total_weight: f64 = aggregated.values().sum();
            if total_weight > 0.0 {
                for weight in aggregated.values_mut() {
                    *weight /= total_weight;
                }
            }

            aggregated
        };

        info!(
            "Mechanism {}: {} challenges, {} unique UIDs, emission share: {:.4}, term-challenge: {}",
            mechanism_id,
            challenges.len(),
            aggregated.len(),
            total_emission_share,
            has_term_challenge
        );

        Ok(MechanismWeights {
            mechanism_id: mechanism_id.to_string(),
            total_emission_share,
            normalized_weights: aggregated,
        })
    }

    /// Combine weights from all mechanisms based on their emission shares
    fn combine_mechanisms(mechanisms: Vec<MechanismWeights>) -> Result<HashMap<String, f64>> {
        let total_emission: f64 = mechanisms.iter().map(|m| m.total_emission_share).sum();

        if total_emission == 0.0 {
            warn!("No mechanisms with emission shares");
            return Ok(HashMap::new());
        }

        let mut combined_weights: HashMap<String, f64> = HashMap::new();

        // Combine weighted by mechanism emission share
        for mechanism in &mechanisms {
            let mechanism_factor = mechanism.total_emission_share / total_emission;

            for (uid, weight) in &mechanism.normalized_weights {
                *combined_weights.entry(uid.clone()).or_insert(0.0) += weight * mechanism_factor;
            }
        }

        // Final normalization to ensure sum equals 1.0
        let final_total: f64 = combined_weights.values().sum();
        if final_total > 0.0 {
            for weight in combined_weights.values_mut() {
                *weight /= final_total;
            }
        }

        Ok(combined_weights)
    }

    /// Normalize weights ensuring sum equals 1.0, with remainder assigned to UID 0
    pub fn normalize_with_uid0_fallback(
        weights: &HashMap<String, f64>,
    ) -> (HashMap<String, f64>, bool) {
        let mut normalized = weights.clone();
        let total: f64 = normalized.values().sum();
        let mut used_uid0 = false;

        if total == 0.0 {
            warn!("All weights sum to zero, cannot normalize");
            return (normalized, false);
        }

        if (total - 1.0).abs() < 1e-10 {
            return (normalized, false);
        }

        if total < 1.0 {
            let remainder = 1.0 - total;
            *normalized.entry("0".to_string()).or_insert(0.0) += remainder;
            used_uid0 = true;
        } else {
            for weight in normalized.values_mut() {
                *weight /= total;
            }
            let adjusted_total: f64 = normalized.values().sum();
            if adjusted_total < 1.0 {
                let remainder = 1.0 - adjusted_total;
                *normalized.entry("0".to_string()).or_insert(0.0) += remainder;
                used_uid0 = true;
            }
        }

        (normalized, used_uid0)
    }

    /// Convert float weights to u16 for chain submission
    pub fn normalize_for_chain(weights: &HashMap<String, f64>, max_value: u16) -> Vec<(u64, u16)> {
        let mut normalized: Vec<(u64, u16)> = Vec::new();
        let max_weight = weights.values().cloned().fold(0.0f64, f64::max);

        if max_weight == 0.0 {
            return normalized;
        }

        for (uid_str, &weight) in weights {
            if let Ok(uid) = uid_str.parse::<u64>() {
                let scaled = ((weight / max_weight) * max_value as f64) as u16;
                if scaled > 0 {
                    normalized.push((uid, scaled));
                }
            }
        }

        normalized.sort_by_key(|(uid, _)| *uid);
        normalized
    }
}
