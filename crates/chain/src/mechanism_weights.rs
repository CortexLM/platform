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

    /// Process weights for a single mechanism
    /// Made public so it can be used to process individual mechanisms separately
    pub fn process_mechanism(
        mechanism_id: u8,
        challenges: Vec<ChallengeWeight>,
    ) -> Result<MechanismWeights> {
        let total_emission_share: f64 = challenges.iter().map(|c| c.emission_share).sum();

        if total_emission_share == 0.0 {
            warn!("Mechanism {} has zero total emission share", mechanism_id);
            return Ok(MechanismWeights {
                mechanism_id: mechanism_id.to_string(), // Keep as String in MechanismWeights for compatibility
                total_emission_share: 0.0,
                normalized_weights: HashMap::new(),
            });
        }

        // Aggregate weights weighted by emission share
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

        info!(
            "Mechanism {}: {} challenges, {} unique UIDs, emission share: {:.4}",
            mechanism_id,
            challenges.len(),
            aggregated.len(),
            total_emission_share
        );

        Ok(MechanismWeights {
            mechanism_id: mechanism_id.to_string(), // Keep as String in MechanismWeights for compatibility
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

        info!(
            "Final aggregation: {} unique UIDs from {} mechanisms",
            combined_weights.len(),
            mechanisms.len()
        );

        Ok(combined_weights)
    }

    /// Normalize weights ensuring sum equals 1.0, with remainder assigned to UID 0
    ///
    /// Args:
    ///   - weights: HashMap mapping UID (as String) to weight (f64)
    ///
    /// Returns:
    ///   - (normalized_weights, used_uid0): Tuple with normalized weights and flag if UID 0 was used
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
            // Already normalized (within floating point precision)
            return (normalized, false);
        }

        if total < 1.0 {
            // Sum is less than 1.0: assign remainder to UID 0
            let remainder = 1.0 - total;
            *normalized.entry("0".to_string()).or_insert(0.0) += remainder;
            used_uid0 = true;
            info!(
                "Weight sum was {:.6} < 1.0, assigned remainder {:.6} to UID 0",
                total, remainder
            );
        } else {
            // Sum is greater than 1.0: renormalize first, then assign remainder to UID 0
            // Renormalize to sum to 1.0
            for weight in normalized.values_mut() {
                *weight /= total;
            }

            // After renormalization, sum should be exactly 1.0
            // But we still assign a small remainder to UID 0 to ensure exact sum
            let adjusted_total: f64 = normalized.values().sum();
            if adjusted_total < 1.0 {
                let remainder = 1.0 - adjusted_total;
                *normalized.entry("0".to_string()).or_insert(0.0) += remainder;
                used_uid0 = true;
                info!(
                    "Weight sum was {:.6} > 1.0, renormalized and assigned remainder {:.6} to UID 0",
                    total, remainder
                );
            }
        }

        // Final verification
        let final_total: f64 = normalized.values().sum();
        if (final_total - 1.0).abs() > 1e-6 {
            warn!(
                "Warning: Final weight sum is {:.6}, expected 1.0 (difference: {:.6})",
                final_total,
                (final_total - 1.0).abs()
            );
        } else {
            info!(
                "Weights normalized successfully (sum: {:.6}, UID 0 used: {})",
                final_total, used_uid0
            );
        }

        (normalized, used_uid0)
    }

    /// Convert float weights to u16 for chain submission
    pub fn normalize_for_chain(weights: &HashMap<String, f64>, max_value: u16) -> Vec<(u64, u16)> {
        let mut normalized: Vec<(u64, u16)> = Vec::new();

        // Find max weight for scaling
        let max_weight = weights.values().cloned().fold(0.0f64, f64::max);

        if max_weight == 0.0 {
            return normalized;
        }

        // Convert and scale
        for (uid_str, &weight) in weights {
            if let Ok(uid) = uid_str.parse::<u64>() {
                let scaled = ((weight / max_weight) * max_value as f64) as u16;
                if scaled > 0 {
                    normalized.push((uid, scaled));
                }
            } else {
                warn!("Invalid UID format: {}", uid_str);
            }
        }

        // Sort by UID for consistency
        normalized.sort_by_key(|(uid, _)| *uid);

        info!(
            "Normalized {} weights for chain submission (max value: {})",
            normalized.len(),
            max_value
        );

        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_mechanism() {
        let mut weights = HashMap::new();
        weights.insert("1".to_string(), 0.6);
        weights.insert("2".to_string(), 0.4);

        let challenges = vec![ChallengeWeight {
            compose_hash: "hash1".to_string(),
            mechanism_id: 1,
            emission_share: 1.0,
            raw_weights: weights,
        }];

        let result = MechanismWeightAggregator::aggregate_weights(challenges, 1000).unwrap();
        assert_eq!(result.weights.len(), 2);
        assert!((result.weights["1"] - 0.6).abs() < 0.001);
        assert!((result.weights["2"] - 0.4).abs() < 0.001);
    }

    #[test]
    fn test_multiple_mechanisms() {
        let mut weights1 = HashMap::new();
        weights1.insert("1".to_string(), 1.0);

        let mut weights2 = HashMap::new();
        weights2.insert("2".to_string(), 1.0);

        let challenges = vec![
            ChallengeWeight {
                compose_hash: "hash1".to_string(),
                mechanism_id: 1,
                emission_share: 0.6,
                raw_weights: weights1,
            },
            ChallengeWeight {
                compose_hash: "hash2".to_string(),
                mechanism_id: 2,
                emission_share: 0.4,
                raw_weights: weights2,
            },
        ];

        let result = MechanismWeightAggregator::aggregate_weights(challenges, 1000).unwrap();
        assert_eq!(result.weights.len(), 2);
        assert!((result.weights["1"] - 0.6).abs() < 0.001);
        assert!((result.weights["2"] - 0.4).abs() < 0.001);
    }

    #[test]
    fn test_normalize_for_chain() {
        let mut weights = HashMap::new();
        weights.insert("10".to_string(), 0.75);
        weights.insert("20".to_string(), 0.25);

        let normalized = MechanismWeightAggregator::normalize_for_chain(&weights, 65535);
        assert_eq!(normalized.len(), 2);
        assert_eq!(normalized[0], (10, 65535)); // Max weight gets max value
        assert_eq!(normalized[1], (20, 21845)); // 0.25 / 0.75 * 65535
    }

    #[test]
    fn test_normalize_with_uid0_fallback_sum_less_than_one() {
        let mut weights = HashMap::new();
        weights.insert("10".to_string(), 0.6);
        weights.insert("20".to_string(), 0.3); // Sum = 0.9

        let (normalized, used_uid0) =
            MechanismWeightAggregator::normalize_with_uid0_fallback(&weights);

        assert!(used_uid0);
        assert!((normalized.get("0").unwrap() - 0.1).abs() < 1e-6);
        let total: f64 = normalized.values().sum();
        assert!((total - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_normalize_with_uid0_fallback_sum_greater_than_one() {
        let mut weights = HashMap::new();
        weights.insert("10".to_string(), 0.8);
        weights.insert("20".to_string(), 0.4); // Sum = 1.2

        let (normalized, used_uid0) =
            MechanismWeightAggregator::normalize_with_uid0_fallback(&weights);

        // After renormalization, weights should be 0.8/1.2 = 0.666... and 0.4/1.2 = 0.333...
        // Then remainder goes to UID 0
        let total: f64 = normalized.values().sum();
        assert!((total - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_normalize_with_uid0_fallback_already_normalized() {
        let mut weights = HashMap::new();
        weights.insert("10".to_string(), 0.6);
        weights.insert("20".to_string(), 0.4); // Sum = 1.0

        let (normalized, used_uid0) =
            MechanismWeightAggregator::normalize_with_uid0_fallback(&weights);

        assert!(!used_uid0);
        assert!(!normalized.contains_key("0"));
        let total: f64 = normalized.values().sum();
        assert!((total - 1.0).abs() < 1e-6);
    }
}
