use anyhow::Result;
use std::collections::{BTreeMap, HashMap};
use tracing::{info, warn};

use super::subtensor_client::{MetagraphState, SubtensorClient};

/// Service for mapping hotkeys to UIDs using metagraph
pub struct HotkeyMapper;

impl HotkeyMapper {
    /// Create a mapping from hotkey to UID from metagraph state
    ///
    /// Uses both validators list and uids map to build comprehensive mapping
    pub fn map_hotkeys_to_uids(metagraph: &MetagraphState) -> BTreeMap<String, u64> {
        let mut mapping = BTreeMap::new();

        // First, populate from validators list (if available)
        for validator in &metagraph.validators {
            mapping.insert(validator.hotkey.clone(), validator.uid as u64);
        }

        // Then, populate from uids map (may have additional entries)
        for (hotkey, uid) in &metagraph.uids {
            // Only add if not already present (validators list takes precedence)
            mapping.entry(hotkey.clone()).or_insert(*uid as u64);
        }

        info!(
            "Created hotkey->UID mapping: {} entries from metagraph (netuid: {}, block: {})",
            mapping.len(),
            metagraph.netuid,
            metagraph.block
        );

        mapping
    }

    /// Convert weights from hotkey-based to UID-based
    ///
    /// Args:
    ///   - hotkey_weights: HashMap mapping hotkey (String) to weight (f64)
    ///   - hotkey_to_uid: Mapping from hotkey to UID
    ///
    /// Returns:
    ///   - HashMap mapping UID (u64) to weight (f64)
    ///   - Logs warnings for hotkeys not found in metagraph
    pub fn convert_weights_to_uids(
        hotkey_weights: &HashMap<String, f64>,
        hotkey_to_uid: &BTreeMap<String, u64>,
    ) -> HashMap<u64, f64> {
        let mut uid_weights = HashMap::new();
        let mut skipped_count = 0;

        for (hotkey, weight) in hotkey_weights {
            match hotkey_to_uid.get(hotkey) {
                Some(&uid) => {
                    // Aggregate weights if multiple hotkeys map to same UID
                    *uid_weights.entry(uid).or_insert(0.0) += weight;
                }
                None => {
                    skipped_count += 1;
                    warn!(
                        "Hotkey '{}' not found in metagraph, skipping weight {:.6}",
                        hotkey, weight
                    );
                }
            }
        }

        if skipped_count > 0 {
            warn!(
                "Skipped {} hotkey(s) not found in metagraph (out of {} total)",
                skipped_count,
                hotkey_weights.len()
            );
        }

        info!(
            "Converted {} hotkey weights to {} UID weights ({} skipped)",
            hotkey_weights.len(),
            uid_weights.len(),
            skipped_count
        );

        uid_weights
    }

    /// Get hotkey to UID mapping from SubtensorClient
    ///
    /// Convenience method that fetches metagraph and creates mapping
    pub async fn get_hotkey_mapping(
        client: &SubtensorClient,
        netuid: u16,
    ) -> Result<BTreeMap<String, u64>> {
        let metagraph = client.get_metagraph(netuid).await?;
        Ok(Self::map_hotkeys_to_uids(&metagraph))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_mock_metagraph() -> MetagraphState {
        use super::super::types::ValidatorInfo;

        MetagraphState {
            netuid: 1,
            block: 1000,
            validators: vec![
                ValidatorInfo {
                    hotkey: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
                    uid: 10,
                    stake: 1000.0,
                    performance_score: 0.9,
                    last_seen: Utc::now(),
                    is_active: true,
                },
                ValidatorInfo {
                    hotkey: "5FHneW46xGXgs5mUyUYEh3Z4qZyRTHGv1Wc2FqPjrQaJKqJf".to_string(),
                    uid: 20,
                    stake: 500.0,
                    performance_score: 0.8,
                    last_seen: Utc::now(),
                    is_active: true,
                },
            ],
            uids: {
                let mut map = BTreeMap::new();
                map.insert(
                    "5FHneW46xGXgs5mUyUYEh3Z4qZyRTHGv1Wc2FqPjrQaJKqJf".to_string(),
                    20,
                );
                map.insert(
                    "5FLSigC9HGRKVhB9F7fJhyhH3N7gJLX6b7v7vGXWqKp3VrF".to_string(),
                    30,
                );
                map
            },
            total_stake: 1500.0,
            last_updated: Utc::now(),
        }
    }

    #[test]
    fn test_map_hotkeys_to_uids() {
        let metagraph = create_mock_metagraph();
        let mapping = HotkeyMapper::map_hotkeys_to_uids(&metagraph);

        assert_eq!(mapping.len(), 3); // 2 from validators + 1 from uids map
        assert_eq!(
            mapping.get("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"),
            Some(&10)
        );
        assert_eq!(
            mapping.get("5FHneW46xGXgs5mUyUYEh3Z4qZyRTHGv1Wc2FqPjrQaJKqJf"),
            Some(&20) // From validators (takes precedence)
        );
        assert_eq!(
            mapping.get("5FLSigC9HGRKVhB9F7fJhyhH3N7gJLX6b7v7vGXWqKp3VrF"),
            Some(&30)
        );
    }

    #[test]
    fn test_convert_weights_to_uids() {
        let metagraph = create_mock_metagraph();
        let mapping = HotkeyMapper::map_hotkeys_to_uids(&metagraph);

        let mut hotkey_weights = HashMap::new();
        hotkey_weights.insert(
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
            0.6,
        );
        hotkey_weights.insert(
            "5FHneW46xGXgs5mUyUYEh3Z4qZyRTHGv1Wc2FqPjrQaJKqJf".to_string(),
            0.4,
        );
        hotkey_weights.insert(
            "5FLSigC9HGRKVhB9F7fJhyhH3N7gJLX6b7v7vGXWqKp3VrF".to_string(),
            0.3,
        );
        // Add a hotkey that doesn't exist in metagraph
        hotkey_weights.insert("5UnknownHotkey".to_string(), 0.1);

        let uid_weights = HotkeyMapper::convert_weights_to_uids(&hotkey_weights, &mapping);

        assert_eq!(uid_weights.len(), 3); // Only 3 valid hotkeys
        assert!((uid_weights.get(&10).unwrap() - 0.6).abs() < 0.0001);
        assert!((uid_weights.get(&20).unwrap() - 0.4).abs() < 0.0001);
        assert!((uid_weights.get(&30).unwrap() - 0.3).abs() < 0.0001);
        assert!(!uid_weights.contains_key(&999)); // Unknown hotkey not present
    }
}
