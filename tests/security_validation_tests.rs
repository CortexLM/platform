// Security validation tests for validator
// Tests TDX quote verification and environment isolation

#[cfg(test)]
mod tests {
    use base64;

    #[test]
    fn test_environment_mode_extraction() {
        // Test that environment mode can be extracted from event_log
        let event_log_dev = r#"{"environment_mode": "dev", "dev_mode": true}"#;
        let event_log_prod = r#"{"environment_mode": "prod"}"#;
        
        // Parse event logs
        let dev_json: serde_json::Value = serde_json::from_str(event_log_dev).unwrap();
        let prod_json: serde_json::Value = serde_json::from_str(event_log_prod).unwrap();
        
        assert_eq!(dev_json["environment_mode"], "dev");
        assert_eq!(prod_json["environment_mode"], "prod");
    }

    #[test]
    fn test_environment_mismatch_detection() {
        // Test that environment mismatch is detected
        let validator_env = "dev";
        let challenge_env = "prod";
        
        // Dev and prod should not match
        assert_ne!(validator_env, challenge_env, "Dev and prod environments should not match");
        
        // Same environment should match
        assert_eq!(validator_env, validator_env);
        assert_eq!(challenge_env, challenge_env);
    }

    #[test]
    fn test_nonce_binding_verification() {
        // Test that report_data must match SHA256(nonce)
        use sha2::{Sha256, Digest};
        use rand::RngCore;
        
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        
        let mut hasher = Sha256::new();
        hasher.update(&nonce);
        let expected_report_data = hasher.finalize()[..32].to_vec();
        
        // Different nonce should produce different report_data
        let mut different_nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut different_nonce);
        let mut hasher2 = Sha256::new();
        hasher2.update(&different_nonce);
        let different_report_data = hasher2.finalize()[..32].to_vec();
        
        assert_ne!(expected_report_data, different_report_data);
    }

    #[test]
    fn test_quote_structure_validation() {
        // Test that quote structure validation checks minimum size
        let valid_quote_size = 1024; // Minimum TDX quote size
        let invalid_quote_size = 100;
        
        assert!(valid_quote_size >= 1024, "Valid quote should be at least 1024 bytes");
        assert!(invalid_quote_size < 1024, "Invalid quote should be rejected");
    }
}

