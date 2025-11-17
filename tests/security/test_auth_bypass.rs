// Security tests for authentication and attestation bypass prevention
//
// Tests dev mode security checks, attestation requirement enforcement,
// and signature verification.

#[cfg(test)]
mod dev_mode_security_tests {
    use std::env;

    #[test]
    fn test_dev_mode_detection() {
        // Test that dev mode can be properly detected and logged

        fn is_dev_mode() -> bool {
            env::var("DEV_MODE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false)
        }

        // Test default (production mode)
        env::remove_var("DEV_MODE");
        assert!(!is_dev_mode(), "Should default to production mode");

        // Test explicit dev mode
        env::set_var("DEV_MODE", "true");
        assert!(is_dev_mode(), "Should detect dev mode");

        // Test invalid value (should default to false)
        env::set_var("DEV_MODE", "invalid");
        assert!(!is_dev_mode(), "Invalid value should default to production");

        // Cleanup
        env::remove_var("DEV_MODE");
    }

    #[test]
    fn test_security_bypass_warnings() {
        // Test that security bypasses are properly logged

        struct SecurityConfig {
            dev_mode: bool,
            tee_enforced: bool,
            jwt_enforced: bool,
        }

        impl SecurityConfig {
            fn from_env() -> Self {
                Self {
                    dev_mode: env::var("DEV_MODE")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(false),
                    tee_enforced: env::var("TEE_ENFORCED")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(true), // Default to true for security
                    jwt_enforced: env::var("JWT_ENFORCED")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(true), // Default to true for security
                }
            }

            fn check_security(&self) -> Vec<String> {
                let mut warnings = Vec::new();

                if self.dev_mode {
                    warnings.push("⚠️  DEV_MODE=true - Development mode active".to_string());
                }

                if !self.tee_enforced {
                    warnings.push("🚨 TEE_ENFORCED=false - TEE attestation disabled".to_string());
                }

                if !self.jwt_enforced {
                    warnings.push("🚨 JWT_ENFORCED=false - JWT authentication disabled".to_string());
                }

                if warnings.is_empty() && !self.dev_mode {
                    warnings.push("✅ All security features enabled".to_string());
                }

                warnings
            }

            fn is_production_ready(&self) -> bool {
                !self.dev_mode && self.tee_enforced && self.jwt_enforced
            }
        }

        // Test production configuration
        env::remove_var("DEV_MODE");
        env::remove_var("TEE_ENFORCED");
        env::remove_var("JWT_ENFORCED");
        
        let config = SecurityConfig::from_env();
        assert!(config.is_production_ready());
        let warnings = config.check_security();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("All security features enabled"));

        // Test dev mode
        env::set_var("DEV_MODE", "true");
        let config = SecurityConfig::from_env();
        assert!(!config.is_production_ready());
        let warnings = config.check_security();
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.contains("DEV_MODE")));

        // Test partial bypass
        env::remove_var("DEV_MODE");
        env::set_var("TEE_ENFORCED", "false");
        let config = SecurityConfig::from_env();
        assert!(!config.is_production_ready());
        let warnings = config.check_security();
        assert!(warnings.iter().any(|w| w.contains("TEE_ENFORCED")));

        // Cleanup
        env::remove_var("DEV_MODE");
        env::remove_var("TEE_ENFORCED");
        env::remove_var("JWT_ENFORCED");
    }

    #[test]
    fn test_explicit_bypass_requirement() {
        // Test that security bypasses require explicit opt-in

        fn allow_bypass(bypass_type: &str) -> Result<(), String> {
            // Bypasses should be explicitly enabled AND acknowledged
            let enabled = env::var(format!("{}_ENABLED", bypass_type))
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false);

            let acknowledged = env::var(format!("{}_ACKNOWLEDGED", bypass_type))
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false);

            if enabled && acknowledged {
                eprintln!("⚠️  {} bypass explicitly enabled and acknowledged", bypass_type);
                Ok(())
            } else if enabled {
                Err(format!("{} bypass enabled but not acknowledged", bypass_type))
            } else {
                Err(format!("{} bypass not enabled", bypass_type))
            }
        }

        // Test auth bypass requires both flags
        env::set_var("AUTH_BYPASS_ENABLED", "true");
        let result = allow_bypass("AUTH_BYPASS");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not acknowledged"));

        // Test with acknowledgment
        env::set_var("AUTH_BYPASS_ACKNOWLEDGED", "true");
        let result = allow_bypass("AUTH_BYPASS");
        assert!(result.is_ok());

        // Cleanup
        env::remove_var("AUTH_BYPASS_ENABLED");
        env::remove_var("AUTH_BYPASS_ACKNOWLEDGED");
    }
}

#[cfg(test)]
mod attestation_tests {
    use std::env;

    #[test]
    fn test_attestation_requirement_enforcement() {
        struct AttestationConfig {
            required: bool,
            enforce_on_connections: bool,
        }

        impl AttestationConfig {
            fn from_env() -> Self {
                let required = env::var("ATTESTATION_REQUIRED")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(true); // Default to required for security

                Self {
                    required,
                    enforce_on_connections: required,
                }
            }

            fn validate_connection(&self, has_attestation: bool) -> Result<(), String> {
                if self.required && !has_attestation {
                    Err("Attestation required but not provided".to_string())
                } else {
                    Ok(())
                }
            }
        }

        // Test default (attestation required)
        env::remove_var("ATTESTATION_REQUIRED");
        let config = AttestationConfig::from_env();
        assert!(config.required);

        // Connection without attestation should fail
        let result = config.validate_connection(false);
        assert!(result.is_err());

        // Connection with attestation should succeed
        let result = config.validate_connection(true);
        assert!(result.is_ok());

        // Test with attestation not required
        env::set_var("ATTESTATION_REQUIRED", "false");
        let config = AttestationConfig::from_env();
        assert!(!config.required);

        // Connection without attestation should now succeed
        let result = config.validate_connection(false);
        assert!(result.is_ok());

        // Cleanup
        env::remove_var("ATTESTATION_REQUIRED");
    }

    #[test]
    fn test_tee_enforcement() {
        fn check_tee_enforcement() -> Result<(), String> {
            let tee_enforced = env::var("TEE_ENFORCED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true); // Default to true for security

            if !tee_enforced {
                // Log error but don't just return Ok()
                eprintln!("🚨 TEE_ENFORCED=false DETECTED - REJECTING CONNECTION");
                return Err("TEE enforcement is disabled".to_string());
            }

            Ok(())
        }

        // Test default (TEE enforced)
        env::remove_var("TEE_ENFORCED");
        let result = check_tee_enforcement();
        assert!(result.is_ok());

        // Test with TEE disabled (should reject)
        env::set_var("TEE_ENFORCED", "false");
        let result = check_tee_enforcement();
        assert!(result.is_err(), "Should reject when TEE_ENFORCED=false");

        // Cleanup
        env::remove_var("TEE_ENFORCED");
    }

    #[test]
    fn test_quote_validation() {
        use sha2::{Digest, Sha256};

        fn validate_quote_binding(quote_data: &[u8], expected_nonce: &[u8]) -> Result<(), String> {
            // Simplified quote validation
            // Real implementation would use dcap-qvl

            if quote_data.len() < 64 {
                return Err("Quote too short".to_string());
            }

            // Check nonce binding (simplified)
            let mut hasher = Sha256::new();
            hasher.update(expected_nonce);
            let nonce_hash = hasher.finalize();

            // In real quote, report_data should match nonce hash
            let report_data = &quote_data[0..32];
            
            if report_data != nonce_hash.as_slice() {
                return Err("Quote not bound to nonce".to_string());
            }

            Ok(())
        }

        // Test valid quote binding
        let nonce = b"test-nonce-12345";
        let mut hasher = Sha256::new();
        hasher.update(nonce);
        let nonce_hash = hasher.finalize();

        let mut quote = vec![0u8; 100];
        quote[0..32].copy_from_slice(&nonce_hash);

        let result = validate_quote_binding(&quote, nonce);
        assert!(result.is_ok());

        // Test invalid quote binding
        let wrong_nonce = b"wrong-nonce-67890";
        let result = validate_quote_binding(&quote, wrong_nonce);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod signature_verification_tests {
    use ring::signature;
    use ring::signature::Ed25519KeyPair;
    use ring::rand::SystemRandom;

    #[test]
    fn test_ed25519_signature_verification() {
        let rng = SystemRandom::new();

        // Generate key pair
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
            .expect("Failed to generate key pair");
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
            .expect("Failed to parse key pair");

        let message = b"Test message for signing";

        // Sign message
        let signature_bytes = key_pair.sign(message);

        // Verify signature
        let public_key = key_pair.public_key();
        let result = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            public_key.as_ref()
        ).verify(message, signature_bytes.as_ref());

        assert!(result.is_ok(), "Signature verification should succeed");

        // Test with wrong message
        let wrong_message = b"Wrong message";
        let result = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            public_key.as_ref()
        ).verify(wrong_message, signature_bytes.as_ref());

        assert!(result.is_err(), "Signature verification should fail");
    }

    #[test]
    fn test_signature_replay_prevention() {
        use std::collections::HashSet;

        struct SignatureCache {
            used_signatures: HashSet<Vec<u8>>,
        }

        impl SignatureCache {
            fn new() -> Self {
                Self {
                    used_signatures: HashSet::new(),
                }
            }

            fn check_and_mark(&mut self, signature: &[u8]) -> Result<(), String> {
                if self.used_signatures.contains(signature) {
                    Err("Signature already used (replay attack)".to_string())
                } else {
                    self.used_signatures.insert(signature.to_vec());
                    Ok(())
                }
            }
        }

        let mut cache = SignatureCache::new();
        let signature = b"signature_123";

        // First use should succeed
        let result = cache.check_and_mark(signature);
        assert!(result.is_ok());

        // Second use should fail (replay)
        let result = cache.check_and_mark(signature);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("replay"));
    }

    #[test]
    fn test_timestamp_validation() {
        use std::time::{SystemTime, UNIX_EPOCH, Duration};

        fn validate_timestamp(
            timestamp: u64,
            max_age_secs: u64
        ) -> Result<(), String> {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs();

            if timestamp > now {
                return Err("Timestamp is in the future".to_string());
            }

            let age = now - timestamp;
            if age > max_age_secs {
                return Err(format!("Timestamp too old ({} seconds)", age));
            }

            Ok(())
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();

        // Test recent timestamp
        let result = validate_timestamp(now - 10, 60);
        assert!(result.is_ok());

        // Test old timestamp
        let result = validate_timestamp(now - 120, 60);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too old"));

        // Test future timestamp
        let result = validate_timestamp(now + 100, 60);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("future"));
    }
}

#[cfg(test)]
mod access_control_tests {
    use std::collections::HashMap;

    #[test]
    fn test_role_based_access_control() {
        #[derive(Debug, PartialEq)]
        enum Role {
            Admin,
            Validator,
            ReadOnly,
        }

        #[derive(Debug, PartialEq)]
        enum Permission {
            Read,
            Write,
            Execute,
            Admin,
        }

        struct AccessControl {
            role_permissions: HashMap<Role, Vec<Permission>>,
        }

        impl AccessControl {
            fn new() -> Self {
                let mut role_permissions = HashMap::new();
                
                role_permissions.insert(Role::Admin, vec![
                    Permission::Read,
                    Permission::Write,
                    Permission::Execute,
                    Permission::Admin,
                ]);

                role_permissions.insert(Role::Validator, vec![
                    Permission::Read,
                    Permission::Execute,
                ]);

                role_permissions.insert(Role::ReadOnly, vec![
                    Permission::Read,
                ]);

                Self { role_permissions }
            }

            fn has_permission(&self, role: &Role, permission: &Permission) -> bool {
                self.role_permissions
                    .get(role)
                    .map(|perms| perms.contains(permission))
                    .unwrap_or(false)
            }
        }

        let ac = AccessControl::new();

        // Test admin permissions
        assert!(ac.has_permission(&Role::Admin, &Permission::Read));
        assert!(ac.has_permission(&Role::Admin, &Permission::Write));
        assert!(ac.has_permission(&Role::Admin, &Permission::Admin));

        // Test validator permissions
        assert!(ac.has_permission(&Role::Validator, &Permission::Read));
        assert!(ac.has_permission(&Role::Validator, &Permission::Execute));
        assert!(!ac.has_permission(&Role::Validator, &Permission::Write));
        assert!(!ac.has_permission(&Role::Validator, &Permission::Admin));

        // Test read-only permissions
        assert!(ac.has_permission(&Role::ReadOnly, &Permission::Read));
        assert!(!ac.has_permission(&Role::ReadOnly, &Permission::Write));
        assert!(!ac.has_permission(&Role::ReadOnly, &Permission::Execute));
    }

    #[test]
    fn test_resource_access_validation() {
        struct Resource {
            owner: String,
            public: bool,
        }

        fn can_access(resource: &Resource, user: &str, is_admin: bool) -> bool {
            if is_admin {
                return true;
            }

            if resource.public {
                return true;
            }

            resource.owner == user
        }

        let public_resource = Resource {
            owner: "alice".to_string(),
            public: true,
        };

        let private_resource = Resource {
            owner: "alice".to_string(),
            public: false,
        };

        // Public resource accessible to all
        assert!(can_access(&public_resource, "bob", false));
        assert!(can_access(&public_resource, "alice", false));

        // Private resource only accessible to owner
        assert!(!can_access(&private_resource, "bob", false));
        assert!(can_access(&private_resource, "alice", false));

        // Admin can access anything
        assert!(can_access(&private_resource, "bob", true));
    }
}

#[cfg(test)]
mod rate_limiting_tests {
    use std::time::{Duration, Instant};
    use std::collections::HashMap;

    #[test]
    fn test_basic_rate_limiting() {
        struct RateLimiter {
            requests_per_second: u32,
            last_request_times: HashMap<String, Vec<Instant>>,
        }

        impl RateLimiter {
            fn new(requests_per_second: u32) -> Self {
                Self {
                    requests_per_second,
                    last_request_times: HashMap::new(),
                }
            }

            fn allow_request(&mut self, client_id: &str) -> bool {
                let now = Instant::now();
                let window_start = now - Duration::from_secs(1);

                let times = self.last_request_times
                    .entry(client_id.to_string())
                    .or_insert_with(Vec::new);

                // Remove old requests outside the window
                times.retain(|&t| t > window_start);

                if times.len() >= self.requests_per_second as usize {
                    false
                } else {
                    times.push(now);
                    true
                }
            }
        }

        let mut limiter = RateLimiter::new(5);

        // First 5 requests should succeed
        for i in 0..5 {
            assert!(limiter.allow_request("client1"), "Request {} should be allowed", i);
        }

        // 6th request should fail
        assert!(!limiter.allow_request("client1"), "6th request should be rate limited");

        // Different client should not be affected
        assert!(limiter.allow_request("client2"));
    }

    #[test]
    fn test_token_bucket_rate_limiting() {
        struct TokenBucket {
            capacity: u32,
            tokens: f64,
            refill_rate: f64, // tokens per second
            last_refill: Instant,
        }

        impl TokenBucket {
            fn new(capacity: u32, refill_rate: f64) -> Self {
                Self {
                    capacity,
                    tokens: capacity as f64,
                    refill_rate,
                    last_refill: Instant::now(),
                }
            }

            fn refill(&mut self) {
                let now = Instant::now();
                let elapsed = now.duration_since(self.last_refill).as_secs_f64();
                
                self.tokens = (self.tokens + elapsed * self.refill_rate)
                    .min(self.capacity as f64);
                
                self.last_refill = now;
            }

            fn try_consume(&mut self, count: u32) -> bool {
                self.refill();

                if self.tokens >= count as f64 {
                    self.tokens -= count as f64;
                    true
                } else {
                    false
                }
            }
        }

        let mut bucket = TokenBucket::new(10, 2.0); // 10 tokens, refill 2/sec

        // Should be able to consume all 10 tokens
        for i in 0..10 {
            assert!(bucket.try_consume(1), "Token {} should be available", i);
        }

        // Next request should fail (bucket empty)
        assert!(!bucket.try_consume(1), "Bucket should be empty");
    }
}

