// Integration tests for CVM provisioning
use platform_engine_executor::{VMExecutor, ExecutorConfig};
use platform_engine_api_client::{PlatformApiClient, ApiConfig};
use platform_engine_challenge_spec::{ChallengeSpec, ResourceRequirements};
use platform_engine_dynamic_values::{DynamicValues, ValueStore};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use serde_json::json;

#[tokio::test]
async fn test_cvm_provisioning_lifecycle() {
    // Setup executor
    let config = ExecutorConfig {
        max_concurrent_vms: 5,
        vm_timeout_seconds: 300,
        vmm_endpoints: vec!["http://localhost:8080".to_string()],
        enable_resource_limits: true,
        enable_network_isolation: true,
        enable_attestation: false, // Disable for testing
    };
    
    let executor = VMExecutor::new(config)
        .await
        .expect("Failed to create executor");
    
    // Create challenge spec
    let challenge_spec = ChallengeSpec {
        id: Uuid::new_v4(),
        name: "test-challenge".to_string(),
        compose_hash: "test_hash_123".to_string(),
        compose_yaml: r#"
version: '3.8'
services:
  challenge:
    image: alpine:latest
    command: ["sleep", "300"]
    environment:
      - TEST_MODE=true
"#.to_string(),
        resources: ResourceRequirements {
            cpu_cores: 2,
            memory_mb: 2048,
            disk_gb: 10,
            gpu_required: false,
            gpu_model: None,
            network_bandwidth_mbps: Some(100),
        },
        timeout_seconds: 300,
        max_retries: 3,
    };
    
    // Test provisioning
    let provision_result = executor.provision_cvm(&challenge_spec)
        .await
        .expect("Failed to provision CVM");
    
    assert!(!provision_result.vm_id.is_empty());
    assert_eq!(provision_result.status, "provisioned");
    assert!(provision_result.ip_address.is_some());
    
    let vm_id = provision_result.vm_id.clone();
    
    // Verify CVM is running
    let status = executor.get_vm_status(&vm_id)
        .await
        .expect("Failed to get VM status");
    
    assert_eq!(status.state, "running");
    assert!(status.resources.cpu_usage < 100.0);
    assert!(status.resources.memory_used_mb < 2048);
    
    // Test CVM connectivity
    let connectivity = executor.check_vm_connectivity(&vm_id)
        .await
        .expect("Failed to check connectivity");
    
    assert!(connectivity.reachable);
    assert!(connectivity.latency_ms < 100.0);
    
    // Test graceful shutdown
    let shutdown_result = executor.shutdown_vm(&vm_id)
        .await
        .expect("Failed to shutdown VM");
    
    assert!(shutdown_result.success);
    
    // Verify VM is terminated
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    let final_status = executor.get_vm_status(&vm_id).await;
    assert!(final_status.is_err() || final_status.unwrap().state == "terminated");
}

#[tokio::test]
async fn test_cvm_resource_enforcement() {
    let config = ExecutorConfig {
        max_concurrent_vms: 2,
        vm_timeout_seconds: 300,
        vmm_endpoints: vec!["http://localhost:8080".to_string()],
        enable_resource_limits: true,
        enable_network_isolation: true,
        enable_attestation: false,
    };
    
    let executor = VMExecutor::new(config)
        .await
        .expect("Failed to create executor");
    
    // Create resource-intensive challenge
    let challenge_spec = ChallengeSpec {
        id: Uuid::new_v4(),
        name: "resource-test".to_string(),
        compose_hash: "resource_test_hash".to_string(),
        compose_yaml: r#"
version: '3.8'
services:
  stress:
    image: progrium/stress
    command: ["--cpu", "4", "--vm", "2", "--vm-bytes", "1G", "--timeout", "10s"]
"#.to_string(),
        resources: ResourceRequirements {
            cpu_cores: 2,      // Limit to 2 cores
            memory_mb: 1024,   // Limit to 1GB
            disk_gb: 5,
            gpu_required: false,
            gpu_model: None,
            network_bandwidth_mbps: Some(50),
        },
        timeout_seconds: 60,
        max_retries: 1,
    };
    
    let provision_result = executor.provision_cvm(&challenge_spec)
        .await
        .expect("Failed to provision resource-limited CVM");
    
    let vm_id = provision_result.vm_id.clone();
    
    // Let stress test run
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    
    // Check resource usage is within limits
    let status = executor.get_vm_status(&vm_id)
        .await
        .expect("Failed to get VM status");
    
    // CPU should be capped at 200% (2 cores)
    assert!(status.resources.cpu_usage <= 200.0);
    
    // Memory should be capped at ~1GB
    assert!(status.resources.memory_used_mb <= 1100); // Allow some overhead
    
    // Cleanup
    executor.shutdown_vm(&vm_id).await.ok();
}

#[tokio::test]
async fn test_cvm_network_isolation() {
    let config = ExecutorConfig {
        max_concurrent_vms: 3,
        vm_timeout_seconds: 300,
        vmm_endpoints: vec!["http://localhost:8080".to_string()],
        enable_resource_limits: true,
        enable_network_isolation: true,
        enable_attestation: false,
    };
    
    let executor = VMExecutor::new(config)
        .await
        .expect("Failed to create executor");
    
    // Create two isolated CVMs
    let challenge_spec1 = create_test_challenge_spec("isolated-1");
    let challenge_spec2 = create_test_challenge_spec("isolated-2");
    
    let vm1 = executor.provision_cvm(&challenge_spec1)
        .await
        .expect("Failed to provision VM1");
    
    let vm2 = executor.provision_cvm(&challenge_spec2)
        .await
        .expect("Failed to provision VM2");
    
    // Test that VMs cannot communicate with each other
    let isolation_test = executor.test_network_isolation(&vm1.vm_id, &vm2.vm_id)
        .await
        .expect("Failed to test isolation");
    
    assert!(isolation_test.isolated);
    assert!(!isolation_test.can_communicate);
    
    // Test that VMs can access whitelisted endpoints
    let whitelist_test = executor.test_network_whitelist(&vm1.vm_id, "api.openai.com")
        .await
        .expect("Failed to test whitelist");
    
    assert!(whitelist_test.accessible);
    
    // Test that VMs cannot access non-whitelisted endpoints
    let blacklist_test = executor.test_network_whitelist(&vm1.vm_id, "malicious.com")
        .await
        .expect("Failed to test blacklist");
    
    assert!(!blacklist_test.accessible);
    
    // Cleanup
    executor.shutdown_vm(&vm1.vm_id).await.ok();
    executor.shutdown_vm(&vm2.vm_id).await.ok();
}

#[tokio::test]
async fn test_cvm_attestation_when_enabled() {
    // Skip if not in TEE environment
    if std::env::var("TEE_AVAILABLE").unwrap_or_default() != "true" {
        println!("Skipping attestation test - TEE not available");
        return;
    }
    
    let config = ExecutorConfig {
        max_concurrent_vms: 1,
        vm_timeout_seconds: 300,
        vmm_endpoints: vec!["http://localhost:8080".to_string()],
        enable_resource_limits: true,
        enable_network_isolation: true,
        enable_attestation: true, // Enable attestation
    };
    
    let executor = VMExecutor::new(config)
        .await
        .expect("Failed to create executor");
    
    let challenge_spec = create_test_challenge_spec("attestation-test");
    
    let provision_result = executor.provision_cvm(&challenge_spec)
        .await
        .expect("Failed to provision CVM with attestation");
    
    // Verify attestation was performed
    assert!(provision_result.attestation_token.is_some());
    
    let attestation_info = executor.get_vm_attestation(&provision_result.vm_id)
        .await
        .expect("Failed to get attestation info");
    
    assert!(attestation_info.verified);
    assert!(!attestation_info.measurements.is_empty());
    assert_eq!(attestation_info.attestation_type, "tdx");
    
    // Cleanup
    executor.shutdown_vm(&provision_result.vm_id).await.ok();
}

#[tokio::test]
async fn test_concurrent_cvm_provisioning() {
    use futures::future::join_all;
    
    let config = ExecutorConfig {
        max_concurrent_vms: 5,
        vm_timeout_seconds: 300,
        vmm_endpoints: vec![
            "http://localhost:8080".to_string(),
            "http://localhost:8081".to_string(),
        ],
        enable_resource_limits: true,
        enable_network_isolation: true,
        enable_attestation: false,
    };
    
    let executor = Arc::new(
        VMExecutor::new(config)
            .await
            .expect("Failed to create executor")
    );
    
    // Provision multiple CVMs concurrently
    let mut provision_tasks = Vec::new();
    
    for i in 0..5 {
        let executor_clone = executor.clone();
        let challenge_spec = create_test_challenge_spec(&format!("concurrent-{}", i));
        
        provision_tasks.push(tokio::spawn(async move {
            executor_clone.provision_cvm(&challenge_spec).await
        }));
    }
    
    let results = join_all(provision_tasks).await;
    
    // Verify all succeeded
    let mut vm_ids = Vec::new();
    for (i, result) in results.iter().enumerate() {
        let provision_result = result
            .as_ref()
            .expect("Task panicked")
            .as_ref()
            .expect(&format!("Failed to provision VM {}", i));
        
        assert_eq!(provision_result.status, "provisioned");
        vm_ids.push(provision_result.vm_id.clone());
    }
    
    // Verify all VMs are distinct
    let unique_ids: std::collections::HashSet<_> = vm_ids.iter().collect();
    assert_eq!(unique_ids.len(), vm_ids.len());
    
    // Cleanup all VMs
    for vm_id in vm_ids {
        executor.shutdown_vm(&vm_id).await.ok();
    }
}

#[tokio::test]
async fn test_cvm_auto_recovery() {
    let config = ExecutorConfig {
        max_concurrent_vms: 3,
        vm_timeout_seconds: 300,
        vmm_endpoints: vec!["http://localhost:8080".to_string()],
        enable_resource_limits: true,
        enable_network_isolation: true,
        enable_attestation: false,
    };
    
    let executor = VMExecutor::new(config)
        .await
        .expect("Failed to create executor");
    
    let challenge_spec = ChallengeSpec {
        id: Uuid::new_v4(),
        name: "crash-test".to_string(),
        compose_hash: "crash_test_hash".to_string(),
        compose_yaml: r#"
version: '3.8'
services:
  crasher:
    image: alpine:latest
    command: ["sh", "-c", "sleep 5 && exit 1"]
"#.to_string(),
        resources: ResourceRequirements {
            cpu_cores: 1,
            memory_mb: 512,
            disk_gb: 5,
            gpu_required: false,
            gpu_model: None,
            network_bandwidth_mbps: None,
        },
        timeout_seconds: 60,
        max_retries: 3,
    };
    
    let provision_result = executor.provision_cvm(&challenge_spec)
        .await
        .expect("Failed to provision CVM");
    
    let vm_id = provision_result.vm_id.clone();
    
    // Wait for container to crash
    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    
    // Check VM status - should detect unhealthy state
    let status = executor.get_vm_status(&vm_id)
        .await
        .expect("Failed to get VM status");
    
    assert!(status.health.is_unhealthy || status.state == "error");
    
    // Trigger recovery
    let recovery_result = executor.recover_vm(&vm_id)
        .await
        .expect("Failed to recover VM");
    
    assert!(recovery_result.recovered);
    assert_eq!(recovery_result.retry_count, 1);
    
    // Cleanup
    executor.shutdown_vm(&vm_id).await.ok();
}

// Helper functions

fn create_test_challenge_spec(name: &str) -> ChallengeSpec {
    ChallengeSpec {
        id: Uuid::new_v4(),
        name: name.to_string(),
        compose_hash: format!("{}_hash", name),
        compose_yaml: format!(r#"
version: '3.8'
services:
  {}:
    image: alpine:latest
    command: ["sleep", "300"]
    environment:
      - SERVICE_NAME={}
"#, name, name),
        resources: ResourceRequirements {
            cpu_cores: 1,
            memory_mb: 512,
            disk_gb: 5,
            gpu_required: false,
            gpu_model: None,
            network_bandwidth_mbps: None,
        },
        timeout_seconds: 300,
        max_retries: 3,
    }
}
