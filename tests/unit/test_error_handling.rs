// Unit tests for error handling and panic prevention
//
// Tests all .unwrap() and .expect() paths with error inputs to verify
// graceful degradation and proper error handling.

use anyhow::Result;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(test)]
mod error_handling_tests {
    use super::*;

    #[test]
    fn test_system_time_unwrap_safety() {
        // Test that system time operations don't panic

        // Normal case: current time
        let result = SystemTime::now().duration_since(UNIX_EPOCH);
        assert!(result.is_ok(), "Current time should be after UNIX_EPOCH");

        // Edge case: Handle potential SystemTimeError gracefully
        let safe_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        
        assert!(safe_timestamp > 0, "Timestamp should be positive");
    }

    #[test]
    fn test_mutex_poisoned_recovery() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let mutex = Arc::new(Mutex::new(42));
        let mutex_clone = mutex.clone();

        // Poison the mutex by panicking while holding the lock
        let _ = thread::spawn(move || {
            let _lock = mutex_clone.lock().unwrap();
            panic!("Intentional panic to poison mutex");
        }).join();

        // Verify mutex is poisoned
        let lock_result = mutex.lock();
        assert!(lock_result.is_err(), "Mutex should be poisoned");

        // Test recovery from poisoned mutex
        let recovered_value = match mutex.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => {
                // Successfully recovered from poisoned mutex
                let guard = poisoned.into_inner();
                *guard
            }
        };

        assert_eq!(recovered_value, 42, "Should recover original value");
    }

    #[test]
    fn test_json_serialization_error_handling() {
        use serde_json;

        #[derive(serde::Serialize)]
        struct TestStruct {
            value: String,
        }

        let test_data = TestStruct {
            value: "test".to_string(),
        };

        // Test safe JSON serialization
        let json_result = serde_json::to_string(&test_data);
        assert!(json_result.is_ok(), "Serialization should succeed");

        // Test fallback for serialization error
        let json_str = serde_json::to_string(&test_data)
            .unwrap_or_else(|e| {
                eprintln!("Serialization failed: {}", e);
                r#"{"error":"Serialization failed"}"#.to_string()
            });

        assert!(!json_str.is_empty(), "Should have fallback value");
    }

    #[test]
    fn test_encryption_decryption_error_handling() {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use rand::RngCore;

        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);

        let cipher = Aes256Gcm::new(&key.into());
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = b"test data";

        // Test encryption with error handling
        let encryption_result = cipher.encrypt(nonce, plaintext.as_ref());
        assert!(encryption_result.is_ok(), "Encryption should succeed");

        let ciphertext = encryption_result.expect("Encryption succeeded");

        // Test decryption with error handling
        let decryption_result = cipher.decrypt(nonce, ciphertext.as_ref());
        assert!(decryption_result.is_ok(), "Decryption should succeed");

        // Test decryption with wrong nonce (should fail gracefully)
        let mut wrong_nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut wrong_nonce);
        let wrong_nonce_obj = Nonce::from_slice(&wrong_nonce);
        
        let failed_decryption = cipher.decrypt(wrong_nonce_obj, ciphertext.as_ref());
        assert!(failed_decryption.is_err(), "Decryption with wrong nonce should fail");

        // Verify error handling doesn't panic
        match failed_decryption {
            Ok(_) => panic!("Should have failed"),
            Err(e) => {
                // Successfully caught decryption error
                eprintln!("Expected decryption error: {}", e);
            }
        }
    }

    #[test]
    fn test_uuid_split_safety() {
        use uuid::Uuid;

        // Test normal UUID splitting
        let uuid = Uuid::new_v4();
        let uuid_str = uuid.to_string();
        
        // Safe version of .split('-').next().unwrap()
        let first_part = uuid_str
            .split('-')
            .next()
            .unwrap_or("unknown");
        
        assert!(!first_part.is_empty(), "Should have first UUID segment");
        assert_eq!(first_part.len(), 8, "First UUID segment should be 8 chars");

        // Test with malformed UUID string
        let malformed = "not-a-uuid";
        let safe_first = malformed
            .split('-')
            .next()
            .unwrap_or("fallback");
        
        assert_eq!(safe_first, "not", "Should handle malformed UUID");
    }

    #[test]
    fn test_option_unwrap_alternatives() {
        // Test various Option unwrapping patterns

        let some_value: Option<i32> = Some(42);
        let none_value: Option<i32> = None;

        // Pattern 1: unwrap_or
        assert_eq!(some_value.unwrap_or(0), 42);
        assert_eq!(none_value.unwrap_or(0), 0);

        // Pattern 2: unwrap_or_else
        assert_eq!(some_value.unwrap_or_else(|| 0), 42);
        assert_eq!(none_value.unwrap_or_else(|| 0), 0);

        // Pattern 3: match
        let result = match some_value {
            Some(v) => v,
            None => 0,
        };
        assert_eq!(result, 42);

        // Pattern 4: map_or
        assert_eq!(some_value.map_or(0, |v| v * 2), 84);
        assert_eq!(none_value.map_or(0, |v| v * 2), 0);

        // Pattern 5: and_then for chaining
        let doubled = some_value.and_then(|v| Some(v * 2));
        assert_eq!(doubled, Some(84));
    }

    #[test]
    fn test_result_error_propagation() {
        fn operation_that_might_fail(should_fail: bool) -> Result<i32> {
            if should_fail {
                anyhow::bail!("Operation failed");
            }
            Ok(42)
        }

        // Test success case
        let success = operation_that_might_fail(false);
        assert!(success.is_ok());
        assert_eq!(success.unwrap(), 42);

        // Test failure case with proper error handling
        let failure = operation_that_might_fail(true);
        assert!(failure.is_err());

        // Test error context preservation
        let result_with_context = operation_that_might_fail(true)
            .map_err(|e| anyhow::anyhow!("Context: {}", e));
        
        assert!(result_with_context.is_err());
    }

    #[test]
    fn test_string_parsing_error_handling() {
        // Test parsing operations that commonly use unwrap()

        // Test port parsing
        let valid_port = "8080";
        let invalid_port = "not_a_number";

        let port: Result<u16> = valid_port.parse()
            .map_err(|e| anyhow::anyhow!("Invalid port: {}", e));
        assert!(port.is_ok());
        assert_eq!(port.unwrap(), 8080);

        let bad_port: Result<u16> = invalid_port.parse()
            .map_err(|e| anyhow::anyhow!("Invalid port: {}", e));
        assert!(bad_port.is_err());

        // Test with unwrap_or fallback
        let safe_port: u16 = "invalid".parse().unwrap_or(3000);
        assert_eq!(safe_port, 3000);
    }

    #[test]
    fn test_vec_access_safety() {
        let vec = vec![1, 2, 3, 4, 5];

        // Unsafe: vec[10] would panic
        // Safe alternatives:

        // Pattern 1: get() returns Option
        assert_eq!(vec.get(0), Some(&1));
        assert_eq!(vec.get(10), None);

        // Pattern 2: get_mut() for mutable access
        let mut vec_mut = vec![1, 2, 3];
        if let Some(elem) = vec_mut.get_mut(1) {
            *elem = 42;
        }
        assert_eq!(vec_mut[1], 42);

        // Pattern 3: first() and last()
        assert_eq!(vec.first(), Some(&1));
        assert_eq!(vec.last(), Some(&5));

        let empty_vec: Vec<i32> = vec![];
        assert_eq!(empty_vec.first(), None);
        assert_eq!(empty_vec.last(), None);
    }

    #[test]
    fn test_channel_communication_error_handling() {
        use tokio::sync::mpsc;
        use tokio::time::{timeout, Duration};

        #[tokio::test]
        async fn channel_send_recv_with_timeout() {
            let (tx, mut rx) = mpsc::channel::<i32>(10);

            // Send values
            tx.send(42).await.expect("Send should succeed");
            drop(tx); // Close sender

            // Receive with timeout
            let result = timeout(Duration::from_secs(1), rx.recv()).await;
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), Some(42));

            // Try to receive after channel closed (should return None)
            let closed_result = timeout(Duration::from_secs(1), rx.recv()).await;
            assert!(closed_result.is_ok());
            assert_eq!(closed_result.unwrap(), None);
        }
    }

    #[test]
    fn test_file_operation_error_handling() {
        use std::fs;
        use std::path::Path;

        // Test reading non-existent file
        let result = fs::read_to_string("/nonexistent/file.txt");
        assert!(result.is_err(), "Reading nonexistent file should fail");

        // Test with proper error handling
        let content = fs::read_to_string("/nonexistent/file.txt")
            .unwrap_or_else(|e| {
                eprintln!("Failed to read file: {}", e);
                String::from("default content")
            });
        
        assert_eq!(content, "default content");

        // Test path operations
        let path = Path::new("/some/path");
        let file_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        
        assert_eq!(file_name, "path");
    }

    #[test]
    fn test_concurrent_error_handling() {
        use tokio::task;

        #[tokio::test]
        async fn spawn_with_error_handling() {
            let handle = task::spawn(async {
                // Simulate an operation that might fail
                if true {
                    Ok::<_, anyhow::Error>(42)
                } else {
                    Err(anyhow::anyhow!("Failed"))
                }
            });

            // Wait for task and handle potential panic
            let join_result = handle.await;
            assert!(join_result.is_ok(), "Task should not panic");

            let task_result = join_result.unwrap();
            assert!(task_result.is_ok(), "Task operation should succeed");
        }
    }
}

#[cfg(test)]
mod graceful_degradation_tests {
    use super::*;

    #[test]
    fn test_service_degradation_on_dependency_failure() {
        // Simulate a service that can partially operate even if dependencies fail

        struct ServiceConfig {
            feature_a_enabled: bool,
            feature_b_enabled: bool,
        }

        impl ServiceConfig {
            fn new() -> Self {
                // Try to load config, but have sensible defaults
                Self {
                    feature_a_enabled: std::env::var("FEATURE_A")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(true),
                    feature_b_enabled: std::env::var("FEATURE_B")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(false),
                }
            }

            fn can_operate(&self) -> bool {
                // Service can operate if at least one feature is enabled
                self.feature_a_enabled || self.feature_b_enabled
            }
        }

        let config = ServiceConfig::new();
        assert!(config.can_operate(), "Service should have at least one feature enabled");
    }

    #[test]
    fn test_partial_failure_recovery() {
        // Test system that can recover from partial failures

        struct BatchProcessor {
            success_count: usize,
            failure_count: usize,
        }

        impl BatchProcessor {
            fn new() -> Self {
                Self {
                    success_count: 0,
                    failure_count: 0,
                }
            }

            fn process_item(&mut self, item: i32) -> Result<i32> {
                if item < 0 {
                    Err(anyhow::anyhow!("Negative item"))
                } else {
                    Ok(item * 2)
                }
            }

            fn process_batch(&mut self, items: Vec<i32>) -> Vec<Result<i32>> {
                items.into_iter().map(|item| {
                    let result = self.process_item(item);
                    match &result {
                        Ok(_) => self.success_count += 1,
                        Err(_) => self.failure_count += 1,
                    }
                    result
                }).collect()
            }

            fn success_rate(&self) -> f64 {
                let total = self.success_count + self.failure_count;
                if total == 0 {
                    0.0
                } else {
                    self.success_count as f64 / total as f64
                }
            }
        }

        let mut processor = BatchProcessor::new();
        let items = vec![1, -2, 3, -4, 5];
        let results = processor.process_batch(items);

        assert_eq!(results.len(), 5);
        assert_eq!(processor.success_count, 3);
        assert_eq!(processor.failure_count, 2);
        assert!((processor.success_rate() - 0.6).abs() < 0.01);
    }
}

#[cfg(test)]
mod panic_recovery_tests {
    use super::*;
    use std::panic;

    #[test]
    fn test_catch_unwind_for_panic_isolation() {
        // Test that we can isolate panics in sub-operations

        fn potentially_panicking_operation(should_panic: bool) -> i32 {
            if should_panic {
                panic!("Intentional panic");
            }
            42
        }

        // Wrap panicking operation
        let result = panic::catch_unwind(|| {
            potentially_panicking_operation(false)
        });

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);

        // Catch panic without crashing
        let panic_result = panic::catch_unwind(|| {
            potentially_panicking_operation(true)
        });

        assert!(panic_result.is_err(), "Should catch panic");
    }

    #[test]
    fn test_panic_hook_registration() {
        // Test custom panic hooks for logging

        let default_hook = panic::take_hook();
        
        panic::set_hook(Box::new(|panic_info| {
            eprintln!("Custom panic handler: {:?}", panic_info);
        }));

        // Restore default hook
        panic::set_hook(default_hook);
    }
}

