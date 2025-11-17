// Unit tests for concurrency, race conditions, and deadlock prevention
//
// Tests concurrent access to shared state, validates proper locking,
// and detects potential race conditions and deadlocks.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::{Semaphore, RwLock as TokioRwLock};
use tokio::time::timeout;

#[cfg(test)]
mod race_condition_tests {
    use super::*;

    #[tokio::test]
    async fn test_concurrent_hashmap_updates() {
        use std::collections::HashMap;
        use tokio::task;

        // Test that concurrent HashMap updates don't cause data races
        let map = Arc::new(TokioRwLock::new(HashMap::<String, i32>::new()));
        let mut handles = vec![];

        // Spawn 10 tasks that update the map concurrently
        for i in 0..10 {
            let map_clone = map.clone();
            let handle = task::spawn(async move {
                let mut write_guard = map_clone.write().await;
                write_guard.insert(format!("key_{}", i), i);
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.expect("Task should not panic");
        }

        // Verify all keys were inserted
        let read_guard = map.read().await;
        assert_eq!(read_guard.len(), 10, "All 10 keys should be inserted");
        
        for i in 0..10 {
            let key = format!("key_{}", i);
            assert_eq!(read_guard.get(&key), Some(&i), "Key {} should exist", key);
        }
    }

    #[tokio::test]
    async fn test_atomic_multi_map_updates() {
        use std::collections::HashMap;

        // Simulate the ChallengeManager's multiple related maps
        struct ChallengeState {
            challenges: HashMap<String, String>,
            challenges_by_name: HashMap<String, String>,
        }

        let state = Arc::new(TokioRwLock::new(ChallengeState {
            challenges: HashMap::new(),
            challenges_by_name: HashMap::new(),
        }));

        // Test atomic update of both maps
        {
            let mut guard = state.write().await;
            let hash = "hash_001";
            let name = "test_challenge";
            
            guard.challenges.insert(hash.to_string(), name.to_string());
            guard.challenges_by_name.insert(name.to_string(), hash.to_string());
        }

        // Verify consistency
        let guard = state.read().await;
        assert_eq!(guard.challenges.get("hash_001"), Some(&"test_challenge".to_string()));
        assert_eq!(guard.challenges_by_name.get("test_challenge"), Some(&"hash_001".to_string()));
    }

    #[tokio::test]
    async fn test_write_lock_not_held_across_await() {
        use std::collections::HashMap;

        let data = Arc::new(TokioRwLock::new(HashMap::<String, i32>::new()));

        // CORRECT: Acquire lock, get data, release lock, then await
        async fn process_with_lock_released(data: Arc<TokioRwLock<HashMap<String, i32>>>) {
            let value = {
                let guard = data.read().await;
                guard.get("key").copied()
            }; // Lock released here

            // Safe to await here without holding lock
            tokio::time::sleep(Duration::from_millis(10)).await;

            if let Some(v) = value {
                println!("Processed: {}", v);
            }
        }

        {
            let mut guard = data.write().await;
            guard.insert("key".to_string(), 42);
        }

        process_with_lock_released(data).await;
    }

    #[tokio::test]
    async fn test_concurrent_reads_exclusive_writes() {
        let data = Arc::new(TokioRwLock::new(vec![1, 2, 3, 4, 5]));
        let mut handles = vec![];

        // Spawn multiple readers
        for _ in 0..5 {
            let data_clone = data.clone();
            let handle = tokio::spawn(async move {
                let guard = data_clone.read().await;
                let sum: i32 = guard.iter().sum();
                sum
            });
            handles.push(handle);
        }

        // All readers should complete successfully
        for handle in handles {
            let sum = handle.await.expect("Read task should complete");
            assert_eq!(sum, 15);
        }

        // Now do an exclusive write
        {
            let mut guard = data.write().await;
            guard.push(6);
        }

        // Verify write succeeded
        let guard = data.read().await;
        assert_eq!(guard.len(), 6);
    }

    #[tokio::test]
    async fn test_semaphore_concurrent_limit() {
        // Test that semaphore properly limits concurrency
        let semaphore = Arc::new(Semaphore::new(3));
        let counter = Arc::new(TokioRwLock::new(0));
        let max_concurrent = Arc::new(TokioRwLock::new(0));
        let mut handles = vec![];

        for _ in 0..10 {
            let sem = semaphore.clone();
            let counter_clone = counter.clone();
            let max_clone = max_concurrent.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.expect("Semaphore acquire failed");
                
                // Increment current counter
                {
                    let mut c = counter_clone.write().await;
                    *c += 1;
                    
                    // Update max if current is higher
                    let mut m = max_clone.write().await;
                    if *c > *m {
                        *m = *c;
                    }
                }

                // Simulate work
                tokio::time::sleep(Duration::from_millis(10)).await;

                // Decrement counter
                {
                    let mut c = counter_clone.write().await;
                    *c -= 1;
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks
        for handle in handles {
            handle.await.expect("Task should complete");
        }

        // Verify no more than 3 ran concurrently
        let max = *max_concurrent.read().await;
        assert!(max <= 3, "At most 3 tasks should run concurrently, got {}", max);
    }

    #[tokio::test]
    async fn test_no_deadlock_with_multiple_locks() {
        // Test that acquiring multiple locks in consistent order prevents deadlocks
        let lock_a = Arc::new(TokioRwLock::new(0));
        let lock_b = Arc::new(TokioRwLock::new(0));

        let lock_a1 = lock_a.clone();
        let lock_b1 = lock_b.clone();
        let handle1 = tokio::spawn(async move {
            // Always acquire in order: A then B
            let _guard_a = lock_a1.write().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
            let _guard_b = lock_b1.write().await;
            // Do work
        });

        let lock_a2 = lock_a.clone();
        let lock_b2 = lock_b.clone();
        let handle2 = tokio::spawn(async move {
            // Same order: A then B
            let _guard_a = lock_a2.write().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
            let _guard_b = lock_b2.write().await;
            // Do work
        });

        // Both tasks should complete without deadlock
        let result1 = timeout(Duration::from_secs(2), handle1).await;
        let result2 = timeout(Duration::from_secs(2), handle2).await;

        assert!(result1.is_ok(), "Task 1 should not timeout");
        assert!(result2.is_ok(), "Task 2 should not timeout");
    }

    #[tokio::test]
    async fn test_channel_concurrent_send_recv() {
        use tokio::sync::mpsc;

        let (tx, mut rx) = mpsc::channel::<i32>(100);

        // Spawn sender tasks
        let mut send_handles = vec![];
        for i in 0..10 {
            let tx_clone = tx.clone();
            let handle = tokio::spawn(async move {
                tx_clone.send(i).await.expect("Send should succeed");
            });
            send_handles.push(handle);
        }

        // Drop original sender
        drop(tx);

        // Wait for all senders
        for handle in send_handles {
            handle.await.expect("Send task should complete");
        }

        // Collect all messages
        let mut received = vec![];
        while let Some(msg) = rx.recv().await {
            received.push(msg);
        }

        // Verify all messages received
        received.sort();
        assert_eq!(received, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }
}

#[cfg(test)]
mod stress_tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_high_concurrency_hashmap_access() {
        // Stress test with high concurrency
        let map = Arc::new(TokioRwLock::new(HashMap::<usize, usize>::new()));
        let mut handles = vec![];

        // Initialize map
        {
            let mut guard = map.write().await;
            for i in 0..100 {
                guard.insert(i, i * 2);
            }
        }

        // Spawn many readers
        for _ in 0..50 {
            let map_clone = map.clone();
            let handle = tokio::spawn(async move {
                for _ in 0..100 {
                    let guard = map_clone.read().await;
                    let _sum: usize = guard.values().sum();
                }
            });
            handles.push(handle);
        }

        // Spawn some writers
        for i in 0..10 {
            let map_clone = map.clone();
            let handle = tokio::spawn(async move {
                for j in 0..10 {
                    let mut guard = map_clone.write().await;
                    guard.insert(100 + i * 10 + j, j);
                }
            });
            handles.push(handle);
        }

        // All tasks should complete without deadlock
        for handle in handles {
            timeout(Duration::from_secs(30), handle)
                .await
                .expect("Task should complete within timeout")
                .expect("Task should not panic");
        }

        // Verify final state
        let guard = map.read().await;
        assert!(guard.len() >= 100, "Map should have at least 100 entries");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_batch_evaluator() {
        // Simulate the BatchEvaluator pattern from the codebase
        struct BatchEvaluator {
            evaluator: Arc<TokioRwLock<HashMap<String, i32>>>,
            semaphore: Arc<Semaphore>,
        }

        impl BatchEvaluator {
            fn new(max_concurrent: usize) -> Self {
                Self {
                    evaluator: Arc::new(TokioRwLock::new(HashMap::new())),
                    semaphore: Arc::new(Semaphore::new(max_concurrent)),
                }
            }

            async fn evaluate(&self, id: String, value: i32) -> Result<i32, String> {
                let _permit = self.semaphore.acquire().await
                    .map_err(|_| "Semaphore closed".to_string())?;

                // IMPROVED: Don't hold write lock across async work
                // Instead, do work, then update
                tokio::time::sleep(Duration::from_millis(10)).await;
                
                {
                    let mut guard = self.evaluator.write().await;
                    guard.insert(id, value);
                }

                Ok(value * 2)
            }
        }

        let evaluator = BatchEvaluator::new(5);
        let mut handles = vec![];

        // Spawn many evaluation tasks
        for i in 0..20 {
            let id = format!("task_{}", i);
            let eval = BatchEvaluator {
                evaluator: evaluator.evaluator.clone(),
                semaphore: evaluator.semaphore.clone(),
            };

            let handle = tokio::spawn(async move {
                eval.evaluate(id, i).await
            });
            handles.push(handle);
        }

        // All evaluations should complete
        for handle in handles {
            let result = handle.await.expect("Task should complete");
            assert!(result.is_ok(), "Evaluation should succeed");
        }

        // Verify all results stored
        let guard = evaluator.evaluator.read().await;
        assert_eq!(guard.len(), 20);
    }
}

#[cfg(test)]
mod lock_ordering_tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_consistent_lock_ordering() {
        // Test that all code paths acquire locks in the same order
        struct Service {
            users: Arc<TokioRwLock<HashMap<String, i32>>>,
            sessions: Arc<TokioRwLock<HashMap<String, String>>>,
        }

        impl Service {
            fn new() -> Self {
                Self {
                    users: Arc::new(TokioRwLock::new(HashMap::new())),
                    sessions: Arc::new(TokioRwLock::new(HashMap::new())),
                }
            }

            // CORRECT: Always acquire locks in order: users, then sessions
            async fn create_session(&self, user_id: String, session_id: String) {
                let mut users = self.users.write().await;
                let mut sessions = self.sessions.write().await;
                
                users.insert(user_id.clone(), 1);
                sessions.insert(session_id, user_id);
            }

            // CORRECT: Same order
            async fn validate_session(&self, session_id: String) -> bool {
                let users = self.users.read().await;
                let sessions = self.sessions.read().await;
                
                if let Some(user_id) = sessions.get(&session_id) {
                    users.contains_key(user_id)
                } else {
                    false
                }
            }
        }

        let service = Service::new();
        
        // Create sessions concurrently
        let mut handles = vec![];
        for i in 0..10 {
            let svc = Service {
                users: service.users.clone(),
                sessions: service.sessions.clone(),
            };
            let handle = tokio::spawn(async move {
                let user_id = format!("user_{}", i);
                let session_id = format!("session_{}", i);
                svc.create_session(user_id, session_id).await;
            });
            handles.push(handle);
        }

        // Wait for all
        for handle in handles {
            timeout(Duration::from_secs(5), handle)
                .await
                .expect("Should not deadlock")
                .expect("Task should complete");
        }

        // Validate sessions concurrently
        let mut handles = vec![];
        for i in 0..10 {
            let svc = Service {
                users: service.users.clone(),
                sessions: service.sessions.clone(),
            };
            let handle = tokio::spawn(async move {
                let session_id = format!("session_{}", i);
                svc.validate_session(session_id).await
            });
            handles.push(handle);
        }

        for handle in handles {
            let result = timeout(Duration::from_secs(5), handle)
                .await
                .expect("Should not deadlock")
                .expect("Task should complete");
            assert!(result, "Session should be valid");
        }
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;

    #[tokio::test]
    async fn test_operation_with_timeout() {
        async fn slow_operation() -> Result<i32, &'static str> {
            tokio::time::sleep(Duration::from_secs(2)).await;
            Ok(42)
        }

        // Test timeout
        let result = timeout(Duration::from_millis(100), slow_operation()).await;
        assert!(result.is_err(), "Should timeout");

        // Test success within timeout
        async fn fast_operation() -> Result<i32, &'static str> {
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok(42)
        }

        let result = timeout(Duration::from_secs(1), fast_operation()).await;
        assert!(result.is_ok(), "Should complete");
        assert_eq!(result.unwrap().unwrap(), 42);
    }

    #[tokio::test]
    async fn test_graceful_timeout_handling() {
        use tokio::select;

        async fn cancelable_operation() -> i32 {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                // Check if cancelled periodically
                tokio::task::yield_now().await;
            }
        }

        let timeout_duration = Duration::from_millis(250);
        
        let result = select! {
            _ = cancelable_operation() => panic!("Should not complete"),
            _ = tokio::time::sleep(timeout_duration) => "timeout",
        };

        assert_eq!(result, "timeout");
    }
}

#[cfg(test)]
mod mutex_poison_tests {
    use super::*;
    use std::panic;

    #[test]
    fn test_mutex_poison_recovery() {
        let mutex = Arc::new(Mutex::new(vec![1, 2, 3]));
        let mutex_clone = mutex.clone();

        // Poison the mutex
        let _ = std::thread::spawn(move || {
            let mut guard = mutex_clone.lock().unwrap();
            guard.push(4);
            panic!("Intentional panic");
        }).join();

        // Recover from poisoned mutex
        let recovered_data = match mutex.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => {
                eprintln!("Mutex poisoned, recovering data");
                let guard = poisoned.into_inner();
                guard.clone()
            }
        };

        assert_eq!(recovered_data, vec![1, 2, 3, 4]);
    }
}

#[cfg(test)]
mod memory_safety_tests {
    use super::*;

    #[tokio::test]
    async fn test_arc_reference_cycles() {
        // Test that we don't create reference cycles with Arc
        use std::sync::Weak;

        struct Node {
            value: i32,
            parent: Option<Weak<TokioRwLock<Node>>>,
            children: Vec<Arc<TokioRwLock<Node>>>,
        }

        let root = Arc::new(TokioRwLock::new(Node {
            value: 1,
            parent: None,
            children: vec![],
        }));

        let child = Arc::new(TokioRwLock::new(Node {
            value: 2,
            parent: Some(Arc::downgrade(&root)),
            children: vec![],
        }));

        {
            let mut root_guard = root.write().await;
            root_guard.children.push(child.clone());
        }

        // Verify no reference cycle (both should be droppable)
        assert_eq!(Arc::strong_count(&root), 1);
        assert_eq!(Arc::strong_count(&child), 2); // root holds one reference
    }
}

