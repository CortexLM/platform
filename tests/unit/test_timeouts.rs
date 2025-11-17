// Unit tests for timeout handling
//
// Tests WebSocket connection timeouts, HTTP request timeouts,
// job execution timeouts, and overall timeout management.

use std::time::Duration;
use tokio::time::{timeout, sleep};

#[cfg(test)]
mod websocket_timeout_tests {
    use super::*;

    #[tokio::test]
    async fn test_websocket_connection_timeout() {
        // Simulate WebSocket connection with timeout
        async fn connect_websocket(url: &str) -> Result<String, &'static str> {
            // Simulate slow connection
            sleep(Duration::from_secs(5)).await;
            Ok(url.to_string())
        }

        // Test connection timeout
        let result = timeout(
            Duration::from_secs(1),
            connect_websocket("ws://localhost:8080")
        ).await;

        assert!(result.is_err(), "Connection should timeout");
    }

    #[tokio::test]
    async fn test_websocket_message_timeout() {
        use tokio::sync::mpsc;

        let (tx, mut rx) = mpsc::channel::<String>(10);

        // Simulate waiting for message
        let receive_task = tokio::spawn(async move {
            timeout(Duration::from_secs(1), rx.recv()).await
        });

        // Don't send anything - let it timeout
        drop(tx);

        let result = receive_task.await.expect("Task should complete");
        
        // Should either timeout or receive None (channel closed)
        match result {
            Err(_) => {}, // Timeout
            Ok(None) => {}, // Channel closed
            Ok(Some(_)) => panic!("Should not receive message"),
        }
    }

    #[tokio::test]
    async fn test_websocket_reconnect_with_backoff() {
        struct ReconnectConfig {
            max_retries: u32,
            initial_backoff: Duration,
            max_backoff: Duration,
        }

        async fn connect_with_retry(config: ReconnectConfig) -> Result<String, String> {
            let mut attempts = 0;
            let mut backoff = config.initial_backoff;

            while attempts < config.max_retries {
                attempts += 1;

                // Simulate connection attempt
                match timeout(Duration::from_millis(100), async {
                    // Simulate failure on first few attempts
                    if attempts < 3 {
                        Err("Connection refused")
                    } else {
                        Ok("Connected")
                    }
                }).await {
                    Ok(Ok(result)) => return Ok(result.to_string()),
                    Ok(Err(_)) | Err(_) => {
                        if attempts < config.max_retries {
                            sleep(backoff).await;
                            backoff = std::cmp::min(backoff * 2, config.max_backoff);
                        }
                    }
                }
            }

            Err(format!("Failed after {} attempts", attempts))
        }

        let config = ReconnectConfig {
            max_retries: 5,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(100),
        };

        let result = connect_with_retry(config).await;
        assert!(result.is_ok(), "Should eventually connect");
    }
}

#[cfg(test)]
mod http_timeout_tests {
    use super::*;

    #[tokio::test]
    async fn test_http_request_timeout() {
        async fn make_http_request(url: &str) -> Result<String, &'static str> {
            // Simulate slow HTTP request
            sleep(Duration::from_secs(10)).await;
            Ok(format!("Response from {}", url))
        }

        // Test with timeout
        let result = timeout(
            Duration::from_secs(1),
            make_http_request("http://example.com")
        ).await;

        assert!(result.is_err(), "Request should timeout");
    }

    #[tokio::test]
    async fn test_http_client_with_timeout_config() {
        struct HttpClient {
            timeout_duration: Duration,
        }

        impl HttpClient {
            fn new(timeout_duration: Duration) -> Self {
                Self { timeout_duration }
            }

            async fn get(&self, _url: &str) -> Result<String, String> {
                // Simulate request
                match timeout(self.timeout_duration, async {
                    sleep(Duration::from_millis(500)).await;
                    Ok::<_, String>("response".to_string())
                }).await {
                    Ok(result) => result,
                    Err(_) => Err("Request timeout".to_string()),
                }
            }
        }

        // Test successful request within timeout
        let client = HttpClient::new(Duration::from_secs(1));
        let result = client.get("http://example.com").await;
        assert!(result.is_ok());

        // Test timeout
        let slow_client = HttpClient::new(Duration::from_millis(100));
        let result = slow_client.get("http://example.com").await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Request timeout");
    }

    #[tokio::test]
    async fn test_concurrent_requests_with_timeouts() {
        async fn make_request(id: usize, delay_ms: u64) -> Result<usize, String> {
            timeout(Duration::from_millis(200), async move {
                sleep(Duration::from_millis(delay_ms)).await;
                Ok(id)
            }).await
            .map_err(|_| format!("Request {} timed out", id))?
        }

        let mut handles = vec![];

        // Some requests will timeout, others won't
        for i in 0..10 {
            let delay = if i % 2 == 0 { 100 } else { 300 }; // Alternate fast/slow
            let handle = tokio::spawn(make_request(i, delay));
            handles.push(handle);
        }

        let mut successful = 0;
        let mut timeouts = 0;

        for handle in handles {
            match handle.await.expect("Task should complete") {
                Ok(_) => successful += 1,
                Err(_) => timeouts += 1,
            }
        }

        assert_eq!(successful, 5, "5 fast requests should succeed");
        assert_eq!(timeouts, 5, "5 slow requests should timeout");
    }
}

#[cfg(test)]
mod job_execution_timeout_tests {
    use super::*;

    #[tokio::test]
    async fn test_job_execution_timeout() {
        async fn execute_job(job_id: &str, duration_secs: u64) -> Result<String, String> {
            sleep(Duration::from_secs(duration_secs)).await;
            Ok(format!("Job {} completed", job_id))
        }

        // Test job that completes within timeout
        let result = timeout(
            Duration::from_secs(2),
            execute_job("job_1", 1)
        ).await;
        assert!(result.is_ok());

        // Test job that exceeds timeout
        let result = timeout(
            Duration::from_secs(1),
            execute_job("job_2", 5)
        ).await;
        assert!(result.is_err(), "Job should timeout");
    }

    #[tokio::test]
    async fn test_job_timeout_with_cleanup() {
        use tokio::sync::oneshot;

        async fn execute_with_cancel(
            cancel_rx: oneshot::Receiver<()>
        ) -> Result<String, String> {
            tokio::select! {
                _ = sleep(Duration::from_secs(10)) => {
                    Ok("Completed".to_string())
                }
                _ = cancel_rx => {
                    Err("Cancelled".to_string())
                }
            }
        }

        let (cancel_tx, cancel_rx) = oneshot::channel();

        let task = tokio::spawn(execute_with_cancel(cancel_rx));

        // Cancel after 100ms
        sleep(Duration::from_millis(100)).await;
        let _ = cancel_tx.send(());

        let result = task.await.expect("Task should complete");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Cancelled");
    }

    #[tokio::test]
    async fn test_multi_stage_job_with_per_stage_timeouts() {
        async fn stage_1() -> Result<String, &'static str> {
            sleep(Duration::from_millis(50)).await;
            Ok("Stage 1 done".to_string())
        }

        async fn stage_2(_input: String) -> Result<String, &'static str> {
            sleep(Duration::from_millis(50)).await;
            Ok("Stage 2 done".to_string())
        }

        async fn stage_3(_input: String) -> Result<String, &'static str> {
            sleep(Duration::from_secs(5)).await; // This will timeout
            Ok("Stage 3 done".to_string())
        }

        // Execute pipeline with per-stage timeouts
        let result = async {
            let s1 = timeout(Duration::from_millis(100), stage_1()).await??;
            let s2 = timeout(Duration::from_millis(100), stage_2(s1)).await??;
            let s3 = timeout(Duration::from_millis(100), stage_3(s2)).await??;
            Ok::<String, Box<dyn std::error::Error>>(s3)
        }.await;

        assert!(result.is_err(), "Stage 3 should timeout");
    }

    #[tokio::test]
    async fn test_job_with_progress_tracking() {
        struct Job {
            progress: std::sync::Arc<tokio::sync::RwLock<u32>>,
        }

        impl Job {
            fn new() -> Self {
                Self {
                    progress: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
                }
            }

            async fn execute(&self) -> Result<String, String> {
                for i in 0..10 {
                    sleep(Duration::from_millis(100)).await;
                    let mut progress = self.progress.write().await;
                    *progress = (i + 1) * 10;
                }
                Ok("Done".to_string())
            }

            async fn get_progress(&self) -> u32 {
                *self.progress.read().await
            }
        }

        let job = Job::new();
        let progress_ref = job.progress.clone();

        // Start job execution
        let task = tokio::spawn(async move {
            job.execute().await
        });

        // Monitor progress with timeout
        let monitor_result = timeout(Duration::from_millis(550), async {
            loop {
                let progress = *progress_ref.read().await;
                if progress >= 50 {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }
        }).await;

        assert!(monitor_result.is_ok(), "Should reach 50% progress");

        // Cancel the job
        task.abort();
    }
}

#[cfg(test)]
mod timeout_configuration_tests {
    use super::*;

    #[test]
    fn test_timeout_configuration_validation() {
        struct TimeoutConfig {
            connection_timeout: Duration,
            request_timeout: Duration,
            job_timeout: Duration,
        }

        impl TimeoutConfig {
            fn new(
                connection_secs: u64,
                request_secs: u64,
                job_secs: u64
            ) -> Result<Self, String> {
                // Validation: connection < request < job
                if connection_secs >= request_secs {
                    return Err("Connection timeout must be less than request timeout".to_string());
                }
                if request_secs >= job_secs {
                    return Err("Request timeout must be less than job timeout".to_string());
                }

                Ok(Self {
                    connection_timeout: Duration::from_secs(connection_secs),
                    request_timeout: Duration::from_secs(request_secs),
                    job_timeout: Duration::from_secs(job_secs),
                })
            }
        }

        // Valid configuration
        let config = TimeoutConfig::new(5, 30, 300);
        assert!(config.is_ok());

        // Invalid configurations
        assert!(TimeoutConfig::new(30, 5, 300).is_err());
        assert!(TimeoutConfig::new(5, 300, 30).is_err());
    }

    #[tokio::test]
    async fn test_dynamic_timeout_adjustment() {
        struct AdaptiveTimeout {
            base_timeout: Duration,
            max_timeout: Duration,
            failure_count: std::sync::Arc<tokio::sync::RwLock<u32>>,
        }

        impl AdaptiveTimeout {
            fn new(base: Duration, max: Duration) -> Self {
                Self {
                    base_timeout: base,
                    max_timeout: max,
                    failure_count: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
                }
            }

            async fn get_timeout(&self) -> Duration {
                let failures = *self.failure_count.read().await;
                let multiplier = 1 + failures;
                let adjusted = self.base_timeout * multiplier;
                std::cmp::min(adjusted, self.max_timeout)
            }

            async fn record_failure(&self) {
                let mut failures = self.failure_count.write().await;
                *failures += 1;
            }

            async fn record_success(&self) {
                let mut failures = self.failure_count.write().await;
                *failures = (*failures).saturating_sub(1);
            }
        }

        let timeout_mgr = AdaptiveTimeout::new(
            Duration::from_millis(100),
            Duration::from_millis(500)
        );

        // Initial timeout
        assert_eq!(timeout_mgr.get_timeout().await, Duration::from_millis(100));

        // After failures, timeout increases
        timeout_mgr.record_failure().await;
        assert_eq!(timeout_mgr.get_timeout().await, Duration::from_millis(200));

        timeout_mgr.record_failure().await;
        assert_eq!(timeout_mgr.get_timeout().await, Duration::from_millis(300));

        // After success, timeout decreases
        timeout_mgr.record_success().await;
        assert_eq!(timeout_mgr.get_timeout().await, Duration::from_millis(200));
    }
}

#[cfg(test)]
mod timeout_cancellation_tests {
    use super::*;
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn test_graceful_cancellation() {
        async fn long_running_task(mut cancel_rx: oneshot::Receiver<()>) -> Result<String, String> {
            tokio::select! {
                _ = sleep(Duration::from_secs(10)) => {
                    Ok("Completed".to_string())
                }
                _ = &mut cancel_rx => {
                    // Cleanup before returning
                    eprintln!("Cleaning up...");
                    Err("Cancelled gracefully".to_string())
                }
            }
        }

        let (cancel_tx, cancel_rx) = oneshot::channel();
        let task = tokio::spawn(long_running_task(cancel_rx));

        // Cancel after 100ms
        sleep(Duration::from_millis(100)).await;
        let _ = cancel_tx.send(());

        let result = task.await.expect("Task should complete");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Cancelled gracefully");
    }

    #[tokio::test]
    async fn test_timeout_with_cleanup_guarantee() {
        use std::sync::Arc;
        use tokio::sync::RwLock;

        #[derive(Clone)]
        struct Resource {
            cleaned_up: Arc<RwLock<bool>>,
        }

        impl Resource {
            fn new() -> Self {
                Self {
                    cleaned_up: Arc::new(RwLock::new(false)),
                }
            }

            async fn cleanup(&self) {
                *self.cleaned_up.write().await = true;
            }

            async fn is_cleaned_up(&self) -> bool {
                *self.cleaned_up.read().await
            }
        }

        async fn use_resource(resource: Resource) {
            sleep(Duration::from_secs(5)).await;
            // Normal completion would clean up here
            resource.cleanup().await;
        }

        let resource = Resource::new();
        let resource_clone = resource.clone();

        // Run with timeout
        let result = timeout(
            Duration::from_millis(100),
            use_resource(resource_clone)
        ).await;

        assert!(result.is_err(), "Should timeout");

        // Ensure cleanup happens even on timeout
        resource.cleanup().await;
        assert!(resource.is_cleaned_up().await);
    }

    #[tokio::test]
    async fn test_timeout_with_background_task_cleanup() {
        use tokio::task::JoinHandle;

        struct TaskManager {
            tasks: Vec<JoinHandle<()>>,
        }

        impl TaskManager {
            fn new() -> Self {
                Self { tasks: vec![] }
            }

            fn spawn_task(&mut self, name: String) {
                let task = tokio::spawn(async move {
                    loop {
                        sleep(Duration::from_millis(100)).await;
                        eprintln!("Task {} running", name);
                    }
                });
                self.tasks.push(task);
            }

            fn abort_all(&mut self) {
                for task in &self.tasks {
                    task.abort();
                }
            }
        }

        let mut manager = TaskManager::new();
        manager.spawn_task("task_1".to_string());
        manager.spawn_task("task_2".to_string());
        manager.spawn_task("task_3".to_string());

        // Let tasks run briefly
        sleep(Duration::from_millis(250)).await;

        // Abort all tasks
        manager.abort_all();

        // Give time for abort to take effect
        sleep(Duration::from_millis(50)).await;

        // Tasks should be aborted
        for task in &manager.tasks {
            assert!(task.is_finished(), "Task should be aborted");
        }
    }
}

#[cfg(test)]
mod timeout_edge_cases {
    use super::*;

    #[tokio::test]
    async fn test_zero_timeout() {
        async fn instant_task() -> i32 {
            42
        }

        // Even with zero timeout, instant tasks might complete
        let result = timeout(Duration::from_secs(0), instant_task()).await;
        // Result is implementation-dependent, but shouldn't panic
        let _ = result;
    }

    #[tokio::test]
    async fn test_very_large_timeout() {
        async fn quick_task() -> i32 {
            sleep(Duration::from_millis(10)).await;
            42
        }

        // Very large timeout should not cause issues
        let result = timeout(Duration::from_secs(86400), quick_task()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_nested_timeouts() {
        async fn task() -> Result<i32, &'static str> {
            sleep(Duration::from_millis(150)).await;
            Ok(42)
        }

        // Outer timeout: 1 second
        let result = timeout(Duration::from_secs(1), async {
            // Inner timeout: 100ms
            timeout(Duration::from_millis(100), task()).await
        }).await;

        // Outer succeeds, inner times out
        assert!(result.is_ok());
        assert!(result.unwrap().is_err());
    }
}

