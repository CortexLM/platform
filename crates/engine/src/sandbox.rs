use crate::{SandboxConfig, EngineResult, EngineError};
use std::collections::BTreeMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};
use platform_engine_executor::{DstackExecutor, TrustedExecutor, RuntimeType};

/// Dstack-based sandbox for secure execution
pub struct Sandbox {
    id: Uuid,
    config: SandboxConfig,
    dstack_executor: DstackExecutor,
    created_at: DateTime<Utc>,
}

/// Sandbox execution result
#[derive(Debug)]
pub struct SandboxResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub execution_time: u64,
    pub resource_usage: ResourceUsage,
}

/// Resource usage during sandbox execution
#[derive(Debug)]
pub struct ResourceUsage {
    pub cpu_time: u64,
    pub memory_peak: u64,
    pub disk_usage: u64,
    pub network_bytes: u64,
}

impl Sandbox {
    pub async fn new(config: SandboxConfig) -> EngineResult<Self> {
        let dstack_executor = DstackExecutor::new().await
        .map_err(|e| EngineError::SandboxError(format!("Failed to create dstack executor: {}", e)))?;

        Ok(Self {
            id: Uuid::new_v4(),
            config,
            dstack_executor,
            created_at: Utc::now(),
        })
    }

    /// Initialize the sandbox using Dstack
    pub async fn initialize(&mut self) -> EngineResult<()> {
        tracing::info!("Initializing Dstack sandbox: {}", self.id);

        // Check if Dstack is available
        if !DstackExecutor::is_dstack_available().await {
            return Err(EngineError::SandboxError("Dstack is not available".to_string()));
        }

        // Dstack executor is already initialized when created

        tracing::info!("Dstack sandbox initialized successfully: {}", self.id);
        Ok(())
    }

    /// Execute command in Dstack sandbox
    pub async fn execute(&self, command: &str, args: &[String]) -> EngineResult<SandboxResult> {
        let start_time = std::time::Instant::now();
        
        tracing::info!("Executing command in Dstack sandbox: {} {}", command, args.join(" "));

        // Create a simple harness bundle for execution
        let harness_bundle = platform_engine_executor::HarnessBundle {
            id: Uuid::new_v4(),
            challenge_id: Uuid::new_v4(),
            digest: "sandbox-harness-digest".to_string(),
            size: 1024,
            image_ref: Some("sandbox:latest".to_string()),
            manifest: Some(format!("#!/bin/bash\n{} {}", command, args.join(" "))),
            config: platform_engine_executor::HarnessConfig {
                runtime: RuntimeType::WasmEnclave,
                resources: platform_engine_executor::ResourceLimits {
                    cpu_cores: 1,
                    memory_mb: 512,
                    disk_mb: 1024,
                    network_bytes: Some(100),
                },
                timeout: 300,
                environment: BTreeMap::new(),
                network_enabled: true,
                attestation_required: true,
            },
            created_at: Utc::now(),
        };

        // Create a dummy submission bundle
        let submission_bundle = platform_engine_executor::SubmissionBundle {
            id: Uuid::new_v4(),
            challenge_id: Uuid::new_v4(),
            miner_hotkey: "sandbox-miner".to_string(),
            digest: "sandbox-submission-digest".to_string(),
            size: 512,
            encrypted: false,
            public_key: Some("sandbox-public-key".to_string()),
            metadata: platform_engine_executor::SubmissionMetadata {
                version: "1.0.0".to_string(),
                tags: vec!["sandbox".to_string()],
                description: Some("Sandbox submission".to_string()),
                author: Some("platform-engine".to_string()),
            },
            created_at: Utc::now(),
        };

        // Execute using Dstack executor
        let eval_result = self.dstack_executor.execute(harness_bundle, submission_bundle).await
            .map_err(|e| EngineError::SandboxError(format!("Dstack execution failed: {}", e)))?;

        let execution_time = start_time.elapsed().as_secs();

        let result = SandboxResult {
            exit_code: if eval_result.error.is_none() { 0 } else { 1 },
            stdout: eval_result.logs.join("\n"),
            stderr: eval_result.error.unwrap_or_default(),
            execution_time,
            resource_usage: ResourceUsage {
                cpu_time: eval_result.resource_usage.cpu_time,
                memory_peak: eval_result.resource_usage.memory_peak,
                disk_usage: eval_result.resource_usage.disk_usage,
                network_bytes: eval_result.resource_usage.network_bytes,
            },
        };

        tracing::info!("Dstack command executed: exit_code={}, time={}s", result.exit_code, execution_time);
        Ok(result)
    }

    /// Clean up Dstack sandbox
    pub async fn cleanup(&mut self) -> EngineResult<()> {
        tracing::info!("Cleaning up Dstack sandbox: {}", self.id);
        
        // Dstack executor handles its own cleanup
        Ok(())
    }

    /// Get Dstack executor metadata
    pub fn get_metadata(&self) -> platform_engine_executor::ExecutorMetadata {
        self.dstack_executor.metadata()
    }

    /// Check if Dstack sandbox is healthy
    pub async fn is_healthy(&self) -> bool {
        self.dstack_executor.is_available().await
    }
}

/// Sandbox configuration extension
impl SandboxConfig {
    pub fn environment(&self) -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    pub fn resource_limits(&self) -> Option<crate::ResourceLimits> {
        None
    }
}

/// Sandbox manager for managing multiple sandboxes
pub struct SandboxManager {
    sandboxes: BTreeMap<Uuid, Sandbox>,
    max_sandboxes: u32,
}

impl SandboxManager {
    pub fn new(max_sandboxes: u32) -> Self {
        Self {
            sandboxes: BTreeMap::new(),
            max_sandboxes,
        }
    }

    pub async fn create_sandbox(&mut self, config: SandboxConfig) -> EngineResult<Uuid> {
        if self.sandboxes.len() >= self.max_sandboxes as usize {
            return Err(EngineError::SandboxError("Maximum sandboxes reached".to_string()));
        }

        let mut sandbox = Sandbox::new(config).await?;
        sandbox.initialize().await?;
        
        let id = sandbox.id;
        self.sandboxes.insert(id, sandbox);
        
        Ok(id)
    }

    pub fn get_sandbox(&self, id: Uuid) -> Option<&Sandbox> {
        self.sandboxes.get(&id)
    }

    pub fn get_sandbox_mut(&mut self, id: Uuid) -> Option<&mut Sandbox> {
        self.sandboxes.get_mut(&id)
    }

    pub async fn destroy_sandbox(&mut self, id: Uuid) -> EngineResult<()> {
        if let Some(mut sandbox) = self.sandboxes.remove(&id) {
            sandbox.cleanup().await?;
        }
        Ok(())
    }

    pub fn list_sandboxes(&self) -> Vec<Uuid> {
        self.sandboxes.keys().cloned().collect()
    }
}
