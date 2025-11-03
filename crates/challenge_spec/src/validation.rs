use crate::{ChallengeSpec, ChallengeSpecError, ChallengeSpecResult};
use validator::Validate;

/// Validation utilities for challenge specifications
pub struct ChallengeValidator;

impl ChallengeValidator {
    /// Validate a challenge specification
    pub fn validate(spec: &ChallengeSpec) -> ChallengeSpecResult<()> {
        // Validate the spec using the Validate trait
        spec.validate().map_err(|e| ChallengeSpecError::ValidationError(e.to_string()))?;
        
        // Additional custom validations
        Self::validate_runtime_compatibility(spec)?;
        Self::validate_resource_limits(spec)?;
        Self::validate_evaluation_spec(spec)?;
        Self::validate_datasets(spec)?;
        
        Ok(())
    }
    
    /// Validate runtime compatibility
    fn validate_runtime_compatibility(spec: &ChallengeSpec) -> ChallengeSpecResult<()> {
        // Check if the runtime supports the required features
        if spec.attestation_required && !spec.runtime.requires_attestation() {
            return Err(ChallengeSpecError::InvalidRuntime(
                format!("Runtime {:?} does not support attestation", spec.runtime)
            ));
        }
        
        if spec.network_enabled && !spec.runtime.supports_network() {
            return Err(ChallengeSpecError::InvalidRuntime(
                format!("Runtime {:?} does not support network access", spec.runtime)
            ));
        }
        
        Ok(())
    }
    
    /// Validate resource limits
    fn validate_resource_limits(spec: &ChallengeSpec) -> ChallengeSpecResult<()> {
        // Check if resource limits are reasonable for the runtime
        let max_memory = spec.runtime.get_default_memory_mb() * 2;
        if spec.resources.memory_mb > max_memory as u64 {
            return Err(ChallengeSpecError::InvalidResourceSpec(
                format!("Memory limit {}MB exceeds maximum {}MB for runtime {:?}", 
                    spec.resources.memory_mb, max_memory, spec.runtime)
            ));
        }
        
        let max_cpu = spec.runtime.get_default_cpu_cores() * 2;
        if spec.resources.cpu_cores > max_cpu {
            return Err(ChallengeSpecError::InvalidResourceSpec(
                format!("CPU cores {} exceeds maximum {} for runtime {:?}", 
                    spec.resources.cpu_cores, max_cpu, spec.runtime)
            ));
        }
        
        // Check timeout limits
        let max_timeout = spec.runtime.get_default_timeout() * 2;
        if spec.timeout > max_timeout as u64 {
            return Err(ChallengeSpecError::InvalidResourceSpec(
                format!("Timeout {}s exceeds maximum {}s for runtime {:?}", 
                    spec.timeout, max_timeout, spec.runtime)
            ));
        }
        
        Ok(())
    }
    
    /// Validate evaluation specification
    fn validate_evaluation_spec(spec: &ChallengeSpec) -> ChallengeSpecResult<()> {
        // Check if weights sum to 1.0 (approximately)
        let total_weight: f64 = spec.evaluation.weights.values().sum();
        if (total_weight - 1.0).abs() > 0.01 {
            return Err(ChallengeSpecError::InvalidEvaluationSpec(
                format!("Weights must sum to 1.0, got {}", total_weight)
            ));
        }
        
        // Check if all weights are positive
        for (metric, weight) in &spec.evaluation.weights {
            if *weight <= 0.0 {
                return Err(ChallengeSpecError::InvalidEvaluationSpec(
                    format!("Weight for metric '{}' must be positive, got {}", metric, weight)
                ));
            }
        }
        
        // Check if thresholds are valid
        for (metric, threshold) in &spec.evaluation.thresholds {
            if *threshold < 0.0 || *threshold > 1.0 {
                return Err(ChallengeSpecError::InvalidEvaluationSpec(
                    format!("Threshold for metric '{}' must be between 0.0 and 1.0, got {}", metric, threshold)
                ));
            }
        }
        
        // Check if metrics are defined
        if spec.evaluation.metrics.is_empty() {
            return Err(ChallengeSpecError::InvalidEvaluationSpec(
                "At least one metric must be defined".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Validate datasets
    fn validate_datasets(spec: &ChallengeSpec) -> ChallengeSpecResult<()> {
        // Check for duplicate dataset names
        let mut names = std::collections::HashSet::new();
        for dataset in &spec.datasets {
            if !names.insert(&dataset.name) {
                return Err(ChallengeSpecError::ValidationError(
                    format!("Duplicate dataset name: {}", dataset.name)
                ));
            }
        }
        
        // Check dataset URLs
        for dataset in &spec.datasets {
            if !Self::is_valid_url(&dataset.url) {
                return Err(ChallengeSpecError::ValidationError(
                    format!("Invalid dataset URL: {}", dataset.url)
                ));
            }
        }
        
        // Check dataset sizes
        for dataset in &spec.datasets {
            if dataset.size == 0 {
                return Err(ChallengeSpecError::ValidationError(
                    format!("Dataset '{}' size cannot be zero", dataset.name)
                ));
            }
        }
        
        Ok(())
    }
    
    /// Check if URL is valid
    fn is_valid_url(url: &str) -> bool {
        // Simple URL validation
        url.starts_with("http://") || url.starts_with("https://") || url.starts_with("file://")
    }
}

/// Validation rules for different runtime types
pub struct RuntimeValidator;

impl RuntimeValidator {
    /// Validate standard runtime
    pub fn validate_standard(_spec: &ChallengeSpec) -> ChallengeSpecResult<()> {
        // Standard runtime has no special requirements
        Ok(())
    }
    
    /// Validate SGX runtime
    pub fn validate_sgx(spec: &ChallengeSpec) -> ChallengeSpecResult<()> {
        // SGX requires attestation
        if !spec.attestation_required {
            return Err(ChallengeSpecError::InvalidRuntime(
                "SGX runtime requires attestation".to_string()
            ));
        }
        
        // SGX has memory limitations
        if spec.resources.memory_mb > 1024 {
            return Err(ChallengeSpecError::InvalidResourceSpec(
                "SGX runtime memory limit is 1GB".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Validate SEV runtime
    pub fn validate_sev(spec: &ChallengeSpec) -> ChallengeSpecResult<()> {
        // SEV requires attestation
        if !spec.attestation_required {
            return Err(ChallengeSpecError::InvalidRuntime(
                "SEV runtime requires attestation".to_string()
            ));
        }
        
        // SEV has memory limitations
        if spec.resources.memory_mb > 4096 {
            return Err(ChallengeSpecError::InvalidResourceSpec(
                "SEV runtime memory limit is 4GB".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Validate WasmEnclave runtime
    pub fn validate_wasm_enclave(spec: &ChallengeSpec) -> ChallengeSpecResult<()> {
        // WasmEnclave requires attestation
        if !spec.attestation_required {
            return Err(ChallengeSpecError::InvalidRuntime(
                "WasmEnclave runtime requires attestation".to_string()
            ));
        }
        
        // WasmEnclave has memory limitations
        if spec.resources.memory_mb > 512 {
            return Err(ChallengeSpecError::InvalidResourceSpec(
                "WasmEnclave runtime memory limit is 512MB".to_string()
            ));
        }
        
        Ok(())
    }
}

/// Validation for specific components
pub struct ComponentValidator;

impl ComponentValidator {
    /// Validate environment variables
    pub fn validate_environment(env: &std::collections::BTreeMap<String, String>) -> ChallengeSpecResult<()> {
        for (key, value) in env {
            if key.is_empty() {
                return Err(ChallengeSpecError::ValidationError(
                    "Environment variable key cannot be empty".to_string()
                ));
            }
            
            if key.contains(' ') {
                return Err(ChallengeSpecError::ValidationError(
                    format!("Environment variable key '{}' cannot contain spaces", key)
                ));
            }
            
            if value.len() > 10000 {
                return Err(ChallengeSpecError::ValidationError(
                    format!("Environment variable '{}' value too long", key)
                ));
            }
        }
        
        Ok(())
    }
    
    /// Validate timeout value
    pub fn validate_timeout(timeout: u64) -> ChallengeSpecResult<()> {
        if timeout == 0 {
            return Err(ChallengeSpecError::ValidationError(
                "Timeout cannot be zero".to_string()
            ));
        }
        
        if timeout > 3600 {
            return Err(ChallengeSpecError::ValidationError(
                "Timeout cannot exceed 1 hour".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Validate resource specifications
    pub fn validate_resources(resources: &crate::ResourceSpec) -> ChallengeSpecResult<()> {
        if resources.cpu_cores == 0 {
            return Err(ChallengeSpecError::InvalidResourceSpec(
                "CPU cores cannot be zero".to_string()
            ));
        }
        
        if resources.memory_mb == 0 {
            return Err(ChallengeSpecError::InvalidResourceSpec(
                "Memory cannot be zero".to_string()
            ));
        }
        
        if resources.disk_mb == 0 {
            return Err(ChallengeSpecError::InvalidResourceSpec(
                "Disk space cannot be zero".to_string()
            ));
        }
        
        Ok(())
    }
}
