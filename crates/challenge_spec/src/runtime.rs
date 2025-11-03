use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Runtime type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuntimeType {
    Standard,
    Sgx,
    Sev,
    WasmEnclave,
}

/// Resource specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSpec {
    pub cpu_cores: u32,
    pub memory_mb: u64,
    pub disk_mb: u64,
    pub network_bytes: Option<u64>,
}

/// Dataset specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetSpec {
    pub name: String,
    pub url: String,
    pub format: String,
    pub compression: Option<String>,
    pub checksum: String,
    pub size: u64,
}

/// Evaluation specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationSpec {
    pub algorithm: String,
    pub weights: BTreeMap<String, f64>,
    pub normalization: NormalizationMethod,
    pub thresholds: BTreeMap<String, f64>,
    pub metrics: Vec<MetricSpec>,
}

/// Normalization method
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NormalizationMethod {
    None,
    MinMax,
    ZScore,
    Robust,
}

/// Metric specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSpec {
    pub name: String,
    pub description: String,
    pub metric_type: MetricType,
    pub weight: f64,
    pub threshold: Option<f64>,
}

/// Metric type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MetricType {
    Accuracy,
    Precision,
    Recall,
    F1Score,
    Custom(String),
}

impl RuntimeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuntimeType::Standard => "standard",
            RuntimeType::Sgx => "sgx",
            RuntimeType::Sev => "sev",
            RuntimeType::WasmEnclave => "wasm_enclave",
        }
    }
    
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "standard" => Some(RuntimeType::Standard),
            "sgx" => Some(RuntimeType::Sgx),
            "sev" => Some(RuntimeType::Sev),
            "wasm_enclave" => Some(RuntimeType::WasmEnclave),
            _ => None,
        }
    }
    
    pub fn is_tee(&self) -> bool {
        match self {
            RuntimeType::Standard => false,
            RuntimeType::Sgx | RuntimeType::Sev | RuntimeType::WasmEnclave => true,
        }
    }
    
    pub fn requires_attestation(&self) -> bool {
        self.is_tee()
    }
    
    pub fn supports_network(&self) -> bool {
        match self {
            RuntimeType::Standard => true,
            RuntimeType::Sgx | RuntimeType::Sev => false,
            RuntimeType::WasmEnclave => true,
        }
    }
    
    pub fn get_default_timeout(&self) -> u64 {
        match self {
            RuntimeType::Standard => 300, // 5 minutes
            RuntimeType::Sgx => 600, // 10 minutes
            RuntimeType::Sev => 900, // 15 minutes
            RuntimeType::WasmEnclave => 300, // 5 minutes
        }
    }
    
    pub fn get_default_memory_mb(&self) -> u64 {
        match self {
            RuntimeType::Standard => 1024, // 1 GB
            RuntimeType::Sgx => 512, // 512 MB
            RuntimeType::Sev => 2048, // 2 GB
            RuntimeType::WasmEnclave => 256, // 256 MB
        }
    }
    
    pub fn get_default_cpu_cores(&self) -> u32 {
        match self {
            RuntimeType::Standard => 4,
            RuntimeType::Sgx => 2,
            RuntimeType::Sev => 8,
            RuntimeType::WasmEnclave => 1,
        }
    }
}

impl ResourceSpec {
    pub fn new(cpu_cores: u32, memory_mb: u64, disk_mb: u64) -> Self {
        Self {
            cpu_cores,
            memory_mb,
            disk_mb,
            network_bytes: None,
        }
    }
    
    pub fn with_network_limit(mut self, network_bytes: u64) -> Self {
        self.network_bytes = Some(network_bytes);
        self
    }
    
    pub fn get_cpu_cores(&self) -> u32 {
        self.cpu_cores
    }
    
    pub fn get_memory_mb(&self) -> u64 {
        self.memory_mb
    }
    
    pub fn get_disk_mb(&self) -> u64 {
        self.disk_mb
    }
    
    pub fn get_network_bytes(&self) -> Option<u64> {
        self.network_bytes
    }
    
    pub fn has_network_limit(&self) -> bool {
        self.network_bytes.is_some()
    }
    
    pub fn get_total_memory_bytes(&self) -> u64 {
        self.memory_mb * 1024 * 1024
    }
    
    pub fn get_total_disk_bytes(&self) -> u64 {
        self.disk_mb * 1024 * 1024
    }
}

impl DatasetSpec {
    pub fn new(
        name: String,
        url: String,
        format: String,
        checksum: String,
        size: u64,
    ) -> Self {
        Self {
            name,
            url,
            format,
            compression: None,
            checksum,
            size,
        }
    }
    
    pub fn with_compression(mut self, compression: String) -> Self {
        self.compression = Some(compression);
        self
    }
    
    pub fn get_name(&self) -> &String {
        &self.name
    }
    
    pub fn get_url(&self) -> &String {
        &self.url
    }
    
    pub fn get_format(&self) -> &String {
        &self.format
    }
    
    pub fn get_compression(&self) -> Option<&String> {
        self.compression.as_ref()
    }
    
    pub fn get_checksum(&self) -> &String {
        &self.checksum
    }
    
    pub fn get_size(&self) -> u64 {
        self.size
    }
    
    pub fn is_compressed(&self) -> bool {
        self.compression.is_some()
    }
    
    pub fn get_size_mb(&self) -> f64 {
        self.size as f64 / (1024.0 * 1024.0)
    }
}

impl EvaluationSpec {
    pub fn new(algorithm: String) -> Self {
        Self {
            algorithm,
            weights: BTreeMap::new(),
            normalization: NormalizationMethod::None,
            thresholds: BTreeMap::new(),
            metrics: Vec::new(),
        }
    }
    
    pub fn with_weight(mut self, metric: String, weight: f64) -> Self {
        self.weights.insert(metric, weight);
        self
    }
    
    pub fn with_threshold(mut self, metric: String, threshold: f64) -> Self {
        self.thresholds.insert(metric, threshold);
        self
    }
    
    pub fn with_metric(mut self, metric: MetricSpec) -> Self {
        self.metrics.push(metric);
        self
    }
    
    pub fn with_normalization(mut self, normalization: NormalizationMethod) -> Self {
        self.normalization = normalization;
        self
    }
    
    pub fn get_algorithm(&self) -> &String {
        &self.algorithm
    }
    
    pub fn get_weight(&self, metric: &str) -> Option<f64> {
        self.weights.get(metric).copied()
    }
    
    pub fn get_threshold(&self, metric: &str) -> Option<f64> {
        self.thresholds.get(metric).copied()
    }
    
    pub fn get_metrics(&self) -> &Vec<MetricSpec> {
        &self.metrics
    }
    
    pub fn get_normalization(&self) -> &NormalizationMethod {
        &self.normalization
    }
}

impl MetricSpec {
    pub fn new(
        name: String,
        description: String,
        metric_type: MetricType,
        weight: f64,
    ) -> Self {
        Self {
            name,
            description,
            metric_type,
            weight,
            threshold: None,
        }
    }
    
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = Some(threshold);
        self
    }
    
    pub fn get_name(&self) -> &String {
        &self.name
    }
    
    pub fn get_description(&self) -> &String {
        &self.description
    }
    
    pub fn get_metric_type(&self) -> &MetricType {
        &self.metric_type
    }
    
    pub fn get_weight(&self) -> f64 {
        self.weight
    }
    
    pub fn get_threshold(&self) -> Option<f64> {
        self.threshold
    }
    
    pub fn has_threshold(&self) -> bool {
        self.threshold.is_some()
    }
}


