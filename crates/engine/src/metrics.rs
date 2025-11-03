use std::collections::BTreeMap;
use chrono::{DateTime, Utc};
use crate::scoring::ScoringMetrics as ScoringEngineMetrics;

/// Metrics collector for engine operations
pub struct MetricsCollector {
    metrics: EngineMetrics,
    start_time: DateTime<Utc>,
}

/// Engine metrics
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct EngineMetrics {
    pub evaluations: EvaluationMetrics,
    pub adapters: AdapterMetrics,
    pub sandboxes: SandboxMetrics,
    pub scoring: ScoringEngineMetrics,
    pub system: SystemMetrics,
}

/// Evaluation metrics
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvaluationMetrics {
    pub total_evaluations: u64,
    pub successful_evaluations: u64,
    pub failed_evaluations: u64,
    pub total_execution_time: u64,
    pub avg_execution_time: f64,
    pub min_execution_time: u64,
    pub max_execution_time: u64,
    pub evaluation_distribution: BTreeMap<String, u64>,
}

/// Adapter metrics
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdapterMetrics {
    pub adapter_usage: BTreeMap<String, u64>,
    pub adapter_success_rate: BTreeMap<String, f64>,
    pub adapter_avg_time: BTreeMap<String, f64>,
    pub adapter_errors: BTreeMap<String, u64>,
}

/// Sandbox metrics
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct SandboxMetrics {
    pub total_sandboxes: u64,
    pub active_sandboxes: u64,
    pub sandbox_creation_time: u64,
    pub sandbox_cleanup_time: u64,
    pub sandbox_errors: u64,
}

/// Scoring metrics
#[derive(Debug, Default)]
pub struct ScoringMetrics {
    pub total_scores: u64,
    pub avg_score: f64,
    pub min_score: f64,
    pub max_score: f64,
    pub score_distribution: BTreeMap<String, u64>,
    pub scoring_time: u64,
}

/// System metrics
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_usage: f64,
    pub uptime: u64,
    pub errors: u64,
    pub warnings: u64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: EngineMetrics::default(),
            start_time: Utc::now(),
        }
    }

    /// Record evaluation metrics
    pub fn record_evaluation(&mut self, success: bool, execution_time: u64, adapter: &str) {
        self.metrics.evaluations.total_evaluations += 1;
        
        if success {
            self.metrics.evaluations.successful_evaluations += 1;
        } else {
            self.metrics.evaluations.failed_evaluations += 1;
        }
        
        self.metrics.evaluations.total_execution_time += execution_time;
        
        if self.metrics.evaluations.total_evaluations == 1 {
            self.metrics.evaluations.min_execution_time = execution_time;
            self.metrics.evaluations.max_execution_time = execution_time;
        } else {
            self.metrics.evaluations.min_execution_time = 
                self.metrics.evaluations.min_execution_time.min(execution_time);
            self.metrics.evaluations.max_execution_time = 
                self.metrics.evaluations.max_execution_time.max(execution_time);
        }
        
        self.metrics.evaluations.avg_execution_time = 
            self.metrics.evaluations.total_execution_time as f64 / 
            self.metrics.evaluations.total_evaluations as f64;
        
        // Update adapter usage
        *self.metrics.adapters.adapter_usage.entry(adapter.to_string()).or_insert(0) += 1;
        
        // Update evaluation distribution
        let bucket = format!("{:.1}", (execution_time as f64 / 100.0).round() * 100.0);
        *self.metrics.evaluations.evaluation_distribution.entry(bucket).or_insert(0) += 1;
    }

    /// Record adapter metrics
    pub fn record_adapter_usage(&mut self, adapter: &str, success: bool, execution_time: u64) {
        let usage = self.metrics.adapters.adapter_usage.entry(adapter.to_string()).or_insert(0);
        *usage += 1;
        
        // Update success rate
        let current_rate = self.metrics.adapters.adapter_success_rate
            .get(adapter).unwrap_or(&0.0);
        let new_rate = if success {
            (current_rate * (*usage - 1) as f64 + 1.0) / *usage as f64
        } else {
            (current_rate * (*usage - 1) as f64) / *usage as f64
        };
        self.metrics.adapters.adapter_success_rate.insert(adapter.to_string(), new_rate);
        
        // Update average time
        let current_avg = self.metrics.adapters.adapter_avg_time
            .get(adapter).unwrap_or(&0.0);
        let new_avg = (current_avg * (*usage - 1) as f64 + execution_time as f64) / *usage as f64;
        self.metrics.adapters.adapter_avg_time.insert(adapter.to_string(), new_avg);
        
        if !success {
            *self.metrics.adapters.adapter_errors.entry(adapter.to_string()).or_insert(0) += 1;
        }
    }

    /// Record sandbox metrics
    pub fn record_sandbox_creation(&mut self, creation_time: u64) {
        self.metrics.sandboxes.total_sandboxes += 1;
        self.metrics.sandboxes.active_sandboxes += 1;
        self.metrics.sandboxes.sandbox_creation_time += creation_time;
    }

    pub fn record_sandbox_cleanup(&mut self, cleanup_time: u64) {
        self.metrics.sandboxes.active_sandboxes = 
            self.metrics.sandboxes.active_sandboxes.saturating_sub(1);
        self.metrics.sandboxes.sandbox_cleanup_time += cleanup_time;
    }

    pub fn record_sandbox_error(&mut self) {
        self.metrics.sandboxes.sandbox_errors += 1;
    }

    /// Record scoring metrics
    pub fn record_scoring(&mut self, score: f64, _scoring_time: u64) {
        self.metrics.scoring.total_scores += 1;
        // scoring_time field doesn't exist in ScoringMetrics
        // self.metrics.scoring.scoring_time += scoring_time;
        
        if self.metrics.scoring.total_scores == 1 {
            self.metrics.scoring.min_score = score;
            self.metrics.scoring.max_score = score;
        } else {
            self.metrics.scoring.min_score = self.metrics.scoring.min_score.min(score);
            self.metrics.scoring.max_score = self.metrics.scoring.max_score.max(score);
        }
        
        self.metrics.scoring.avg_score = 
            (self.metrics.scoring.avg_score * (self.metrics.scoring.total_scores - 1) as f64 + score) / 
            self.metrics.scoring.total_scores as f64;
        
        // Update score distribution
        let bucket = format!("{:.1}", (score * 10.0).round() / 10.0);
        *self.metrics.scoring.score_distribution.entry(bucket).or_insert(0) += 1;
    }

    /// Record system metrics
    pub fn record_system_metrics(&mut self, cpu: f64, memory: f64, disk: f64, network: f64) {
        self.metrics.system.cpu_usage = cpu;
        self.metrics.system.memory_usage = memory;
        self.metrics.system.disk_usage = disk;
        self.metrics.system.network_usage = network;
        self.metrics.system.uptime = (Utc::now() - self.start_time).num_seconds() as u64;
    }

    /// Record error
    pub fn record_error(&mut self) {
        self.metrics.system.errors += 1;
    }

    /// Record warning
    pub fn record_warning(&mut self) {
        self.metrics.system.warnings += 1;
    }

    /// Get all metrics
    pub fn get_metrics(&self) -> &EngineMetrics {
        &self.metrics
    }

    /// Get metrics summary
    pub fn get_summary(&self) -> MetricsSummary {
        MetricsSummary {
            uptime: self.metrics.system.uptime,
            total_evaluations: self.metrics.evaluations.total_evaluations,
            success_rate: if self.metrics.evaluations.total_evaluations > 0 {
                self.metrics.evaluations.successful_evaluations as f64 / 
                self.metrics.evaluations.total_evaluations as f64
            } else {
                0.0
            },
            avg_execution_time: self.metrics.evaluations.avg_execution_time,
            avg_score: self.metrics.scoring.avg_score,
            active_sandboxes: self.metrics.sandboxes.active_sandboxes,
            errors: self.metrics.system.errors,
            warnings: self.metrics.system.warnings,
        }
    }

    /// Reset metrics
    pub fn reset(&mut self) {
        self.metrics = EngineMetrics::default();
        self.start_time = Utc::now();
    }

    /// Export metrics to JSON
    pub fn export_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(&self.metrics)
    }

    /// Export metrics to Prometheus format
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();
        
        // Engine uptime
        output.push_str(&format!("platform_engine_uptime_seconds {}\n", self.metrics.system.uptime));
        
        // Evaluation metrics
        output.push_str(&format!("platform_engine_evaluations_total {}\n", self.metrics.evaluations.total_evaluations));
        output.push_str(&format!("platform_engine_evaluations_successful {}\n", self.metrics.evaluations.successful_evaluations));
        output.push_str(&format!("platform_engine_evaluations_failed {}\n", self.metrics.evaluations.failed_evaluations));
        output.push_str(&format!("platform_engine_evaluation_duration_seconds_avg {}\n", self.metrics.evaluations.avg_execution_time));
        
        // Adapter metrics
        for (adapter, usage) in &self.metrics.adapters.adapter_usage {
            output.push_str(&format!("platform_engine_adapter_usage_total{{adapter=\"{}\"}} {}\n", adapter, usage));
        }
        
        for (adapter, success_rate) in &self.metrics.adapters.adapter_success_rate {
            output.push_str(&format!("platform_engine_adapter_success_rate{{adapter=\"{}\"}} {}\n", adapter, success_rate));
        }
        
        // Sandbox metrics
        output.push_str(&format!("platform_engine_sandboxes_total {}\n", self.metrics.sandboxes.total_sandboxes));
        output.push_str(&format!("platform_engine_sandboxes_active {}\n", self.metrics.sandboxes.active_sandboxes));
        
        // Scoring metrics
        output.push_str(&format!("platform_engine_scores_total {}\n", self.metrics.scoring.total_scores));
        output.push_str(&format!("platform_engine_score_avg {}\n", self.metrics.scoring.avg_score));
        
        // System metrics
        output.push_str(&format!("platform_engine_cpu_usage_percent {}\n", self.metrics.system.cpu_usage));
        output.push_str(&format!("platform_engine_memory_usage_percent {}\n", self.metrics.system.memory_usage));
        output.push_str(&format!("platform_engine_disk_usage_percent {}\n", self.metrics.system.disk_usage));
        output.push_str(&format!("platform_engine_network_usage_bytes {}\n", self.metrics.system.network_usage));
        output.push_str(&format!("platform_engine_errors_total {}\n", self.metrics.system.errors));
        output.push_str(&format!("platform_engine_warnings_total {}\n", self.metrics.system.warnings));
        
        output
    }
}

/// Metrics summary
#[derive(Debug)]
pub struct MetricsSummary {
    pub uptime: u64,
    pub total_evaluations: u64,
    pub success_rate: f64,
    pub avg_execution_time: f64,
    pub avg_score: f64,
    pub active_sandboxes: u64,
    pub errors: u64,
    pub warnings: u64,
}

/// Metrics exporter for external systems
pub struct MetricsExporter {
    collector: MetricsCollector,
    export_interval: u64,
    last_export: DateTime<Utc>,
}

impl MetricsExporter {
    pub fn new(export_interval: u64) -> Self {
        Self {
            collector: MetricsCollector::new(),
            export_interval,
            last_export: Utc::now(),
        }
    }

    pub fn get_collector(&mut self) -> &mut MetricsCollector {
        &mut self.collector
    }

    pub fn should_export(&self) -> bool {
        (Utc::now() - self.last_export).num_seconds() >= self.export_interval as i64
    }

    pub fn export(&mut self) -> MetricsExport {
        self.last_export = Utc::now();
        
        MetricsExport {
            timestamp: self.last_export,
            summary: self.collector.get_summary(),
            metrics: self.collector.get_metrics().clone(),
        }
    }
}

/// Metrics export
#[derive(Debug)]
pub struct MetricsExport {
    pub timestamp: DateTime<Utc>,
    pub summary: MetricsSummary,
    pub metrics: EngineMetrics,
}
