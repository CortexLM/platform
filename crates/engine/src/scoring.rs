use crate::{ScoringConfig, ScoringAlgorithm, NormalizationMethod, EvalResult, EngineResult, EngineError};
use std::collections::BTreeMap;

/// Scoring engine for evaluation results
pub struct ScoringEngine {
    config: ScoringConfig,
    metrics: ScoringMetrics,
}

/// Scoring metrics
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScoringMetrics {
    pub total_scores: u64,
    pub avg_score: f64,
    pub min_score: f64,
    pub max_score: f64,
    pub score_distribution: BTreeMap<String, u64>,
}

impl ScoringEngine {
    pub fn new(config: ScoringConfig) -> Self {
        Self {
            config,
            metrics: ScoringMetrics::default(),
        }
    }

    /// Score an evaluation result
    pub fn score(&mut self, result: &EvalResult) -> EngineResult<f64> {
        tracing::info!("Scoring evaluation result: {}", result.id);

        let raw_score = self.calculate_raw_score(result)?;
        let normalized_score = self.normalize_score(raw_score)?;
        let final_score = self.apply_weights(normalized_score, result)?;

        // Update metrics
        self.update_metrics(final_score);

        tracing::info!("Score calculated: {}", final_score);
        Ok(final_score)
    }

    /// Score multiple results
    pub fn score_batch(&mut self, results: &[EvalResult]) -> EngineResult<Vec<f64>> {
        let mut scores = Vec::new();
        
        for result in results {
            let score = self.score(result)?;
            scores.push(score);
        }
        
        Ok(scores)
    }

    /// Get scoring metrics
    pub fn get_metrics(&self) -> &ScoringMetrics {
        &self.metrics
    }

    /// Reset metrics
    pub fn reset_metrics(&mut self) {
        self.metrics = ScoringMetrics::default();
    }

    fn calculate_raw_score(&self, result: &EvalResult) -> EngineResult<f64> {
        match self.config.algorithm {
            ScoringAlgorithm::Linear => self.calculate_linear_score(result),
            ScoringAlgorithm::Logarithmic => self.calculate_logarithmic_score(result),
            ScoringAlgorithm::Exponential => self.calculate_exponential_score(result),
            ScoringAlgorithm::Custom(ref algorithm) => self.calculate_custom_score(result, algorithm),
        }
    }

    fn calculate_linear_score(&self, result: &EvalResult) -> EngineResult<f64> {
        // Simple linear combination of scores
        let mut total_score = 0.0;
        let mut total_weight = 0.0;

        for (metric, score) in &result.scores {
            let weight = self.config.weights.get(metric).unwrap_or(&1.0);
            total_score += score * weight;
            total_weight += weight;
        }

        if total_weight > 0.0 {
            Ok(total_score / total_weight)
        } else {
            Ok(0.0)
        }
    }

    fn calculate_logarithmic_score(&self, result: &EvalResult) -> EngineResult<f64> {
        // Logarithmic scoring to reduce impact of outliers
        let mut total_score = 0.0;
        let mut total_weight = 0.0;

        for (metric, score) in &result.scores {
            let weight = self.config.weights.get(metric).unwrap_or(&1.0);
            let log_score = (score + 1.0).ln();
            total_score += log_score * weight;
            total_weight += weight;
        }

        if total_weight > 0.0 {
            Ok(total_score / total_weight)
        } else {
            Ok(0.0)
        }
    }

    fn calculate_exponential_score(&self, result: &EvalResult) -> EngineResult<f64> {
        // Exponential scoring to amplify differences
        let mut total_score = 0.0;
        let mut total_weight = 0.0;

        for (metric, score) in &result.scores {
            let weight = self.config.weights.get(metric).unwrap_or(&1.0);
            let exp_score = score.exp();
            total_score += exp_score * weight;
            total_weight += weight;
        }

        if total_weight > 0.0 {
            Ok(total_score / total_weight)
        } else {
            Ok(0.0)
        }
    }

    fn calculate_custom_score(&self, result: &EvalResult, algorithm: &str) -> EngineResult<f64> {
        // Custom scoring algorithm
        // For now, fall back to linear scoring
        tracing::warn!("Custom scoring algorithm not implemented: {}", algorithm);
        self.calculate_linear_score(result)
    }

    fn normalize_score(&self, score: f64) -> EngineResult<f64> {
        match self.config.normalization {
            NormalizationMethod::None => Ok(score),
            NormalizationMethod::MinMax => self.normalize_minmax(score),
            NormalizationMethod::ZScore => self.normalize_zscore(score),
            NormalizationMethod::Robust => self.normalize_robust(score),
        }
    }

    fn normalize_minmax(&self, score: f64) -> EngineResult<f64> {
        // Min-max normalization to [0, 1]
        let min_score = self.config.thresholds.get("min").unwrap_or(&0.0);
        let max_score = self.config.thresholds.get("max").unwrap_or(&1.0);
        
        if max_score > min_score {
            Ok((score - min_score) / (max_score - min_score))
        } else {
            Ok(score)
        }
    }

    fn normalize_zscore(&self, score: f64) -> EngineResult<f64> {
        // Z-score normalization
        let mean = self.config.thresholds.get("mean").unwrap_or(&0.5);
        let std_dev = self.config.thresholds.get("std_dev").unwrap_or(&0.1);
        
        if *std_dev > 0.0 {
            Ok((score - mean) / std_dev)
        } else {
            Ok(score)
        }
    }

    fn normalize_robust(&self, score: f64) -> EngineResult<f64> {
        // Robust normalization using median and IQR
        let median = self.config.thresholds.get("median").unwrap_or(&0.5);
        let iqr = self.config.thresholds.get("iqr").unwrap_or(&0.2);
        
        if *iqr > 0.0 {
            Ok((score - median) / iqr)
        } else {
            Ok(score)
        }
    }

    fn apply_weights(&self, score: f64, result: &EvalResult) -> EngineResult<f64> {
        let mut weighted_score = score;

        // Apply time-based weighting
        if let Some(time_weight) = self.config.weights.get("execution_time") {
            let time_factor = 1.0 / (1.0 + result.execution_time as f64 / 1000.0);
            weighted_score *= time_factor * time_weight;
        }

        // Apply resource-based weighting
        if let Some(resource_weight) = self.config.weights.get("resource_usage") {
            let memory_factor = 1.0 / (1.0 + result.resource_usage.memory_peak as f64 / (1024.0 * 1024.0 * 1024.0));
            weighted_score *= memory_factor * resource_weight;
        }

        // Apply error penalty
        if result.error.is_some() {
            if let Some(error_penalty) = self.config.thresholds.get("error_penalty") {
                weighted_score *= error_penalty;
            }
        }

        Ok(weighted_score)
    }

    fn update_metrics(&mut self, score: f64) {
        self.metrics.total_scores += 1;
        
        if self.metrics.total_scores == 1 {
            self.metrics.min_score = score;
            self.metrics.max_score = score;
        } else {
            self.metrics.min_score = self.metrics.min_score.min(score);
            self.metrics.max_score = self.metrics.max_score.max(score);
        }
        
        self.metrics.avg_score = 
            (self.metrics.avg_score * (self.metrics.total_scores - 1) as f64 + score) / 
            self.metrics.total_scores as f64;
        
        // Update score distribution
        let bucket = format!("{:.1}", (score * 10.0).round() / 10.0);
        *self.metrics.score_distribution.entry(bucket).or_insert(0) += 1;
    }
}

/// Score aggregator for multiple evaluations
pub struct ScoreAggregator {
    scores: Vec<f64>,
    weights: Vec<f64>,
}

impl ScoreAggregator {
    pub fn new() -> Self {
        Self {
            scores: Vec::new(),
            weights: Vec::new(),
        }
    }

    pub fn add_score(&mut self, score: f64, weight: f64) {
        self.scores.push(score);
        self.weights.push(weight);
    }

    pub fn aggregate(&self) -> EngineResult<f64> {
        if self.scores.is_empty() {
            return Err(EngineError::ScoringError("No scores to aggregate".to_string()));
        }

        let total_weight: f64 = self.weights.iter().sum();
        if total_weight == 0.0 {
            return Err(EngineError::ScoringError("Total weight is zero".to_string()));
        }

        let weighted_sum: f64 = self.scores.iter()
            .zip(self.weights.iter())
            .map(|(score, weight)| score * weight)
            .sum();

        Ok(weighted_sum / total_weight)
    }

    pub fn get_statistics(&self) -> ScoreStatistics {
        if self.scores.is_empty() {
            return ScoreStatistics::default();
        }

        let mut sorted_scores = self.scores.clone();
        sorted_scores.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let count = sorted_scores.len();
        let sum: f64 = sorted_scores.iter().sum();
        let mean = sum / count as f64;
        
        let median = if count % 2 == 0 {
            (sorted_scores[count / 2 - 1] + sorted_scores[count / 2]) / 2.0
        } else {
            sorted_scores[count / 2]
        };

        let variance: f64 = sorted_scores.iter()
            .map(|score| (score - mean).powi(2))
            .sum::<f64>() / count as f64;
        let std_dev = variance.sqrt();

        ScoreStatistics {
            count,
            mean,
            median,
            std_dev,
            min: sorted_scores[0],
            max: sorted_scores[count - 1],
        }
    }
}

/// Score statistics
#[derive(Debug, Default)]
pub struct ScoreStatistics {
    pub count: usize,
    pub mean: f64,
    pub median: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
}
