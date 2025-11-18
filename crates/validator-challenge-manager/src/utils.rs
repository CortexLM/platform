use anyhow::Result;
use reqwest;
use serde_json;

/// Parse memory string (e.g., "2G", "512M") to MB
pub fn parse_memory(memory: &str) -> Result<u32> {
    let memory = memory.trim().to_lowercase();
    if memory.ends_with("g") {
        Ok(memory.trim_end_matches("g").parse::<u32>()? * 1024)
    } else if memory.ends_with("m") {
        Ok(memory.trim_end_matches("m").parse::<u32>()?)
    } else {
        Ok(memory.parse::<u32>()?)
    }
}

/// Parse disk size string (e.g., "20G", "512M") to GB
pub fn parse_disk_size(disk: &str) -> Result<u32> {
    let disk = disk.trim().to_lowercase();
    if disk.ends_with("g") {
        Ok(disk.trim_end_matches("g").parse::<u32>()?)
    } else if disk.ends_with("m") {
        Ok(disk.trim_end_matches("m").parse::<u32>()? / 1024)
    } else {
        Ok(disk.parse::<u32>()?)
    }
}

/// Forward heartbeat to platform API
pub async fn forward_heartbeat(payload: serde_json::Value) -> Result<()> {
    let platform_api_url = std::env::var("PLATFORM_API_URL")
        .unwrap_or_else(|_| "http://platform-api:3000".to_string());
    let client = reqwest::Client::new();
    let _ = client
        .post(format!("{}/results/heartbeat", platform_api_url))
        .json(&payload)
        .send()
        .await;
    Ok(())
}

/// Forward logs to platform API
pub async fn forward_logs(payload: serde_json::Value) -> Result<()> {
    let platform_api_url = std::env::var("PLATFORM_API_URL")
        .unwrap_or_else(|_| "http://platform-api:3000".to_string());
    let client = reqwest::Client::new();
    let _ = client
        .post(format!("{}/results/logs", platform_api_url))
        .json(&payload)
        .send()
        .await;
    Ok(())
}

/// Forward submit to platform API
pub async fn forward_submit(payload: serde_json::Value) -> Result<()> {
    let platform_api_url = std::env::var("PLATFORM_API_URL")
        .unwrap_or_else(|_| "http://platform-api:3000".to_string());
    let client = reqwest::Client::new();
    let _ = client
        .post(format!("{}/results/submit", platform_api_url))
        .json(&payload)
        .send()
        .await;
    Ok(())
}

