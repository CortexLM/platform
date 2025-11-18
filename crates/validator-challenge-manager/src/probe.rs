use anyhow::{Context, Result};
use chrono::Utc;
use platform_validator_core::ChallengeState;
use reqwest;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::manager::ChallengeManager;

pub async fn probe_health(manager: &ChallengeManager, compose_hash: &str, api_url: &str) -> Result<()> {
    let is_docker = api_url.starts_with("http://") && !api_url.starts_with("https://");

    if is_docker {
        info!("Probing Docker container health for challenge {} at {}", compose_hash, api_url);

        let mut challenges = manager.challenges().write().await;
        if let Some(instance) = challenges.get_mut(compose_hash) {
            instance.last_probe = Some(Utc::now());
            instance.probe_attempts += 1;
        }
        drop(challenges);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()?;

        let probe_start = std::time::Instant::now();
        let probe_timeout = std::time::Duration::from_secs(30);
        let mut healthy = false;

        while !healthy && probe_start.elapsed() < probe_timeout {
            match client.get(&format!("{}/sdk/health", api_url)).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        healthy = true;
                        let mut challenges = manager.challenges().write().await;
                        if let Some(instance) = challenges.get_mut(compose_hash) {
                            instance.state = ChallengeState::Active;
                            instance.probe_attempts = 0;
                            info!("Challenge {} is healthy (Docker)", compose_hash);
                            info!("✅ Challenge {} is ready", compose_hash);
                        }
                        break;
                    } else {
                        debug!("Health check returned status {} for {}", response.status(), api_url);
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                }
                Err(e) => {
                    debug!("Health check error for {}: {}", api_url, e);
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }

        if !healthy {
            let mut challenges = manager.challenges().write().await;
            if let Some(instance) = challenges.get_mut(compose_hash) {
                warn!("Challenge {} health probe failed after 30s: error sending request for url ({}/sdk/health)", compose_hash, api_url);
                instance.state = ChallengeState::Failed;
            }
        }

        return Ok(());
    }

    let challenges = manager.challenges().write().await;

    let has_empty_instance_id = api_url.contains("https://-")
        || api_url.contains("wss://-")
        || api_url.contains("ws://-");
    if has_empty_instance_id {
        let cvm_id = {
            let instance = challenges.get(compose_hash);
            instance.and_then(|i| i.cvm_instance_id.clone())
        };
        drop(challenges);

        if let Some(cvm_id_clone) = cvm_id {
            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(60);
            let mut instance_id = None;

            while instance_id.is_none() && start.elapsed() < timeout {
                match manager.vmm_client().get_vm_info(&cvm_id_clone).await {
                    Ok(vm_info) => {
                        if let Some(id) = vm_info.instance_id {
                            if !id.trim().is_empty() {
                                instance_id = Some(id);
                                break;
                            } else {
                                info!("Waiting for challenge {} instance_id...", compose_hash);
                            }
                        } else {
                            info!("Waiting for challenge {} instance_id...", compose_hash);
                        }
                    }
                    Err(e) => {
                        warn!("Failed to get VM info for {}: {}", cvm_id_clone, e);
                    }
                }

                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }

            let mut challenges = manager.challenges().write().await;
            if let Some(instance) = challenges.get_mut(compose_hash) {
                if let Some(id) = instance_id {
                    let base_domain = manager
                        .get_gateway_base_domain_internal()
                        .await
                        .context("Failed to get gateway base_domain")?;
                    let gateway_port = manager
                        .get_gateway_port_internal()
                        .await
                        .context("Failed to get gateway port")?;
                    let host = format!("{}-10000.{}:{}", id, base_domain, gateway_port);

                    let http_url = format!("https://{}", host);
                    instance.challenge_api_url = Some(http_url.clone());
                    info!("Updated challenge {} URL with instance_id: https://{}", compose_hash, host);
                    drop(challenges);

                    let client = reqwest::Client::builder()
                        .danger_accept_invalid_certs(true)
                        .timeout(std::time::Duration::from_secs(3))
                        .build()?;

                    let probe_start = std::time::Instant::now();
                    let probe_timeout = std::time::Duration::from_secs(120);
                    let mut healthy = false;

                    while !healthy && probe_start.elapsed() < probe_timeout {
                        match client.get(&format!("{}/sdk/health", http_url)).send().await {
                            Ok(response) => {
                                if response.status().is_success() {
                                    healthy = true;
                                    let mut challenges = manager.challenges().write().await;
                                    if let Some(instance) = challenges.get_mut(compose_hash) {
                                        instance.state = ChallengeState::Active;
                                        instance.probe_attempts = 0;
                                        info!("Challenge {} is healthy", compose_hash);
                                        info!("✅ Challenge {} is ready", compose_hash);
                                    }
                                    break;
                                } else {
                                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                                }
                            }
                            Err(_) => {
                                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                            }
                        }
                    }

                    if !healthy {
                        let mut challenges = manager.challenges().write().await;
                        if let Some(instance) = challenges.get_mut(compose_hash) {
                            warn!("Challenge {} health probe failed after 120s: error sending request for url ({}/sdk/health)", compose_hash, http_url);
                        }
                    }

                    return Ok(());
                } else {
                    let mut challenges = manager.challenges().write().await;
                    if let Some(instance) = challenges.get_mut(compose_hash) {
                        error!("Challenge {} instance_id not available after 60s timeout", compose_hash);
                        instance.state = ChallengeState::Failed;
                    }
                    return Ok(());
                }
            }
        } else {
            let mut challenges = manager.challenges().write().await;
            if let Some(instance) = challenges.get_mut(compose_hash) {
                error!("Challenge {} has invalid URL and no CVM ID", compose_hash);
                instance.state = ChallengeState::Failed;
            }
            return Ok(());
        }
    }

    let mut challenges = manager.challenges().write().await;

    if let Some(instance) = challenges.get_mut(compose_hash) {
        instance.last_probe = Some(Utc::now());
        instance.probe_attempts += 1;

        let api_url_clone = api_url.to_string();
        drop(challenges);

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(3))
            .build()?;

        let probe_start = std::time::Instant::now();
        let probe_timeout = std::time::Duration::from_secs(120);
        let mut healthy = false;

        while !healthy && probe_start.elapsed() < probe_timeout {
            match client.get(&format!("{}/sdk/health", api_url_clone)).send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        healthy = true;
                        let mut challenges = manager.challenges().write().await;
                        if let Some(instance) = challenges.get_mut(compose_hash) {
                            instance.state = ChallengeState::Active;
                            instance.probe_attempts = 0;
                            info!("Challenge {} is healthy", compose_hash);
                            info!("✅ Challenge {} is ready", compose_hash);
                        }
                        break;
                    } else {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    }
                }
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }

        if !healthy {
            let mut challenges = manager.challenges().write().await;
            if let Some(instance) = challenges.get_mut(compose_hash) {
                warn!("Challenge {} health probe failed after 120s: error sending request for url ({}/sdk/health)", compose_hash, api_url_clone);
                instance.state = ChallengeState::Failed;
            }
        }
    }

    Ok(())
}
