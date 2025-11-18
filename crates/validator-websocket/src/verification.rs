use anyhow::{anyhow, Context, Result};
use base64;
use sha2::{Digest, Sha256};

/// Validator quote data for mutual attestation
#[derive(Debug, Clone)]
pub struct ValidatorQuoteData {
    pub quote_b64: String,
    pub event_log: String,
    pub rtmrs: Vec<String>,
}

/// Verify TDX quote using dcap-qvl
pub async fn verify_tdx_quote(quote_b64: &str, nonce_bytes: &[u8; 32]) -> Result<()> {
    let quote_bytes = base64::decode(quote_b64)?;

    tracing::info!("Verifying TDX quote with dcap-qvl: {} bytes", quote_bytes.len());

    let pccs_url = std::env::var("PCCS_URL")
        .unwrap_or_else(|_| "https://pccs.bittensor.com/sgx/certification/v4/".to_string());
    
    let collateral = match dcap_qvl::collateral::get_collateral(&pccs_url, &quote_bytes).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to get collateral from PCCS, trying Intel PCS: {}", e);
            dcap_qvl::collateral::get_collateral_from_pcs(&quote_bytes)
                .await
                .context("Failed to get collateral from Intel PCS")?
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
            
    let verified_report = dcap_qvl::verify::verify(&quote_bytes, &collateral, now)
        .context("Failed to verify TDX quote")?;

    tracing::info!("TDX quote verified successfully - TCB Status: {}", verified_report.status);

    let valid_statuses = ["UpToDate", "SWHardeningNeeded", "ConfigurationNeeded"];
    if !valid_statuses.contains(&verified_report.status.as_str()) {
        return Err(anyhow!(
            "Invalid TCB status: {}. Quote may be out of date or from unrecognized hardware.",
            verified_report.status
        ));
    }

    let quote_struct = dcap_qvl::quote::Quote::parse(&quote_bytes)
        .map_err(|e| anyhow!("Failed to parse quote: {:?}", e))?;
            
    let report_data = match &quote_struct.report {
        dcap_qvl::quote::Report::SgxEnclave(enclave_report) => &enclave_report.report_data,
        dcap_qvl::quote::Report::TD10(td_report) => &td_report.report_data,
        dcap_qvl::quote::Report::TD15(td_report) => &td_report.base.report_data,
    };

    let mut hasher = Sha256::new();
    hasher.update(nonce_bytes);
    let expected = hasher.finalize();
        
    if &report_data[..32] != expected.as_slice() {
        return Err(anyhow!(
            "Nonce binding verification failed: report_data does not match SHA256(nonce)"
        ));
    }

    tracing::info!("✅ TDX quote fully verified with dcap-qvl");
    Ok(())
}

/// Verify environment mode match between validator and challenge
pub async fn verify_environment_match(challenge_event_log: Option<&str>) -> Option<String> {
    let validator_env_mode = std::env::var("ENVIRONMENT_MODE").unwrap_or_else(|_| {
        if std::env::var("VALIDATOR_MOCK_VMM").unwrap_or_else(|_| "false".to_string()) == "true"
        {
            "dev".to_string()
        } else {
            "prod".to_string()
        }
    });

    if let Some(event_log_str) = challenge_event_log {
        if let Ok(event_log_json) = serde_json::from_str::<serde_json::Value>(event_log_str) {
            if let Some(challenge_env_mode) = event_log_json
                .get("environment_mode")
                .and_then(|v| v.as_str())
            {
                if challenge_env_mode != validator_env_mode {
                    return Some(format!(
                        "Challenge environment is '{}' but validator environment is '{}'. Dev and prod environments cannot communicate.",
                        challenge_env_mode, validator_env_mode
                    ));
                }
            } else if let Some(dev_mode) =
                event_log_json.get("dev_mode").and_then(|v| v.as_bool())
            {
                let challenge_env = if dev_mode { "dev" } else { "prod" };
                if challenge_env != validator_env_mode {
                    return Some(format!(
                        "Challenge environment is '{}' (from dev_mode flag) but validator environment is '{}'. Dev and prod environments cannot communicate.",
                        challenge_env, validator_env_mode
                    ));
                }
            }
        }
    }

    None
}

/// Extract compose_hash from challenge event log
fn extract_challenge_compose_hash(event_log: Option<&str>) -> Result<String> {
    let event_log_str = event_log
        .ok_or_else(|| anyhow::anyhow!("Missing event log - cannot extract compose_hash"))?;

    let event_log_json: serde_json::Value = serde_json::from_str(event_log_str)
        .context("Failed to parse event log")?;

    event_log_json
        .as_array()
        .and_then(|events| {
            for event in events {
                if let Some(event_type) = event.get("event").and_then(|e| e.as_str()) {
                    if event_type == "compose-hash" {
                        if let Some(payload) = event.get("event_payload").and_then(|p| p.as_str()) {
                            return Some(payload.to_string());
                        }
                    }
                }
            }
            None
        })
        .ok_or_else(|| anyhow::anyhow!("Missing compose-hash in event log"))
}

/// Verify challenge compose_hash matches expected value
pub async fn verify_challenge_compose_hash(
    event_log: Option<&str>,
    expected_compose_hash: &str,
) -> Result<()> {
    let challenge_compose_hash = extract_challenge_compose_hash(event_log)?;

    tracing::info!(
        "Compose hash comparison - Challenge: {}, Expected: {}",
        challenge_compose_hash, expected_compose_hash
    );

    if challenge_compose_hash != expected_compose_hash {
        return Err(anyhow::anyhow!(
            "Compose hash mismatch: challenge reports {} but expected {}. \
             The challenge is not running the expected docker-compose configuration.",
            challenge_compose_hash,
            expected_compose_hash
        ));
    }

    tracing::info!("✅ Challenge compose_hash verified");
    Ok(())
}
