use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformVersionInfo {
    pub platform_api: PlatformApiVersion,
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformApiVersion {
    pub cargo_version: String,
    pub git_commit: String,
    pub compose_hash: String, // Docker Compose hash (attested by TDX)
    pub build_time: String,
    pub public_key: String, // Public key for verification
}

pub struct PlatformVerifier {
    client: reqwest::Client,
    platform_api_url: String,
    allowed_commits: HashSet<String>,
    last_verified_commit: Option<String>,
}

impl PlatformVerifier {
    pub fn new(platform_api_url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            platform_api_url,
            allowed_commits: HashSet::new(),
            last_verified_commit: None,
        }
    }

    /// Add an allowed Docker commit SHA
    pub fn add_allowed_commit(&mut self, commit: String) {
        let commit_clone = commit.clone();
        self.allowed_commits.insert(commit);
        info!("Added allowed Docker commit: {}", commit_clone);
    }

    /// Verify platform-api is using the correct Docker commit
    pub async fn verify_platform_api(&mut self) -> Result<bool> {
        let url = format!("{}/version", self.platform_api_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to request platform-api version")?;

        let version_info: PlatformVersionInfo = response
            .json()
            .await
            .context("Failed to parse version info")?;

        let compose_hash = &version_info.platform_api.compose_hash;

        // Check if warning is present
        if let Some(warning) = &version_info.warning {
            if !warning.is_empty() {
                warn!("Platform-API warning: {}", warning);
            }
        }

        // Get public key
        let public_key = &version_info.platform_api.public_key;
        info!("Platform-API public key: {}", public_key);

        // Check if compose_hash is unknown
        if compose_hash == "unknown" {
            error!("Platform-API compose_hash is UNKNOWN - Cannot verify integrity");
            error!("   Compose hash not available from TDX attestation");
            return Ok(false);
        }

        // Verify public key matches expected key for this compose_hash
        if let Some(expected_key) = self.calculate_expected_public_key(compose_hash) {
            if &expected_key != public_key {
                error!("Platform-API public key MISMATCH");
                error!("   Expected: {}", expected_key);
                error!("   Received: {}", public_key);
                error!("   WARNING: Possible key compromise or wrong compose_hash");
                return Ok(false);
            } else {
                info!("Platform-API public key verified");
            }
        }

        // Check if compose_hash changed
        if let Some(last_hash) = &self.last_verified_commit {
            if last_hash != compose_hash {
                warn!("Platform-API compose_hash CHANGED");
                warn!("   Previous: {}", last_hash);
                warn!("   Current:  {}", compose_hash);
                warn!("   WARNING: Possible compromise or update - investigate immediately");
            }
        } else {
            info!(
                "First verification of platform-api compose_hash: {}",
                compose_hash
            );
        }

        // Check if compose_hash is in allowed list
        if !self.allowed_commits.is_empty() {
            if !self.allowed_commits.contains(compose_hash) {
                error!("Platform-API compose_hash NOT IN ALLOWED LIST");
                error!("   Compose hash: {}", compose_hash);
                error!("   Allowed hashes: {:?}", self.allowed_commits);
                error!("   WARNING: UNAUTHORIZED Docker image - Possible compromise");
                return Ok(false);
            } else {
                info!("Platform-API compose_hash verified: {}", compose_hash);
            }
        } else {
            // No allowed hashes configured - just log the hash
            info!(
                "Platform-API compose_hash: {} (no allowed list configured)",
                compose_hash
            );

            // Compare with previous check
            if let Some(last_hash) = &self.last_verified_commit {
                if last_hash != compose_hash {
                    warn!(
                        "WARNING: Compose hash changed from {} to {}",
                        last_hash, compose_hash
                    );
                }
            }
        }

        self.last_verified_commit = Some(compose_hash.clone());
        Ok(true)
    }

    /// Get the last verified commit
    pub fn get_last_verified_commit(&self) -> Option<&String> {
        self.last_verified_commit.as_ref()
    }

    /// Calculate expected public key for a given commit SHA
    fn calculate_expected_public_key(&self, commit_sha: &str) -> Option<String> {
        use sha2::{Digest, Sha256};

        // Derive seed from commit SHA (same logic as platform-api)
        let mut hasher = Sha256::new();
        hasher.update(b"platform-api-security");
        hasher.update(commit_sha.as_bytes());
        let hash = hasher.finalize();

        // Convert to seed
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hash[..32]);

        // Derive key pair (using ed25519_dalek)
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        Some(hex::encode(verifying_key.to_bytes()))
    }
}
