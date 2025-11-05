use anyhow::{Context, Result};
use dialoguer::{Input, Password};
use platform_engine_dynamic_values::DynamicValuesManager;
use reqwest;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{self, IsTerminal};
use toml;
use tracing::{info, warn};

/// Platform.toml structure for validator configuration
#[derive(Debug, Deserialize, Serialize)]
struct PlatformToml {
    #[serde(default)]
    validator: Option<ValidatorConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ValidatorConfig {
    /// Required private environment variables
    #[serde(default)]
    required_env_vars: Vec<EnvVarConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
struct EnvVarConfig {
    /// Environment variable name (e.g., "CHUTES_API_TOKEN")
    name: String,
    /// Description for the prompt
    #[serde(default)]
    description: Option<String>,
    /// Whether this env var is optional
    #[serde(default)]
    optional: bool,
}

/// Download and parse platform.toml from GitHub repository
async fn load_platform_toml_from_github(github_repo: &str) -> Result<Option<PlatformToml>> {
    // Parse GitHub URL to extract owner/repo and branch/commit
    // Format: https://github.com/owner/repo or https://github.com/owner/repo/tree/branch
    let url = if github_repo.starts_with("http://") || github_repo.starts_with("https://") {
        github_repo.to_string()
    } else {
        // Assume it's owner/repo format
        format!("https://github.com/{}", github_repo)
    };

    // Extract owner and repo from URL
    let url_parts: Vec<&str> = url
        .trim_start_matches("https://github.com/")
        .trim_start_matches("http://github.com/")
        .split('/')
        .collect();

    if url_parts.len() < 2 {
        warn!("Invalid GitHub URL format: {}", github_repo);
        return Ok(None);
    }

    let owner = url_parts[0];
    let repo = url_parts[1].trim_end_matches(".git");
    
    // Determine branch (default to main/master)
    let branch = if url_parts.len() > 3 && url_parts[2] == "tree" {
        url_parts[3].to_string()
    } else {
        "main".to_string() // Default branch
    };

    // Construct raw GitHub URL for platform.toml
    let raw_url = format!(
        "https://raw.githubusercontent.com/{}/{}/{}/platform.toml",
        owner, repo, branch
    );

    info!("Downloading platform.toml from: {}", raw_url);

    // Download platform.toml
    let client = reqwest::Client::new();
    let response = match client.get(&raw_url).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                resp
            } else {
                warn!("platform.toml not found at {} (status: {})", raw_url, resp.status());
                return Ok(None);
            }
        }
        Err(e) => {
            warn!("Failed to download platform.toml from {}: {}", raw_url, e);
            return Ok(None);
        }
    };

    let content = response.text().await.context("Failed to read platform.toml content")?;

    // Parse TOML
    let platform_toml: PlatformToml = toml::from_str(&content)
        .context("Failed to parse platform.toml")?;

    Ok(Some(platform_toml))
}

/// Detect required environment variables for a challenge from platform.toml
async fn detect_required_env_vars_from_platform_toml(
    github_repo: Option<&String>,
) -> Result<Vec<EnvVarConfig>> {
    // If no GitHub repo, return empty
    let github_repo = match github_repo {
        Some(repo) if !repo.is_empty() => repo,
        _ => {
            warn!("No GitHub repository specified, cannot load platform.toml");
            return Ok(Vec::new());
        }
    };

    // Try to load platform.toml
    match load_platform_toml_from_github(github_repo).await {
        Ok(Some(platform_toml)) => {
            if let Some(validator_config) = platform_toml.validator {
                info!(
                    "Found {} required env vars in platform.toml",
                    validator_config.required_env_vars.len()
                );
                return Ok(validator_config.required_env_vars);
            } else {
                warn!("platform.toml found but no [validator] section");
                return Ok(Vec::new());
            }
        }
        Ok(None) => {
            warn!("platform.toml not found in repository, falling back to default detection");
            return Ok(Vec::new());
        }
        Err(e) => {
            warn!("Failed to load platform.toml: {}, falling back to default detection", e);
            return Ok(Vec::new());
        }
    }
}

/// Detect required environment variables for a challenge
/// First tries to read from platform.toml, then falls back to name-based detection
async fn detect_required_env_vars(
    challenge_name: &str,
    github_repo: Option<&String>,
) -> Result<Vec<EnvVarConfig>> {
    // First, try to load from platform.toml
    let mut env_vars = detect_required_env_vars_from_platform_toml(github_repo).await?;

    // If platform.toml didn't provide any, fall back to name-based detection
    if env_vars.is_empty() {
        warn!("No env vars found in platform.toml, using fallback detection");
        
        // Check challenge name or common patterns
        if challenge_name.contains("term") || challenge_name.contains("terminal") {
            env_vars.push(EnvVarConfig {
                name: "CHUTES_API_TOKEN".to_string(),
                description: Some("CHUTES API token for LLM validation".to_string()),
                optional: false,
            });
        }
    }

    Ok(env_vars)
}

/// Prompt for private environment variables for a challenge with configs from platform.toml
/// Returns a HashMap of env var names to their values
async fn prompt_for_challenge_env_vars_with_config(
    dynamic_values: &DynamicValuesManager,
    challenge_id: &str,
    challenge_name: &str,
    env_configs: &[EnvVarConfig],
) -> Result<HashMap<String, String>> {
    info!(
        "Prompting for private environment variables for challenge: {} ({})",
        challenge_name, challenge_id
    );

    if env_configs.is_empty() {
        info!("No required environment variables detected for challenge {}", challenge_name);
        return Ok(HashMap::new());
    }

    // Check if running in interactive mode
    let is_interactive = io::stdin().is_terminal() && io::stdout().is_terminal();
    let is_dev_mode = std::env::var("VALIDATOR_MOCK_VMM")
        .unwrap_or_else(|_| "false".to_string())
        .to_lowercase() == "true"
        || std::env::var("DEV_MODE")
            .unwrap_or_else(|_| "false".to_string())
            .to_lowercase() == "true";

    if !is_interactive || is_dev_mode {
        // Non-interactive mode: try to read from environment variables
        warn!(
            "Non-interactive mode detected (dev mode or non-TTY). Reading private env vars from environment."
        );
        
        let mut env_vars = HashMap::new();
        for env_config in env_configs {
            let var_name = &env_config.name;
            
            // Skip optional vars in non-interactive mode if not set
            if env_config.optional {
                if let Ok(Some(existing_value)) = dynamic_values.get_private_env_var(challenge_id, var_name).await {
                    env_vars.insert(var_name.clone(), existing_value);
                } else if let Ok(env_value) = std::env::var(var_name) {
                    if !env_value.is_empty() {
                        dynamic_values
                            .set_private_env_var(challenge_id, var_name, &env_value)
                            .await?;
                        env_vars.insert(var_name.clone(), env_value);
                    }
                }
                continue;
            }

            // First check if already stored in DB
            if let Ok(Some(existing_value)) = dynamic_values.get_private_env_var(challenge_id, var_name).await {
                env_vars.insert(var_name.clone(), existing_value);
                info!("Using stored value for {} from database", var_name);
                continue;
            }

            // Then try to read from environment
            if let Ok(env_value) = std::env::var(var_name) {
                if !env_value.is_empty() {
                    // Store in database for future use
                    dynamic_values
                        .set_private_env_var(challenge_id, var_name, &env_value)
                        .await?;
                    env_vars.insert(var_name.clone(), env_value);
                    info!("Read {} from environment variable", var_name);
                    continue;
                }
            }

            // If not found, warn but continue (dev mode)
            warn!(
                "Private env var {} not found in DB or environment. Challenge may fail without it.",
                var_name
            );
        }

        return Ok(env_vars);
    }

    println!("\n📋 Configuration requise pour le challenge: {}", challenge_name);
    println!("   Challenge ID: {}\n", challenge_id);

    let mut env_vars = HashMap::new();

    for env_config in env_configs {
        let var_name = &env_config.name;
        
        // Skip optional vars if not set
        if env_config.optional {
            // For optional vars, check if already stored, otherwise skip
            if let Ok(Some(existing_value)) = dynamic_values.get_private_env_var(challenge_id, var_name).await {
                env_vars.insert(var_name.clone(), existing_value);
            }
            continue;
        }

        // Check if already stored
        if let Ok(Some(existing_value)) = dynamic_values.get_private_env_var(challenge_id, var_name).await {
            println!("🔑 Variable d'environnement détectée: {}", var_name);
            if let Some(desc) = &env_config.description {
                println!("   Description: {}", desc);
            }
            let use_existing: String = Input::<String>::new()
                .with_prompt(&format!("   Utiliser la valeur existante? (o/n)"))
                .default("o".to_string())
                .interact_text()?;

            if use_existing.to_lowercase().starts_with('o') {
                println!("   ✅ Utilisation de la valeur existante");
                env_vars.insert(var_name.clone(), existing_value);
                continue;
            }
        }

        // Prompt for new value
        println!("\n🔑 Variable d'environnement requise: {}", var_name);
        if let Some(desc) = &env_config.description {
            println!("   Description: {}", desc);
        }
        
        let value = if var_name.contains("TOKEN") || var_name.contains("SECRET") || var_name.contains("KEY") || var_name.contains("PASSWORD") {
            // Use password input for sensitive values
            Password::new()
                .with_prompt(&format!("   Entrez la valeur de {} (masqué)", var_name))
                .with_confirmation("   Confirmez la valeur", "Les valeurs ne correspondent pas")
                .interact()?
        } else {
            // Use regular input for non-sensitive values
            Input::<String>::new()
                .with_prompt(&format!("   Entrez la valeur de {}", var_name))
                .interact_text()?
        };

        // Store in database
        dynamic_values
            .set_private_env_var(challenge_id, var_name, &value)
            .await?;

        env_vars.insert(var_name.clone(), value);
        println!("   ✅ Variable stockée\n");
    }

    info!(
        "Stored {} private environment variables for challenge {}",
        env_vars.len(),
        challenge_id
    );

    Ok(env_vars)
}

/// Get stored private environment variables for a challenge
/// If any required vars are missing, prompt for them
pub async fn get_or_prompt_env_vars(
    dynamic_values: &DynamicValuesManager,
    challenge_id: &str,
    challenge_name: &str,
    github_repo: Option<&String>,
) -> Result<HashMap<String, String>> {
    // Detect required vars from platform.toml
    let required_env_configs = detect_required_env_vars(challenge_name, github_repo).await?;

    if required_env_configs.is_empty() {
        // No required vars, just return empty map
        return Ok(HashMap::new());
    }

    // Extract just the names for checking
    let required_var_names: Vec<String> = required_env_configs
        .iter()
        .map(|config| config.name.clone())
        .collect();

    // Get stored vars
    let mut stored_vars = dynamic_values.get_private_env_vars(challenge_id).await?;

    // Check if all required vars are present
    let mut missing_vars = Vec::new();
    for var_name in &required_var_names {
        if !stored_vars.contains_key(var_name) {
            missing_vars.push(var_name.clone());
        }
    }

    if !missing_vars.is_empty() {
        warn!(
            "Missing required environment variables for challenge {}: {:?}",
            challenge_id, missing_vars
        );
        
        // Prompt for missing vars (pass the configs with descriptions)
        let prompted_vars = prompt_for_challenge_env_vars_with_config(
            dynamic_values,
            challenge_id,
            challenge_name,
            &required_env_configs,
        )
        .await?;
        
        // Merge with stored vars
        for (key, value) in prompted_vars {
            stored_vars.insert(key, value);
        }
    }

    Ok(stored_vars)
}

