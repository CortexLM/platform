use anyhow::Result;
use std::collections::HashMap;
use tracing::{info, warn};
use dialoguer::{Input, Password};
use crate::dynamic_values::DynamicValuesManager;

/// Environment variable configuration from platform.toml
#[derive(Debug, Clone)]
pub struct EnvVarConfig {
    pub name: String,
    pub description: Option<String>,
    pub default_value: Option<String>,
    pub validation: Option<EnvVarValidation>,
}

#[derive(Debug, Clone)]
pub enum EnvVarValidation {
    Number { min: Option<f64>, max: Option<f64> },
    String { pattern: Option<String> },
    Boolean,
}

/// Detect required environment variables for a challenge based on its name and GitHub repo
pub async fn detect_required_env_vars(
    challenge_name: &str,
    github_repo: Option<&String>,
) -> Result<Vec<EnvVarConfig>> {
    let mut required_vars = Vec::new();

    // Detect based on challenge name
    if challenge_name.contains("term") || challenge_name.contains("terminal") {
        required_vars.push(EnvVarConfig {
            name: "CHUTES_API_TOKEN".to_string(),
            description: Some("The API token for the CHUTES LLM service. Required for terminal challenges.".to_string()),
            default_value: None,
            validation: None,
        });
    }

    // Detect based on GitHub repo if available
    if let Some(repo) = github_repo {
        // Could parse platform.toml from repo if needed
        // For now, just use name-based detection
    }

    Ok(required_vars)
}

/// Prompt for challenge environment variables with configuration
pub async fn prompt_for_challenge_env_vars_with_config(
    dynamic_values: &DynamicValuesManager,
    challenge_id: &str,
    challenge_name: &str,
    env_configs: &[EnvVarConfig],
) -> Result<HashMap<String, String>> {
    let mut env_vars = HashMap::new();

    for env_config in env_configs {
        let var_name = &env_config.name;

        // Check if already stored
        if let Ok(Some(existing_value)) = dynamic_values.get_private_env_var(challenge_id, var_name).await {
            println!("🔑 Environment variable detected: {}", var_name);
            if let Some(desc) = &env_config.description {
                println!("   Description: {}", desc);
            }
            let use_existing: String = Input::<String>::new()
                .with_prompt(&format!("   Use existing value? (y/n)"))
                .default("y".to_string())
                .interact_text()?;

            if use_existing.to_lowercase().starts_with('y') {
                println!("   ✅ Using existing value");
                env_vars.insert(var_name.clone(), existing_value);
                continue;
            }
        }

        // Prompt for new value
        println!("\n🔑 Required environment variable: {}", var_name);
        if let Some(desc) = &env_config.description {
            println!("   Description: {}", desc);
        }
        
        let value = if var_name.contains("TOKEN") || var_name.contains("SECRET") || var_name.contains("KEY") || var_name.contains("PASSWORD") {
            // Use password input for sensitive values
            Password::new()
                .with_prompt(&format!("   Enter value for {} (hidden)", var_name))
                .with_confirmation("   Confirm value", "Values do not match")
                .interact()?
        } else {
            // Use regular input for non-sensitive values
            Input::<String>::new()
                .with_prompt(&format!("   Enter value for {}", var_name))
                .interact_text()?
        };

        // Store in database
        dynamic_values
            .set_private_env_var(challenge_id, var_name, &value)
            .await?;

        env_vars.insert(var_name.clone(), value);
        println!("   ✅ Variable stored\n");
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
