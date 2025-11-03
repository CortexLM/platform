use anyhow::Result;
use clap::{Args, Parser};
use git2::Repository;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Parser)]
pub struct ChallengeInstallCmd {
    #[command(subcommand)]
    command: ChallengeCommands,
}

#[derive(Parser)]
enum ChallengeCommands {
    /// Install a challenge from a Git repository
    Install(InstallArgs),

    /// Validate a challenge installation
    Validate(ValidateArgs),
}

#[derive(Args)]
struct InstallArgs {
    /// Git repository URL
    #[arg(long)]
    repo_url: String,

    /// Branch or commit hash
    #[arg(long, default_value = "main")]
    ref_name: String,

    /// Installation directory
    #[arg(short, long, default_value = "./challenges")]
    install_dir: PathBuf,

    /// Validator URL
    #[arg(long, default_value = "http://localhost:3030")]
    validator_url: String,
}

#[derive(Args)]
struct ValidateArgs {
    /// Challenge directory
    #[arg(short, long)]
    challenge_dir: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
struct PlatformJson {
    name: String,
    description: Option<String>,
    version: String,
    #[serde(default)]
    dynamic_values_global: HashMap<String, Value>,
    #[serde(default)]
    dynamic_values_validator: HashMap<String, Value>,
    #[serde(default)]
    interactive_installation: Option<InteractiveInstallation>,
}

#[derive(Debug, Deserialize, Serialize)]
struct InteractiveInstallation {
    required_validator_values: Vec<ValidatorValueConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ValidatorValueConfig {
    key: String,
    description: String,
    #[serde(default)]
    default_value: Option<Value>,
    #[serde(default)]
    validation: Option<ValidationConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ValidationConfig {
    #[serde(rename = "type")]
    validation_type: String,
    #[serde(default)]
    pattern: Option<String>,
    #[serde(default)]
    min: Option<f64>,
    #[serde(default)]
    max: Option<f64>,
}

impl ChallengeInstallCmd {
    pub async fn execute(&self) -> Result<()> {
        match &self.command {
            ChallengeCommands::Install(args) => self.install_challenge(args).await,
            ChallengeCommands::Validate(args) => self.validate_challenge(args).await,
        }
    }

    async fn install_challenge(&self, args: &InstallArgs) -> Result<()> {
        println!("🔍 Cloning repository: {}", args.repo_url);

        // Create temp directory for cloning
        let temp_dir = std::env::temp_dir().join(format!("pv-install-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir)?;

        // Clone repository
        let repo = match Repository::clone(&args.repo_url, &temp_dir) {
            Ok(repo) => repo,
            Err(e) => anyhow::bail!("Failed to clone repository: {}", e),
        };

        // Checkout specific ref
        let commit = if args.ref_name.len() == 40 {
            // Looks like a commit hash
            repo.find_commit(git2::Oid::from_str(&args.ref_name)?)?
        } else {
            // Branch or tag
            let ref_name = format!("refs/remotes/origin/{}", args.ref_name);
            let reference = repo.find_reference(&ref_name)?;
            reference.peel_to_commit()?
        };

        println!("✓ Checked out commit: {}", commit.id());

        // Load platform.json
        let platform_json_path = temp_dir.join("platform.json");
        if !platform_json_path.exists() {
            anyhow::bail!("platform.json not found in repository");
        }

        let platform_json_content = std::fs::read_to_string(&platform_json_path)?;
        let platform_json: PlatformJson = serde_json::from_str(&platform_json_content)?;

        println!(
            "✓ Loaded platform.json for challenge: {}",
            platform_json.name
        );
        println!(
            "  Description: {}",
            platform_json.description.as_deref().unwrap_or("N/A")
        );
        println!("  Version: {}", platform_json.version);

        // Display config
        println!("\n📋 Configuration:");
        println!(
            "  Global dynamic values: {} keys",
            platform_json.dynamic_values_global.len()
        );
        println!(
            "  Validator dynamic values: {} keys",
            platform_json.dynamic_values_validator.len()
        );

        // Interactive installation if required
        if let Some(installation) = &platform_json.interactive_installation {
            println!("\n🔧 Interactive Installation Required");
            self.handle_interactive_installation(
                installation,
                &platform_json.name,
                &args.validator_url,
            )
            .await?;
        }

        // Copy to installation directory
        let challenge_install_dir = args.install_dir.join(&platform_json.name);
        std::fs::create_dir_all(&challenge_install_dir)?;

        self.copy_directory(&temp_dir, &challenge_install_dir)?;

        println!("\n✓ Challenge installed successfully!");
        println!("  Directory: {}", challenge_install_dir.display());
        println!("  Commit: {}", commit.id());

        // Cleanup temp directory
        std::fs::remove_dir_all(&temp_dir)?;

        Ok(())
    }

    async fn handle_interactive_installation(
        &self,
        installation: &InteractiveInstallation,
        challenge_id: &str,
        validator_url: &str,
    ) -> Result<()> {
        use inquire::{Confirm, Text};

        println!("\nThis challenge requires validator-specific configuration:");

        for value_config in &installation.required_validator_values {
            println!("\n📝 {}", value_config.description);

            let default_value = value_config
                .default_value
                .as_ref()
                .map(|v| serde_json::to_string(v).unwrap_or_default())
                .unwrap_or_default();

            let input_prompt = if !default_value.is_empty() {
                format!(
                    "Enter value for '{}' (default: {})",
                    value_config.key, default_value
                )
            } else {
                format!("Enter value for '{}'", value_config.key)
            };

            let user_input = Text::new(&input_prompt)
                .with_default(&default_value)
                .prompt()?;

            // Validate input
            if let Some(validation) = &value_config.validation {
                if let Err(e) = self.validate_value(&user_input, validation) {
                    println!("❌ Validation error: {}", e);
                    if !Confirm::new("Do you want to try again?").prompt()? {
                        anyhow::bail!("Installation cancelled");
                    }
                    continue;
                }
            }

            // Parse and set value
            let json_value: Value = serde_json::from_str(&user_input)?;

            // Set via HTTP API
            let client = reqwest::Client::new();
            let url = format!("{}/challenges/{}/values", validator_url, challenge_id);

            let response = client
                .post(&url)
                .json(&serde_json::json!({
                    "key": value_config.key,
                    "value": json_value
                }))
                .send()
                .await?;

            if response.status().is_success() {
                println!("✓ Set {} = {}", value_config.key, user_input);
            } else {
                anyhow::bail!("Failed to set value: {}", response.status());
            }
        }

        Ok(())
    }

    fn validate_value(&self, value: &str, validation: &ValidationConfig) -> Result<()> {
        match validation.validation_type.as_str() {
            "number" => {
                let num: f64 = value
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Must be a number"))?;

                if let Some(min) = validation.min {
                    if num < min {
                        anyhow::bail!("Must be >= {}", min);
                    }
                }

                if let Some(max) = validation.max {
                    if num > max {
                        anyhow::bail!("Must be <= {}", max);
                    }
                }
            }
            "string" => {
                if let Some(pattern) = &validation.pattern {
                    let re = Regex::new(pattern)?;
                    if !re.is_match(value) {
                        anyhow::bail!("Does not match pattern: {}", pattern);
                    }
                }
            }
            "boolean" => {
                value
                    .parse::<bool>()
                    .map_err(|_| anyhow::anyhow!("Must be true or false"))?;
            }
            _ => {
                anyhow::bail!("Unknown validation type: {}", validation.validation_type);
            }
        }

        Ok(())
    }

    fn copy_directory(&self, src: &Path, dst: &Path) -> Result<()> {
        use walkdir::WalkDir;

        for entry in WalkDir::new(src) {
            let entry = entry?;
            let path = entry.path();
            let relative_path = path.strip_prefix(src)?;
            let dst_path = dst.join(relative_path);

            if path.is_dir() {
                std::fs::create_dir_all(&dst_path)?;
            } else {
                std::fs::copy(path, &dst_path)?;
            }
        }

        Ok(())
    }

    async fn validate_challenge(&self, args: &ValidateArgs) -> Result<()> {
        let platform_json_path = args.challenge_dir.join("platform.json");

        if !platform_json_path.exists() {
            anyhow::bail!(
                "platform.json not found in {}",
                args.challenge_dir.display()
            );
        }

        let platform_json_content = std::fs::read_to_string(&platform_json_path)?;
        let platform_json: PlatformJson = serde_json::from_str(&platform_json_content)?;

        println!("✓ Valid challenge configuration");
        println!("  Name: {}", platform_json.name);
        println!("  Version: {}", platform_json.version);
        println!(
            "  Global values: {} keys",
            platform_json.dynamic_values_global.len()
        );
        println!(
            "  Validator values: {} keys",
            platform_json.dynamic_values_validator.len()
        );

        if let Some(installation) = &platform_json.interactive_installation {
            println!(
                "  Interactive installation: {} required values",
                installation.required_validator_values.len()
            );
        }

        Ok(())
    }
}
