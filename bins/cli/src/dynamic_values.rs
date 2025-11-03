use anyhow::Result;
use clap::{Args, Parser};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Parser)]
pub struct DynamicValuesCmd {
    #[command(subcommand)]
    command: DynamicCommands,
}

#[derive(Parser)]
enum DynamicCommands {
    /// Set a dynamic value for a challenge
    Set(SetArgs),

    /// Get a dynamic value for a challenge
    Get(GetArgs),

    /// List all dynamic values for a challenge
    List(ListArgs),

    /// Delete a dynamic value for a challenge
    Delete(DeleteArgs),
}

#[derive(Args)]
struct SetArgs {
    /// Challenge ID
    #[arg(short, long)]
    challenge_id: String,

    /// Key to set
    #[arg(short, long)]
    key: String,

    /// Value to set (JSON format)
    #[arg(short, long)]
    value: String,

    /// Validator URL
    #[arg(long, default_value = "http://localhost:3030")]
    validator_url: String,
}

#[derive(Args)]
struct GetArgs {
    /// Challenge ID
    #[arg(short, long)]
    challenge_id: String,

    /// Key to get
    #[arg(short, long)]
    key: String,

    /// Validator URL
    #[arg(long, default_value = "http://localhost:3030")]
    validator_url: String,
}

#[derive(Args)]
struct ListArgs {
    /// Challenge ID
    #[arg(short, long)]
    challenge_id: String,

    /// Validator URL
    #[arg(long, default_value = "http://localhost:3030")]
    validator_url: String,
}

#[derive(Args)]
struct DeleteArgs {
    /// Challenge ID
    #[arg(short, long)]
    challenge_id: String,

    /// Key to delete
    #[arg(short, long)]
    key: String,

    /// Validator URL
    #[arg(long, default_value = "http://localhost:3030")]
    validator_url: String,
}

impl DynamicValuesCmd {
    pub async fn execute(&self) -> Result<()> {
        match &self.command {
            DynamicCommands::Set(args) => self.set_value(args).await,
            DynamicCommands::Get(args) => self.get_value(args).await,
            DynamicCommands::List(args) => self.list_values(args).await,
            DynamicCommands::Delete(args) => self.delete_value(args).await,
        }
    }

    async fn set_value(&self, args: &SetArgs) -> Result<()> {
        let client = reqwest::Client::new();

        // Parse JSON value
        let value: Value = serde_json::from_str(&args.value)?;

        let url = format!(
            "{}/challenges/{}/values",
            args.validator_url, args.challenge_id
        );

        let response = client
            .post(&url)
            .json(&serde_json::json!({
                "key": args.key,
                "value": value
            }))
            .send()
            .await?;

        if response.status().is_success() {
            let result: HashMap<String, String> = response.json().await?;
            println!("✓ Successfully set {} = {}", args.key, args.value);
            if let Some(msg) = result.get("message") {
                println!("  {}", msg);
            }
        } else {
            anyhow::bail!("Failed to set value: {}", response.status());
        }

        Ok(())
    }

    async fn get_value(&self, args: &GetArgs) -> Result<()> {
        let client = reqwest::Client::new();

        let url = format!(
            "{}/challenges/{}/values/{}",
            args.validator_url, args.challenge_id, args.key
        );

        let response = client.get(&url).send().await?;

        if response.status().is_success() {
            let result: HashMap<String, Option<Value>> = response.json().await?;
            if let Some(value) = result.get("value") {
                if let Some(v) = value {
                    println!("{} = {}", args.key, serde_json::to_string_pretty(v)?);
                } else {
                    println!("No value found for key: {}", args.key);
                }
            }
        } else {
            anyhow::bail!("Failed to get value: {}", response.status());
        }

        Ok(())
    }

    async fn list_values(&self, args: &ListArgs) -> Result<()> {
        let client = reqwest::Client::new();

        let url = format!(
            "{}/challenges/{}/values",
            args.validator_url, args.challenge_id
        );

        let response = client.get(&url).send().await?;

        if response.status().is_success() {
            let result: HashMap<String, HashMap<String, Value>> = response.json().await?;
            if let Some(values) = result.get("values") {
                println!("Dynamic values for challenge '{}':", args.challenge_id);
                for (key, value) in values {
                    println!("  {} = {}", key, serde_json::to_string_pretty(value)?);
                }
            }
        } else {
            anyhow::bail!("Failed to list values: {}", response.status());
        }

        Ok(())
    }

    async fn delete_value(&self, args: &DeleteArgs) -> Result<()> {
        let client = reqwest::Client::new();

        let url = format!(
            "{}/challenges/{}/values/{}",
            args.validator_url, args.challenge_id, args.key
        );

        let response = client.delete(&url).send().await?;

        if response.status().is_success() {
            let result: HashMap<String, String> = response.json().await?;
            println!("✓ Successfully deleted key: {}", args.key);
            if let Some(msg) = result.get("message") {
                println!("  {}", msg);
            }
        } else {
            anyhow::bail!("Failed to delete value: {}", response.status());
        }

        Ok(())
    }
}
