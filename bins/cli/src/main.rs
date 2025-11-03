use anyhow::Result;
use clap::{Parser, Subcommand};

mod challenge_install;
mod dynamic_values;

use challenge_install::ChallengeInstallCmd;
use dynamic_values::DynamicValuesCmd;

#[derive(Parser)]
#[command(name = "pv")]
#[command(about = "Platform Validator CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage dynamic values for challenges
    Dynamic(DynamicValuesCmd),

    /// Install and manage challenges
    Challenge(ChallengeInstallCmd),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Dynamic(cmd) => cmd.execute().await,
        Commands::Challenge(cmd) => cmd.execute().await,
    }
}
