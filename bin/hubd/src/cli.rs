//! CLI for hubd.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::testnet;

#[derive(Parser, Debug)]
#[command(name = "hubd")]
#[command(about = "SourceHub validator node (commonware + REVM)")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to config file.
    #[arg(short, long, value_name = "FILE", global = true)]
    pub config: Option<PathBuf>,

    /// Enable verbose logging.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Override chain ID.
    #[arg(long, global = true)]
    pub chain_id: Option<u64>,

    /// Override data directory.
    #[arg(long, global = true)]
    pub data_dir: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Commands {
    /// Run validator node.
    Validator(ValidatorArgs),
    /// Run single-node devnet (no DKG required).
    Devnet(DevnetArgs),
    /// Run multi-node local testnet (trusted-dealer DKG).
    Testnet(testnet::TestnetArgs),
    /// Interact with a running hub node.
    Client(crate::client::ClientArgs),
}

#[derive(clap::Args, Debug)]
pub(crate) struct ValidatorArgs {
    /// Shared seed for deterministic threshold scheme generation.
    #[arg(long)]
    pub seed: u64,

    /// Path to peers.json file containing participant information.
    #[arg(long)]
    pub peers: PathBuf,

    /// Override JSON-RPC port (default: 8545 + validator_index).
    #[arg(long)]
    pub rpc_port: Option<u16>,

    /// Leader proposal timeout in milliseconds.
    #[arg(long)]
    pub leader_timeout_ms: Option<u64>,

    /// Notarization timeout in milliseconds.
    #[arg(long)]
    pub notarization_timeout_ms: Option<u64>,

    /// Nullification retry interval in milliseconds.
    #[arg(long)]
    pub nullify_retry_ms: Option<u64>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct DevnetArgs {
    /// Genesis file path (defaults to built-in devnet genesis).
    #[arg(long)]
    pub genesis: Option<PathBuf>,

    /// JSON-RPC listen port.
    #[arg(long, default_value = "8545")]
    pub rpc_port: u16,

    /// Leader proposal timeout in milliseconds.
    #[arg(long)]
    pub leader_timeout_ms: Option<u64>,

    /// Notarization timeout in milliseconds.
    #[arg(long)]
    pub notarization_timeout_ms: Option<u64>,

    /// Nullification retry interval in milliseconds.
    #[arg(long)]
    pub nullify_retry_ms: Option<u64>,
}

impl Cli {
    pub(crate) fn run(self) -> eyre::Result<()> {
        // Client takes ownership; extract it before borrowing self for other arms.
        if let Some(Commands::Client(args)) = self.command {
            return args.run();
        }
        match &self.command {
            Some(Commands::Validator(args)) => self.run_validator(args),
            Some(Commands::Devnet(args)) => self.run_devnet(args),
            Some(Commands::Testnet(args)) => {
                let chain_id = self.chain_id.unwrap_or(9001);
                let data_dir = self.data_dir.clone().unwrap_or_else(|| {
                    std::env::temp_dir().join(format!("hub-testnet-{}", std::process::id()))
                });
                testnet::run(chain_id, data_dir, args)
            }
            Some(Commands::Client(_)) => unreachable!(),
            None => {
                eprintln!("No subcommand given. Use --help for usage.");
                std::process::exit(1);
            }
        }
    }

    fn run_validator(&self, _args: &ValidatorArgs) -> eyre::Result<()> {
        eyre::bail!("consensus is not wired in this build");
    }

    fn run_devnet(&self, _args: &DevnetArgs) -> eyre::Result<()> {
        eyre::bail!("consensus is not wired in this build");
    }
}
