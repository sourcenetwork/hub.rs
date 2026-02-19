//! CLI for hubd.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use hub_config::NodeConfig;
use hub_genesis::HubGenesis;
use hub_jsonrpc::NodeState;
use hub_runner::{ConsensusParams, HubRunner};

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
    pub(crate) fn load_config(&self) -> eyre::Result<NodeConfig> {
        let mut config = NodeConfig::load(self.config.as_deref())?;

        if let Some(chain_id) = self.chain_id {
            config.chain_id = chain_id;
        }
        if let Some(ref data_dir) = self.data_dir {
            config.data_dir = data_dir.clone();
        }

        Ok(config)
    }

    pub(crate) fn run(self) -> eyre::Result<()> {
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
            None => {
                eprintln!("No subcommand given. Use --help for usage.");
                std::process::exit(1);
            }
        }
    }

    fn run_validator(&self, args: &ValidatorArgs) -> eyre::Result<()> {
        let config = self.load_config()?;

        tracing::info!(chain_id = config.chain_id, "Starting hub validator");

        let peers = load_peers(&args.peers)?;
        let identity_key = config.validator_key()?;
        let n = peers.participants.len();

        let (scheme, group_pub_key, validator_index) =
            hub_runner::generate_for_validator(args.seed, n, &identity_key)
                .map_err(|e| eyre::eyre!("Failed to generate threshold scheme: {}", e))?;

        tracing::info!(validator_index, "Generated threshold scheme from seed");

        let mut config = config;
        config.network.bootstrap_peers = peers
            .bootstrappers
            .iter()
            .map(|(pk, addr)| format!("{}@{}", hex::encode(pk.as_ref()), addr))
            .collect();

        let genesis_path = config.data_dir.join("genesis.json");
        let hub_genesis = HubGenesis::load(&genesis_path)
            .map_err(|e| eyre::eyre!("Failed to load genesis: {}", e))?;
        let bootstrap = hub_genesis
            .to_bootstrap_config()
            .map_err(|e| eyre::eyre!("Failed to parse genesis: {}", e))?;

        let rpc_port = args.rpc_port.unwrap_or(8545 + validator_index as u16);
        let rpc_addr: std::net::SocketAddr = format!("0.0.0.0:{}", rpc_port).parse()?;
        let node_state = NodeState::new(
            config.chain_id,
            validator_index,
            scheme.participants().len() as u32,
        );

        let mut runner = HubRunner::new(
            scheme,
            config.chain_id,
            hub_config::DEFAULT_GAS_LIMIT,
            bootstrap,
            group_pub_key,
        )
        .with_rpc(node_state, rpc_addr);

        if let Some(consensus) = parse_consensus_params(
            args.leader_timeout_ms,
            args.notarization_timeout_ms,
            args.nullify_retry_ms,
        ) {
            runner = runner.with_consensus(consensus);
        }

        runner
            .run_standalone(config)
            .map_err(|e| eyre::eyre!("Runner failed: {}", e))
    }

    fn run_devnet(&self, args: &DevnetArgs) -> eyre::Result<()> {
        use commonware_cryptography::Signer as _;

        let genesis = if let Some(ref path) = args.genesis {
            HubGenesis::load(path).map_err(|e| eyre::eyre!("Failed to load genesis: {}", e))?
        } else {
            HubGenesis::devnet()
        };

        let chain_id = self.chain_id.unwrap_or(genesis.chain_id);
        tracing::info!(chain_id, "Starting hub devnet (single-node)");

        let bootstrap = genesis
            .to_bootstrap_config()
            .map_err(|e| eyre::eyre!("Failed to parse genesis: {}", e))?;

        const DEVNET_SEED: u64 = 0;

        let (_participants, schemes) = hub_crypto::threshold_schemes(DEVNET_SEED, 1)
            .map_err(|e| eyre::eyre!("Failed to generate threshold scheme: {}", e))?;
        let scheme = schemes.into_iter().next().expect("exactly one scheme");

        let mut group_public_key = Vec::new();
        commonware_codec::Write::write(scheme.identity(), &mut group_public_key);

        let validator_key = commonware_cryptography::ed25519::PrivateKey::from_seed(DEVNET_SEED);
        let validator_pk = validator_key.public_key();
        tracing::info!(pk = %hex::encode(commonware_codec::Encode::encode(&validator_pk)), "Devnet validator");

        let data_dir = self.data_dir.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("hub-devnet-{}", std::process::id()))
        });
        std::fs::create_dir_all(&data_dir)?;

        let key_bytes = commonware_codec::Encode::encode(&validator_key);
        std::fs::write(data_dir.join("validator.key"), key_bytes.as_ref())?;
        tracing::info!(?data_dir, "Devnet data directory ready");

        let config = hub_config::NodeConfig {
            chain_id,
            data_dir,
            ..Default::default()
        };

        let rpc_addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.rpc_port).parse()?;
        let node_state = hub_jsonrpc::NodeState::new(chain_id, 0, 1);

        let mut runner = HubRunner::new(
            scheme,
            chain_id,
            hub_config::DEFAULT_GAS_LIMIT,
            bootstrap,
            group_public_key,
        )
        .with_rpc(node_state, rpc_addr);

        if let Some(consensus) = parse_consensus_params(
            args.leader_timeout_ms,
            args.notarization_timeout_ms,
            args.nullify_retry_ms,
        ) {
            runner = runner.with_consensus(consensus);
        }

        tracing::info!(rpc_port = args.rpc_port, "Starting hub devnet node");

        runner
            .run_standalone(config)
            .map_err(|e| eyre::eyre!("Runner failed: {}", e))
    }
}

#[derive(Debug)]
struct PeersInfo {
    participants: Vec<commonware_cryptography::ed25519::PublicKey>,
    bootstrappers: Vec<(commonware_cryptography::ed25519::PublicKey, String)>,
}

fn load_peers(path: &PathBuf) -> eyre::Result<PeersInfo> {
    use commonware_codec::ReadExt;

    let content = std::fs::read_to_string(path)?;
    let json: serde_json::Value = serde_json::from_str(&content)?;

    let participants_hex: Vec<String> = json["participants"]
        .as_array()
        .ok_or_else(|| eyre::eyre!("missing participants"))?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let mut participants = Vec::with_capacity(participants_hex.len());
    for pk_hex in &participants_hex {
        let bytes = hex::decode(pk_hex)?;
        let pk = commonware_cryptography::ed25519::PublicKey::read(&mut bytes.as_slice())?;
        participants.push(pk);
    }

    let bootstrappers_obj = json["bootstrappers"]
        .as_object()
        .ok_or_else(|| eyre::eyre!("missing bootstrappers"))?;

    let mut bootstrappers = Vec::new();
    for (pk_hex, addr) in bootstrappers_obj {
        let bytes = hex::decode(pk_hex)?;
        let pk = commonware_cryptography::ed25519::PublicKey::read(&mut bytes.as_slice())?;
        let addr_str = addr
            .as_str()
            .ok_or_else(|| eyre::eyre!("invalid address"))?;
        bootstrappers.push((pk, addr_str.to_string()));
    }

    Ok(PeersInfo {
        participants,
        bootstrappers,
    })
}

fn parse_consensus_params(
    leader_timeout_ms: Option<u64>,
    notarization_timeout_ms: Option<u64>,
    nullify_retry_ms: Option<u64>,
) -> Option<ConsensusParams> {
    if leader_timeout_ms.is_none()
        && notarization_timeout_ms.is_none()
        && nullify_retry_ms.is_none()
    {
        return None;
    }

    let defaults = ConsensusParams::default();
    Some(ConsensusParams {
        leader_timeout: leader_timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or(defaults.leader_timeout),
        notarization_timeout: notarization_timeout_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or(defaults.notarization_timeout),
        nullify_retry: nullify_retry_ms
            .map(std::time::Duration::from_millis)
            .unwrap_or(defaults.nullify_retry),
    })
}
