//! TestCluster builder — composes keys, config, and genesis into a runnable cluster.

use std::{
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

use super::{
    genesis::GenesisBuilder,
    health::{self, HealthCheckConfig},
    keys::KeySet,
    node_config::{ConsensusPreset, NodeConfigBuilder},
};
use crate::{
    ManagedProcess, TestRunDir, generate_run_id,
    observe::{ClusterState, LogTracker, RpcPoller},
};

/// A running test cluster with managed node processes.
///
/// Field order matters: `nodes` must be dropped before `_run_dir` so
/// processes are killed before their data directory is removed.
#[derive(Debug)]
pub struct TestCluster {
    nodes: Vec<TestNode>,
    chain_id: u64,
    _run_dir: TestRunDir,
}

/// A single managed node in the test cluster.
#[derive(Debug)]
pub struct TestNode {
    /// JSON-RPC port.
    pub rpc_port: u16,
    /// P2P port.
    pub p2p_port: u16,
    /// Node data directory.
    pub data_dir: PathBuf,
    /// Log directory for this node.
    pub log_dir: PathBuf,
    /// Managed child process.
    pub process: ManagedProcess,
}

impl TestNode {
    /// JSON-RPC URL for this node.
    pub fn rpc_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }

    /// WebSocket URL for this node (same port as JSON-RPC).
    pub fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}", self.rpc_port)
    }
}

impl TestCluster {
    /// Create a new builder.
    pub fn builder() -> TestClusterBuilder {
        TestClusterBuilder::default()
    }

    /// Number of nodes in the cluster.
    pub const fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Access a specific node.
    pub fn node(&self, index: usize) -> &TestNode {
        &self.nodes[index]
    }

    /// Get all RPC URLs.
    pub fn rpc_urls(&self) -> Vec<String> {
        self.nodes.iter().map(|n| n.rpc_url()).collect()
    }

    /// Chain ID of the cluster.
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Wait for all nodes' JSON-RPC endpoints to become responsive.
    pub async fn wait_ready(&self, timeout: Duration) -> eyre::Result<()> {
        let config = HealthCheckConfig {
            poll_interval: Duration::from_millis(50),
            timeout,
        };
        health::wait_all_healthy(&self.rpc_urls(), &config).await
    }

    /// Kill a node's process. The node can be restarted later with `restart_node`.
    pub fn kill_node(&mut self, index: usize) {
        self.nodes[index].process.kill();
    }

    /// Restart a previously killed node by respawning its process.
    pub fn restart_node(&mut self, index: usize) -> eyre::Result<()> {
        self.nodes[index].process.respawn()
    }

    /// Create an observability handle for this cluster.
    ///
    /// Spawns background LogTracker tasks per node and an RpcPoller.
    /// Call once and hold the result — each call spawns new background tasks.
    pub fn observe(&self, poll_interval: Duration) -> ClusterState {
        let trackers: Vec<LogTracker> = self
            .nodes
            .iter()
            .map(|n| LogTracker::new(n.log_dir.join("stdout.log")))
            .collect();

        let poller = RpcPoller::new(self.rpc_urls(), poll_interval);
        ClusterState::new(trackers, poller)
    }
}

type JmtSeeder = Box<dyn Fn(&Path, u64) + Send>;

/// Builder for `TestCluster`.
pub struct TestClusterBuilder {
    node_count: usize,
    seed: Option<u64>,
    genesis: Option<GenesisBuilder>,
    preset: ConsensusPreset,
    chain_id: u64,
    jmt_seeder: Option<JmtSeeder>,
}

impl fmt::Debug for TestClusterBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestClusterBuilder")
            .field("node_count", &self.node_count)
            .field("seed", &self.seed)
            .field("genesis", &self.genesis)
            .field("preset", &self.preset)
            .field("chain_id", &self.chain_id)
            .field("has_jmt_seeder", &self.jmt_seeder.is_some())
            .finish()
    }
}

impl Default for TestClusterBuilder {
    fn default() -> Self {
        Self {
            node_count: 1,
            seed: None,
            genesis: None,
            preset: ConsensusPreset::Fast,
            chain_id: 9001,
            jmt_seeder: None,
        }
    }
}

impl TestClusterBuilder {
    /// Set the number of nodes.
    #[must_use]
    pub const fn nodes(mut self, n: usize) -> Self {
        self.node_count = n;
        self
    }

    /// Use a deterministic seed.
    #[must_use]
    pub const fn seed(mut self, s: u64) -> Self {
        self.seed = Some(s);
        self
    }

    /// Set the genesis configuration.
    #[must_use]
    pub fn genesis(mut self, g: GenesisBuilder) -> Self {
        self.genesis = Some(g);
        self
    }

    /// Set the consensus preset.
    #[must_use]
    pub const fn preset(mut self, p: ConsensusPreset) -> Self {
        self.preset = p;
        self
    }

    /// Set the chain ID.
    #[must_use]
    pub const fn chain_id(mut self, id: u64) -> Self {
        self.chain_id = id;
        self
    }

    /// Set a JMT state seeder called for each node before process startup.
    #[must_use]
    pub fn jmt_seeder(mut self, f: impl Fn(&Path, u64) + Send + 'static) -> Self {
        self.jmt_seeder = Some(Box::new(f));
        self
    }

    /// Build and start the cluster.
    pub async fn build(self) -> eyre::Result<TestCluster> {
        let n = self.node_count;
        let chain_id = self.chain_id;
        let run_id = generate_run_id();
        let run_dir = TestRunDir::new(&run_id)?;

        let genesis_builder = self.genesis.unwrap_or_else(GenesisBuilder::devnet);
        let genesis = genesis_builder.chain_id(chain_id).build();

        let node_config = NodeConfigBuilder::new()
            .chain_id(chain_id)
            .preset(self.preset);

        let consensus = node_config.consensus();

        // Build keys.
        let mut key_builder = KeySet::builder().nodes(n);
        if let Some(seed) = self.seed {
            key_builder = key_builder.seed(seed);
        }
        let keys = key_builder.build()?;

        // Allocate ports.
        let all_ports = crate::allocate_ports(n * 2)?;
        let p2p_ports = &all_ports[0..n];
        let rpc_ports = &all_ports[n..n * 2];

        // Create node directories and write config files.
        let node_dirs: Vec<PathBuf> = (0..n)
            .map(|i| run_dir.component_dir(&format!("node{}", i)))
            .collect::<eyre::Result<Vec<_>>>()?;

        // Write key material.
        keys.write_to(&node_dirs)?;

        // Write genesis to each node.
        let genesis_json = serde_json::to_string_pretty(&genesis)?;
        for dir in &node_dirs {
            std::fs::write(dir.join("genesis.json"), &genesis_json)?;
        }

        // Write node configs.
        for (i, dir) in node_dirs.iter().enumerate() {
            let config = node_config.build_node_config(dir.clone(), p2p_ports[i], rpc_ports[i]);
            let config_path = dir.join("config.toml");
            std::fs::write(&config_path, config.to_toml()?)?;
        }

        // For multi-node: write peers.json.
        let peers_path = run_dir.path().join("peers.json");
        if n > 1 {
            keys.write_peers(&peers_path, p2p_ports)?;
        }

        // Seed JMT state before spawning processes.
        if let Some(seeder) = &self.jmt_seeder {
            for dir in &node_dirs {
                seeder(dir, chain_id);
            }
        }

        // Consensus timing CLI args.
        let leader_ms = consensus.leader_timeout.as_millis().to_string();
        let notarization_ms = consensus.notarization_timeout.as_millis().to_string();
        let nullify_ms = consensus.nullify_retry.as_millis().to_string();

        // Spawn nodes.
        let binary = find_hub_binary()?;
        let rust_log = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
        let seed_str = keys.seed().to_string();
        let chain_id_str = chain_id.to_string();
        let peers_str = peers_path.to_str().unwrap().to_string();

        let mut nodes = Vec::with_capacity(n);

        for i in 0..n {
            let node_dir = &node_dirs[i];
            let log_dir = node_dir.join("logs");

            let rpc_port_str = rpc_ports[i].to_string();
            let node_dir_str = node_dir.to_str().unwrap().to_string();
            let genesis_str = node_dir.join("genesis.json").to_str().unwrap().to_string();
            let config_str = node_dir.join("config.toml").to_str().unwrap().to_string();

            let args: Vec<&str> = if n == 1 {
                vec![
                    "devnet",
                    "--rpc-port",
                    &rpc_port_str,
                    "--genesis",
                    &genesis_str,
                    "--data-dir",
                    &node_dir_str,
                    "--chain-id",
                    &chain_id_str,
                    "--leader-timeout-ms",
                    &leader_ms,
                    "--notarization-timeout-ms",
                    &notarization_ms,
                    "--nullify-retry-ms",
                    &nullify_ms,
                ]
            } else {
                vec![
                    "--config",
                    &config_str,
                    "--data-dir",
                    &node_dir_str,
                    "--chain-id",
                    &chain_id_str,
                    "validator",
                    "--seed",
                    &seed_str,
                    "--peers",
                    &peers_str,
                    "--rpc-port",
                    &rpc_port_str,
                    "--leader-timeout-ms",
                    &leader_ms,
                    "--notarization-timeout-ms",
                    &notarization_ms,
                    "--nullify-retry-ms",
                    &nullify_ms,
                ]
            };

            let envs: Vec<(&str, &str)> = vec![("RUST_LOG", &rust_log), ("NO_COLOR", "1")];

            let process =
                ManagedProcess::spawn(&format!("node{}", i), &binary, &args, &envs, &log_dir)?;

            nodes.push(TestNode {
                rpc_port: rpc_ports[i],
                p2p_port: p2p_ports[i],
                data_dir: node_dir.clone(),
                log_dir,
                process,
            });
        }

        Ok(TestCluster {
            _run_dir: run_dir,
            nodes,
            chain_id,
        })
    }
}

/// Find the hubd binary in the target directory.
fn find_hub_binary() -> eyre::Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let binary = manifest_dir
        .parent()
        .and_then(Path::parent)
        .unwrap_or(Path::new("."))
        .join("target")
        .join("debug")
        .join("hubd");

    if !binary.exists() {
        return Err(eyre::eyre!(
            "hubd binary not found at {}. Run `cargo build -p hubd` first.",
            binary.display()
        ));
    }

    Ok(binary)
}
