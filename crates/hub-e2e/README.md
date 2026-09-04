# hub-e2e

End-to-end integration tests. Each test stands up a real multi-node `hubd`
cluster (BFT consensus needs ≥4 nodes) and drives it over JSON-RPC, exercising
both the EVM (`eth_sendRawTransaction`) and native BLS (`hub_sendNativeTx`)
transaction paths.

## Required pre-build

Tests spawn the real `hubd` binary, so build it first:

```bash
cargo build -p hubd
```

## Binary selection

The harness's `resolve_binary()` (via `test_infra::BinaryResolver`, `HUBD`
prefix) looks for the binary in this order:

1. `HUBD_BINARY` — explicit path, no version check
2. `HUBD_WORKSPACE` — a hub.rs checkout; builds the `hubd` package there
3. `hubd` on `PATH`
4. a `backbone.toml` manifest pin

It does **not** auto-discover `target/debug/hubd`, so point it at a build
explicitly. The recommended, serial-safe invocation uses an absolute
`HUBD_BINARY` and runs one test target at a time:

```bash
cargo build -p hubd
HUBD_BINARY="$(pwd)/target/debug/hubd" \
  cargo test -p hub-e2e --test hub_e2e_canonical
```

## Serial / global-lock expectation

Each target starts a real multi-process cluster, and the Fast timing preset is
sensitive to host load. Run targets one at a time. Each cluster gets an isolated
run directory and ephemeral ports; `validator_bootstrap.rs` additionally uses a
process-wide `Mutex` (`validator_test_lock`) to serialize its two tests. Do not
run e2e targets concurrently in the same checkout.

## Test targets

All targets live in `crates/hub-e2e/tests/`:

| Target | Test(s) | Purpose |
|--------|---------|---------|
| `hub_e2e_canonical` | `canonical_module_test` | **Baseline gate.** Full module lifecycle on a 4-node cluster through both tx paths: ACP (policy, object, relationship, access), Bulletin (namespace, collaborator, post), cross-path verification (BLS write + EVM query and vice versa), and cluster health. Any change that breaks this has broken the core pipeline. |
| `contract_deploy` | `deploy_and_interact` | Deploys a minimal storage contract via CREATE, then exercises read (`eth_getStorageAt`) and write (`eth_sendRawTransaction`) paths against it. |
| `core_chain` | `cluster_observability_canonical` | 4-node BFT cluster with observability attached; cross-validates block heights and events between `LogTracker`, `RpcPoller`, and `ClusterState`. |
| `cross_object_acp` | `cross_object_grant_replicates_across_nodes` | Seeds a cross-object parent edge (subject is another object's userset) plus a child grant on node 0, then asserts on every other node that both replicate and that access resolves across the edge via `TupleToUserset`. |
| `gossip_headers` | `gossip_headers_subscription` | Verifies `eth_subscribe("headers")` delivers signed `GossipHeader` events (chain id, height, hashes, roots, signature) as blocks finalize. |
| `light_client` | `light_client_proof_verification` | Full light-client pipeline: gossip headers, `verify_light_block` on the BLS threshold certificate + epoch group key, module state proofs against `module_state_root`, and state-change detection across block boundaries. |
| `node_restart` | `node_restart_preserves_state` | Starts 4 nodes, submits EVM + BLS txs, kills node 3, verifies the 3-node cluster continues, restarts it, and verifies pre-kill state survived (QMDB persistence), catch-up, post-restart txs on both paths, and tx submission *through* the restarted node. |
| `validator_bootstrap` | `validator_bootstrap`, `validator_registry_adversarial` | Validators configured in genesis are readable via the ValidatorRegistry precompile; add/remove/status-change/self-update writes work through EVM txs, and adversarial inputs are rejected. Tests serialize on the global lock above. |
| `validator_epoch_transition` | `validator_epoch_transition` | Verifies ValidatorRegistry membership feeds resharing and that the engine actually enters the next epoch whose key material includes a newly registered validator. |

## Harness environment and file contracts

- `HUB_E2E_DIR` — base directory for run artifacts (default `target/e2e`).
  Each run gets an isolated `{timestamp}-{random}` directory.
- `HUB_E2E_KEEP=1` — preserve the run directory on drop instead of deleting it.
- `RUST_LOG` — forwarded to every node process (default `info`); `NO_COLOR=1`
  is always set for node logs.
- Per-node layout under the run dir: `node{i}/` holds the node's config,
  data dir, and `logs/`; `TestNode` exposes `rpc_url()` / `ws_url()` on
  ephemeral OS-allocated ports (RPC and P2P allocated together per node).
- `GenesisBuilder` produces the genesis file (funded Hardhat accounts,
  optional `ValidatorConfig`s, `blocks_per_epoch`); `ConsensusPreset` selects
  Fast/Normal/Stress timing.
- Receipt polling constants `RECEIPT_POLL_INTERVAL` (300 ms) and
  `RECEIPT_POLL_ATTEMPTS` (400) are re-exported from `hub_e2e` for tests.

## Diagnostic preservation

When a test fails, the cluster's run directory is the primary diagnostic: node
logs under `node{i}/logs/`, per-node config/genesis, and data dirs. Re-run the
failing target with `HUB_E2E_KEEP=1` to retain the whole run directory for
inspection instead of letting RAII cleanup remove it.
