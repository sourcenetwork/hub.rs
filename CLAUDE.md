# hub.rs

Rust rewrite of SourceHub on Commonware consensus with EVM execution. Trust layer for Source Network: ACP policies, bulletin board, and identity management with native BLS12-381 signing.

## Plan

The implementation plan lives in GitHub issues. **#23 is the master tracking issue.**

**Current phase: Phase 10** — Production hardening (#22). Phases 1-9 complete.

| Phase | What | Tracking |
|-------|------|----------|
| 1 | Copy bankd, strip to skeleton | #1 |
| 2 | API surface stubs + transaction types | #5 |
| 3 | State model deep dive | #9 |
| 4 | Annotate stubs with implementation specs | #10 |
| 5 | Wire precompile shims | #14 |
| 6 | Wire native BLS tx path (HubExecutor) | #18 |
| 7 | hub-client crate | #19 |
| 8 | Integration test framework | #20 |
| 9 | Implement stubs | #21 |
| 10 | Production hardening | #22 |

## Related Repos

All repos follow gopath convention at `/Users/johnzampolin/go/src/github.com/{org}/{repo}`:

| Repo | Org | Purpose |
|------|-----|---------|
| **hub.rs** | sourcenetwork | This repo — SourceHub rewrite on Commonware |
| **sourcehub** | sourcenetwork | Go implementation (Cosmos SDK) — the upstream being replaced |
| **orbis-rs** | sourcenetwork | Threshold key management — primary consumer of hub.rs (BLS native txs) |
| **defradb.rs** | sourcenetwork | CRDT storage — queries ACP via hub.rs (EVM precompile calls) |
| **bankd-commonware** | mizufinance | Reference: Commonware + REVM chain (infrastructure source for Phase 1) |
| **monorepo** | commonwarexyz | Commonware primitives (consensus, crypto, p2p, storage) |

### Code reuse across repos

| Component | Source repo | Used in hub.rs for |
|-----------|-----------|-------------------|
| Zanzibar engine (relation-tuple graph) | defradb.rs `crates/acp/src/zanzibar/` | ACP policy evaluation |
| DID types, identity crate | defradb.rs `crates/identity/` | DID resolution (also check orbis-rs) |
| YAML policy parser | defradb.rs `crates/acp/src/policy_yaml/` | ACP policy creation |
| Simplex consensus, REVM executor, e2e harness | bankd-commonware | Consensus, EVM execution, testing |
| BLS12-381 threshold crypto | commonware monorepo | Block signing, native tx verification |

## Architecture

### Node assembly (`hub-node`)

`hubd` parses its CLI into `NodeSettings` and calls `hub_node::run_node`, which
assembles the Commonware actor graph on a tokio runtime and runs until one actor
stops:

- **P2P:** `commonware_p2p::authenticated::discovery` network bootstrapped from
  `peers.json`, with registered channels for votes, certificates, the marshal
  resolver, backfill, block broadcast, DKG, DKG probe, and the mempool.
- **Consensus:** the Commonware `marshal` actor (block archive + finalization
  storage) driven by the glue `orchestrator` running Simplex with a
  `FixedEpocher` over genesis `blocks_per_epoch` and a VRF elector that feeds
  each round's threshold seed to the application.
- **Execution:** the glue `Stateful` actor wrapping `hub-app`'s
  `StatefulHubApp` (below).
- **DKG/resharing:** the glue `probe` actor discovers the latest epoch when a
  node needs state sync, while the `reshare` actor deals BLS shares for the next
  epoch to the active set returned by `RegistryParticipants` from finalized
  state. Shares persist in `FileSecretStore`. Production validators create
  epoch-0 material together with `hubd genesis`, which runs Commonware's
  distributed bootstrap DKG; `trusted_setup` is limited to local dev/test
  networks and is reused by `hub-harness`.
- **Transaction gossip:** `TxGossip` admits RPC-submitted transactions via a
  `MempoolValidator` checked against committed state and forwards them to all
  validators. There is no leader prediction.
- **RPC:** the `hub-jsonrpc` server over the live committed state (below).

### Execution (`hub-app` + `hub-executor`)

`StatefulHubApp` implements `commonware_glue::stateful::Application`: it builds
blocks from the mempool, executes them against forked QMDB batch state, verifies
proposals by re-execution, and hands finalized receipts to a `FinalizedSink`
(`NodeSink`), which indexes blocks, logs, and light blocks and feeds the RPC
subscription channels. Block execution goes through `HubExecutor`:

```
                     HubExecutor
                          |
          +---------------+---------------+
          |                               |
     Native BLS txs                  EVM txs
     (processed first)               (processed second)
          |                               |
     BLS verify → did:key             REVM execution
     Deserialize NativeTx                 |
          |                          Precompile calls
     Dispatch to module              hit same modules
          |                               |
          v                               v
    module.method(args)  ←— same Rust code —→  module.method(args)
```

### Precompile addresses

| Address | Module | Purpose |
|---------|--------|---------|
| `0x0810` | ACP | Access control policies (Zanzibar relation tuples) |
| `0x0811` | Bulletin | Coordination / DKG messages / posts |
| `0x0812` | Hub | Identity / JWS token lifecycle |
| `0x0813` | ValidatorRegistry | Validator identity management (feeds resharing) |

### Shared module pattern

Each module is a plain Rust struct. Two thin shims sit on top:
- **Precompile shim:** ABI decode calldata → `module.method(args)`
- **Native tx shim:** BLS verify + deserialize → `module.method(args)`

Business logic lives once.

### State (QMDB)

`hub-backend` provides `HubStateSet`, the three QMDB partitions (accounts,
storage, code) over Commonware storage; `BatchState` is the executor's
`StateDb` over pending batches. Per-partition `DbTargets` are committed in each
block for glue's state-sync bookkeeping; the peer QMDB resolver remains stubbed
pending issue #99. Module state (ACP, Bulletin, Hub, native nonces) lives in
JMT-backed `ModuleStateTree`s (`hub-state`, RocksDB) and is combined into the
block header. `hub-app::VeraStateSet` adds these modules as a fourth managed
database beside the execution partitions. Module snapshots follow pending
batches, and their height/root participate in target matching and recovery.
Database apply persists module state before the application publishes receipts.
Peer snapshot synchronization is still disabled for both execution and modules.

The block commitments are:

```
Block header:
    state_root:             QMDB root (EVM accounts + storage + code)
    module_state_root:      Combined root of the four module JMTs
        acp_root:           Policies, relationships, objects (zanzi engine)
        bulletin_root:      Namespaces, collaborators, posts
        hub_root:           JWS tokens, invalidation records
        nonces_root:        BLS identity nonces
    db_targets:             Per-partition QMDB targets for state sync
```

### RPC surfaces

`hub-jsonrpc` serves HTTP + WebSocket JSON-RPC:

| Surface | Methods | Consumer |
|----------|---------|----------|
| `eth_*` | `eth_sendRawTransaction`, `eth_call`, `eth_getStorageAt`, `eth_getTransactionReceipt`, … | defradb.rs, MetaMask, wallets |
| `eth_subscribe` | `newHeads`, `logs` | Indexers, light clients |
| `hub_*` | `hub_nodeStatus`, `hub_sendNativeTx`, `hub_getTransactionReceipt`, `hub_getNativeNonce`, `hub_getStateProof`, `hub_getLightBlock` | orbis-rs, BLS identities, light clients |

### Light-client material

A `LightBlock` carries the canonical block, the BLS threshold finalization
certificate, and the epoch's group public key; `hub_domain::verify_light_block`
verifies it with one aggregate signature. `ModuleStateProof`s verify module
state against the header's `module_state_root`. Both are served over the `hub_*`
RPC methods above, and signed `GossipHeader`s stream to `eth_subscribe("headers")`
subscribers as blocks finalize.

## Crate Structure

Workspace membership comes from the root `Cargo.toml` (`bin/hubd` + `crates/*`).

```
hub.rs/
    bin/hubd/                  # CLI binary: validator, devnet, testnet, genesis DKG, client
    crates/
        hub-app/               # Glue stateful Application around the block executor
        hub-backend/           # Concrete QMDB backend: HubStateSet, BatchState, DbTargets
        hub-cli/               # CLI utilities (backtrace + SIGSEGV handlers)
        hub-client/            # Rust client library (EVM + BLS tx paths, typed queries)
        hub-config/            # Node configuration types (node, network, rpc, execution)
        hub-consensus/         # Consensus application layer: mempool, proposal, traits
        hub-crypto/            # BLS12-381, secp256k1, and JWT utilities
        hub-domain/            # Block, tx, light block, proof, and DKG payload types
        hub-e2e/               # End-to-end test harness (see crates/hub-e2e/README.md)
        hub-executor/          # Block execution: REVM, precompiles, HubExecutor
        hub-genesis/           # Extended genesis configuration (validators, native mint)
        hub-harness/           # Node manager, cluster builder, observability (test-only)
        hub-indexer/           # Block/tx/light-block indexes backing RPC queries
        hub-jsonrpc/           # eth_* + hub_* JSON-RPC server and subscriptions
        hub-modules/           # ACP, Bulletin, Hub, ValidatorRegistry module logic
        hub-node/              # Validator assembly: p2p, marshal, DKG, stateful glue, RPC
        hub-overlay/           # Overlay state for unpersisted QMDB changes
        hub-qmdb/              # Core QMDB abstractions and traits
        hub-state/             # JMT-backed module state trees (RocksDB persistence)
        hub-traits/            # StateDb trait abstractions for storage/consensus
        test-infra/            # Shared test primitives: process, ports, logs, binary resolver
```

## Building

```bash
cargo check                        # type-check workspace
cargo build -p hubd                # build binary
cargo test --workspace --exclude hub-e2e  # run non-e2e tests
cargo clippy --all -- -D warnings  # lint
cargo fmt --all                    # format
```

## Development Principles

Borrowed from [defradb.rs](https://github.com/sourcenetwork/defradb.rs):

**No commented-out code. No TODO comments (create issues instead). No speculative docs.**

| Zone | Contains | Lives in |
|------|----------|----------|
| Past | How we got here | Git history, closed issues/PRs |
| Present | What the code does now | Working tree |
| Future | What we might do next | GitHub issues |

**One concept per file. Small files over large files.** Under 200 lines is fine, 200-400 check if doing one thing, over 400 consider splitting.

**Minimal comments.** Code should be self-documenting. Comment non-obvious WHY, safety invariants, public API docs (`///`). Don't comment what the code does, no TODO/FIXME, no commented-out code.

## Before Committing

1. `cargo check` passes
2. `cargo test --workspace --exclude hub-e2e` passes
3. `cargo clippy --all -- -D warnings` clean
4. `cargo fmt --all` applied
5. `cargo test -p hub-e2e --test hub_e2e_canonical` passes (requires `cargo build -p hubd` first)

The e2e test (`hub_e2e_canonical`) is the baseline gate. It exercises both EVM and BLS transaction paths through a 4-node cluster: create policies, verify receipts, query state back, check cross-node consistency, and assert cluster health. Any change that breaks this test has broken the core pipeline.

## Git Conventions

- Present tense commit messages
- AI attribution: `Co-Authored-By: Claude <model> <noreply@anthropic.com>`
- Worktree workflow: `git worktree add ../hub.rs-foo -b feat/foo`
