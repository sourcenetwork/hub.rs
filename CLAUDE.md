# hub.rs

Native Rust implementation of Vera's access control, bulletin, identity and transparency services, using Commonware consensus and storage. Native requests use BLS12-381 signing; optional EVM execution reaches the same module logic.

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
  resolver, backfill, block broadcast, DKG, DKG probe, mempool, history, and
  authenticated state transfer. Each channel permits 1,000 messages/second per
  peer with a burst of 64. Commonware sizes queues from retained-peer count
  times burst size, so the burst also controls startup queue allocation.
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

Provider relay grants use the same operator quorum as administrative changes.
Relay assertions bind a stable `did:opk` actor, native worker, genesis, scope,
grant generation and exact operation. ACP stores the actor as owner; token
records retain the signing relay as issuer. See docs/delegated-policies.md.

Delegated policy creation and editing preserve the actor as owner while a
separate worker signs the submission. Creation and editing require distinct
scopes; existing object-command tokens do not authorize either operation.
Created records bind the owner, worker, signed submission ID and creation
revision. See `docs/delegated-policies.md` for result verification.
Signed caller operation identities deduplicate successful effects across workers.
Outcomes are bounded, expire without allowing ID reuse, and share the execution
rollback boundary. Operator approvals configure the retained outcome budget.
See `docs/operation-identities.md`.

### State and recovery

The node uses `hub-app::OrderedState`: three execution partitions (accounts,
storage, code) and four ordered Commonware current-QMDB partitions (ACP, bulletin,
hub, native sequences). `StatefulHubApp` seals all seven targets into each proposal
and verifies them by re-execution. An in-memory commitment participates in the same
Commonware coordinator generation, binding the native current-state root to the
selected operation-log targets. It is reconstructed from the durable recovery
anchor, not persisted as an independent journal.

ACP and token lifecycle errors reject proposal execution and re-verification.
Malformed token records encountered during reads or expiry are errors, including a mismatch between the storage key
and the record's token hash. Failed lifecycle work cannot publish its module view. Token expiry uses an ordered
deadline index, leaving invalidated and non-expiring tokens out of each revision's
sweep. See `docs/token-lifecycle.md`.

Pending alternatives retain isolated module snapshots. Database transitions finish
before query maps are published. Startup aligns all journals to marshal's durable
anchor, checks the combined native root, and then enables admission and RPC.
Finalized receipts and certificates are recovered through `FinalizedHistory`.
Native proposals also bind ordered receipt fields and the execution gas limit
through `Block::receipt_commitment`. Re-execution verifies this commitment;
history checks it before persistence and before indexing a recovered record.
See `docs/receipt-commitments.md` for the canonical encoding.

First boot records a durable initialization intent before changing journals, then
publishes `native-genesis.bin` after all seven partitions are durable. Interrupted
initialization can rewind and retry only with the same genesis configuration.
Existing JMT directories or a legacy genesis record require an explicit migration;
this node does not convert them. Missing genesis records alongside finalized
history are rejected instead of resetting state.
Native genesis predating receipt commitments also requires an explicit migration.

Seven authenticated peer resolvers serve bounded operation-log ranges. Fetches
allow up to 64 operations, with eight-operation inspection batches and responses
below the 4 MiB transport limit. Native keys are limited to 64 KiB; values and
commit metadata to 1 MiB. Code-partition peer messages cap values at 1 MiB even
though the older local journal codec permits larger records.

A `[snapshot]` configuration section requests initial authenticated snapshot
catch-up for an admitted member. Startup resumes interrupted synchronization from
durable metadata and uses retained-history replay after snapshot completion.
History and receipts are imported at the actual synchronized revision before
query-state publication and normal execution. See `docs/snapshot-recovery.md`. `OrderedCheckpoint` separately verifies direct
or descendant finality against caller-provisioned trust and authenticates native
log targets through `SyncProof`. Synchronization and recovery check reconstructed
current-state roots before publishing query maps. Operation-log proofs do not
provide historical activity or absence proofs.

`FinalizedHistory` provides 64 KiB record chunks and a bounded reverse-ancestry
import API. The import selection and cursor are durable, and imported history
remains unavailable until recovery at the matching state anchor completes.
Starting an import selects metadata format 3 to prevent older binaries from
discarding its unfinished records. The node serves chunks through Commonware's
resolver on authenticated channel 16. `HistoryPeer::import_next_from` bounds
record and finality-proof assembly, verifies both before persistence and cancels
pending fetches when dropped. Imported certificates retain their verifier material
and any descendants beyond the recovery anchor without advancing execution.
The storage handoff waits for history recovery at the final selected revision.
See `docs/receipt-commitments.md` for protocol and upgrade details.

`hub-backend::native` rebuilds query maps from the retained operation log and
activity bitmap, reading at most 32 operations at a time under partition read
locks. This bounds temporary hydration buffers; all live query maps remain in
memory. Keys sharing their first 256 bytes scan one index bucket.

`hub_getCurrentPermissionProof` returns a selected finalized revision with its
Commonware membership, absence and complete-prefix witnesses. Generation holds
all four native partition read locks and applies aggregate record and byte
limits, then releases the locks before waiting for the revision's certificate.
`HubClient::verify_current_access` verifies the certificate, caller's minimum
height and evidence before running the shared ACP evaluator. Callers supply any
additional freshness policy. The separate `hub_getPermissionProof` endpoint
requires the requested root to remain available.
`hub_getCurrentRecordProof` captures a native record and its certified revision;
`HubClient::read_current_record` verifies membership or absence against the requested
module, key and minimum revision. `hub_getCurrentPrefixProof` and
`HubClient::read_current_prefix` provide complete native prefixes with the same
captured-revision guarantees. `PrefixResponse::verify_object_owner` derives live
ownership from complete owner evidence and treats archived records as unregistered. Standalone `hub_getStateProof` and
`hub_getRelationProof` remain JMT-only and are unavailable on the native node.
Historical native activity proofs are not retained.
Proof RPCs share eight in-flight slots per node; blocking historical certificate
lookups have a separate eight-slot limit. Excess work returns JSON-RPC -32002
with `retryable: true` before starting. Cancelling a lookup does not release its
slot until its blocking task finishes.
See `docs/permission-proofs.md` for formats and limits.

Legacy `VeraStateSet` and JMT proof support remain available to explicit library
callers. Native blocks select a tagged commitment encoding and carry four
additional module log targets and a receipt commitment; blocks omitting both
retain their original encoding. Native and legacy application layouts cannot
share one consensus group.

### RPC surfaces

`hub-jsonrpc` limits each batch to 64 calls and each connection to eight
subscriptions, eight queued output messages and eight WebSocket request tasks.
The receive loop stops accepting messages at the task limit; each task retains
its slot until its response enters the output queue.

`hub-jsonrpc` serves HTTP + WebSocket JSON-RPC:

| Surface | Methods | Consumer |
|----------|---------|----------|
| `eth_*` | `eth_sendRawTransaction`, `eth_call`, `eth_getStorageAt`, `eth_getTransactionReceipt`, … | defradb.rs, MetaMask, wallets |
| `eth_subscribe` | `newHeads`, `logs` | Indexers, light clients |
| `hub_subscribeHeaders` | `hub_header` notifications; `hub_unsubscribeHeaders` cancellation | Native verified consumers |
| `hub_*` | `hub_nodeStatus`, `hub_sendNativeTx`, `hub_getTransactionReceipt`, `hub_getNativeNonce`, `hub_getStateProof`, `hub_getLightBlock` | orbis-rs, BLS identities, light clients |

### Light-client material

A `LightBlock` carries the canonical block, the BLS threshold finalization
certificate, and the epoch's group public key; `hub_domain::verify_light_block`
verifies it with one aggregate signature. `ModuleStateProof`s verify module
state against the header's `module_state_root`. Both are served over the `hub_*`
RPC methods above, and signed `GossipHeader`s stream through `hub_subscribeHeaders` as blocks finalize.
The native stream is available with only the header broadcaster configured.
Consumers authenticate headers against their configured finality trust; receiving a
notification alone does not establish its authority.

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
- Worktree workflow: `git worktree add ../hub.rs-foo -b feat/foo`
