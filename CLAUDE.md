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

### Dual transaction model

Blocks contain both BLS-signed native txs and secp256k1-signed EVM txs, processed sequentially by the HubExecutor:

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

### Shared module pattern

Each module is a plain Rust struct. Two thin shims sit on top:
- **Precompile shim:** ABI decode calldata → `module.method(args)`
- **Native tx shim:** BLS verify + deserialize → `module.method(args)`

Business logic lives once.

### State model

All module state is stored in QMDB (same Merkle-ized KV store that backs EVM state):

```
Block state commitment:
    state_root:             QMDB root (EVM accounts + storage + code)
    module_state_root:      Combined root of module state trees
        acp_root:           Policies, relationships, objects (zanzi engine)
        bulletin_root:      Namespaces, collaborators, posts
        hub_root:           JWS tokens, invalidation records
        native_nonce_root:  BLS identity nonces
```

### RPC surfaces

| Endpoint | Signing | Consumer |
|----------|---------|----------|
| `eth_sendRawTransaction` | secp256k1 | defradb.rs, MetaMask, wallets |
| `hub_sendNativeTx` | BLS12-381 | orbis-rs, BLS identities |
| `eth_call` | none (read-only) | All queries |

## Crate Structure

```
hub.rs/
    bin/hubd/                  # CLI binary (devnet, testnet, validator)
    crates/
        hub-app/               # Application trait impl, block executor (HubExecutor)
        hub-modules/           # ACP, Bulletin, Hub module implementations
        hub-precompiles/       # EVM precompile shims (ABI decode → module calls)
        hub-native/            # Native BLS tx format, verification, dispatch
        hub-domain/            # Block, tx, state root types
        hub-consensus/         # Simplex integration, scheme config
        hub-state/             # State tree management (per-module Merkle trees)
        hub-jsonrpc/           # eth_* + hub_* JSON-RPC methods
        hub-client/            # Rust client library (EVM + BLS paths)
        hub-e2e/               # Integration test framework
```

## Building

```bash
cargo check                        # type-check workspace
cargo build -p hubd                # build binary
cargo test --workspace             # run all tests
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
2. `cargo test --workspace` passes
3. `cargo clippy --all -- -D warnings` clean
4. `cargo fmt --all` applied
5. `cargo test -p hub-e2e --test hub_e2e_canonical` passes (requires `cargo build -p hubd` first)

The e2e test (`hub_e2e_canonical`) is the baseline gate. It exercises both EVM and BLS transaction paths through a 4-node cluster: create policies, verify receipts, query state back, check cross-node consistency, and assert cluster health. Any change that breaks this test has broken the core pipeline.

## Git Conventions

- Present tense commit messages
- AI attribution: `Co-Authored-By: Claude <model> <noreply@anthropic.com>`
- Worktree workflow: `git worktree add ../hub.rs-foo -b feat/foo`
