# hub.rs

Rust rewrite of SourceHub on Commonware consensus with EVM execution. Trust layer for Source Network: ACP policies, bulletin board, and identity management with native BLS12-381 signing.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full design (dual tx model, module-to-precompile mapping, implementation phases).

## Related Repos

All repos follow gopath convention at `/Users/johnzampolin/go/src/github.com/{org}/{repo}`:

| Repo | Org | Purpose |
|------|-----|---------|
| **hub.rs** | sourcenetwork | This repo — SourceHub rewrite on Commonware |
| **sourcehub** | sourcenetwork | Go implementation (Cosmos SDK) — the upstream being replaced |
| **orbis-rs** | sourcenetwork | Threshold key management — primary consumer of hub.rs |
| **defradb.rs** | sourcenetwork | CRDT storage — queries ACP via hub.rs |
| **bankd-commonware** | mizufinance | Reference: Commonware + REVM chain (fork source for Phase 1) |
| **monorepo** | commonwarexyz | Commonware primitives (consensus, crypto, p2p, storage) |

## Current Phase

**Phase 1: Fork bankd, strip to skeleton.** See ARCHITECTURE.md for the full 7-phase plan.

## Building

```bash
cargo check                        # type-check workspace
cargo build -p hubd                # build binary
cargo test --workspace             # run all tests
cargo clippy --all -- -D warnings  # lint
cargo fmt --all                    # format
```

## Crate Structure

```
hub.rs/
    bin/hubd/                  # CLI binary (devnet, testnet, validator)
    crates/
        hub-app/               # Application trait impl, block executor
        hub-modules/           # ACP, Bulletin, Hub module implementations
        hub-precompiles/       # EVM precompile shims (ABI decode -> module calls)
        hub-native/            # Native BLS tx format, verification, dispatch
        hub-domain/            # Block, tx, state root types
        hub-consensus/         # Simplex integration, scheme config
        hub-state/             # State tree management (per-module Merkle trees)
        hub-jsonrpc/           # eth_* + hub_* JSON-RPC methods
        hub-e2e/               # Integration test framework
```

## Key Architecture Decisions

**Dual transaction model.** Blocks contain both BLS-signed native txs (SourceHub operations) and secp256k1-signed EVM txs (tokens, bridges, DeFi). No relayer needed for BLS identities.

**Shared module implementations.** Each SourceHub module (ACP, Bulletin, Hub) is a plain Rust struct. Two thin shims sit on top: a native tx shim (verify BLS, deserialize, call method) and a precompile shim (ABI decode, call same method). Business logic lives once.

**Precompile addresses.** Each module is an EVM precompile with its own address and state:

| Address | Module |
|---------|--------|
| `0x0810` | ACP (access control policies) |
| `0x0811` | Bulletin (coordination / posts) |
| `0x0812` | Hub (identity / JWS lifecycle) |

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

## Git Conventions

- Present tense commit messages
- AI attribution: `Co-Authored-By: Claude <model> <noreply@anthropic.com>`
- Worktree workflow: `git worktree add ../hub.rs-foo -b feat/foo`
