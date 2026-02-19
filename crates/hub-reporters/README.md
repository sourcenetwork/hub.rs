# `kora-reporters`

<a href="https://github.com/refcell/kora/actions/workflows/ci.yml"><img src="https://github.com/refcell/kora/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/refcell/kora/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-d1d1f6.svg" alt="License"></a>

Consensus reporters for Kora nodes.

This crate provides reusable `commonware_consensus::Reporter` implementations used by
Kora node applications.

## Key Types

- `SeedReporter` - captures simplex activity seeds and hashes them for later proposals
- `FinalizedReporter` - replays finalized blocks, validates roots, and persists snapshots
- `NodeStateReporter` - updates RPC-visible node state (view, finalized count, nullified count) from consensus activity
- `BlockContextProvider` - trait for providing block execution context

These reporters are designed to work with `kora-ledger` and can be used in both the
example REVM chain and production nodes.

## Usage

```rust,ignore
use kora_reporters::{SeedReporter, FinalizedReporter, NodeStateReporter};

// Create reporters for consensus integration
let seed_reporter = SeedReporter::new(ledger_service.clone());
let finalized_reporter = FinalizedReporter::new(
    ledger_service.clone(),
    context,
    executor,
    provider,
);
let node_state_reporter = NodeStateReporter::new(node_state);
```

## License

This project is licensed under the [MIT License](../../LICENSE).
