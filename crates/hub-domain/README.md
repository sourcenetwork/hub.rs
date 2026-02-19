# `kora-domain`

<a href="https://github.com/refcell/kora/actions/workflows/ci.yml"><img src="https://github.com/refcell/kora/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/refcell/kora/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-d1d1f6.svg" alt="License"></a>

Core domain types used across Kora nodes.

This crate provides the foundational data structures for blocks, transactions,
state commitments, and ledger events that are shared by consensus, execution,
and storage layers.

## Key Types

- `Block` / `BlockCfg` - block structure with header and transaction list
- `Tx` / `TxCfg` - transaction wrapper types
- `BlockId`, `TxId`, `StateRoot` - identifier types
- `AccountChange`, `StateChanges` - state commitment structures
- `LedgerEvent`, `LedgerEvents` - ledger notification events
- `BootstrapConfig` - genesis bootstrapping configuration
- `ConsensusDigest`, `PublicKey` - consensus type aliases

## Features

- `evm` - enables EVM-specific domain types for Ethereum-compatible execution

## Usage

```rust,ignore
use kora_domain::{Block, BlockId, StateRoot, LedgerEvent};

// Create block identifiers
let block_id: BlockId = digest.into();
let state_root: StateRoot = root.into();
```

## License

This project is licensed under the [MIT License](../../LICENSE).
