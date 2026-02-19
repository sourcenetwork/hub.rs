# `kora-ledger`

<a href="https://github.com/refcell/kora/actions/workflows/ci.yml"><img src="https://github.com/refcell/kora/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/refcell/kora/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-d1d1f6.svg" alt="License"></a>

Ledger services for Kora nodes.

This crate wraps the consensus in-memory components (mempool, snapshot store, seed
tracker) together with a QMDB-backed state store. It exposes a `LedgerView` for
asynchronous access to the ledger state and a `LedgerService` that publishes
`LedgerEvent` notifications.

## Key Types

- `LedgerView` - mutex-protected access to mempool, snapshots, seeds, and state
- `LedgerService` - higher-level API with event publishing
- `LedgerSnapshot` - snapshot type alias used by the ledger

## Usage

```rust,ignore
use kora_ledger::LedgerView;

let ledger = LedgerView::init(context, buffer_pool, "partition".to_string(), alloc).await?;
```

## License

This project is licensed under the [MIT License](../../LICENSE).
