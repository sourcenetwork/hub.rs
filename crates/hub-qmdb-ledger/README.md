# `kora-qmdb-ledger`

<a href="https://github.com/refcell/kora/actions/workflows/ci.yml"><img src="https://github.com/refcell/kora/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/refcell/kora/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-d1d1f6.svg" alt="License"></a>

QMDB-backed ledger adapter for Kora.

This crate bundles the QMDB backend, handlers, and state traits into a
single helper that can initialize genesis allocations, compute roots,
and commit changes.

## Key Types

- `QmdbLedger` - QMDB-backed ledger service
- `QmdbConfig` - Configuration for the QMDB backend
- `QmdbState` - State handle used by executors
- `QmdbChangeSet` - Change set type for QMDB writes

## Usage

```rust,ignore
use kora_qmdb_ledger::{QmdbConfig, QmdbLedger};

let ledger = QmdbLedger::init(context, QmdbConfig::new(prefix, pool), allocations).await?;
let state = ledger.state();
```

## License

[MIT License](https://github.com/refcell/kora/blob/main/LICENSE)
