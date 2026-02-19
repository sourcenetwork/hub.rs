# `kora-handlers`

<a href="https://github.com/refcell/kora/actions/workflows/ci.yml"><img src="https://github.com/refcell/kora/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/refcell/kora/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-d1d1f6.svg" alt="License"></a>

Thread-safe database handles for Kora.

This crate provides synchronized wrappers around storage backends,
implementing REVM database traits for EVM execution.

## Key Types

- `QmdbHandle` - Thread-safe handle to QMDB stores with `Arc<RwLock>` synchronization
- `QmdbRefDb` - Tokio-backed REVM `DatabaseRef` adapter for async QMDB handles
- `HandleError` - Error type implementing REVM's `DBErrorMarker`

## Usage

```rust,ignore
use kora_handlers::QmdbHandle;
use revm::database_interface::DatabaseRef;

// Create handle from stores
let handle = QmdbHandle::new(accounts, storage, code);

// Use as REVM database
let account = handle.basic_ref(address)?;

// Or wrap with a Tokio-backed adapter for sync REVM access
let db = kora_handlers::QmdbRefDb::new(handle).expect("tokio runtime");
let account = db.basic_ref(address)?;
```

## Design

This crate implements Layer 2 of a 2-layer architecture:

1. **Layer 1 (kora-qmdb)**: Pure store logic, state transitions, no synchronization
2. **Layer 2 (this crate)**: Thread-safe handles, REVM trait implementations

## License

[MIT License](https://github.com/refcell/kora/blob/main/LICENSE)
