# `kora-backend`

<a href="https://github.com/refcell/kora/actions/workflows/ci.yml"><img src="https://github.com/refcell/kora/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/refcell/kora/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-d1d1f6.svg" alt="License"></a>

Concrete storage backend for Kora QMDB.

This crate implements the `QmdbGettable` and `QmdbBatchable` traits from [`kora-qmdb`](../qmdb)
using `commonware-storage` QMDB partitions.

- **AccountStore** - Account state (nonce, balance, code hash, generation)
- **StorageStore** - Contract storage slots
- **CodeStore** - Contract bytecode

## Usage

```rust,ignore
use commonware_runtime::buffer::PoolRef;
use commonware_utils::{NZU16, NZUsize};
use kora_backend::{CommonwareBackend, QmdbBackendConfig};

let buffer_pool = PoolRef::new(NZU16!(16_384), NZUsize!(10_000));
let config = QmdbBackendConfig::new("node-0-qmdb", buffer_pool);
let backend = CommonwareBackend::open(context, config).await?;

// Get state root
let root = backend.state_root()?;
```

## License

[MIT License](https://github.com/refcell/kora/blob/main/LICENSE)
