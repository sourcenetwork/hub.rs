# `kora-simplex`

<a href="https://github.com/refcell/kora/actions/workflows/ci.yml"><img src="https://github.com/refcell/kora/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/refcell/kora/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-d1d1f6.svg" alt="License"></a>

Commonware simplex consensus engine integration for Kora.

This crate provides default configurations and wrappers for the
[commonware-simplex](https://github.com/commonwarexyz/monorepo) consensus engine,
which drives BLS12-381 threshold signature-based consensus in Kora nodes.

## Key Types

- `DefaultEngine` - preconfigured simplex consensus engine
- `DefaultConfig` - consensus timing and buffer configuration with sensible defaults
- `DefaultPool` - memory pool for pending proposals
- `DefaultQuota` - rate limiting configuration for consensus messages

## Configuration Defaults

| Parameter | Default Value |
|-----------|---------------|
| Leader timeout | `DEFAULT_LEADER_TIMEOUT` |
| Notarization timeout | `DEFAULT_NOTARIZATION_TIMEOUT` |
| Activity timeout | `DEFAULT_ACTIVITY_TIMEOUT` |
| Fetch timeout | `DEFAULT_FETCH_TIMEOUT` |
| Pool capacity | `DEFAULT_POOL_CAPACITY` |
| Requests per second | `DEFAULT_REQUESTS_PER_SECOND` |

## Usage

```rust,ignore
use kora_simplex::{DefaultEngine, DefaultConfig, DefaultPool};

// Create consensus engine with default configuration
let config = DefaultConfig::default();
let pool = DefaultPool::new();
let engine = DefaultEngine::new(config, pool);
```

## License

This project is licensed under the [MIT License](../../LICENSE).
