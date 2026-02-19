# `kora-overlay`

<a href="https://github.com/refcell/kora/actions/workflows/ci.yml"><img src="https://github.com/refcell/kora/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/refcell/kora/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-d1d1f6.svg" alt="License"></a>

Overlay state helpers for Kora.

This crate provides an `OverlayState` wrapper that layers an in-memory
change set on top of a base `StateDb`. It is used to execute blocks and
compute roots against unpersisted ancestor changes.

## Key Types

- `OverlayState` - StateDb implementation that merges a base state with pending changes

## Usage

```rust,ignore
use kora_overlay::OverlayState;

let overlay = OverlayState::new(base_state, pending_changes);
let balance = overlay.balance(&address).await?;
```

## License

[MIT License](https://github.com/refcell/kora/blob/main/LICENSE)
