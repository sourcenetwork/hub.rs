# `kora-cli`

<a href="https://github.com/refcell/kora/actions/workflows/ci.yml"><img src="https://github.com/refcell/kora/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/refcell/kora/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-d1d1f6.svg" alt="License"></a>

Minimal CLI utilities for the Kora binary.

## Overview

This crate provides essential utilities for CLI applications:

- **`Backtracing`**: Enables `RUST_BACKTRACE=1` if not already set, ensuring backtraces are available for debugging.
- **`SigsegvHandler`**: Installs a signal handler for `SIGSEGV` that prints a backtrace before exiting, useful for diagnosing stack overflows and segmentation faults.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
kora-cli = { path = "crates/utilities/cli" }
```

Initialize at the start of your main function:

```rust,ignore
fn main() {
    kora_cli::Backtracing::enable();
    #[cfg(unix)]
    kora_cli::SigsegvHandler::install();

    // ... rest of your application
}
```

## License

[MIT License](https://github.com/refcell/kora/blob/main/LICENSE)
