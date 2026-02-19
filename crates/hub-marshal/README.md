# `kora-marshal`

<a href="https://github.com/refcell/kora/actions/workflows/ci.yml"><img src="https://github.com/refcell/kora/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/refcell/kora/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-d1d1f6.svg" alt="License"></a>

Block dissemination handler using commonware's [`Marshaled`][marshaled] application adapter.

## Overview

The [`Marshaled`][marshaled] adapter handles epoch transitions and validates block ancestry.
This adapter "wraps" the application to handle the following ancestry checks automatically
during verification:

- **Block Ancestry**: Parent Commitment matches the consensus context's expected parent.
- **Epoch Transitions**: Block height is exactly one greater than the parent's height.

## Key Types

- `Marshal` - Core block dissemination handler
- `MarshalConfig` - Configuration for marshal behavior

## License

[MIT License](https://github.com/refcell/kora/blob/main/LICENSE)

[marshaled]: https://docs.rs/commonware-consensus/latest/commonware_consensus/application/marshaled/struct.Marshaled.html
