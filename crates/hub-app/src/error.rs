//! Application errors.

use thiserror::Error;

/// Errors raised while building, verifying, or applying a block.
#[derive(Debug, Error)]
pub enum AppError {
    /// The executor rejected the block.
    #[error("execution: {0}")]
    Execution(String),
    /// A state batch operation failed.
    #[error("state: {0}")]
    State(#[from] hub_backend::BackendError),
    /// The computed roots differ from the block's.
    #[error("root mismatch: {0}")]
    RootMismatch(&'static str),
}
