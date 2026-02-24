//! ValidatorRegistry error types.

use thiserror::Error;

/// Errors produced by the ValidatorRegistry module.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum ValidatorRegistryError {
    #[error("validator already exists: {0}")]
    ValidatorAlreadyExists(String),

    #[error("validator not found: {0}")]
    ValidatorNotFound(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("native transactions not supported for ValidatorRegistry")]
    NativeNotSupported,

    #[error("state error: {0}")]
    State(String),
}
