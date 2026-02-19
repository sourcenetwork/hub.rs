//! Hub module error types.

use thiserror::Error;

/// Errors produced by the Hub module.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum HubError {
    #[error("JWS token not found: {token_hash}")]
    TokenNotFound { token_hash: String },

    #[error("JWS token already invalidated: {token_hash}")]
    TokenAlreadyInvalidated { token_hash: String },

    #[error("invalid JWS: {reason}")]
    InvalidJws { reason: String },

    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },

    #[error("chain config already set")]
    ChainConfigAlreadySet,

    #[error("state error: {0}")]
    State(String),
}
