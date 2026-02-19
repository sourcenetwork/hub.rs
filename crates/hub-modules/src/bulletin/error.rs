//! Bulletin module error types.

use thiserror::Error;

/// Errors produced by the Bulletin module.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum BulletinError {
    #[error("namespace not found: {namespace}")]
    NamespaceNotFound { namespace: String },

    #[error("namespace already exists: {namespace}")]
    NamespaceAlreadyExists { namespace: String },

    #[error("post not found: {namespace}/{id}")]
    PostNotFound { namespace: String, id: String },

    #[error("post already exists: {namespace}/{id}")]
    PostAlreadyExists { namespace: String, id: String },

    #[error("not a collaborator on namespace {namespace}")]
    NotCollaborator { namespace: String },

    #[error("collaborator already exists: {namespace}/{did}")]
    CollaboratorAlreadyExists { namespace: String, did: String },

    #[error("collaborator not found: {namespace}/{did}")]
    CollaboratorNotFound { namespace: String, did: String },

    #[error("invalid post payload: payload must be non-empty")]
    InvalidPostPayload,

    #[error("invalid post proof: proof must be non-empty")]
    InvalidPostProof,

    #[error("policy not initialized")]
    PolicyNotInitialized,

    #[error("failed to initialize module policy: {0}")]
    PolicyInitFailed(String),

    #[error("unauthorized: {reason}")]
    Unauthorized { reason: String },

    #[error("invalid glob pattern: {pattern}")]
    InvalidGlob { pattern: String },

    #[error("state error: {0}")]
    State(String),
}
