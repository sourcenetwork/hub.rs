//! Error types for the backend.

use thiserror::Error;

/// Error type for backend operations.
#[derive(Debug, Error)]
pub enum BackendError {
    /// Native synchronization evidence does not match its trusted state root.
    #[error("invalid sync proof: {0}")]
    InvalidSyncProof(&'static str),
    /// Logical native records cannot be encoded safely by this storage configuration.
    #[error("invalid module change: {0}")]
    InvalidModuleChange(&'static str),
    /// Storage I/O error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Database not initialized.
    #[error("database not initialized")]
    NotInitialized,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_error_display() {
        let err = BackendError::Storage("disk full".to_string());
        assert_eq!(err.to_string(), "storage error: disk full");
    }

    #[test]
    fn test_not_initialized_display() {
        let err = BackendError::NotInitialized;
        assert_eq!(err.to_string(), "database not initialized");
    }

    #[test]
    fn test_backend_error_debug() {
        let err = BackendError::NotInitialized;
        let debug = format!("{:?}", err);
        assert!(debug.contains("NotInitialized"));
    }

    #[test]
    fn test_backend_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<BackendError>();
    }
}
