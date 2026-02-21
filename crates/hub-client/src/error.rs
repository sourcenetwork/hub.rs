//! Client error types.

use crate::types::TransactionReceipt;

/// Errors returned by [`HubClient`](crate::HubClient) methods.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// JSON-RPC error returned by the node.
    #[error("RPC error ({code}): {message}")]
    Rpc {
        /// JSON-RPC error code.
        code: i64,
        /// Human-readable error message.
        message: String,
    },

    /// ABI decoding failed on a precompile response.
    #[error("ABI decode error: {0}")]
    AbiDecode(String),

    /// Transaction was included but reverted.
    #[error("transaction reverted: status={status}")]
    TxReverted {
        /// EVM status code (0 = revert).
        status: u64,
        /// Full receipt for inspection.
        receipt: Box<TransactionReceipt>,
    },

    /// Receipt polling exhausted without finding the receipt.
    #[error("receipt not available after {attempts} attempts")]
    ReceiptTimeout {
        /// Number of poll attempts made.
        attempts: u32,
    },

    /// Transaction signing failed.
    #[error("signing error: {0}")]
    Signing(String),

    /// BLS operation failed.
    #[error("BLS error: {0}")]
    Bls(String),

    /// JSON-RPC response contained no `result` field.
    #[error("missing result in RPC response")]
    MissingResult,

    /// HTTP transport error.
    #[error(transparent)]
    Transport(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_error_display() {
        let err = ClientError::Rpc {
            code: -32600,
            message: "invalid request".into(),
        };
        assert_eq!(err.to_string(), "RPC error (-32600): invalid request");
    }

    #[test]
    fn missing_result_display() {
        let err = ClientError::MissingResult;
        assert_eq!(err.to_string(), "missing result in RPC response");
    }

    #[test]
    fn receipt_timeout_display() {
        let err = ClientError::ReceiptTimeout { attempts: 10 };
        assert_eq!(err.to_string(), "receipt not available after 10 attempts");
    }

    #[test]
    fn abi_decode_display() {
        let err = ClientError::AbiDecode("bad selector".into());
        assert_eq!(err.to_string(), "ABI decode error: bad selector");
    }

    #[test]
    fn bls_error_display() {
        let err = ClientError::Bls("invalid key".into());
        assert_eq!(err.to_string(), "BLS error: invalid key");
    }
}
