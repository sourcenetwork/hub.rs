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

    /// The server explicitly rejected work because temporary capacity is exhausted.
    #[error("RPC service busy: {0}")]
    ResourceBusy(String),

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

    /// Durable submission state could not be read, validated or persisted.
    #[error("native worker state: {0}")]
    Worker(String),

    /// BLS operation failed.
    #[error("BLS error: {0}")]
    Bls(String),

    /// JSON-RPC response contained no `result` field.
    #[error("missing result in RPC response")]
    MissingResult,

    /// Response exceeded the transport byte limit.
    #[error("RPC response exceeds {0} bytes")]
    ResponseTooLarge(usize),

    /// Response metadata did not match the request.
    #[error("invalid RPC response: {0}")]
    InvalidResponse(&'static str),

    /// Permission evidence or evaluation failed.
    #[error(transparent)]
    Permission(#[from] hub_permission::PermissionError),

    /// Finalization could not be verified against configured trust.
    #[error(transparent)]
    Finalization(#[from] hub_domain::LightBlockError),

    /// Receipt evidence did not match finalized execution.
    #[error(transparent)]
    Receipt(#[from] hub_domain::ReceiptResponseError),

    /// HTTP transport error.
    #[error(transparent)]
    Transport(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

impl ClientError {
    /// Whether a request was rejected for temporary capacity exhaustion.
    ///
    /// Callers must still bound retries and preserve submission identity.
    #[must_use]
    pub fn is_throttled(&self) -> bool {
        matches!(self, Self::ResourceBusy(_))
            || matches!(self, Self::Transport(error) if error.status() == Some(reqwest::StatusCode::TOO_MANY_REQUESTS))
    }

    pub(crate) fn from_rpc(error: &serde_json::Value) -> Self {
        let code = error
            .get("code")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        let message = error
            .get("message")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        if code == -32002
            && error.get("data").and_then(|data| data.get("retryable"))
                == Some(&serde_json::Value::Bool(true))
        {
            Self::ResourceBusy(message)
        } else {
            Self::Rpc { code, message }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_explicit_capacity_errors_are_throttled() {
        for (code, data, expected) in [
            (-32002, serde_json::json!({"retryable": true}), true),
            (-32002, serde_json::json!({"retryable": false}), false),
            (-32002, serde_json::json!({"retryable": "true"}), false),
            (-32002, serde_json::Value::Null, false),
            (-32602, serde_json::json!({"retryable": true}), false),
        ] {
            let error = ClientError::from_rpc(&serde_json::json!({
                "code": code, "message": "unavailable", "data": data,
            }));
            assert_eq!(error.is_throttled(), expected);
            if !expected {
                assert!(matches!(error, ClientError::Rpc { code: actual, .. } if actual == code));
            }
        }
    }

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
