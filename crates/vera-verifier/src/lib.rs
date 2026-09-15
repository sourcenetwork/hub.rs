//! C interface to native policy compilation and proof verification.

use alloy_primitives::{B256, Bytes};
use commonware_codec::DecodeExt as _;
use hub_domain::{ConsensusPublicKey, RECEIPT_RESPONSE_BYTES, ReceiptResponse};
use hub_permission::{
    AccessRequest, DecisionOperation, ModuleId, Object, PERMISSION_LIMITS, PermissionResponse,
    PrefixResponse, RECORD_PROOF_BYTES, RecordResponse,
};
use serde::Deserialize;
use serde_json::{Value, json};

/// Maximum encoded verification request, including independently configured trust.
pub const MAX_REQUEST_BYTES: usize =
    RECEIPT_RESPONSE_BYTES + 4 * hub_permission::current::MAX_KEY_BYTES + 4096;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    PrefixPage {
        trusted_key: String,
        request: hub_permission::PrefixPageRequest,
        minimum_height: u64,
        proof: Box<hub_permission::PrefixPageResponse>,
    },
    ValidatePolicy {
        definition: String,
        format: String,
    },
    Receipt {
        trusted_key: String,
        submission: B256,
        proof: Box<ReceiptResponse>,
    },
    Record {
        trusted_key: String,
        module: ModuleId,
        key: Bytes,
        minimum_height: u64,
        proof: Box<RecordResponse>,
    },
    AccessDecision {
        trusted_key: String,
        deployment_id: u64,
        decision_id: String,
        minimum_height: u64,
        proof: Box<RecordResponse>,
    },
    DecisionOutcome {
        trusted_key: String,
        operation: DecisionOperation,
        minimum_height: u64,
        proof: Box<RecordResponse>,
    },
    Permission {
        trusted_key: String,
        policy_id: String,
        request: AccessRequest,
        minimum_height: u64,
        proof: Box<PermissionResponse>,
    },
    ObjectOwner {
        trusted_key: String,
        policy_id: String,
        object: Object,
        minimum_height: u64,
        proof: Box<PrefixResponse>,
    },
}

fn trusted_key(value: &str) -> Result<ConsensusPublicKey, String> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if raw.len() != 192 {
        return Err("consensus key must contain 96 bytes".into());
    }
    let raw = hex::decode(raw).map_err(|error| error.to_string())?;
    ConsensusPublicKey::decode(raw.as_slice()).map_err(|error| error.to_string())
}

fn verify(input: &[u8]) -> Result<Value, String> {
    if input.len() > MAX_REQUEST_BYTES {
        return Err("verification request exceeds byte limit".into());
    }
    let request: Request = serde_json::from_slice(input).map_err(|error| error.to_string())?;
    match request {
        Request::PrefixPage {
            trusted_key: key,
            request,
            minimum_height,
            proof,
        } => {
            let page = proof
                .verify(
                    &request,
                    minimum_height,
                    &trusted_key(&key)?,
                    hub_permission::PAGE_PROOF_BYTES,
                )
                .map_err(|error| error.to_string())?;
            let entries: Vec<_> = page
                .entries
                .into_iter()
                .map(|entry| {
                    json!({
                        "key": Bytes::from(entry.key), "value": Bytes::from(entry.value)
                    })
                })
                .collect();
            Ok(
                json!({"height": proof.revision.height, "timestamp": proof.revision.timestamp,
                "entries": entries, "continuation": page.continuation}),
            )
        }
        Request::ValidatePolicy { definition, format } => {
            use hub_modules::acp::types::PolicyMarshalingType;
            let marshal_type = if format.eq_ignore_ascii_case("yaml") {
                PolicyMarshalingType::ShortYaml
            } else if format.eq_ignore_ascii_case("json") {
                PolicyMarshalingType::ShortJson
            } else {
                PolicyMarshalingType::Unknown
            };
            match hub_modules::acp::AcpModule::validate_policy_definition(&definition, marshal_type)
            {
                Ok(_) => Ok(json!({"valid": true, "reason": ""})),
                Err(error) => Ok(json!({"valid": false, "reason": error.to_string()})),
            }
        }
        Request::Receipt {
            trusted_key: key,
            submission,
            proof,
        } => {
            let receipt = proof
                .verify(submission, &trusted_key(&key)?)
                .map_err(|error| error.to_string())?;
            Ok(
                json!({"height": proof.revision.height, "timestamp": proof.revision.timestamp,
                "submission": receipt.tx_hash, "success": receipt.success(), "logs": receipt.logs()}),
            )
        }
        Request::Record {
            trusted_key: key_string,
            module,
            key,
            minimum_height,
            proof,
        } => {
            proof
                .verify(
                    module,
                    &key,
                    minimum_height,
                    &trusted_key(&key_string)?,
                    RECORD_PROOF_BYTES,
                )
                .map_err(|error| error.to_string())?;
            Ok(
                json!({"height": proof.revision.height, "timestamp": proof.revision.timestamp, "value": proof.record.value}),
            )
        }
        Request::AccessDecision {
            trusted_key: key,
            deployment_id,
            decision_id,
            minimum_height,
            proof,
        } => {
            let record = proof
                .verify_access_decision(
                    deployment_id,
                    &decision_id,
                    minimum_height,
                    &trusted_key(&key)?,
                )
                .map_err(|error| error.to_string())?;
            Ok(
                json!({"height": proof.revision.height, "timestamp": proof.revision.timestamp, "record": record}),
            )
        }
        Request::DecisionOutcome {
            trusted_key: key,
            operation,
            minimum_height,
            proof,
        } => {
            let outcome = proof
                .verify_decision_outcome(&operation, minimum_height, &trusted_key(&key)?)
                .map_err(|error| error.to_string())?;
            Ok(
                json!({"height": proof.revision.height, "timestamp": proof.revision.timestamp, "outcome": outcome}),
            )
        }
        Request::Permission {
            trusted_key: key,
            policy_id,
            request,
            minimum_height,
            proof,
        } => {
            let allowed = proof
                .verify(
                    &policy_id,
                    &request,
                    minimum_height,
                    &trusted_key(&key)?,
                    PERMISSION_LIMITS,
                )
                .map_err(|error| error.to_string())?;
            Ok(json!({"height": proof.revision.height,
                "timestamp": proof.revision.timestamp, "allowed": allowed}))
        }
        Request::ObjectOwner {
            trusted_key: key,
            policy_id,
            object,
            minimum_height,
            proof,
        } => {
            let owner = proof
                .verify_object_owner(&policy_id, &object, minimum_height, &trusted_key(&key)?)
                .map_err(|error| error.to_string())?;
            Ok(json!({"height": proof.revision.height,
                "timestamp": proof.revision.timestamp, "owner": owner}))
        }
    }
}

/// Owned bytes returned by the verifier. Release once with `vera_buffer_free`.
#[derive(Debug)]
#[repr(C)]
pub struct VeraBuffer {
    /// Start of a Rust-owned allocation.
    pub data: *mut u8,
    /// Allocation length, in bytes.
    pub len: usize,
}

impl VeraBuffer {
    fn new(bytes: Vec<u8>) -> Self {
        let boxed = bytes.into_boxed_slice();
        let len = boxed.len();
        Self {
            data: Box::into_raw(boxed).cast::<u8>(),
            len,
        }
    }
}

/// Verify a bounded JSON request and return canonical JSON result or error.
/// Only returned results may be used as authenticated data by the caller.
///
/// # Safety
/// A non-null `input` with `len` in `1..=MAX_REQUEST_BYTES` must point to
/// `len` readable bytes for the duration of the call. Other lengths are rejected
/// without reading the pointer.
/// The returned buffer must be released exactly once with `vera_buffer_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vera_verify(input: *const u8, len: usize) -> VeraBuffer {
    let result = std::panic::catch_unwind(|| {
        if input.is_null() || len == 0 || len > MAX_REQUEST_BYTES {
            return Err("invalid verification input length".to_string());
        }
        // The foreign caller retains the input allocation until this call returns.
        verify(unsafe { std::slice::from_raw_parts(input, len) })
    })
    .unwrap_or_else(|_| Err("verification failed".into()));
    let output = match result {
        Ok(value) => json!({"result": value}),
        Err(error) => json!({"error": error}),
    };
    VeraBuffer::new(output.to_string().into_bytes())
}

/// Release an allocation returned by `vera_verify`.
///
/// # Safety
/// `buffer` must be an unchanged, unreleased buffer returned by `vera_verify`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vera_buffer_free(buffer: VeraBuffer) {
    if !buffer.data.is_null() {
        // Reconstruct the exact boxed slice allocated by VeraBuffer::new.
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(buffer.data, buffer.len)) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_validation_selects_json_or_yaml_without_fallback() {
        for (definition, format, expected) in [
            (
                r#"{"name":"sample","resources":[{"name":"file"}]}"#,
                "JSON",
                true,
            ),
            ("name: sample\nresources:\n  - name: file\n", "yaml", true),
            ("name: sample\nresources:\n  - name: file\n", "json", false),
            (r#"{"name":"sample","extra":true}"#, "json", false),
            ("{}", "unknown", false),
        ] {
            let input = serde_json::to_vec(
                &json!({"kind":"validate_policy", "definition":definition, "format":format}),
            )
            .unwrap();
            let output = unsafe { vera_verify(input.as_ptr(), input.len()) };
            let bytes = unsafe { std::slice::from_raw_parts(output.data, output.len) };
            let response: Value = serde_json::from_slice(bytes).unwrap();
            unsafe { vera_buffer_free(output) };
            assert_eq!(response["result"]["valid"], expected, "{response}");
        }
    }

    #[test]
    fn invalid_foreign_inputs_return_owned_errors() {
        for (input, len) in [
            (std::ptr::null(), 0),
            (b"x".as_ptr(), MAX_REQUEST_BYTES + 1),
            (b"x".as_ptr(), 1),
        ] {
            // Valid readable memory is supplied whenever the length passes the boundary checks.
            let output = unsafe { vera_verify(input, len) };
            let bytes = unsafe { std::slice::from_raw_parts(output.data, output.len) };
            let json: Value = serde_json::from_slice(bytes).unwrap();
            assert!(json["error"].is_string());
            assert!(json.get("result").is_none());
            unsafe { vera_buffer_free(output) };
        }
    }
}
