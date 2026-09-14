use alloy_primitives::B256;
use commonware_codec::{Encode as _, EncodeSize as _};
use hub_permission::{ModuleId, PermissionError, RECORD_PROOF_BYTES, RecordProof};

use super::{BackendError, MAX_KEY_BYTES, NativeDb, combine_module_roots};

/// Prove a current record while the caller retains all four partition read guards.
pub async fn record_proof_at(
    databases: [&NativeDb; 4],
    expected: B256,
    module: ModuleId,
    key: &[u8],
) -> Result<RecordProof, BackendError> {
    if key.len() > MAX_KEY_BYTES {
        return Err(PermissionError::Limit.into());
    }
    let roots = databases.map(|db| db.root().0);
    if combine_module_roots(&roots) != expected {
        return Err(PermissionError::Invalid("selected module root changed").into());
    }
    let db = databases[module.index()];
    let key = key.to_vec();
    let value = db.get(&key).await.map_err(storage)?;
    let proof = if value.is_some() {
        let proof = db.key_value_proof(key.clone()).await.map_err(storage)?;
        if proof.encode_size() > RECORD_PROOF_BYTES / 2 {
            return Err(PermissionError::Limit.into());
        }
        proof.encode()
    } else {
        let proof = db.exclusion_proof(&key).await.map_err(storage)?;
        if proof.encode_size() > RECORD_PROOF_BYTES / 2 {
            return Err(PermissionError::Limit.into());
        }
        proof.encode()
    };
    let record = RecordProof {
        module,
        key: key.into(),
        value: value.map(Into::into),
        roots: roots.map(B256::from),
        proof: proof.into(),
    };
    record.verify(expected, module, &record.key, RECORD_PROOF_BYTES)?;
    Ok(record)
}

fn storage(error: impl std::fmt::Display) -> BackendError {
    BackendError::Storage(error.to_string())
}
