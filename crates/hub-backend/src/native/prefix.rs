use alloy_primitives::B256;
use commonware_codec::Encode as _;
use hub_permission::{
    ModuleId, PERMISSION_LIMITS, PermissionError, PrefixProof, RECORD_PROOF_BYTES,
};

use super::{BackendError, MAX_KEY_BYTES, NativeDb, combine_module_roots};

/// Prove a complete prefix while the caller retains all four partition read guards.
pub async fn prefix_proof_at(
    databases: [&NativeDb; 4],
    expected: B256,
    module: ModuleId,
    prefix: &[u8],
) -> Result<PrefixProof, BackendError> {
    if prefix.len() > MAX_KEY_BYTES {
        return Err(PermissionError::Limit.into());
    }
    let roots = databases.map(|db| db.root().0);
    if combine_module_roots(&roots) != expected {
        return Err(PermissionError::Invalid("selected module root changed").into());
    }
    let mut remaining = PERMISSION_LIMITS.reads;
    let evidence = super::permission::prefix_proof(
        databases[module.index()],
        prefix,
        &mut remaining,
        RECORD_PROOF_BYTES / 2,
    )
    .await?;
    let proof = PrefixProof {
        module,
        prefix: prefix.to_vec().into(),
        roots: roots.map(B256::from),
        proof: evidence.encode().into(),
    };
    proof.verify(expected, module, prefix, RECORD_PROOF_BYTES)?;
    Ok(proof)
}

/// Prove one bounded page while retaining all four partition read guards.
pub async fn prefix_page_at(
    databases: [&NativeDb; 4],
    expected: B256,
    request: &hub_permission::PrefixPageRequest,
) -> Result<hub_permission::PrefixPageProof, BackendError> {
    use hub_permission::{PAGE_PROOF_BYTES, PrefixPageProof, encoded_size};
    request.validate()?;
    let roots = databases.map(|db| db.root().0);
    if combine_module_roots(&roots) != expected {
        return Err(PermissionError::Invalid("selected module root changed").into());
    }
    let mut proof = PrefixPageProof {
        request: request.clone(),
        roots: roots.map(B256::from),
        proof: Default::default(),
    };
    let overhead = encoded_size(&proof, PAGE_PROOF_BYTES)?;
    let evidence = super::permission::page_proof(
        databases[request.module.index()],
        request,
        (PAGE_PROOF_BYTES - overhead) / 2,
    )
    .await?;
    proof.proof = evidence.encode().into();
    proof.verify(expected, request, PAGE_PROOF_BYTES)?;
    Ok(proof)
}
