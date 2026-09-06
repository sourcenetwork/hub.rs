use alloy_primitives::B256;
use commonware_codec::{Encode as _, EncodeSize as _};
use hub_permission::{
    AccessRequest, PermissionError, PermissionLimits, PermissionProof, PermissionRead, ReadLimits,
    RecordRead, capture_reads,
    current::{Entry, Exclusion, PrefixEvidence, successor},
    encoded_size, verify_permission_proof,
};

use super::{BackendError, InMemoryKvStore, NativeDb, NativeStateSet, combine_module_roots};

/// Capture permission evidence at the selected current-state root.
///
/// All namespace read locks remain held through generation. The snapshot selects
/// candidate reads only; authenticated replay must succeed before returning them.
/// Historical roots unavailable in the live databases return an error.
pub async fn permission_proof(
    set: &NativeStateSet,
    expected: B256,
    snapshot: InMemoryKvStore,
    policy: &str,
    request: &AccessRequest,
    limits: PermissionLimits,
) -> Result<PermissionProof, BackendError> {
    let (a, b, h, n) = futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
    permission_proof_at(
        [&a, &b, &h, &n],
        expected,
        snapshot,
        policy,
        request,
        limits,
    )
    .await
}

/// Generate evidence from immutable partition borrows held at one selected revision.
/// Shared database callers must retain their read guards until this call returns.
pub async fn permission_proof_at(
    [a, b, h, n]: [&NativeDb; 4],
    expected: B256,
    snapshot: InMemoryKvStore,
    policy: &str,
    request: &AccessRequest,
    limits: PermissionLimits,
) -> Result<PermissionProof, BackendError> {
    let roots = [a.root().0, b.root().0, h.root().0, n.root().0];
    if combine_module_roots(&roots) != expected {
        return Err(PermissionError::Invalid("selected module root changed").into());
    }
    let reads = capture_reads(snapshot, policy, request, limits)?;
    let mut proof = PermissionProof {
        roots: Some(roots.map(B256::from)),
        reads: Vec::new(),
    };
    let mut bytes = limits.proof_bytes - encoded_size(&proof, limits.proof_bytes)?;
    let mut records = limits.reads;
    for read in reads {
        let read = match read {
            RecordRead::Key(key) => {
                charge(&mut records.bytes, key.len())?;
                let value = a.get(&key).await.map_err(storage)?;
                if let Some(value) = &value {
                    charge(&mut records.records, 1)?;
                    charge(&mut records.bytes, value.len())?;
                }
                let evidence = if value.is_some() {
                    let evidence = a.key_value_proof(key.clone()).await.map_err(storage)?;
                    if evidence.encode_size() > bytes / 2 {
                        return Err(PermissionError::Limit.into());
                    }
                    evidence.encode()
                } else {
                    let evidence = a.exclusion_proof(&key).await.map_err(storage)?;
                    if evidence.encode_size() > bytes / 2 {
                        return Err(PermissionError::Limit.into());
                    }
                    evidence.encode()
                };
                PermissionRead::CurrentPoint {
                    key: key.into(),
                    value: value.map(Into::into),
                    proof: evidence.into(),
                }
            }
            RecordRead::Prefix(prefix) => {
                let evidence = prefix_proof(a, &prefix, &mut records, bytes / 2).await?;
                PermissionRead::CurrentPrefix {
                    prefix: prefix.into(),
                    proof: evidence.encode().into(),
                }
            }
        };
        let size = encoded_size(&read, bytes)?;
        charge(&mut bytes, size + usize::from(!proof.reads.is_empty()))?;
        proof.reads.push(read);
    }
    // Current-state evidence is bound to the supplied root; it has no separate height field.
    verify_permission_proof(expected, 0, policy, request, &proof, limits)?;
    Ok(proof)
}

fn charge(remaining: &mut usize, amount: usize) -> Result<(), PermissionError> {
    *remaining = remaining
        .checked_sub(amount)
        .ok_or(PermissionError::Limit)?;
    Ok(())
}

fn storage(error: impl std::fmt::Display) -> BackendError {
    BackendError::Storage(error.to_string())
}

async fn prefix_proof(
    db: &NativeDb,
    prefix: &[u8],
    remaining: &mut ReadLimits,
    mut bytes: usize,
) -> Result<PrefixEvidence, BackendError> {
    charge(&mut remaining.bytes, prefix.len())?;
    let key = prefix.to_vec();
    let boundary = if db.get(&key).await.map_err(storage)?.is_some() {
        None
    } else {
        Some(db.exclusion_proof(&key).await.map_err(storage)?)
    };
    charge(&mut bytes, boundary.encode_size() + 0_usize.encode_size())?;
    let mut next = match &boundary {
        None => Some(key),
        Some(Exclusion::KeyValue(_, record)) => {
            successor(prefix, &record.next_key, prefix).map(<[u8]>::to_vec)
        }
        Some(Exclusion::Commit(..)) => None,
    };
    let mut entries = Vec::new();
    while let Some(key) = next {
        charge(&mut remaining.records, 1)?;
        charge(&mut remaining.bytes, key.len())?;
        let value = db
            .get(&key)
            .await
            .map_err(storage)?
            .ok_or(PermissionError::Invalid("prefix successor unavailable"))?;
        charge(&mut remaining.bytes, value.len())?;
        let proof = db.key_value_proof(key.clone()).await.map_err(storage)?;
        next = successor(&key, &proof.next_key, prefix).map(<[u8]>::to_vec);
        let entry = Entry { key, value, proof };
        charge(
            &mut bytes,
            entry.encode_size() + (entries.len() + 1).encode_size() - entries.len().encode_size(),
        )?;
        entries.push(entry);
    }
    Ok(PrefixEvidence { boundary, entries })
}

#[cfg(test)]
mod tests;
