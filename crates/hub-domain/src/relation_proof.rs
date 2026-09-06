//! Complete relationship prefixes verified at an externally selected revision.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

use crate::relation_index::{
    RELATION_INDEX_VERSION, RELATION_INDEX_VERSION_KEY, is_relation_prefix, relation_count_key,
};
use crate::{ModuleId, ModuleStateProof, ProofError, verify_module_state_proof};

/// Inclusion proofs for every record counted by an authenticated relation index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationPrefixProof {
    /// Proof that this revision uses the supported count invariant.
    pub version: ModuleStateProof,
    /// Exact prefix cardinality, or proven absence for an empty prefix.
    pub count: ModuleStateProof,
    /// All records under the prefix, in strictly increasing raw-key order.
    pub records: Vec<ModuleStateProof>,
}

/// Caller limits checked before proof decoding or cryptographic verification.
#[derive(Debug, Clone, Copy)]
pub struct RelationProofLimits {
    /// Maximum number of returned relationship records.
    pub records: usize,
    /// Maximum total encoded string bytes, plus the requested prefix.
    pub bytes: usize,
}

/// Invalid coverage, metadata, bounds or cryptographic evidence.
#[derive(Debug, thiserror::Error)]
pub enum RelationProofError {
    /// Proof did not satisfy the complete-prefix contract.
    #[error("invalid relationship proof: {0}")]
    Invalid(&'static str),
    /// An individual inclusion or absence proof failed verification.
    #[error(transparent)]
    Record(#[from] ProofError),
}

type Entry = (Vec<u8>, Vec<u8>);

/// Verify complete enumeration against a trusted finalized root and height.
///
/// Archived records count as records. Callers evaluate their contents only after
/// verification. A revision without the format marker cannot prove an empty scan.
pub fn verify_relation_prefix_proof(
    root: B256,
    height: u64,
    prefix: &[u8],
    proof: &RelationPrefixProof,
    limits: RelationProofLimits,
) -> Result<Vec<Entry>, RelationProofError> {
    use RelationProofError::Invalid;
    if !is_relation_prefix(prefix) {
        return Err(Invalid("unsupported prefix"));
    }
    if proof.records.len() > limits.records {
        return Err(Invalid("record limit exceeded"));
    }
    let mut remaining = limits
        .bytes
        .checked_sub(prefix.len())
        .ok_or(Invalid("byte limit exceeded"))?;
    for record in [&proof.version, &proof.count]
        .into_iter()
        .chain(&proof.records)
    {
        for text in [
            record.key.as_str(),
            record.value.as_deref().unwrap_or(""),
            &record.jmt_proof,
            &record.module_root,
        ]
        .into_iter()
        .chain(record.all_module_roots.iter().map(String::as_str))
        {
            remaining = remaining
                .checked_sub(text.len())
                .ok_or(Invalid("byte limit exceeded"))?;
        }
    }
    let read = |record: &ModuleStateProof| {
        if record.module != ModuleId::Acp || record.height != height {
            return Err(Invalid("record belongs to another module or height"));
        }
        verify_module_state_proof(root, record)?;
        let key = decode(&record.key)?;
        let value = record.value.as_deref().map(decode).transpose()?;
        Ok((key, value))
    };
    let (key, version) = read(&proof.version)?;
    if key != RELATION_INDEX_VERSION_KEY || version.as_deref() != Some(RELATION_INDEX_VERSION) {
        return Err(Invalid("relationship index is unavailable or unsupported"));
    }
    let (key, count) = read(&proof.count)?;
    if key != relation_count_key(prefix) {
        return Err(Invalid("count belongs to another prefix"));
    }
    let count = count
        .map(|bytes| {
            bytes
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| Invalid("invalid count encoding"))
        })
        .transpose()?
        .unwrap_or(0);
    if usize::try_from(count).ok() != Some(proof.records.len()) {
        return Err(Invalid("record count mismatch"));
    }
    let mut entries: Vec<Entry> = Vec::with_capacity(proof.records.len());
    for record in &proof.records {
        let (key, value) = read(record)?;
        if !key.starts_with(prefix) || entries.last().is_some_and(|(last, _)| last >= &key) {
            return Err(Invalid(
                "records are outside the prefix, repeated or unordered",
            ));
        }
        entries.push((key, value.ok_or(Invalid("record is absent"))?));
    }
    Ok(entries)
}

fn decode(value: &str) -> Result<Vec<u8>, RelationProofError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|_| RelationProofError::Invalid("invalid record hex"))
}
