use bytes::Bytes;
use commonware_codec::EncodeSize;
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::tokio::Context;
use commonware_storage::{
    mmr,
    qmdb::{
        Error,
        any::value::VariableEncoding,
        current::ordered::{
            ExclusionProof,
            variable::{Db, KeyValueProof},
        },
    },
    translator::EightCap,
};

pub(super) type Store = Db<mmr::Family, Context, Vec<u8>, Bytes, Sha256, EightCap, 32, Sequential>;
type Boundary = ExclusionProof<mmr::Family, Vec<u8>, VariableEncoding<Bytes>, Digest, 32>;
type Membership = KeyValueProof<mmr::Family, Vec<u8>, Digest, 32>;
const MAX_RECORDS: usize = 4096;

#[derive(Clone)]
pub(super) struct Entry {
    pub(super) key: Vec<u8>,
    pub(super) value: Bytes,
    pub(super) proof: Membership,
}

#[derive(Clone)]
pub(super) struct PrefixProof {
    pub(super) boundary: Option<Boundary>,
    pub(super) entries: Vec<Entry>,
}

impl PrefixProof {
    // Includes encoded components, excluding any future protocol envelope.
    pub(super) fn component_bytes(&self) -> usize {
        self.boundary.encode_size()
            + self
                .entries
                .iter()
                .map(|entry| {
                    entry.key.encode_size() + entry.value.encode_size() + entry.proof.encode_size()
                })
                .sum::<usize>()
    }

    pub(super) fn verify(&self, prefix: &[u8], root: &Digest) -> bool {
        if self.entries.len() > MAX_RECORDS {
            return false;
        }
        let mut expected = match &self.boundary {
            None => Some(prefix),
            Some(boundary) => {
                if !Store::verify_exclusion_proof(&prefix.to_vec(), boundary, root) {
                    return false;
                }
                match boundary {
                    Boundary::KeyValue(_, update) => successor(prefix, &update.next_key, prefix),
                    Boundary::Commit(..) => None,
                }
            }
        };
        for entry in &self.entries {
            if expected != Some(entry.key.as_slice())
                || !Store::verify_key_value_proof(
                    entry.key.clone(),
                    entry.value.clone(),
                    &entry.proof,
                    root,
                )
            {
                return false;
            }
            expected = successor(&entry.key, &entry.proof.next_key, prefix);
        }
        expected.is_none()
    }
}

// Successors wrap at the maximum key; crossing either end terminates the prefix.
fn successor<'a>(key: &[u8], next: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    (next > key && next.starts_with(prefix)).then_some(next)
}

pub(super) async fn prove(db: &Store, prefix: &[u8]) -> Result<PrefixProof, Error<mmr::Family>> {
    let key = prefix.to_vec();
    let boundary = if db.get(&key).await?.is_some() {
        None
    } else {
        Some(db.exclusion_proof(&key).await?)
    };
    let mut next = match &boundary {
        None => Some(key),
        Some(Boundary::KeyValue(_, update)) => {
            successor(prefix, &update.next_key, prefix).map(<[u8]>::to_vec)
        }
        Some(Boundary::Commit(..)) => None,
    };
    let mut entries = Vec::new();
    while let Some(key) = next {
        assert!(
            entries.len() < MAX_RECORDS,
            "prefix exceeds experiment limit"
        );
        let value = db.get(&key).await?.ok_or(Error::KeyNotFound)?;
        let proof = db.key_value_proof(key.clone()).await?;
        next = successor(&key, &proof.next_key, prefix).map(<[u8]>::to_vec);
        entries.push(Entry { key, value, proof });
    }
    Ok(PrefixProof { boundary, entries })
}
