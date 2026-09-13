use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use borsh::BorshDeserialize;
use jmt::{
    JellyfishMerkleIterator, KeyHash, RootHash, Sha256Jmt,
    proof::SparseMerkleRangeProof,
    restore::{JellyfishMerkleRestore, StateSnapshotReceiver},
    storage::{HasPreimage, Node, NodeBatch, NodeKey},
};
use sha2::{Digest, Sha256};

use crate::{ModuleStateTree, TreeSnapshot, store::JmtStore};

const MAX_RECORDS: usize = 128;
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const MAX_PROOF_BYTES: usize = 4 + 256 * 65;

/// At most 128 records and 1 MiB of keys, values and length fields, in key-hash order.
#[derive(Clone, Debug)]
pub struct SnapshotChunk {
    /// Raw keys include authenticated module metadata, but exclude local store metadata.
    pub records: Vec<(Vec<u8>, Vec<u8>)>,
    /// Borsh JMT range proof; bounded before decoding during restoration.
    pub proof: Vec<u8>,
}

impl TreeSnapshot {
    /// Export committed records strictly after `after`, or from the start if absent.
    /// Keep this view alive for the entire transfer to prevent startup rewind.
    pub fn export_chunk(&self, after: Option<KeyHash>) -> Result<Option<SnapshotChunk>> {
        ensure!(
            self.pending.is_empty(),
            "cannot export pending module state"
        );
        if self.version == 0 {
            return Ok(None);
        }
        let iter = JellyfishMerkleIterator::new(
            self.store.clone(),
            self.version,
            after.unwrap_or(KeyHash([0; 32])),
        )?;
        let mut records = Vec::new();
        let mut bytes = 0;
        let mut last = None;
        for item in iter {
            let (hash, value) = item?;
            if Some(hash) == after {
                continue;
            }
            let key = self
                .store
                .preimage(hash)?
                .context("missing snapshot key preimage")?;
            ensure!(
                KeyHash::with::<Sha256>(&key) == hash,
                "invalid snapshot key preimage"
            );
            let size = record_size(&key, &value)?;
            ensure!(
                size <= MAX_RECORD_BYTES,
                "snapshot record exceeds byte limit"
            );
            if bytes + size > MAX_RECORD_BYTES {
                break;
            }
            bytes += size;
            records.push((key, value));
            last = Some(hash);
            if records.len() == MAX_RECORDS {
                break;
            }
        }
        let Some(last) = last else {
            return Ok(None);
        };
        let proof = Sha256Jmt::new(self.store.as_ref()).get_range_proof(last, self.version)?;
        Ok(Some(SnapshotChunk {
            records,
            proof: borsh::to_vec(&proof)?,
        }))
    }
}

/// Restore one module into a new directory against an independently authenticated root.
/// Errors invalidate the receiver. Incomplete directories cannot be opened as module trees.
/// This does not install a node-wide checkpoint or resume interrupted transfers.
pub struct ModuleRestore {
    path: PathBuf,
    store: Arc<JmtStore>,
    receiver: Option<JellyfishMerkleRestore<Sha256>>,
    root: RootHash,
    height: u64,
    received: bool,
}

impl std::fmt::Debug for ModuleRestore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModuleRestore")
            .field("path", &self.path)
            .field("height", &self.height)
            .finish_non_exhaustive()
    }
}

impl ModuleRestore {
    /// Create a fresh staging directory. Existing paths are rejected without modification.
    pub fn create(path: impl AsRef<Path>, height: u64, root: RootHash) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        std::fs::create_dir(&path).context("create module restore directory")?;
        let store = Arc::new(JmtStore::open(&path)?);
        store.begin_restore()?;
        let receiver = Some(JellyfishMerkleRestore::new(store.clone(), 1, root)?);
        Ok(Self {
            path,
            store,
            receiver,
            root,
            height,
            received: false,
        })
    }

    /// Verify and persist the next bounded chunk. Any error requires a fresh restore.
    pub fn add_chunk(&mut self, chunk: SnapshotChunk) -> Result<()> {
        // The JMT receiver mutates before verifying; never reuse it after an error.
        let mut receiver = self.receiver.take().context("module restore has failed")?;
        ensure!(
            !chunk.records.is_empty() && chunk.records.len() <= MAX_RECORDS,
            "invalid snapshot record count"
        );
        let mut bytes = 0usize;
        for (key, value) in &chunk.records {
            bytes = bytes
                .checked_add(record_size(key, value)?)
                .context("snapshot size overflow")?;
            ensure!(
                bytes <= MAX_RECORD_BYTES,
                "snapshot chunk exceeds byte limit"
            );
        }
        ensure!(
            chunk.proof.len() >= 4 && chunk.proof.len() <= MAX_PROOF_BYTES,
            "invalid snapshot proof length"
        );
        let siblings = u32::from_le_bytes(chunk.proof[..4].try_into()?);
        ensure!(siblings <= 256, "snapshot proof exceeds tree depth");
        let proof = SparseMerkleRangeProof::<Sha256>::try_from_slice(&chunk.proof)?;
        receiver.add_chunk(
            chunk
                .records
                .iter()
                .map(|(key, value)| (KeyHash::with::<Sha256>(key), value.clone()))
                .collect(),
            proof,
        )?;
        self.store.restore_entries(&chunk.records)?;
        self.received = true;
        self.receiver = Some(receiver);
        Ok(())
    }

    /// Check completeness and durably publish this module's canonical revision.
    pub fn finish(mut self) -> Result<ModuleStateTree> {
        let receiver = self.receiver.take().context("module restore has failed")?;
        let version = if self.received {
            receiver.finish()?;
            ensure!(
                Sha256Jmt::new(self.store.as_ref()).get_root_hash(1)? == self.root,
                "incomplete module snapshot"
            );
            1
        } else {
            drop(receiver);
            if self.root == RootHash(Sha256::digest([]).into()) {
                0
            } else {
                // JMT's empty root differs from the never-written module root.
                let mut batch = NodeBatch::default();
                batch.insert_node(NodeKey::new(1, std::iter::empty().collect()), Node::Null);
                self.store.write_batch(&batch, &[])?;
                ensure!(
                    Sha256Jmt::new(self.store.as_ref()).get_root_hash(1)? == self.root,
                    "missing module snapshot records"
                );
                1
            }
        };
        self.store.finish_restore(version, self.height)?;
        drop(self.store);
        ModuleStateTree::open(self.path)
    }
}

fn record_size(key: &[u8], value: &[u8]) -> Result<usize> {
    key.len()
        .checked_add(value.len())
        .and_then(|size| size.checked_add(8))
        .context("snapshot record size overflow")
}

#[cfg(test)]
mod tests;
