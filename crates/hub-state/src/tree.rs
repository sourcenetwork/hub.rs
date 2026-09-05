//! Canonical module trees and preparation of immutable branch updates.

use crate::{TreeSnapshot, snapshot::Entries, store::JmtStore};
use anyhow::{Result, ensure};
use jmt::{KeyHash, RootHash, Sha256Jmt, proof::SparseMerkleProof, storage::NodeBatch};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, sync::Arc};

const HEIGHT_RETENTION: u64 = 64;

/// Persistent canonical state. Preparing a snapshot never writes to this tree.
#[derive(Debug)]
pub struct ModuleStateTree {
    store: Arc<JmtStore>,
    canonical_version: u64,
    canonical_height: u64,
    height_versions: BTreeMap<u64, u64>,
}

impl ModuleStateTree {
    /// Open a tree and restore its canonical revision and retained proof heights.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let store = Arc::new(JmtStore::open(path)?);
        let canonical_version = store.read_canonical_version()?.unwrap_or(0);
        let canonical_height = store.read_canonical_height()?.unwrap_or(0);
        let mut height_versions = store.read_height_versions()?;
        let stored = height_versions
            .entry(canonical_height)
            .or_insert(canonical_version);
        ensure!(
            *stored == canonical_version,
            "canonical height and version metadata disagree"
        );
        Ok(Self {
            store,
            canonical_version,
            canonical_height,
            height_versions,
        })
    }

    /// Current committed JMT version.
    pub const fn version(&self) -> u64 {
        self.canonical_version
    }
    /// Last committed application height.
    pub const fn canonical_height(&self) -> u64 {
        self.canonical_height
    }

    /// Take a read-only view of the current canonical state.
    pub fn snapshot(&self) -> Result<TreeSnapshot> {
        Ok(TreeSnapshot {
            store: self.store.clone(),
            base_version: self.canonical_version,
            version: self.canonical_version,
            root: self.root()?,
            pending: Vec::new(),
        })
    }

    /// Prepare updates on a committed or pending parent without changing disk state.
    pub fn prepare(&self, parent: &TreeSnapshot, entries: Entries) -> Result<TreeSnapshot> {
        ensure!(
            Arc::ptr_eq(&self.store, &parent.store),
            "snapshot belongs to another tree"
        );
        let mut parent = parent.clone();
        parent.rebase(self.canonical_version, self.root()?);
        parent.prepare(entries)
    }

    /// Persist the next selected revision; repeated delivery of that revision is harmless.
    pub fn commit_prepared(&mut self, height: u64, snapshot: &TreeSnapshot) -> Result<()> {
        ensure!(
            height >= self.canonical_height,
            "cannot commit below canonical height"
        );
        if height == self.canonical_height {
            ensure!(
                snapshot.version == self.canonical_version && snapshot.root == self.root()?,
                "conflicting revision at canonical height"
            );
        }
        self.persist(height, snapshot)
    }

    fn persist(&mut self, height: u64, snapshot: &TreeSnapshot) -> Result<()> {
        ensure!(
            Arc::ptr_eq(&self.store, &snapshot.store),
            "snapshot belongs to another tree"
        );
        let empty = NodeBatch::default();
        let (nodes, entries) =
            if snapshot.version == self.canonical_version && snapshot.root == self.root()? {
                (&empty, [].as_slice())
            } else {
                let update = snapshot
                    .pending
                    .last()
                    .ok_or_else(|| anyhow::anyhow!("missing prepared update"))?;
                ensure!(
                    update.parent_version == self.canonical_version
                        && update.parent_root == self.root()?,
                    "prepared update does not extend canonical state"
                );
                (&update.nodes, update.entries.as_slice())
            };
        let retain_from = height.saturating_sub(HEIGHT_RETENTION);
        self.store
            .write_revision(nodes, entries, snapshot.version, height, retain_from)?;
        self.canonical_version = snapshot.version;
        self.canonical_height = height;
        self.height_versions.insert(height, snapshot.version);
        self.height_versions.retain(|&h, _| h >= retain_from);
        Ok(())
    }

    /// Write one key during setup or direct tree use.
    pub fn put(&mut self, key: &[u8], value: Option<Vec<u8>>) -> Result<RootHash> {
        self.commit(vec![(key.to_vec(), value)])
    }
    /// Atomically update tree nodes, raw values and canonical metadata.
    pub fn commit(&mut self, entries: Entries) -> Result<RootHash> {
        let next = self.prepare(&self.snapshot()?, entries)?;
        self.persist(self.canonical_height, &next)?;
        Ok(next.root)
    }
    /// Read a value at the canonical revision.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.snapshot()?.get(key)
    }
    /// Prove a key against the canonical root.
    pub fn prove(&self, key: &[u8]) -> Result<(Option<Vec<u8>>, SparseMerkleProof<Sha256>)> {
        Sha256Jmt::new(self.store.as_ref())
            .get_with_proof(KeyHash::with::<Sha256>(key), self.canonical_version)
    }
    /// Prove a key at a retained finalized height.
    pub fn prove_at_height(
        &self,
        key: &[u8],
        height: u64,
    ) -> Result<(Option<Vec<u8>>, SparseMerkleProof<Sha256>, RootHash)> {
        let version = self.version_at_height(height)?;
        ensure!(version != 0, "tree is empty at height {height}");
        let tree = Sha256Jmt::new(self.store.as_ref());
        let (value, proof) = tree.get_with_proof(KeyHash::with::<Sha256>(key), version)?;
        Ok((value, proof, tree.get_root_hash(version)?))
    }
    /// Root of the canonical state.
    pub fn root(&self) -> Result<RootHash> {
        self.root_at_version(self.canonical_version)
    }
    /// Root at a retained finalized height.
    pub fn root_at_height(&self, height: u64) -> Result<RootHash> {
        self.root_at_version(self.version_at_height(height)?)
    }
    fn version_at_height(&self, height: u64) -> Result<u64> {
        self.height_versions
            .get(&height)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("no JMT version for height {height}"))
    }
    fn root_at_version(&self, version: u64) -> Result<RootHash> {
        if version == 0 {
            return Ok(RootHash(empty_root()));
        }
        Sha256Jmt::new(self.store.as_ref()).get_root_hash(version)
    }
    /// Load canonical key-value pairs for module initialization.
    pub fn load_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.store.raw_kv_iter()
    }
}

fn empty_root() -> [u8; 32] {
    Sha256::digest([]).into()
}

#[cfg(test)]
mod tests;
