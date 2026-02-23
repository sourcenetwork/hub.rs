//! Module state tree backed by JMT with native sparse Merkle proof support.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::Result;
use jmt::{KeyHash, RootHash, Sha256Jmt, proof::SparseMerkleProof};
use sha2::{Digest, Sha256};

use crate::store::JmtStore;

/// Maximum number of height→version entries to retain. Only the most recent
/// `HEIGHT_RETENTION` heights are kept; older entries are evicted.
const HEIGHT_RETENTION: u64 = 64;

/// Module state tree backed by JMT with overlay-based execution isolation.
///
/// During block execution (between `begin_execution` and `flush_overlay`),
/// all writes go to an in-memory overlay — the persistent JMT is not
/// modified. `root()` computes a speculative Merkle root by applying the
/// overlay on top of the canonical base. After execution, `flush_overlay()`
/// commits the overlay to the persistent JMT and the `raw_kv` column family.
///
/// Outside of execution, `put`/`commit` write directly to both the JMT and
/// `raw_kv` for convenience in tests and setup code.
#[derive(Debug)]
pub struct ModuleStateTree {
    store: JmtStore,

    /// Canonical JMT version — advances only via `flush_overlay()` or
    /// direct writes outside execution.
    canonical_version: u64,

    /// Highest height whose entries have been flushed to the canonical JMT.
    canonical_height: u64,

    /// Maps height -> canonical JMT version after flushing that height.
    height_versions: HashMap<u64, u64>,

    /// True between `begin_execution` and `flush_overlay`.
    in_execution: bool,

    /// Current execution's height (set by `begin_execution`).
    execution_height: u64,

    /// JMT version representing committed state before the current
    /// execution height. Set once on the first `begin_execution` call
    /// at each new height; subsequent calls at the same height reuse
    /// the saved value.
    execution_base_version: u64,

    /// In-memory overlay for the current execution's writes.
    overlay: HashMap<Vec<u8>, Option<Vec<u8>>>,

    /// Keys written to raw_kv in the most recent flush at `canonical_height`.
    /// Used to clean up stale entries when re-flushing at the same height
    /// (view change scenario).
    last_flushed_keys: HashSet<Vec<u8>>,
}

impl ModuleStateTree {
    /// Opens (or creates) a module state tree at the given path.
    ///
    /// Canonical version and height are loaded from persisted metadata
    /// in the `raw_kv` column family. Fresh stores start at version 0.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let store = JmtStore::open(path)?;
        let canonical_version = store.read_canonical_version()?.unwrap_or(0);
        let canonical_height = store.read_canonical_height()?.unwrap_or(0);
        Ok(Self {
            store,
            canonical_version,
            canonical_height,
            height_versions: HashMap::new(),
            in_execution: false,
            execution_height: 0,
            execution_base_version: 0,
            overlay: HashMap::new(),
            last_flushed_keys: HashSet::new(),
        })
    }

    /// Returns the current canonical JMT version.
    pub const fn version(&self) -> u64 {
        self.canonical_version
    }

    /// Prepares the tree for a new block execution at the given height.
    pub fn begin_execution(&mut self, height: u64) {
        self.overlay.clear();

        if height != self.execution_height {
            self.execution_base_version = self.base_version_for_execution_at(height);
            self.last_flushed_keys.clear();
        }

        self.execution_height = height;
        self.in_execution = true;
    }

    /// Inserts or deletes a key-value pair.
    ///
    /// During execution: writes to the overlay only (deferred).
    /// Outside execution: writes directly to JMT + raw_kv.
    pub fn put(&mut self, key: &[u8], value: Option<Vec<u8>>) -> Result<RootHash> {
        if self.in_execution {
            self.overlay.insert(key.to_vec(), value);
            return self.root();
        }

        let key_hash = KeyHash::with::<Sha256>(key);
        let tree = Sha256Jmt::new(&self.store);
        let next = self.canonical_version + 1;
        let (root, batch) = tree.put_value_set([(key_hash, value.clone())], next)?;
        self.store
            .write_batch(&batch.node_batch, &[(key_hash, key)])?;
        self.store.raw_kv_write_batch(&[(key.to_vec(), value)])?;
        self.canonical_version = next;
        self.store
            .write_metadata(self.canonical_version, self.canonical_height)?;
        Ok(root)
    }

    /// Reads the value for `key`.
    ///
    /// During execution, reads check the overlay first, then fall back to
    /// the canonical JMT at the base version.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.in_execution
            && let Some(value) = self.overlay.get(key)
        {
            return Ok(value.clone());
        }

        let version = if self.in_execution {
            self.execution_base_version
        } else {
            self.canonical_version
        };

        if version == 0 {
            return Ok(None);
        }

        let key_hash = KeyHash::with::<Sha256>(key);
        let tree = Sha256Jmt::new(&self.store);
        tree.get(key_hash, version)
    }

    /// Generates a native JMT sparse Merkle proof for `key` at the canonical version.
    pub fn prove(&self, key: &[u8]) -> Result<(Option<Vec<u8>>, SparseMerkleProof<Sha256>)> {
        let key_hash = KeyHash::with::<Sha256>(key);
        let tree = Sha256Jmt::new(&self.store);
        tree.get_with_proof(key_hash, self.canonical_version)
    }

    /// Returns the Merkle root.
    ///
    /// During execution: speculative root from canonical base + overlay.
    /// Outside execution: canonical JMT root.
    pub fn root(&self) -> Result<RootHash> {
        if !self.in_execution || self.overlay.is_empty() {
            if self.canonical_version == 0 {
                return Ok(RootHash(empty_root()));
            }
            let tree = Sha256Jmt::new(&self.store);
            return tree.get_root_hash(self.canonical_version);
        }

        let base_ver = self.execution_base_version;
        let kvs: Vec<_> = self
            .overlay
            .iter()
            .map(|(k, v)| (KeyHash::with::<Sha256>(k), v.clone()))
            .collect();

        let tree = Sha256Jmt::new(&self.store);
        if base_ver == 0 {
            let (root, _) = tree.put_value_set(kvs, 1)?;
            return Ok(root);
        }

        let temp = base_ver + 1;
        let (root, _) = tree.put_value_set(kvs, temp)?;
        Ok(root)
    }

    /// Batch-insert multiple key-value pairs.
    pub fn commit(&mut self, entries: Vec<(Vec<u8>, Option<Vec<u8>>)>) -> Result<RootHash> {
        if self.in_execution {
            for (k, v) in entries {
                self.overlay.insert(k, v);
            }
            return self.root();
        }

        let next = self.canonical_version + 1;
        let mut kvs = Vec::with_capacity(entries.len());
        let mut preimages = Vec::with_capacity(entries.len());
        for (k, v) in &entries {
            let key_hash = KeyHash::with::<Sha256>(k);
            preimages.push((key_hash, k.as_slice()));
            kvs.push((key_hash, v.clone()));
        }

        let tree = Sha256Jmt::new(&self.store);
        let (root, batch) = tree.put_value_set(kvs, next)?;
        self.store.write_batch(&batch.node_batch, &preimages)?;

        let raw_ops: Vec<_> = entries.into_iter().collect();
        self.store.raw_kv_write_batch(&raw_ops)?;

        self.canonical_version = next;
        self.store
            .write_metadata(self.canonical_version, self.canonical_height)?;
        Ok(root)
    }

    /// Persist the current execution's overlay to the canonical JMT and raw_kv.
    ///
    /// Always writes at `execution_base_version + 1` so that repeated
    /// flushes at the same height overwrite each other instead of layering.
    /// Stale raw_kv entries from a previous flush at the same height are
    /// deleted to prevent superseded proposal keys from leaking.
    pub fn flush_overlay(&mut self) -> Result<()> {
        self.in_execution = false;

        if self.canonical_height > self.execution_height {
            self.overlay.clear();
            return Ok(());
        }

        let is_overwrite =
            self.execution_height == self.canonical_height && !self.last_flushed_keys.is_empty();

        if self.overlay.is_empty() {
            if is_overwrite {
                let stale: Vec<_> = self.last_flushed_keys.drain().map(|k| (k, None)).collect();
                self.store.raw_kv_write_batch(&stale)?;
            }
            self.height_versions
                .insert(self.execution_height, self.execution_base_version);
            self.canonical_version = self.execution_base_version;
            self.canonical_height = self.canonical_height.max(self.execution_height);
            self.store
                .write_metadata(self.canonical_version, self.canonical_height)?;
            self.evict_old_heights();
            return Ok(());
        }

        let next = self.execution_base_version + 1;
        let mut kvs = Vec::with_capacity(self.overlay.len());
        let mut preimages: Vec<(KeyHash, &[u8])> = Vec::with_capacity(self.overlay.len());

        let entries: Vec<_> = self.overlay.drain().collect();
        for (k, v) in &entries {
            let key_hash = KeyHash::with::<Sha256>(k);
            preimages.push((key_hash, k.as_slice()));
            kvs.push((key_hash, v.clone()));
        }

        let tree = Sha256Jmt::new(&self.store);
        let (_, batch) = tree.put_value_set(kvs, next)?;
        self.store.write_batch(&batch.node_batch, &preimages)?;

        let current_keys: HashSet<Vec<u8>> = entries.iter().map(|(k, _)| k.clone()).collect();

        // Delete stale raw_kv entries from previous flush at same height.
        if is_overwrite {
            let stale_deletes: Vec<_> = self
                .last_flushed_keys
                .difference(&current_keys)
                .map(|k| (k.clone(), None))
                .collect();
            if !stale_deletes.is_empty() {
                self.store.raw_kv_write_batch(&stale_deletes)?;
            }
        }

        let raw_ops: Vec<_> = entries.into_iter().collect();
        self.store.raw_kv_write_batch(&raw_ops)?;

        self.last_flushed_keys = current_keys;
        self.canonical_version = next;
        self.height_versions
            .insert(self.execution_height, self.canonical_version);
        self.canonical_height = self.canonical_height.max(self.execution_height);
        self.store
            .write_metadata(self.canonical_version, self.canonical_height)?;
        self.evict_old_heights();
        Ok(())
    }

    /// Discard the current execution's overlay without writing to JMT.
    pub fn discard_overlay(&mut self) {
        self.overlay.clear();
        self.in_execution = false;
    }

    /// Load all key-value pairs from the `raw_kv` column family.
    pub fn load_all(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        self.store.raw_kv_iter()
    }

    fn base_version_for_execution_at(&self, height: u64) -> u64 {
        if height > 1
            && let Some(&v) = self.height_versions.get(&(height - 1))
        {
            return v;
        }
        self.canonical_version
    }

    fn evict_old_heights(&mut self) {
        let cutoff = self.canonical_height.saturating_sub(HEIGHT_RETENTION);
        self.height_versions.retain(|&h, _| h >= cutoff);
    }
}

fn empty_root() -> [u8; 32] {
    Sha256::digest([]).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn open_tree(dir: &TempDir) -> ModuleStateTree {
        ModuleStateTree::open(dir.path().join("db")).unwrap()
    }

    #[test]
    fn put_get_roundtrip() {
        let dir = TempDir::new().unwrap();
        let mut tree = open_tree(&dir);
        tree.put(b"key/a", Some(b"val-a".to_vec())).unwrap();
        let val = tree.get(b"key/a").unwrap();
        assert_eq!(val, Some(b"val-a".to_vec()));
    }

    #[test]
    fn prove_existence() {
        let dir = TempDir::new().unwrap();
        let mut tree = open_tree(&dir);
        tree.put(b"key/a", Some(b"val-a".to_vec())).unwrap();
        let (val, proof) = tree.prove(b"key/a").unwrap();
        assert_eq!(val, Some(b"val-a".to_vec()));

        let root = tree.root().unwrap();
        assert!(
            proof
                .verify(root, KeyHash::with::<Sha256>(b"key/a"), val)
                .is_ok()
        );
    }

    #[test]
    fn prove_nonexistence() {
        let dir = TempDir::new().unwrap();
        let mut tree = open_tree(&dir);
        tree.put(b"key-a", Some(b"val".to_vec())).unwrap();
        let (val, _proof) = tree.prove(b"key-missing").unwrap();
        assert!(val.is_none());
    }

    #[test]
    fn delete_via_put_none() {
        let dir = TempDir::new().unwrap();
        let mut tree = open_tree(&dir);
        tree.put(b"key", Some(b"val".to_vec())).unwrap();
        assert!(tree.get(b"key").unwrap().is_some());
        tree.put(b"key", None).unwrap();
        assert!(tree.get(b"key").unwrap().is_none());
    }

    #[test]
    fn versioned_reads() {
        let dir = TempDir::new().unwrap();
        let mut tree = open_tree(&dir);
        tree.put(b"key", Some(b"v1".to_vec())).unwrap();
        assert_eq!(tree.version(), 1);
        tree.put(b"key", Some(b"v2".to_vec())).unwrap();
        assert_eq!(tree.version(), 2);
        let val = tree.get(b"key").unwrap();
        assert_eq!(val, Some(b"v2".to_vec()));
    }

    #[test]
    fn root_changes_on_put() {
        let dir = TempDir::new().unwrap();
        let mut tree = open_tree(&dir);
        let r1 = tree.put(b"k1", Some(b"v1".to_vec())).unwrap();
        let r2 = tree.put(b"k2", Some(b"v2".to_vec())).unwrap();
        assert_ne!(r1.0, r2.0);
    }

    #[test]
    fn empty_tree_root_is_stable() {
        let d1 = TempDir::new().unwrap();
        let d2 = TempDir::new().unwrap();
        let t1 = open_tree(&d1);
        let t2 = open_tree(&d2);
        assert_eq!(t1.root().unwrap().0, t2.root().unwrap().0);
    }

    #[test]
    fn multiple_keys_single_commit() {
        let dir = TempDir::new().unwrap();
        let mut tree = open_tree(&dir);
        let root = tree
            .commit(vec![
                (b"a".to_vec(), Some(b"1".to_vec())),
                (b"b".to_vec(), Some(b"2".to_vec())),
                (b"c".to_vec(), Some(b"3".to_vec())),
            ])
            .unwrap();
        assert_eq!(tree.version(), 1);
        assert_eq!(tree.get(b"a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(tree.get(b"b").unwrap(), Some(b"2".to_vec()));
        assert_eq!(tree.get(b"c").unwrap(), Some(b"3".to_vec()));
        assert_ne!(root.0, empty_root());
    }

    // ── raw_kv tests ────────────────────────────────────────────────────

    #[test]
    fn raw_kv_populated_by_direct_put() {
        let dir = TempDir::new().unwrap();
        let mut tree = open_tree(&dir);
        tree.put(b"key-1", Some(b"val-1".to_vec())).unwrap();
        tree.put(b"key-2", Some(b"val-2".to_vec())).unwrap();

        let all = tree.load_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0], (b"key-1".to_vec(), b"val-1".to_vec()));
        assert_eq!(all[1], (b"key-2".to_vec(), b"val-2".to_vec()));
    }

    #[test]
    fn raw_kv_populated_by_commit() {
        let dir = TempDir::new().unwrap();
        let mut tree = open_tree(&dir);
        tree.commit(vec![
            (b"x".to_vec(), Some(b"10".to_vec())),
            (b"y".to_vec(), Some(b"20".to_vec())),
        ])
        .unwrap();

        let all = tree.load_all().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn raw_kv_populated_by_flush_overlay() {
        let dir = TempDir::new().unwrap();
        let mut tree = open_tree(&dir);

        tree.begin_execution(1);
        tree.put(b"overlay-key", Some(b"overlay-val".to_vec()))
            .unwrap();
        tree.flush_overlay().unwrap();

        let all = tree.load_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], (b"overlay-key".to_vec(), b"overlay-val".to_vec()));
    }

    #[test]
    fn raw_kv_delete_removes_entry() {
        let dir = TempDir::new().unwrap();
        let mut tree = open_tree(&dir);
        tree.put(b"keep", Some(b"val".to_vec())).unwrap();
        tree.put(b"remove", Some(b"val".to_vec())).unwrap();
        tree.put(b"remove", None).unwrap();

        let all = tree.load_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, b"keep".to_vec());
    }

    #[test]
    fn load_all_on_reopen() {
        let dir = TempDir::new().unwrap();
        {
            let mut tree = open_tree(&dir);
            tree.put(b"persist-a", Some(b"val-a".to_vec())).unwrap();
            tree.put(b"persist-b", Some(b"val-b".to_vec())).unwrap();
        }

        let tree = ModuleStateTree::open(dir.path().join("db")).unwrap();
        assert_eq!(tree.version(), 2);
        let all = tree.load_all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0], (b"persist-a".to_vec(), b"val-a".to_vec()));
        assert_eq!(all[1], (b"persist-b".to_vec(), b"val-b".to_vec()));
    }

    // ── Execution isolation tests ────────────────────────────────────

    #[test]
    fn begin_execution_isolates_reads() {
        let dir = TempDir::new().unwrap();
        let mut tree = open_tree(&dir);

        tree.put(b"seed-key", Some(b"seed-val".to_vec())).unwrap();

        tree.begin_execution(1);
        tree.put(b"ack", Some(b"ack-data".to_vec())).unwrap();
        assert_eq!(tree.get(b"ack").unwrap(), Some(b"ack-data".to_vec()));

        tree.begin_execution(1);
        assert!(tree.get(b"ack").unwrap().is_none());
        assert_eq!(tree.get(b"seed-key").unwrap(), Some(b"seed-val".to_vec()));
    }

    #[test]
    fn begin_execution_advances_base_on_new_height() {
        let dir = TempDir::new().unwrap();
        let mut tree = open_tree(&dir);

        tree.begin_execution(1);
        tree.put(b"ack-1", Some(b"data".to_vec())).unwrap();
        tree.flush_overlay().unwrap();

        tree.begin_execution(2);
        assert_eq!(tree.get(b"ack-1").unwrap(), Some(b"data".to_vec()));
    }

    #[test]
    fn reverify_at_flushed_height() {
        let dir = TempDir::new().unwrap();
        let mut tree = open_tree(&dir);

        tree.begin_execution(1);
        tree.put(b"consensus-1", Some(b"h1".to_vec())).unwrap();
        tree.flush_overlay().unwrap();

        tree.begin_execution(2);
        tree.put(b"ack-2", Some(b"ack".to_vec())).unwrap();
        let original_root = tree.root().unwrap();
        tree.flush_overlay().unwrap();

        tree.begin_execution(2);
        tree.put(b"ack-2", Some(b"ack".to_vec())).unwrap();
        let reverify_root = tree.root().unwrap();

        assert_eq!(original_root.0, reverify_root.0);

        let ver_before = tree.version();
        tree.flush_overlay().unwrap();
        assert_eq!(tree.version(), ver_before);
    }

    #[test]
    fn root_deterministic_across_repeated_executions() {
        let dir = TempDir::new().unwrap();
        let mut tree = open_tree(&dir);

        tree.begin_execution(1);
        tree.put(b"consensus-1", Some(b"h1".to_vec())).unwrap();
        tree.flush_overlay().unwrap();

        tree.begin_execution(2);
        tree.put(b"consensus-2", Some(b"h2".to_vec())).unwrap();
        tree.commit(vec![(b"data".to_vec(), Some(b"val".to_vec()))])
            .unwrap();
        let root_build1 = tree.root().unwrap();

        tree.begin_execution(2);
        tree.put(b"consensus-2", Some(b"h2".to_vec())).unwrap();
        tree.commit(vec![(b"data".to_vec(), Some(b"val".to_vec()))])
            .unwrap();
        let root_build2 = tree.root().unwrap();

        assert_eq!(root_build1.0, root_build2.0);
    }

    #[test]
    fn nullified_proposal_does_not_corrupt_state() {
        let d1 = TempDir::new().unwrap();
        let d2 = TempDir::new().unwrap();
        let mut proposer = open_tree(&d1);
        let mut verifier = open_tree(&d2);

        proposer.begin_execution(1);
        proposer.put(b"host/cs/1", Some(b"cs1".to_vec())).unwrap();
        proposer.flush_overlay().unwrap();

        verifier.begin_execution(1);
        verifier.put(b"host/cs/1", Some(b"cs1".to_vec())).unwrap();
        verifier.flush_overlay().unwrap();

        proposer.begin_execution(2);
        proposer
            .put(b"host/cs/2", Some(b"ts-100".to_vec()))
            .unwrap();
        let proposer_root_h2 = proposer.root().unwrap();
        proposer.flush_overlay().unwrap();

        verifier.begin_execution(2);
        verifier
            .put(b"host/cs/2", Some(b"ts-999".to_vec()))
            .unwrap();
        verifier.flush_overlay().unwrap();

        verifier.begin_execution(2);
        verifier
            .put(b"host/cs/2", Some(b"ts-100".to_vec()))
            .unwrap();
        let verifier_root_h2 = verifier.root().unwrap();
        verifier.flush_overlay().unwrap();

        assert_eq!(proposer_root_h2.0, verifier_root_h2.0);
    }

    #[test]
    fn view_change_with_disjoint_keys_root_matches() {
        let d_proposer = TempDir::new().unwrap();
        let d_verifier = TempDir::new().unwrap();
        let mut proposer = open_tree(&d_proposer);
        let mut verifier = open_tree(&d_verifier);

        for h in 1..=5 {
            proposer.begin_execution(h);
            proposer
                .put(
                    format!("host/cs/{h}").as_bytes(),
                    Some(format!("cs{h}").into_bytes()),
                )
                .unwrap();
            proposer.flush_overlay().unwrap();

            verifier.begin_execution(h);
            verifier
                .put(
                    format!("host/cs/{h}").as_bytes(),
                    Some(format!("cs{h}").into_bytes()),
                )
                .unwrap();
            verifier.flush_overlay().unwrap();
        }

        proposer.begin_execution(6);
        proposer
            .put(b"host/cs/6", Some(b"cs6-ts200".to_vec()))
            .unwrap();
        let proposer_root_h6 = proposer.root().unwrap();
        proposer.flush_overlay().unwrap();

        verifier.begin_execution(6);
        verifier
            .put(b"host/cs/6", Some(b"cs6-ts100".to_vec()))
            .unwrap();
        verifier
            .put(
                b"clients/07-tendermint-0/clientState",
                Some(b"client-state-data".to_vec()),
            )
            .unwrap();
        verifier.flush_overlay().unwrap();

        verifier.begin_execution(6);
        verifier
            .put(b"host/cs/6", Some(b"cs6-ts200".to_vec()))
            .unwrap();
        let verifier_root_h6 = verifier.root().unwrap();
        verifier.flush_overlay().unwrap();

        assert_eq!(
            proposer_root_h6.0, verifier_root_h6.0,
            "winning proposal root must match regardless of prior superseded flushes"
        );

        // raw_kv must not contain superseded proposal's keys (critical for startup loading).
        let all = verifier.load_all().unwrap();
        let keys: Vec<&[u8]> = all.iter().map(|(k, _)| k.as_slice()).collect();
        assert!(
            !keys.contains(&b"clients/07-tendermint-0/clientState".as_slice()),
            "superseded proposal's client keys must not leak into raw_kv"
        );
    }

    #[test]
    fn discard_overlay_does_not_persist() {
        let dir = TempDir::new().unwrap();
        let mut tree = open_tree(&dir);

        tree.begin_execution(1);
        tree.put(b"cs/1", Some(b"h1".to_vec())).unwrap();
        tree.flush_overlay().unwrap();

        tree.begin_execution(2);
        tree.put(b"cs/2", Some(b"wrong".to_vec())).unwrap();
        tree.discard_overlay();

        assert!(tree.get(b"cs/2").unwrap().is_none());
        assert_eq!(tree.get(b"cs/1").unwrap(), Some(b"h1".to_vec()));

        let all = tree.load_all().unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn persistence_across_reopen() {
        let dir = TempDir::new().unwrap();
        let root_at_close;
        {
            let mut tree = open_tree(&dir);
            tree.put(b"key-a", Some(b"val-a".to_vec())).unwrap();
            tree.put(b"key-b", Some(b"val-b".to_vec())).unwrap();
            root_at_close = tree.root().unwrap();
        }
        let tree = ModuleStateTree::open(dir.path().join("db")).unwrap();
        assert_eq!(tree.version(), 2);
        assert_eq!(tree.get(b"key-a").unwrap(), Some(b"val-a".to_vec()));
        assert_eq!(tree.get(b"key-b").unwrap(), Some(b"val-b".to_vec()));
        assert_eq!(tree.root().unwrap().0, root_at_close.0);
    }
}
