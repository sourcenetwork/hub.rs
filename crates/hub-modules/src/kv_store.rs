//! Module-level KV store trait and in-memory implementation.

use std::collections::{BTreeMap, HashSet};

/// Key-value store abstraction for module state.
///
/// Each module holds a single `impl ModuleKvStore` instead of raw `HashMap`s.
/// The `InMemoryKvStore` implementation wraps a `BTreeMap` so that
/// `prefix_scan` returns keys in sorted order (enabling efficient
/// sub-prefix iteration).
pub trait ModuleKvStore: Clone + std::fmt::Debug + Default + Send + Sync {
    /// Read a value by key.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;

    /// Write a key-value pair.
    fn put(&mut self, key: &[u8], value: Vec<u8>);

    /// Delete a key.
    fn delete(&mut self, key: &[u8]);

    /// Return all key-value pairs whose key starts with `prefix`, in sorted order.
    fn prefix_scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)>;

    /// Check whether a key exists.
    fn has(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }
}

/// `BTreeMap`-backed in-memory KV store.
///
/// Tracks dirty keys modified since the last `reset_dirty()` call (or clone).
/// Cloning produces a copy with an empty dirty set — execution isolation
/// starts from a clean slate so only that execution's mutations are captured.
#[derive(Debug, Default)]
pub struct InMemoryKvStore {
    data: BTreeMap<Vec<u8>, Vec<u8>>,
    dirty: HashSet<Vec<u8>>,
}

impl Clone for InMemoryKvStore {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            dirty: HashSet::new(),
        }
    }
}

impl InMemoryKvStore {
    /// Construct a store from raw key-value pairs (e.g. loaded from RocksDB raw_kv CF).
    pub fn from_pairs(pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Self {
        Self {
            data: pairs.into_iter().collect(),
            dirty: HashSet::new(),
        }
    }

    /// Serialize the entire store contents to a Borsh byte vector.
    pub fn serialize(&self) -> Vec<u8> {
        borsh::to_vec(&self.data).expect("BTreeMap serialization cannot fail")
    }

    /// Reconstruct a store from Borsh-serialized bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, borsh::io::Error> {
        let data: BTreeMap<Vec<u8>, Vec<u8>> = borsh::from_slice(bytes)?;
        Ok(Self {
            data,
            dirty: HashSet::new(),
        })
    }

    /// Check whether the store contains any entries.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns each dirty key and its current value (`None` if deleted).
    pub fn dirty_entries(&self) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        self.dirty
            .iter()
            .map(|k| {
                let val = self.data.get(k).cloned();
                (k.clone(), val)
            })
            .collect()
    }

    /// Clear the dirty set.
    pub fn reset_dirty(&mut self) {
        self.dirty.clear();
    }

    /// Compute the diff between `self` and `base`, returning all changed/added/deleted keys.
    ///
    /// Each entry is `(key, Some(value))` for additions/updates, `(key, None)` for deletions.
    /// This captures ALL mutations regardless of clone boundaries, making it safe to use
    /// when intermediate clones reset the dirty set (e.g. the precompile clone path).
    pub fn diff_from(&self, base: &Self) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        let mut changes = Vec::new();
        for (k, v) in &self.data {
            if base.data.get(k) != Some(v) {
                changes.push((k.clone(), Some(v.clone())));
            }
        }
        for k in base.data.keys() {
            if !self.data.contains_key(k) {
                changes.push((k.clone(), None));
            }
        }
        changes
    }
}

impl ModuleKvStore for InMemoryKvStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.data.get(key).cloned()
    }

    fn put(&mut self, key: &[u8], value: Vec<u8>) {
        self.dirty.insert(key.to_vec());
        self.data.insert(key.to_vec(), value);
    }

    fn delete(&mut self, key: &[u8]) {
        self.dirty.insert(key.to_vec());
        self.data.remove(key);
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.data
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_and_get() {
        let mut store = InMemoryKvStore::default();
        store.put(b"key1", b"val1".to_vec());
        assert_eq!(store.get(b"key1").unwrap(), b"val1");
    }

    #[test]
    fn get_missing() {
        let store = InMemoryKvStore::default();
        assert!(store.get(b"missing").is_none());
    }

    #[test]
    fn delete_key() {
        let mut store = InMemoryKvStore::default();
        store.put(b"key1", b"val1".to_vec());
        store.delete(b"key1");
        assert!(store.get(b"key1").is_none());
    }

    #[test]
    fn has_key() {
        let mut store = InMemoryKvStore::default();
        assert!(!store.has(b"key1"));
        store.put(b"key1", b"val1".to_vec());
        assert!(store.has(b"key1"));
    }

    #[test]
    fn prefix_scan_returns_sorted() {
        let mut store = InMemoryKvStore::default();
        store.put(b"acp/policy/2", b"p2".to_vec());
        store.put(b"acp/policy/1", b"p1".to_vec());
        store.put(b"acp/other/x", b"ox".to_vec());
        store.put(b"bulletin/ns/1", b"ns1".to_vec());

        let results = store.prefix_scan(b"acp/policy/");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, b"acp/policy/1");
        assert_eq!(results[1].0, b"acp/policy/2");
    }

    #[test]
    fn prefix_scan_empty() {
        let store = InMemoryKvStore::default();
        assert!(store.prefix_scan(b"any/").is_empty());
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let mut store = InMemoryKvStore::default();
        store.put(b"key1", b"val1".to_vec());
        store.put(b"key2", b"val2".to_vec());

        let bytes = store.serialize();
        let restored = InMemoryKvStore::deserialize(&bytes).unwrap();

        assert_eq!(restored.get(b"key1").unwrap(), b"val1");
        assert_eq!(restored.get(b"key2").unwrap(), b"val2");
    }

    #[test]
    fn serialize_empty_store() {
        let store = InMemoryKvStore::default();
        assert!(store.is_empty());
        let bytes = store.serialize();
        let restored = InMemoryKvStore::deserialize(&bytes).unwrap();
        assert!(restored.is_empty());
    }

    #[test]
    fn clone_isolation() {
        let mut store = InMemoryKvStore::default();
        store.put(b"key", b"val".to_vec());
        let mut fork = store.clone();
        fork.put(b"key", b"new".to_vec());
        assert_eq!(store.get(b"key").unwrap(), b"val");
        assert_eq!(fork.get(b"key").unwrap(), b"new");
    }

    #[test]
    fn dirty_tracks_puts() {
        let mut store = InMemoryKvStore::default();
        store.put(b"a", b"1".to_vec());
        store.put(b"b", b"2".to_vec());
        let dirty = store.dirty_entries();
        assert_eq!(dirty.len(), 2);
        assert!(
            dirty
                .iter()
                .any(|(k, v)| k == b"a" && v.as_deref() == Some(b"1".as_slice()))
        );
        assert!(
            dirty
                .iter()
                .any(|(k, v)| k == b"b" && v.as_deref() == Some(b"2".as_slice()))
        );
    }

    #[test]
    fn dirty_tracks_deletes() {
        let mut store = InMemoryKvStore::default();
        store.put(b"key", b"val".to_vec());
        store.reset_dirty();
        store.delete(b"key");
        let dirty = store.dirty_entries();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0], (b"key".to_vec(), None));
    }

    #[test]
    fn clone_resets_dirty() {
        let mut store = InMemoryKvStore::default();
        store.put(b"key", b"val".to_vec());
        assert!(!store.dirty_entries().is_empty());
        let fork = store.clone();
        assert!(fork.dirty_entries().is_empty());
        assert_eq!(fork.get(b"key").unwrap(), b"val");
    }

    #[test]
    fn reset_dirty_clears() {
        let mut store = InMemoryKvStore::default();
        store.put(b"a", b"1".to_vec());
        store.put(b"b", b"2".to_vec());
        assert_eq!(store.dirty_entries().len(), 2);
        store.reset_dirty();
        assert!(store.dirty_entries().is_empty());
        assert_eq!(store.get(b"a").unwrap(), b"1");
    }

    #[test]
    fn diff_from_captures_adds_updates_deletes() {
        let mut base = InMemoryKvStore::default();
        base.put(b"keep", b"same".to_vec());
        base.put(b"update", b"old".to_vec());
        base.put(b"delete", b"gone".to_vec());

        let mut current = base.clone();
        current.put(b"update", b"new".to_vec());
        current.delete(b"delete");
        current.put(b"add", b"fresh".to_vec());

        let diff = current.diff_from(&base);
        assert_eq!(diff.len(), 3);
        assert!(
            diff.iter()
                .any(|(k, v)| k == b"update" && v.as_deref() == Some(b"new".as_slice()))
        );
        assert!(diff.iter().any(|(k, v)| k == b"delete" && v.is_none()));
        assert!(
            diff.iter()
                .any(|(k, v)| k == b"add" && v.as_deref() == Some(b"fresh".as_slice()))
        );
    }

    #[test]
    fn from_pairs_no_dirty() {
        let store = InMemoryKvStore::from_pairs(vec![
            (b"k1".to_vec(), b"v1".to_vec()),
            (b"k2".to_vec(), b"v2".to_vec()),
        ]);
        assert!(store.dirty_entries().is_empty());
        assert_eq!(store.get(b"k1").unwrap(), b"v1");
        assert_eq!(store.get(b"k2").unwrap(), b"v2");
    }
}
