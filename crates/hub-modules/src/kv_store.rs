//! Module-level KV store trait and in-memory implementation.

use std::collections::BTreeMap;

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
#[derive(Clone, Debug, Default)]
pub struct InMemoryKvStore {
    data: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl InMemoryKvStore {
    /// Serialize the entire store contents to a Borsh byte vector.
    pub fn serialize(&self) -> Vec<u8> {
        borsh::to_vec(&self.data).expect("BTreeMap serialization cannot fail")
    }

    /// Reconstruct a store from Borsh-serialized bytes.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, borsh::io::Error> {
        let data: BTreeMap<Vec<u8>, Vec<u8>> = borsh::from_slice(bytes)?;
        Ok(Self { data })
    }

    /// Check whether the store contains any entries.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl ModuleKvStore for InMemoryKvStore {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.data.get(key).cloned()
    }

    fn put(&mut self, key: &[u8], value: Vec<u8>) {
        self.data.insert(key.to_vec(), value);
    }

    fn delete(&mut self, key: &[u8]) {
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
}
