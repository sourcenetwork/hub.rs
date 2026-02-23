//! RocksDB-backed JMT store with four column families.

use std::path::Path;

use anyhow::{Context, Result};
use borsh::BorshDeserialize;
use jmt::{
    KeyHash, OwnedValue, Version,
    storage::{HasPreimage, LeafNode, Node, NodeBatch, NodeKey, TreeReader, TreeWriter},
};
use rocksdb::{ColumnFamilyDescriptor, DB, Options};

const CF_NODES: &str = "jmt_nodes";
const CF_VALUES: &str = "jmt_values";
const CF_PREIMAGES: &str = "jmt_preimages";
const CF_RAW_KV: &str = "raw_kv";

/// RocksDB-backed JMT store with four column families:
/// - `jmt_nodes`: `Borsh<NodeKey> -> Borsh<Node>`
/// - `jmt_values`: `KeyHash (32B) ++ Version (8B BE) -> Borsh<Option<OwnedValue>>`
/// - `jmt_preimages`: `KeyHash (32B) -> raw key bytes`
/// - `raw_kv`: `raw key bytes -> raw value bytes` (sorted, for startup load + prefix iteration)
pub struct JmtStore {
    db: DB,
}

impl std::fmt::Debug for JmtStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JmtStore").finish_non_exhaustive()
    }
}

impl JmtStore {
    /// Opens (or creates) the store at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_opts = Options::default();
        let cfs = [CF_NODES, CF_VALUES, CF_PREIMAGES, CF_RAW_KV]
            .into_iter()
            .map(|name| ColumnFamilyDescriptor::new(name, cf_opts.clone()));

        let db = DB::open_cf_descriptors(&opts, path, cfs).context("failed to open JmtStore")?;
        Ok(Self { db })
    }

    fn get_raw(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let handle = self
            .db
            .cf_handle(cf)
            .with_context(|| format!("missing column family: {cf}"))?;
        self.db
            .get_cf(&handle, key)
            .with_context(|| format!("rocksdb get failed in {cf}"))
    }

    /// Iterate all entries in the `raw_kv` column family.
    pub fn raw_kv_iter(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let handle = self
            .db
            .cf_handle(CF_RAW_KV)
            .context("missing raw_kv column family")?;
        let iter = self.db.iterator_cf(&handle, rocksdb::IteratorMode::Start);
        let mut result = Vec::new();
        for item in iter {
            let (k, v) = item.context("rocksdb iterator error in raw_kv")?;
            result.push((k.to_vec(), v.to_vec()));
        }
        Ok(result)
    }

    /// Atomically write a batch of operations to the `raw_kv` column family.
    ///
    /// Each entry is `(key, Option<value>)` — `None` means delete.
    pub fn raw_kv_write_batch(&self, ops: &[(Vec<u8>, Option<Vec<u8>>)]) -> Result<()> {
        let handle = self.db.cf_handle(CF_RAW_KV).context("missing raw_kv CF")?;
        let mut batch = rocksdb::WriteBatch::default();
        for (key, value) in ops {
            match value {
                Some(v) => batch.put_cf(&handle, key, v),
                None => batch.delete_cf(&handle, key),
            }
        }
        self.db
            .write(batch)
            .context("rocksdb raw_kv batch write failed")
    }
}

impl TreeReader for JmtStore {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        let key_bytes = borsh::to_vec(node_key)?;
        match self.get_raw(CF_NODES, &key_bytes)? {
            Some(bytes) => Ok(Some(Node::try_from_slice(&bytes)?)),
            None => Ok(None),
        }
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        let handle = self
            .db
            .cf_handle(CF_NODES)
            .context("missing jmt_nodes column family")?;
        let mut result: Option<(NodeKey, LeafNode)> = None;

        let iter = self.db.iterator_cf(&handle, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key_bytes, val_bytes) = item.context("rocksdb iterator error")?;
            let node = Node::try_from_slice(&val_bytes)?;
            if let Node::Leaf(leaf) = node {
                let node_key = NodeKey::try_from_slice(&key_bytes)?;
                if result.is_none() || leaf.key_hash() > result.as_ref().unwrap().1.key_hash() {
                    result = Some((node_key, leaf));
                }
            }
        }
        Ok(result)
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        let handle = self
            .db
            .cf_handle(CF_VALUES)
            .context("missing jmt_values column family")?;

        let seek_key = value_key(max_version, key_hash);
        let iter = self.db.iterator_cf(
            &handle,
            rocksdb::IteratorMode::From(&seek_key, rocksdb::Direction::Reverse),
        );

        let prefix = &key_hash.0;
        for item in iter {
            let (k, v) = item.context("rocksdb iterator error")?;
            if k.len() < 40 || &k[..32] != prefix {
                break;
            }
            let stored_version = u64::from_be_bytes(
                k[32..40]
                    .try_into()
                    .context("corrupt value key: expected 8-byte version suffix")?,
            );
            if stored_version <= max_version {
                let value: Option<OwnedValue> = BorshDeserialize::deserialize(&mut &v[..])
                    .with_context(|| {
                        format!("corrupt value at version {stored_version} in {CF_VALUES}")
                    })?;
                return Ok(value);
            }
        }
        Ok(None)
    }
}

impl TreeWriter for JmtStore {
    fn write_node_batch(&self, node_batch: &NodeBatch) -> Result<()> {
        self.write_batch(node_batch, &[])
    }
}

impl HasPreimage for JmtStore {
    fn preimage(&self, key_hash: KeyHash) -> Result<Option<Vec<u8>>> {
        self.get_raw(CF_PREIMAGES, &key_hash.0)
    }
}

impl JmtStore {
    /// Atomically writes JMT nodes, values, and preimages in a single RocksDB batch.
    pub(crate) fn write_batch(
        &self,
        node_batch: &NodeBatch,
        preimages: &[(KeyHash, &[u8])],
    ) -> Result<()> {
        let nodes_cf = self
            .db
            .cf_handle(CF_NODES)
            .context("missing jmt_nodes CF")?;
        let values_cf = self
            .db
            .cf_handle(CF_VALUES)
            .context("missing jmt_values CF")?;
        let preimages_cf = self
            .db
            .cf_handle(CF_PREIMAGES)
            .context("missing jmt_preimages CF")?;

        let mut batch = rocksdb::WriteBatch::default();
        for (key_hash, preimage) in preimages {
            batch.put_cf(&preimages_cf, key_hash.0, preimage);
        }
        for (node_key, node) in node_batch.nodes() {
            let key_bytes = borsh::to_vec(node_key).context("failed to serialize JMT node key")?;
            let val_bytes = borsh::to_vec(node).context("failed to serialize JMT node")?;
            batch.put_cf(&nodes_cf, key_bytes, val_bytes);
        }
        for ((version, key_hash), value) in node_batch.values() {
            let val_bytes = borsh::to_vec(value).context("failed to serialize JMT value")?;
            batch.put_cf(&values_cf, value_key(*version, *key_hash), val_bytes);
        }
        self.db.write(batch).context("rocksdb batch write failed")
    }
}

/// Encodes a value-table key as `key_hash (32B) ++ version (8B big-endian)`.
fn value_key(version: Version, key_hash: KeyHash) -> [u8; 40] {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(&key_hash.0);
    buf[32..].copy_from_slice(&version.to_be_bytes());
    buf
}
