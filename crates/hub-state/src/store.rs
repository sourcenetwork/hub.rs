//! RocksDB-backed JMT store with four column families.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

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

/// Well-known key in `raw_kv` for persisting the canonical JMT version.
/// Starts with a null byte so it sorts before any module data key.
const META_VERSION_KEY: &[u8] = b"\x00__canonical_version__";

/// Well-known key in `raw_kv` for persisting the canonical height.
const META_HEIGHT_KEY: &[u8] = b"\x00__canonical_height__";
const HEIGHT_PREFIX: &[u8] = b"\x00__height_version__";

/// RocksDB-backed JMT store with four column families:
/// - `jmt_nodes`: `Borsh<NodeKey> -> Borsh<Node>`
/// - `jmt_values`: `KeyHash (32B) ++ Version (8B BE) -> Borsh<Option<OwnedValue>>`
/// - `jmt_preimages`: `KeyHash (32B) -> raw key bytes`
/// - `raw_kv`: `raw key bytes -> raw value bytes` (sorted, for startup load + prefix iteration)
pub struct JmtStore {
    db: DB,
    /// Cached rightmost leaf node. `None` outer = not yet populated.
    rightmost_leaf_cache: Mutex<Option<Option<(NodeKey, LeafNode)>>>,
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
        Ok(Self {
            db,
            rightmost_leaf_cache: Mutex::new(None),
        })
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

    /// Iterate all entries in the `raw_kv` column family, excluding metadata keys.
    pub fn raw_kv_iter(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let handle = self
            .db
            .cf_handle(CF_RAW_KV)
            .context("missing raw_kv column family")?;
        let iter = self.db.iterator_cf(&handle, rocksdb::IteratorMode::Start);
        let mut result = Vec::new();
        for item in iter {
            let (k, v) = item.context("rocksdb iterator error in raw_kv")?;
            if k.first() == Some(&0x00) {
                continue;
            }
            result.push((k.to_vec(), v.to_vec()));
        }
        Ok(result)
    }

    /// Read the persisted canonical JMT version from `raw_kv` metadata.
    pub fn read_canonical_version(&self) -> Result<Option<u64>> {
        match self.get_raw(CF_RAW_KV, META_VERSION_KEY)? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("corrupt canonical version metadata"))?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    /// Read the persisted canonical height from `raw_kv` metadata.
    pub fn read_canonical_height(&self) -> Result<Option<u64>> {
        match self.get_raw(CF_RAW_KV, META_HEIGHT_KEY)? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("corrupt canonical height metadata"))?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
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
        let mut cache = self.rightmost_leaf_cache.lock().unwrap();
        if let Some(ref cached) = *cache {
            return Ok(cached.clone());
        }

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
        *cache = Some(result.clone());
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
    pub(crate) fn read_height_versions(&self) -> Result<BTreeMap<u64, u64>> {
        let cf = self.db.cf_handle(CF_RAW_KV).context("missing raw_kv CF")?;
        let mut versions = BTreeMap::new();
        for item in self.db.iterator_cf(
            &cf,
            rocksdb::IteratorMode::From(HEIGHT_PREFIX, rocksdb::Direction::Forward),
        ) {
            let (key, value) = item?;
            let Some(suffix) = key.strip_prefix(HEIGHT_PREFIX) else {
                break;
            };
            let height = u64::from_be_bytes(suffix.try_into().context("corrupt height key")?);
            let version = u64::from_be_bytes(
                value
                    .as_ref()
                    .try_into()
                    .context("corrupt height version")?,
            );
            versions.insert(height, version);
        }
        Ok(versions)
    }

    pub(crate) fn write_revision(
        &self,
        nodes: &NodeBatch,
        entries: &[(Vec<u8>, Option<Vec<u8>>)],
        version: u64,
        height: u64,
        retain_from: u64,
    ) -> Result<()> {
        let preimages: Vec<_> = entries
            .iter()
            .map(|(key, _)| (KeyHash::with::<sha2::Sha256>(key), key.as_slice()))
            .collect();
        let mut batch = rocksdb::WriteBatch::default();
        self.append_nodes(&mut batch, nodes, &preimages)?;
        let cf = self.db.cf_handle(CF_RAW_KV).context("missing raw_kv CF")?;
        for (key, value) in entries {
            match value {
                Some(value) => batch.put_cf(&cf, key, value),
                None => batch.delete_cf(&cf, key),
            }
        }
        batch.put_cf(&cf, META_VERSION_KEY, version.to_be_bytes());
        batch.put_cf(&cf, META_HEIGHT_KEY, height.to_be_bytes());
        let height_key = |h: u64| [HEIGHT_PREFIX, &h.to_be_bytes()].concat();
        batch.put_cf(&cf, height_key(height), version.to_be_bytes());
        if retain_from > 0 {
            batch.delete_range_cf(&cf, height_key(0), height_key(retain_from));
        }
        let mut options = rocksdb::WriteOptions::default();
        options.set_sync(true);
        self.db
            .write_opt(batch, &options)
            .context("rocksdb revision write failed")?;
        *self.rightmost_leaf_cache.lock().unwrap() = None;
        Ok(())
    }

    /// Atomically writes JMT nodes, values, and preimages in a single RocksDB batch.
    pub(crate) fn write_batch(
        &self,
        node_batch: &NodeBatch,
        preimages: &[(KeyHash, &[u8])],
    ) -> Result<()> {
        let mut batch = rocksdb::WriteBatch::default();
        self.append_nodes(&mut batch, node_batch, preimages)?;
        self.db.write(batch).context("rocksdb batch write failed")?;
        *self.rightmost_leaf_cache.lock().unwrap() = None;
        Ok(())
    }

    fn append_nodes(
        &self,
        batch: &mut rocksdb::WriteBatch,
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
        Ok(())
    }
}

/// Encodes a value-table key as `key_hash (32B) ++ version (8B big-endian)`.
fn value_key(version: Version, key_hash: KeyHash) -> [u8; 40] {
    let mut buf = [0u8; 40];
    buf[..32].copy_from_slice(&key_hash.0);
    buf[32..].copy_from_slice(&version.to_be_bytes());
    buf
}
