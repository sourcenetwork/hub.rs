use std::sync::Arc;

use anyhow::{Result, bail};
use jmt::{
    KeyHash, OwnedValue, RootHash, Sha256Jmt, Version,
    storage::{LeafNode, Node, NodeBatch, NodeKey, TreeReader},
};
use sha2::Sha256;

use crate::store::JmtStore;

pub(crate) type Entries = Vec<(Vec<u8>, Option<Vec<u8>>)>;

#[derive(Debug)]
pub(crate) struct Update {
    pub parent_version: u64,
    pub parent_root: RootHash,
    pub version: u64,
    pub root: RootHash,
    pub entries: Entries,
    pub nodes: NodeBatch,
}

/// An immutable tree view with branch-local updates above a committed version.
#[derive(Clone, Debug)]
pub struct TreeSnapshot {
    pub(crate) store: Arc<JmtStore>,
    pub(crate) base_version: u64,
    pub(crate) version: u64,
    pub(crate) root: RootHash,
    pub(crate) pending: Vec<Arc<Update>>,
}

impl TreeSnapshot {
    /// Root authenticated by this view.
    pub const fn root(&self) -> RootHash {
        self.root
    }

    /// Read a value from this branch, including pending writes and deletions.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.version == 0 {
            return Ok(None);
        }
        Sha256Jmt::new(self).get(KeyHash::with::<Sha256>(key), self.version)
    }

    pub(crate) fn prepare(mut self, entries: Entries) -> Result<Self> {
        if entries.is_empty() {
            return Ok(self);
        }
        let version = self
            .version
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("tree version exhausted"))?;
        let values = entries
            .iter()
            .map(|(key, value)| (KeyHash::with::<Sha256>(key), value.clone()));
        let (root, batch) = Sha256Jmt::new(&self).put_value_set(values, version)?;
        self.pending.push(Arc::new(Update {
            parent_version: self.version,
            parent_root: self.root,
            version,
            root,
            entries,
            nodes: batch.node_batch,
        }));
        self.version = version;
        self.root = root;
        Ok(self)
    }

    pub(crate) fn rebase(&mut self, version: u64, root: RootHash) {
        if self
            .pending
            .iter()
            .any(|update| update.version == version && update.root == root)
        {
            self.pending.retain(|update| update.version > version);
            self.base_version = version;
        }
    }
}

impl TreeReader for TreeSnapshot {
    fn get_node_option(&self, key: &NodeKey) -> Result<Option<Node>> {
        for update in self.pending.iter().rev() {
            if let Some(node) = update.nodes.get_node(key) {
                return Ok(Some(node.clone()));
            }
        }
        if key.version() > self.base_version {
            return Ok(None);
        }
        self.store.get_node_option(key)
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        for update in self.pending.iter().rev() {
            if update.version <= max_version
                && let Some(value) = update.nodes.values().get(&(update.version, key_hash))
            {
                return Ok(value.clone());
            }
        }
        if self.base_version == 0 {
            return Ok(None);
        }
        self.store
            .get_value_option(max_version.min(self.base_version), key_hash)
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        bail!("pending tree views cannot be used for tree restoration")
    }
}
