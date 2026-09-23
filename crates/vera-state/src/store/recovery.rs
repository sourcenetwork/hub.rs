use super::*;
use borsh::{BorshDeserialize, BorshSerialize};

pub(super) const UNDO_PREFIX: &[u8] = b"\x00__undo__";

#[derive(BorshSerialize, BorshDeserialize)]
struct Undo {
    height: u64,
    version: u64,
    values: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    nodes: Vec<NodeKey>,
    value_keys: Vec<(Version, KeyHash)>,
}

pub(super) fn height_key(prefix: &[u8], height: u64) -> Vec<u8> {
    [prefix, &height.to_be_bytes()].concat()
}

impl JmtStore {
    pub(super) fn append_undo(
        &self,
        batch: &mut rocksdb::WriteBatch,
        height: u64,
        nodes: &NodeBatch,
        entries: &[(Vec<u8>, Option<Vec<u8>>)],
    ) -> Result<()> {
        let previous_height = self.read_canonical_height()?.unwrap_or(0);
        if height <= previous_height {
            return Ok(());
        }
        let values = entries
            .iter()
            .map(|(key, _)| Ok((key.clone(), self.get_raw(CF_RAW_KV, key)?)))
            .collect::<Result<Vec<_>>>()?;
        let undo = Undo {
            height: previous_height,
            version: self.read_canonical_version()?.unwrap_or(0),
            values,
            nodes: nodes.nodes().keys().cloned().collect(),
            value_keys: nodes.values().keys().copied().collect(),
        };
        let cf = self.db.cf_handle(CF_RAW_KV).context("missing raw_kv CF")?;
        batch.put_cf(
            &cf,
            height_key(HEIGHT_PREFIX, previous_height),
            undo.version.to_be_bytes(),
        );
        batch.put_cf(&cf, height_key(UNDO_PREFIX, height), borsh::to_vec(&undo)?);
        Ok(())
    }

    pub(crate) fn rewind_revision(&self, height: u64, target: u64) -> Result<(u64, u64)> {
        anyhow::ensure!(
            self.read_canonical_height()? == Some(height),
            "rewind height does not match stored revision"
        );
        let key = height_key(UNDO_PREFIX, height);
        let bytes = self
            .get_raw(CF_RAW_KV, &key)?
            .context("required undo revision is not retained")?;
        let undo = Undo::try_from_slice(&bytes).context("corrupt undo revision")?;
        anyhow::ensure!(
            undo.height >= target && undo.height < height,
            "undo revision does not reach requested height"
        );
        let raw = self.db.cf_handle(CF_RAW_KV).context("missing raw_kv CF")?;
        let nodes = self
            .db
            .cf_handle(CF_NODES)
            .context("missing jmt_nodes CF")?;
        let values = self
            .db
            .cf_handle(CF_VALUES)
            .context("missing jmt_values CF")?;
        let mut batch = rocksdb::WriteBatch::default();
        for (key, value) in undo.values {
            match value {
                Some(value) => batch.put_cf(&raw, key, value),
                None => batch.delete_cf(&raw, key),
            }
        }
        for key in undo.nodes {
            batch.delete_cf(&nodes, borsh::to_vec(&key)?);
        }
        for (version, hash) in undo.value_keys {
            batch.delete_cf(&values, value_key(version, hash));
        }
        batch.put_cf(&raw, META_VERSION_KEY, undo.version.to_be_bytes());
        batch.put_cf(&raw, META_HEIGHT_KEY, undo.height.to_be_bytes());
        batch.delete_cf(&raw, height_key(HEIGHT_PREFIX, height));
        batch.delete_cf(&raw, key);
        let mut options = rocksdb::WriteOptions::default();
        options.set_sync(true);
        self.db
            .write_opt(batch, &options)
            .context("rocksdb rewind write failed")?;
        *self.rightmost_leaf_cache.lock().unwrap() = None;
        Ok((undo.height, undo.version))
    }
}
