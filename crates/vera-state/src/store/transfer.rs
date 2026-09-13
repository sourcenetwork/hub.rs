use super::*;
use anyhow::ensure;

const RESTORE_KEY: &[u8] = b"\0__restore_in_progress__";

impl JmtStore {
    pub(crate) fn restore_in_progress(&self) -> Result<bool> {
        Ok(self.get_raw(CF_RAW_KV, RESTORE_KEY)?.is_some())
    }

    pub(crate) fn begin_restore(&self) -> Result<()> {
        let cf = self.db.cf_handle(CF_RAW_KV).context("missing raw_kv CF")?;
        let mut options = rocksdb::WriteOptions::default();
        options.set_sync(true);
        self.db.put_cf_opt(&cf, RESTORE_KEY, [], &options)?;
        Ok(())
    }

    pub(crate) fn restore_entries(&self, entries: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
        let raw = self.db.cf_handle(CF_RAW_KV).context("missing raw_kv CF")?;
        let preimages = self
            .db
            .cf_handle(CF_PREIMAGES)
            .context("missing preimages CF")?;
        let mut batch = rocksdb::WriteBatch::default();
        for (key, value) in entries {
            ensure!(
                key != META_VERSION_KEY
                    && key != META_HEIGHT_KEY
                    && key != RESTORE_KEY
                    && !key.starts_with(HEIGHT_PREFIX)
                    && !key.starts_with(UNDO_PREFIX),
                "snapshot record collides with local store metadata"
            );
            batch.put_cf(&raw, key, value);
            batch.put_cf(&preimages, KeyHash::with::<sha2::Sha256>(key).0, key);
        }
        self.db.write(batch)?;
        Ok(())
    }

    pub(crate) fn finish_restore(&self, version: u64, height: u64) -> Result<()> {
        let cf = self.db.cf_handle(CF_RAW_KV).context("missing raw_kv CF")?;
        let mut batch = rocksdb::WriteBatch::default();
        batch.put_cf(&cf, META_VERSION_KEY, version.to_be_bytes());
        batch.put_cf(&cf, META_HEIGHT_KEY, height.to_be_bytes());
        batch.put_cf(
            &cf,
            height_key(HEIGHT_PREFIX, height),
            version.to_be_bytes(),
        );
        batch.delete_cf(&cf, RESTORE_KEY);
        let mut options = rocksdb::WriteOptions::default();
        options.set_sync(true);
        self.db.write_opt(batch, &options)?;
        Ok(())
    }
}
