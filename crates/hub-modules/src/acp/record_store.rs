//! Fallible record access for permission evaluation and proof-backed readers.

use zanzibar::error::{Error, Result};

use crate::kv_store::ModuleKvStore;

/// Record access used by the shared permission evaluator.
///
/// A missing proof must return an error, not `None` or an empty scan. Successful
/// scans must contain every record under the prefix, in key order. Readers
/// reject writes unless they explicitly implement the mutation methods.
pub trait RecordStore: Send + Sync {
    /// Read a record, distinguishing proven absence from unavailable data.
    fn read_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Read the complete ordered set of records under a prefix.
    fn scan_records(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>>;

    /// Write a record when this store supports mutation.
    fn write_record(&mut self, _key: &[u8], _value: Vec<u8>) -> Result<()> {
        Err(Error::Serialization("record store is read-only".into()))
    }

    /// Remove a record when this store supports mutation.
    fn remove_record(&mut self, _key: &[u8]) -> Result<()> {
        Err(Error::Serialization("record store is read-only".into()))
    }
}

impl<S: ModuleKvStore> RecordStore for S {
    fn read_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.get(key))
    }

    fn scan_records(&self, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        Ok(self.prefix_scan(prefix))
    }

    fn write_record(&mut self, key: &[u8], value: Vec<u8>) -> Result<()> {
        self.put(key, value);
        Ok(())
    }

    fn remove_record(&mut self, key: &[u8]) -> Result<()> {
        self.delete(key);
        Ok(())
    }
}
