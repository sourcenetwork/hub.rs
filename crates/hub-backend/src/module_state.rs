//! Module state persistence backed by commonware-storage.

use commonware_codec::RangeCfg;
use commonware_storage::kv::Batchable as _;
use hub_modules::{ModuleState, kv_store::InMemoryKvStore};

use crate::{
    BackendError, QmdbBackendConfig,
    backend::store_config,
    types::{Context, ModuleDb, ModuleKey, StoreSlot},
};

const MODULE_BLOB_MAX_BYTES: usize = 16 * 1024 * 1024;

const ACP_SLOT: ModuleKey = ModuleKey::new([0]);
const BULLETIN_SLOT: ModuleKey = ModuleKey::new([1]);
const HUB_SLOT: ModuleKey = ModuleKey::new([2]);
const NONCE_SLOT: ModuleKey = ModuleKey::new([3]);

const ALL_SLOTS: [ModuleKey; 4] = [ACP_SLOT, BULLETIN_SLOT, HUB_SLOT, NONCE_SLOT];

/// Persistence layer for module state (ACP, Bulletin, Hub, Nonces).
///
/// Each module's `InMemoryKvStore` is Borsh-serialized into a single QMDB
/// entry keyed by a one-byte module index. Loads return `ModuleState::default()`
/// for fresh nodes with no persisted data.
pub struct ModuleStateBackend {
    inner: StoreSlot<ModuleDb>,
}

impl ModuleStateBackend {
    /// Open (or create) the module state partition.
    pub async fn open(context: Context, config: &QmdbBackendConfig) -> Result<Self, BackendError> {
        let var_config = store_config(
            &config.partition_prefix,
            "modules",
            config.page_cache.clone(),
            (RangeCfg::new(0..=MODULE_BLOB_MAX_BYTES), ()),
        );
        let inner = ModuleDb::init(context, var_config)
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        Ok(Self {
            inner: StoreSlot::new(inner),
        })
    }

    /// Load all four module stores from QMDB. Returns `ModuleState::default()`
    /// if no data has been persisted yet (fresh node).
    pub async fn load(&self) -> Result<ModuleState, BackendError> {
        let db = self.inner.get()?;
        let mut blobs: [Option<Vec<u8>>; 4] = [None, None, None, None];
        for (i, slot) in ALL_SLOTS.iter().enumerate() {
            blobs[i] = db
                .get(slot)
                .await
                .map_err(|e| BackendError::Storage(e.to_string()))?;
        }
        let stores = [
            deserialize_or_default(blobs[0].as_deref())?,
            deserialize_or_default(blobs[1].as_deref())?,
            deserialize_or_default(blobs[2].as_deref())?,
            deserialize_or_default(blobs[3].as_deref())?,
        ];
        Ok(ModuleState::from_stores(stores))
    }

    /// Persist all four module stores to QMDB.
    pub async fn save(&mut self, state: &ModuleState) -> Result<(), BackendError> {
        let blobs = state.serialize_stores();
        let ops = ALL_SLOTS
            .iter()
            .zip(blobs)
            .map(|(slot, blob)| (slot.clone(), Some(blob)));
        let inner = self.inner.take()?;
        let mut dirty = inner.into_mutable();
        dirty
            .write_batch(ops)
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        let (committed, _) = dirty
            .commit(None)
            .await
            .map_err(|e| BackendError::Storage(e.to_string()))?;
        let inner = committed.into_merkleized();
        self.inner.restore(inner);
        Ok(())
    }
}

impl std::fmt::Debug for ModuleStateBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModuleStateBackend").finish_non_exhaustive()
    }
}

fn deserialize_or_default(bytes: Option<&[u8]>) -> Result<InMemoryKvStore, BackendError> {
    bytes.map_or_else(
        || Ok(InMemoryKvStore::default()),
        |b| InMemoryKvStore::deserialize(b).map_err(|e| BackendError::Storage(e.to_string())),
    )
}
