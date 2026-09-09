//! In-memory index of the public Commonware artifacts needed by light clients.

use std::collections::{HashMap, VecDeque};

use parking_lot::RwLock;

/// Maximum number of finalizations retained in the hot proof cache.
pub const MAX_CACHED_FINALIZATIONS: usize = 1024;
const MAX_FINALIZATION_PAYLOAD_BYTES: usize = 64 << 20;

#[derive(Debug, Default)]
struct FinalizationCache {
    entries: HashMap<[u8; 32], StoredFinalization>,
    order: VecDeque<[u8; 32]>,
    payload_bytes: usize,
}

/// An encoded Simplex finalization and the epoch whose key verifies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFinalization {
    /// Consensus epoch.
    pub epoch: u64,
    /// Canonical `Finalization<ConsensusScheme, ConsensusDigest>` bytes.
    pub bytes: Vec<u8>,
    /// Canonical Hub block bytes authenticated by this finalization.
    pub block: Vec<u8>,
}

impl StoredFinalization {
    const fn payload_capacity(&self) -> usize {
        self.bytes.capacity().saturating_add(self.block.capacity())
    }
}

/// Canonical public verifier material for one DKG epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEpochMaterial {
    /// Canonical `EpochMaterial<MinSig>` bytes.
    pub bytes: Vec<u8>,
}

/// In-memory index of finalizations and their epoch verifier material.
///
/// Finalizations are keyed by consensus digest (SHA-256 of the EVM block ID),
/// while verifier material is keyed by epoch. Both artifacts are public and
/// can be reconstructed from marshal storage and finalized epoch-boundary
/// blocks after restart. Finalizations are a FIFO cache capped at 1,024 entries
/// and 64 MiB of vector capacity; callers must fall back to durable history on
/// a miss. Epoch verifier material remains retained for historical proofs.
#[derive(Debug, Default)]
pub struct LightBlockIndex {
    finalizations: RwLock<FinalizationCache>,
    epoch_material: RwLock<HashMap<u64, StoredEpochMaterial>>,
}

impl LightBlockIndex {
    /// Create an empty light-block artifact index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Cache an encoded finalization after persisting it in durable history.
    /// Oversized payloads are not retained; older entries may be evicted.
    pub fn insert_finalization(&self, digest: [u8; 32], finalization: StoredFinalization) {
        let bytes = finalization.payload_capacity();
        if bytes > MAX_FINALIZATION_PAYLOAD_BYTES {
            return;
        }
        let mut cache = self.finalizations.write();
        if let Some(previous) = cache.entries.remove(&digest) {
            cache.payload_bytes -= previous.payload_capacity();
            cache.order.retain(|key| key != &digest);
        }
        while cache.entries.len() >= MAX_CACHED_FINALIZATIONS
            || cache.payload_bytes > MAX_FINALIZATION_PAYLOAD_BYTES - bytes
        {
            let oldest = cache.order.pop_front().expect("cache eviction order");
            let removed = cache.entries.remove(&oldest).expect("cached finalization");
            cache.payload_bytes -= removed.payload_capacity();
        }
        cache.payload_bytes += bytes;
        cache.order.push_back(digest);
        cache.entries.insert(digest, finalization);
    }

    /// Retrieve an encoded finalization by proposal payload digest.
    #[must_use]
    pub fn get_finalization(&self, digest: &[u8; 32]) -> Option<StoredFinalization> {
        self.finalizations.read().entries.get(digest).cloned()
    }

    /// Store public verifier material for an epoch.
    pub fn insert_epoch_material(&self, epoch: u64, material: StoredEpochMaterial) {
        self.epoch_material.write().insert(epoch, material);
    }

    /// Retrieve public verifier material for an epoch.
    #[must_use]
    pub fn get_epoch_material(&self, epoch: u64) -> Option<StoredEpochMaterial> {
        self.epoch_material.read().get(&epoch).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get_finalization() {
        let index = LightBlockIndex::new();
        let digest = [0xAA; 32];
        let finalization = StoredFinalization {
            epoch: 7,
            bytes: vec![0x11; 131],
            block: vec![0x33; 256],
        };

        index.insert_finalization(digest, finalization.clone());
        assert_eq!(index.get_finalization(&digest), Some(finalization));
    }

    #[test]
    fn finalization_cache_bounds_capacity_and_replacements() {
        let index = LightBlockIndex::new();
        let entry = |capacity| StoredFinalization {
            epoch: 0,
            bytes: Vec::with_capacity(capacity),
            block: vec![],
        };
        for _ in 0..MAX_CACHED_FINALIZATIONS + 1 {
            index.insert_finalization([1; 32], entry(8));
        }
        {
            let cache = index.finalizations.read();
            assert_eq!(cache.entries.len(), 1);
            assert_eq!(cache.order.len(), 1);
            assert_eq!(cache.payload_bytes, 8);
        }
        index.insert_finalization([1; 32], entry(16));
        assert_eq!(index.finalizations.read().payload_bytes, 16);
        index.insert_finalization([2; 32], entry(MAX_FINALIZATION_PAYLOAD_BYTES));
        assert!(index.get_finalization(&[1; 32]).is_none());
        assert_eq!(
            index.finalizations.read().payload_bytes,
            MAX_FINALIZATION_PAYLOAD_BYTES
        );
        index.insert_finalization([3; 32], entry(1));
        assert!(index.get_finalization(&[2; 32]).is_none());
        index.insert_finalization([4; 32], entry(MAX_FINALIZATION_PAYLOAD_BYTES + 1));
        assert!(index.get_finalization(&[4; 32]).is_none());
        assert!(index.get_finalization(&[3; 32]).is_some());
        assert_eq!(index.finalizations.read().payload_bytes, 1);
        for number in 0..MAX_CACHED_FINALIZATIONS {
            let mut digest = [0; 32];
            digest[..8].copy_from_slice(&(number as u64).to_be_bytes());
            index.insert_finalization(digest, entry(0));
        }
        let cache = index.finalizations.read();
        assert_eq!(cache.entries.len(), MAX_CACHED_FINALIZATIONS);
        assert_eq!(cache.order.len(), MAX_CACHED_FINALIZATIONS);
        assert_eq!(cache.payload_bytes, 0);
        assert!(!cache.entries.contains_key(&[3; 32]));
    }

    #[test]
    fn missing_finalization_returns_none() {
        assert!(
            LightBlockIndex::new()
                .get_finalization(&[0xFF; 32])
                .is_none()
        );
    }

    #[test]
    fn insert_and_get_epoch_material() {
        let index = LightBlockIndex::new();
        let material = StoredEpochMaterial {
            bytes: vec![0x22; 423],
        };

        index.insert_epoch_material(3, material.clone());
        assert_eq!(index.get_epoch_material(3), Some(material));
    }

    #[test]
    fn missing_epoch_material_returns_none() {
        assert!(LightBlockIndex::new().get_epoch_material(99).is_none());
    }
}
