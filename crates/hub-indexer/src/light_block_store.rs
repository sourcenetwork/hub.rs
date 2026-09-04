//! In-memory index of the public Commonware artifacts needed by light clients.

use std::collections::HashMap;

use parking_lot::RwLock;

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
/// blocks after restart.
#[derive(Debug, Default)]
pub struct LightBlockIndex {
    finalizations: RwLock<HashMap<[u8; 32], StoredFinalization>>,
    epoch_material: RwLock<HashMap<u64, StoredEpochMaterial>>,
}

impl LightBlockIndex {
    /// Create an empty light-block artifact index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Store an encoded finalization keyed by its proposal payload digest.
    pub fn insert_finalization(&self, digest: [u8; 32], finalization: StoredFinalization) {
        self.finalizations.write().insert(digest, finalization);
    }

    /// Retrieve an encoded finalization by proposal payload digest.
    #[must_use]
    pub fn get_finalization(&self, digest: &[u8; 32]) -> Option<StoredFinalization> {
        self.finalizations.read().get(digest).cloned()
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
