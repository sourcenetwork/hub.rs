//! In-memory store for finalization certificates and validator sets.

use std::collections::HashMap;

use parking_lot::RwLock;

/// A stored finalization certificate from Simplex consensus.
#[derive(Debug, Clone)]
pub struct StoredCertificate {
    /// Consensus epoch.
    pub epoch: u64,
    /// View in which the proposal was finalized.
    pub view: u64,
    /// View of the parent proposal.
    pub parent_view: u64,
    /// Payload digest (SHA-256 of the block hash).
    pub payload: [u8; 32],
    /// Indices of the validators that signed.
    pub signer_indices: Vec<u32>,
    /// Raw ed25519 signatures (64 bytes each), ordered by signer index.
    pub signatures: Vec<[u8; 64]>,
}

/// An ordered set of ed25519 validator public keys for an epoch.
#[derive(Debug, Clone)]
pub struct StoredValidatorSet {
    /// Ordered ed25519 public keys (32 bytes each).
    pub pubkeys: Vec<[u8; 32]>,
}

/// In-memory index of finalization certificates and validator sets.
///
/// Certificates are keyed by consensus digest (the SHA-256 of the block hash).
/// Validator sets are keyed by epoch number.
#[derive(Debug)]
pub struct LightBlockIndex {
    certificates: RwLock<HashMap<[u8; 32], StoredCertificate>>,
    validators: RwLock<HashMap<u64, StoredValidatorSet>>,
}

impl Default for LightBlockIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl LightBlockIndex {
    /// Create a new empty light block index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            certificates: RwLock::new(HashMap::new()),
            validators: RwLock::new(HashMap::new()),
        }
    }

    /// Store a finalization certificate keyed by consensus digest.
    pub fn insert_certificate(&self, digest: [u8; 32], cert: StoredCertificate) {
        self.certificates.write().insert(digest, cert);
    }

    /// Retrieve a finalization certificate by consensus digest.
    pub fn get_certificate(&self, digest: &[u8; 32]) -> Option<StoredCertificate> {
        self.certificates.read().get(digest).cloned()
    }

    /// Store a validator set for the given epoch.
    pub fn insert_validators(&self, epoch: u64, validators: StoredValidatorSet) {
        self.validators.write().insert(epoch, validators);
    }

    /// Retrieve the validator set for the given epoch.
    pub fn get_validators(&self, epoch: u64) -> Option<StoredValidatorSet> {
        self.validators.read().get(&epoch).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_get_certificate() {
        let index = LightBlockIndex::new();
        let digest = [0xAA; 32];
        let cert = StoredCertificate {
            epoch: 0,
            view: 1,
            parent_view: 0,
            payload: digest,
            signer_indices: vec![0, 1, 2],
            signatures: vec![[0x11; 64], [0x22; 64], [0x33; 64]],
        };

        index.insert_certificate(digest, cert.clone());
        let retrieved = index.get_certificate(&digest).unwrap();
        assert_eq!(retrieved.epoch, 0);
        assert_eq!(retrieved.view, 1);
        assert_eq!(retrieved.signer_indices, vec![0, 1, 2]);
    }

    #[test]
    fn missing_certificate_returns_none() {
        let index = LightBlockIndex::new();
        assert!(index.get_certificate(&[0xFF; 32]).is_none());
    }

    #[test]
    fn insert_and_get_validators() {
        let index = LightBlockIndex::new();
        let vs = StoredValidatorSet {
            pubkeys: vec![[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32]],
        };

        index.insert_validators(0, vs.clone());
        let retrieved = index.get_validators(0).unwrap();
        assert_eq!(retrieved.pubkeys.len(), 4);
        assert_eq!(retrieved.pubkeys[0], [0x01; 32]);
    }

    #[test]
    fn missing_validators_returns_none() {
        let index = LightBlockIndex::new();
        assert!(index.get_validators(99).is_none());
    }
}
