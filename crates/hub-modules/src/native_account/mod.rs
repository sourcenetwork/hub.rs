//! Native account state — DID-keyed nonce tracking for BLS transactions.

pub mod keys;

use std::collections::HashMap;

use thiserror::Error;

/// Nonce validation error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum NonceError {
    /// Transaction nonce does not match the expected value.
    #[error("nonce mismatch for {did}: expected {expected}, got {got}")]
    Mismatch {
        /// The DID of the signer.
        did: String,
        /// The next expected nonce.
        expected: u64,
        /// The nonce present in the transaction.
        got: u64,
    },

    /// Nonce counter would overflow `u64::MAX`.
    #[error("nonce overflow for {0}")]
    Overflow(String),
}

/// In-memory per-DID nonce store for native BLS transactions.
///
/// Tracks the next expected nonce for each DID. New accounts start at 0.
/// The executor clones this store per-block, so the `HashMap` backend
/// fits the existing clone-per-block pattern.
#[derive(Clone, Debug, Default)]
pub struct NativeNonceStore {
    nonces: HashMap<String, u64>,
}

impl NativeNonceStore {
    /// Return the current nonce for the given DID (0 for new accounts).
    pub fn get_nonce(&self, did: &str) -> u64 {
        self.nonces.get(did).copied().unwrap_or(0)
    }

    /// Validate `tx_nonce == stored` and increment. Returns an error on mismatch.
    pub fn check_and_increment(&mut self, did: &str, tx_nonce: u64) -> Result<(), NonceError> {
        let expected = self.get_nonce(did);
        if tx_nonce != expected {
            return Err(NonceError::Mismatch {
                did: did.to_string(),
                expected,
                got: tx_nonce,
            });
        }
        let next = expected
            .checked_add(1)
            .ok_or_else(|| NonceError::Overflow(did.to_string()))?;
        self.nonces.insert(did.to_string(), next);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_account_starts_at_zero() {
        let store = NativeNonceStore::default();
        assert_eq!(store.get_nonce("did:key:z6MkNew"), 0);
    }

    #[test]
    fn check_and_increment_success() {
        let mut store = NativeNonceStore::default();
        let did = "did:key:z6MkAlice";

        store.check_and_increment(did, 0).unwrap();
        assert_eq!(store.get_nonce(did), 1);

        store.check_and_increment(did, 1).unwrap();
        assert_eq!(store.get_nonce(did), 2);
    }

    #[test]
    fn check_and_increment_mismatch() {
        let mut store = NativeNonceStore::default();
        let did = "did:key:z6MkAlice";

        let err = store.check_and_increment(did, 5).unwrap_err();
        assert_eq!(
            err,
            NonceError::Mismatch {
                did: did.to_string(),
                expected: 0,
                got: 5,
            }
        );
        // Nonce unchanged after rejection.
        assert_eq!(store.get_nonce(did), 0);
    }

    #[test]
    fn independent_dids() {
        let mut store = NativeNonceStore::default();
        store.check_and_increment("did:key:z6MkAlice", 0).unwrap();
        store.check_and_increment("did:key:z6MkBob", 0).unwrap();

        assert_eq!(store.get_nonce("did:key:z6MkAlice"), 1);
        assert_eq!(store.get_nonce("did:key:z6MkBob"), 1);
    }

    #[test]
    fn clone_isolation() {
        let mut store = NativeNonceStore::default();
        store.check_and_increment("did:key:z6Mk1", 0).unwrap();

        let mut fork = store.clone();
        fork.check_and_increment("did:key:z6Mk1", 1).unwrap();

        assert_eq!(store.get_nonce("did:key:z6Mk1"), 1);
        assert_eq!(fork.get_nonce("did:key:z6Mk1"), 2);
    }

    #[test]
    fn sequential_nonces_in_block() {
        let mut store = NativeNonceStore::default();
        let did = "did:key:z6MkAlice";

        for i in 0..10 {
            store.check_and_increment(did, i).unwrap();
        }
        assert_eq!(store.get_nonce(did), 10);
    }

    #[test]
    fn replay_rejected() {
        let mut store = NativeNonceStore::default();
        let did = "did:key:z6MkAlice";

        store.check_and_increment(did, 0).unwrap();
        let err = store.check_and_increment(did, 0).unwrap_err();
        assert_eq!(
            err,
            NonceError::Mismatch {
                did: did.to_string(),
                expected: 1,
                got: 0,
            }
        );
    }

    #[test]
    fn error_display() {
        let err = NonceError::Mismatch {
            did: "did:key:z6Mk1".to_string(),
            expected: 3,
            got: 1,
        };
        assert_eq!(
            err.to_string(),
            "nonce mismatch for did:key:z6Mk1: expected 3, got 1"
        );
    }

    #[test]
    fn overflow_rejected() {
        let mut store = NativeNonceStore::default();
        let did = "did:key:z6MkMax";
        store.nonces.insert(did.to_string(), u64::MAX);

        let err = store.check_and_increment(did, u64::MAX).unwrap_err();
        assert_eq!(err, NonceError::Overflow(did.to_string()));
        // Nonce unchanged.
        assert_eq!(store.get_nonce(did), u64::MAX);
    }
}
