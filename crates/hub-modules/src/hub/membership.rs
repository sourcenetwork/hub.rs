//! Immutable consensus rosters included in native state commitments.

use super::{HubError, HubModule};
use crate::kv_store::ModuleKvStore as _;

fn roster_key(epoch: u64) -> Vec<u8> {
    let mut key = b"consensus_roster/".to_vec();
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

impl HubModule {
    /// Read the canonical concatenation of 32-byte consensus identities.
    pub fn consensus_roster(&self, epoch: u64) -> Option<&[u8]> {
        self.store.get_ref(&roster_key(epoch))
    }

    /// Persist an execution-selected roster without allowing its replacement.
    pub fn record_consensus_roster(
        &mut self,
        epoch: u64,
        keys: &[[u8; 32]],
    ) -> Result<(), HubError> {
        if keys.is_empty() || !keys.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(HubError::State(
                "consensus roster must be nonempty and strictly sorted".into(),
            ));
        }
        let bytes: Vec<u8> = keys.iter().flatten().copied().collect();
        if let Some(existing) = self.consensus_roster(epoch) {
            return if existing == bytes {
                Ok(())
            } else {
                Err(HubError::State("consensus roster already selected".into()))
            };
        }
        self.store.put(&roster_key(epoch), bytes);
        Ok(())
    }
}
