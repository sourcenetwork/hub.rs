//! Immutable consensus rosters included in native state commitments.

use super::{HubError, HubModule};
use crate::kv_store::ModuleKvStore as _;

const ROSTER_PREFIX: &[u8] = b"consensus_roster/";

fn roster_key(epoch: u64) -> Vec<u8> {
    let mut key = ROSTER_PREFIX.to_vec();
    key.extend_from_slice(&epoch.to_be_bytes());
    key
}

impl HubModule {
    /// Read the canonical concatenation of 32-byte consensus identities.
    pub fn consensus_roster(&self, epoch: u64) -> Option<&[u8]> {
        self.store.get_ref(&roster_key(epoch))
    }

    /// Retain the latest three epoch selections without replacing or resurrecting one.
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
        let key = roster_key(epoch);
        if self
            .store
            .prefix_iter(ROSTER_PREFIX)
            .last()
            .is_some_and(|(latest, _)| latest >= key.as_slice())
        {
            return Err(HubError::State(
                "consensus roster is older than the retained window".into(),
            ));
        }
        let cutoff = roster_key(epoch.saturating_sub(2));
        let expired: Vec<_> = self
            .store
            .prefix_iter(ROSTER_PREFIX)
            .take_while(|(key, _)| *key < cutoff.as_slice())
            .map(|(key, _)| key.to_vec())
            .collect();
        for key in expired {
            self.store.delete(&key);
        }
        self.store.put(&key, bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roster_window_bounds_live_state_and_preserves_parent_snapshots() {
        let keys: Vec<_> = (1..=64).map(|byte| [byte; 32]).collect();
        let mut hub = HubModule::default();
        hub.record_consensus_roster(3, &keys).unwrap();
        let parent = hub.clone();
        for epoch in 4..=1003 {
            hub = hub.clone();
            hub.record_consensus_roster(epoch, &keys).unwrap();
            assert!(hub.store.serialize().len() < 6400);
        }
        assert_eq!(hub.store.prefix_iter(ROSTER_PREFIX).count(), 3);
        assert!(hub.consensus_roster(1000).is_none());
        for epoch in 1001..=1003 {
            assert!(hub.consensus_roster(epoch).is_some());
        }
        assert!(parent.consensus_roster(3).is_some());
        assert!(hub.record_consensus_roster(3, &keys).is_err());
        hub.record_consensus_roster(2000, &keys).unwrap();
        assert_eq!(hub.store.prefix_iter(ROSTER_PREFIX).count(), 1);
        assert!(hub.consensus_roster(1003).is_none());
    }
}
