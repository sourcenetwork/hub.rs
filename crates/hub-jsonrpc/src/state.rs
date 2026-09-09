//! Node state management for RPC endpoints.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Shared node state that can be updated by the consensus engine.
#[derive(Debug, Clone)]
pub struct NodeState {
    inner: Arc<NodeStateInner>,
}

#[derive(Debug)]
struct NodeStateInner {
    chain_id: u64,
    validator_index: u32,
    validator_count: u32,
    started_at: Instant,
    current_view: AtomicU64,
    finalized_count: AtomicU64,
    proposed_count: AtomicU64,
    nullified_count: AtomicU64,
    peer_count: AtomicU64,
    is_leader: RwLock<bool>,
    backfilling: AtomicBool,
    snapshot_revision: AtomicU64,
    proof_requests: Arc<tokio::sync::Semaphore>,
    light_lookups: Arc<tokio::sync::Semaphore>,
    proof_progress: tokio::sync::watch::Sender<()>,
}

fn acquire(
    semaphore: &Arc<tokio::sync::Semaphore>,
) -> jsonrpsee::core::RpcResult<tokio::sync::OwnedSemaphorePermit> {
    semaphore.clone().try_acquire_owned().map_err(|_| {
        jsonrpsee::types::ErrorObjectOwned::owned(
            crate::error::codes::RESOURCE_UNAVAILABLE,
            "proof service busy; retry later",
            Some(serde_json::json!({"retryable": true})),
        )
    })
}

impl NodeState {
    /// Create a new node state.
    #[must_use]
    pub fn new(chain_id: u64, validator_index: u32, validator_count: u32) -> Self {
        Self {
            inner: Arc::new(NodeStateInner {
                chain_id,
                validator_index,
                validator_count: validator_count.max(1),
                started_at: Instant::now(),
                current_view: AtomicU64::new(0),
                finalized_count: AtomicU64::new(0),
                proposed_count: AtomicU64::new(0),
                nullified_count: AtomicU64::new(0),
                peer_count: AtomicU64::new(0),
                is_leader: RwLock::new(false),
                backfilling: AtomicBool::new(false),
                snapshot_revision: AtomicU64::new(0),
                proof_requests: Arc::new(tokio::sync::Semaphore::new(8)),
                light_lookups: Arc::new(tokio::sync::Semaphore::new(8)),
                proof_progress: tokio::sync::watch::channel(()).0,
            }),
        }
    }

    pub(crate) fn proof_permit(
        &self,
    ) -> jsonrpsee::core::RpcResult<tokio::sync::OwnedSemaphorePermit> {
        acquire(&self.inner.proof_requests)
    }

    pub(crate) fn light_lookup_permit(
        &self,
    ) -> jsonrpsee::core::RpcResult<tokio::sync::OwnedSemaphorePermit> {
        acquire(&self.inner.light_lookups)
    }

    /// Wake proof readers after publishing an execution index or finality evidence.
    pub fn notify_proof_progress(&self) {
        self.inner.proof_progress.send_replace(());
    }

    pub(crate) fn proof_updates(&self) -> tokio::sync::watch::Receiver<()> {
        self.inner.proof_progress.subscribe()
    }

    /// Update the current view.
    pub fn set_view(&self, view: u64) {
        self.inner.current_view.store(view, Ordering::Relaxed);
        let is_leader = self.leader_index_for_view(view) == self.inner.validator_index;
        *self.inner.is_leader.write() = is_leader;
    }

    /// Get the current consensus view.
    pub fn current_view(&self) -> u64 {
        self.inner.current_view.load(Ordering::Relaxed)
    }

    /// Get this validator's index.
    pub fn validator_index(&self) -> u32 {
        self.inner.validator_index
    }

    /// Get the total number of validators.
    pub fn validator_count(&self) -> u32 {
        self.inner.validator_count
    }

    /// Compute the leader index for a given view (round-robin).
    pub fn leader_index_for_view(&self, view: u64) -> u32 {
        (view % u64::from(self.inner.validator_count)) as u32
    }

    /// Whether this node is the leader for the current view.
    pub fn is_current_leader(&self) -> bool {
        *self.inner.is_leader.read()
    }

    /// Increment finalized block count.
    pub fn inc_finalized(&self) {
        self.inner.finalized_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment proposed block count.
    pub fn inc_proposed(&self) {
        self.inner.proposed_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment nullified round count.
    pub fn inc_nullified(&self) {
        self.inner.nullified_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Update peer count.
    pub fn set_peer_count(&self, count: u64) {
        self.inner.peer_count.store(count, Ordering::Relaxed);
    }

    /// Set whether this node is backfilling historical blocks.
    pub fn set_backfilling(&self, backfilling: bool) {
        self.inner.backfilling.store(backfilling, Ordering::Relaxed);
    }

    /// Whether this node is currently backfilling.
    pub fn is_backfilling(&self) -> bool {
        self.inner.backfilling.load(Ordering::Relaxed)
    }

    /// Record the revision recovered through snapshot transfer or its persisted startup floor.
    pub fn set_snapshot_revision(&self, revision: u64) {
        self.inner
            .snapshot_revision
            .store(revision, Ordering::Relaxed);
    }

    /// Get the finalized block count.
    pub fn finalized_count(&self) -> u64 {
        self.inner.finalized_count.load(Ordering::Relaxed)
    }

    /// Get current node status.
    pub fn status(&self) -> NodeStatus {
        let snapshot_revision = self.inner.snapshot_revision.load(Ordering::Relaxed);
        NodeStatus {
            chain_id: self.inner.chain_id,
            validator_index: self.inner.validator_index,
            validator_count: self.inner.validator_count,
            uptime_secs: self.inner.started_at.elapsed().as_secs(),
            current_view: self.inner.current_view.load(Ordering::Relaxed),
            finalized_count: self.inner.finalized_count.load(Ordering::Relaxed),
            proposed_count: self.inner.proposed_count.load(Ordering::Relaxed),
            nullified_count: self.inner.nullified_count.load(Ordering::Relaxed),
            peer_count: self.inner.peer_count.load(Ordering::Relaxed),
            is_leader: *self.inner.is_leader.read(),
            backfilling: self.inner.backfilling.load(Ordering::Relaxed),
            snapshot_revision: (snapshot_revision > 0).then_some(snapshot_revision),
        }
    }
}

/// Serializable node status for RPC responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatus {
    /// Chain ID.
    pub chain_id: u64,
    /// This validator's index (0-3).
    pub validator_index: u32,
    /// Total number of validators.
    pub validator_count: u32,
    /// Seconds since node started.
    pub uptime_secs: u64,
    /// Current consensus view number.
    pub current_view: u64,
    /// Number of finalized blocks.
    pub finalized_count: u64,
    /// Number of blocks proposed by this node.
    pub proposed_count: u64,
    /// Number of nullified rounds.
    pub nullified_count: u64,
    /// Number of connected peers.
    pub peer_count: u64,
    /// Whether this node is the current leader.
    pub is_leader: bool,
    /// Whether this node is backfilling historical blocks.
    pub backfilling: bool,
    /// Revision recovered through snapshot transfer, or its persisted recovery floor on restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_revision: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_status_serde_roundtrip() {
        let status = NodeStatus {
            chain_id: 1337,
            validator_index: 2,
            validator_count: 4,
            uptime_secs: 3600,
            current_view: 100,
            finalized_count: 50,
            proposed_count: 10,
            nullified_count: 5,
            peer_count: 3,
            is_leader: true,
            backfilling: false,
            snapshot_revision: None,
        };

        let json = serde_json::to_string(&status).unwrap();
        let parsed: NodeStatus = serde_json::from_str(&json).unwrap();

        assert_eq!(status.chain_id, parsed.chain_id);
        assert_eq!(status.validator_index, parsed.validator_index);
        assert_eq!(status.validator_count, parsed.validator_count);
        assert_eq!(status.uptime_secs, parsed.uptime_secs);
        assert_eq!(status.current_view, parsed.current_view);
        assert_eq!(status.finalized_count, parsed.finalized_count);
        assert_eq!(status.proposed_count, parsed.proposed_count);
        assert_eq!(status.nullified_count, parsed.nullified_count);
        assert_eq!(status.peer_count, parsed.peer_count);
        assert_eq!(status.is_leader, parsed.is_leader);
        assert_eq!(status.backfilling, parsed.backfilling);
    }

    #[test]
    fn snapshot_revision_is_optional_and_serialized() {
        let state = NodeState::new(1, 0, 4);
        let before = serde_json::to_value(state.status()).unwrap();
        assert!(before.get("snapshotRevision").is_none());
        assert!(
            serde_json::from_value::<NodeStatus>(before)
                .unwrap()
                .snapshot_revision
                .is_none()
        );
        state.set_snapshot_revision(42);
        assert_eq!(
            serde_json::to_value(state.status()).unwrap()["snapshotRevision"],
            42
        );
    }

    #[test]
    fn node_status_json_uses_camel_case() {
        let status = NodeStatus {
            chain_id: 1,
            validator_index: 0,
            validator_count: 4,
            uptime_secs: 0,
            current_view: 0,
            finalized_count: 0,
            proposed_count: 0,
            nullified_count: 0,
            peer_count: 0,
            is_leader: false,
            backfilling: false,
            snapshot_revision: None,
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("chainId"));
        assert!(json.contains("validatorIndex"));
        assert!(json.contains("validatorCount"));
        assert!(json.contains("uptimeSecs"));
        assert!(json.contains("currentView"));
        assert!(json.contains("finalizedCount"));
        assert!(json.contains("proposedCount"));
        assert!(json.contains("nullifiedCount"));
        assert!(json.contains("peerCount"));
        assert!(json.contains("isLeader"));
        assert!(json.contains("backfilling"));
    }

    #[test]
    fn node_state_new() {
        let state = NodeState::new(1337, 2, 4);
        let status = state.status();
        assert_eq!(status.chain_id, 1337);
        assert_eq!(status.validator_index, 2);
        assert!(!status.is_leader);
    }

    #[test]
    fn node_state_set_view() {
        let state = NodeState::new(1, 0, 4);
        state.set_view(4);
        let status = state.status();
        assert_eq!(status.current_view, 4);
        assert!(status.is_leader);
    }

    #[test]
    fn node_state_leader_schedule() {
        let state = NodeState::new(1, 2, 5);
        assert_eq!(state.leader_index_for_view(0), 0);
        assert_eq!(state.leader_index_for_view(2), 2);
        assert_eq!(state.leader_index_for_view(5), 0);
        assert_eq!(state.leader_index_for_view(7), 2);

        state.set_view(7);
        assert!(state.is_current_leader());
        state.set_view(8);
        assert!(!state.is_current_leader());
    }

    #[test]
    fn node_state_inc_counters() {
        let state = NodeState::new(1, 0, 4);
        state.inc_finalized();
        state.inc_finalized();
        state.inc_proposed();
        state.inc_nullified();

        let status = state.status();
        assert_eq!(status.finalized_count, 2);
        assert_eq!(status.proposed_count, 1);
        assert_eq!(status.nullified_count, 1);
    }

    #[test]
    fn node_state_set_peer_count() {
        let state = NodeState::new(1, 0, 4);
        state.set_peer_count(5);
        assert_eq!(state.status().peer_count, 5);
    }
}
