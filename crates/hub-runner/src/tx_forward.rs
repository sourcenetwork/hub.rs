//! Gulf Stream tx forwarding — routes transactions to the predicted leader.
//!
//! With `RoundRobin` election, the leader for view `v` at epoch `e` is
//! `participants[(e + v) % N]`. We forward txs to the current and next
//! leader so the proposer has them ready for its block proposal.
//!
//! A gossip loop re-broadcasts pending txs on two triggers:
//! - Immediately when a new tx is inserted (via `Notify`)
//! - Periodically as a safety net for P2P message drops
//!
//! Txs are removed from the mempool only after finalization (prune),
//! so the loop retries until inclusion.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use alloy_primitives::Bytes;
use commonware_cryptography::ed25519;
use commonware_p2p::Recipients;
use commonware_runtime::Spawner;
use hub_consensus::Mempool as _;
use hub_consensus::components::InMemoryMempool;
use hub_domain::Tx;
use hub_transport::{Receiver, Sender};
use tracing::{trace, warn};

const GOSSIP_INTERVAL_MS: u64 = 100;
const MAX_FORWARD_BATCH: usize = 256;

type MempoolSender = Sender<ed25519::PublicKey, commonware_runtime::tokio::Context>;
type MempoolReceiver = Receiver<ed25519::PublicKey>;

/// Computes current and next leader from the RoundRobin schedule.
///
/// Holds the participant list (in Set-sorted order, matching the
/// `RoundRobin` elector's permutation) and a shared view counter
/// updated by the consensus reporters.
#[derive(Clone, Debug)]
pub struct LeaderSchedule {
    participants: Vec<ed25519::PublicKey>,
    view: Arc<AtomicU64>,
}

impl LeaderSchedule {
    /// Create a new leader schedule.
    ///
    /// `participants` must be in Set-sorted order (matching the order
    /// used by `commonware_consensus::simplex::elector::RoundRobin`).
    ///
    /// The formula `view % N` matches the `RoundRobin` elector because:
    /// - `EPOCH_LENGTH = u64::MAX` guarantees epoch remains 0, so `(epoch + view) % N == view % N`
    /// - `RoundRobin::default()` uses the identity permutation (no shuffle seed)
    pub fn new(participants: Vec<ed25519::PublicKey>, view: Arc<AtomicU64>) -> Self {
        assert!(!participants.is_empty(), "no participants");
        Self { participants, view }
    }

    /// Returns a shared handle for updating the current view.
    pub fn view_tracker(&self) -> Arc<AtomicU64> {
        self.view.clone()
    }

    fn leader_for_view(&self, view: u64) -> &ed25519::PublicKey {
        let n = self.participants.len();
        let idx = view as usize % n;
        &self.participants[idx]
    }

    /// Returns the recipients for targeted forwarding: current + next leader.
    ///
    /// If both point to the same validator, returns a single-element set.
    fn target_leaders(&self) -> Recipients<ed25519::PublicKey> {
        let view = self.view.load(Ordering::Relaxed);
        let current = self.leader_for_view(view);
        let next = self.leader_for_view(view + 1);
        if current == next {
            Recipients::One(current.clone())
        } else {
            Recipients::Some(vec![current.clone(), next.clone()])
        }
    }
}

/// Tx forwarding actor with targeted leader routing (Gulfstream).
///
/// When a `LeaderSchedule` is provided, transactions are forwarded only
/// to the current and next leader. Without a schedule, falls back to
/// broadcasting to all peers.
#[derive(Debug)]
pub struct TxForwarder {
    mempool: InMemoryMempool,
    notify: Arc<::tokio::sync::Notify>,
    schedule: Option<LeaderSchedule>,
}

impl TxForwarder {
    /// Create a new tx forwarder with targeted leader routing.
    pub fn new(mempool: InMemoryMempool, schedule: LeaderSchedule) -> Self {
        Self {
            mempool,
            notify: Arc::new(::tokio::sync::Notify::new()),
            schedule: Some(schedule),
        }
    }

    /// Create a tx forwarder without leader targeting (broadcast to all).
    pub fn broadcast_only(mempool: InMemoryMempool) -> Self {
        Self {
            mempool,
            notify: Arc::new(::tokio::sync::Notify::new()),
            schedule: None,
        }
    }

    /// Returns a handle that wakes the gossip loop when called.
    pub fn notifier(&self) -> Arc<::tokio::sync::Notify> {
        self.notify.clone()
    }

    /// Spawn the receiver loop: reads forwarded txs from P2P and inserts into local mempool.
    pub fn spawn_receiver<S: Spawner>(&self, spawner: S, mut receiver: MempoolReceiver) {
        let mempool = self.mempool.clone();
        let notify = self.notify.clone();
        spawner.shared(true).spawn(move |_| async move {
            use commonware_p2p::Receiver as _;
            loop {
                match receiver.recv().await {
                    Ok((sender_pk, msg)) => {
                        let tx = Tx::new(Bytes::copy_from_slice(msg.as_ref()));
                        let inserted = mempool.insert(tx);
                        if inserted {
                            notify.notify_one();
                        }
                        trace!(
                            from = %hex::encode(&sender_pk.as_ref()[..4]),
                            bytes = msg.len(),
                            inserted,
                            "received forwarded tx"
                        );
                    }
                    Err(_) => {
                        warn!("mempool channel closed");
                        break;
                    }
                }
            }
        });
    }

    /// Spawn the gossip loop with targeted leader forwarding.
    pub fn spawn_gossip_loop<S: Spawner>(&self, spawner: S, mut sender: MempoolSender) {
        let mempool = self.mempool.clone();
        let notify = self.notify.clone();
        let schedule = self.schedule.clone();

        spawner.shared(true).spawn(move |_| async move {
            use commonware_p2p::Sender as _;
            let interval = std::time::Duration::from_millis(GOSSIP_INTERVAL_MS);

            loop {
                ::tokio::select! {
                    _ = notify.notified() => {}
                    _ = ::tokio::time::sleep(interval) => {}
                }

                let pending = mempool.build(MAX_FORWARD_BATCH, &std::collections::BTreeSet::new());

                if pending.is_empty() {
                    continue;
                }

                let recipients = schedule
                    .as_ref()
                    .map_or(Recipients::All, LeaderSchedule::target_leaders);

                trace!(count = pending.len(), ?recipients, "forwarding pending txs");

                for tx in &pending {
                    if let Err(e) = sender
                        .send(
                            recipients.clone(),
                            bytes::Bytes::copy_from_slice(&tx.bytes),
                            false,
                        )
                        .await
                    {
                        warn!(error = ?e, ?recipients, "failed to forward tx to leader");
                        break;
                    }
                }
            }
        });
    }

    /// Forward a single tx to the targeted leaders (called on RPC submission).
    pub async fn forward_tx(
        sender: &mut MempoolSender,
        schedule: &Option<LeaderSchedule>,
        tx_bytes: &Bytes,
    ) {
        use commonware_p2p::Sender as _;
        let recipients = schedule
            .as_ref()
            .map_or(Recipients::All, LeaderSchedule::target_leaders);
        trace!(bytes = tx_bytes.len(), ?recipients, "forwarding tx");
        if let Err(e) = sender
            .send(recipients, bytes::Bytes::copy_from_slice(tx_bytes), false)
            .await
        {
            warn!(error = ?e, bytes = tx_bytes.len(), "failed to forward tx on submission");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Signer as _;

    fn test_participants(n: u32) -> Vec<ed25519::PublicKey> {
        (0..n)
            .map(|i| ed25519::PrivateKey::from_seed(u64::from(i)).public_key())
            .collect()
    }

    fn schedule(participants: Vec<ed25519::PublicKey>, view: u64) -> LeaderSchedule {
        LeaderSchedule::new(participants, Arc::new(AtomicU64::new(view)))
    }

    #[test]
    fn leader_for_view_round_robins() {
        let ps = test_participants(4);
        let s = schedule(ps.clone(), 0);
        assert_eq!(s.leader_for_view(0), &ps[0]);
        assert_eq!(s.leader_for_view(1), &ps[1]);
        assert_eq!(s.leader_for_view(2), &ps[2]);
        assert_eq!(s.leader_for_view(3), &ps[3]);
        assert_eq!(s.leader_for_view(4), &ps[0]);
        assert_eq!(s.leader_for_view(7), &ps[3]);
    }

    #[test]
    fn target_leaders_returns_two_distinct() {
        let ps = test_participants(4);
        let s = schedule(ps.clone(), 0);
        match s.target_leaders() {
            Recipients::Some(leaders) => {
                assert_eq!(leaders.len(), 2);
                assert_eq!(leaders[0], ps[0]);
                assert_eq!(leaders[1], ps[1]);
            }
            other => panic!("expected Some, got {other:?}"),
        }
    }

    #[test]
    fn target_leaders_deduplicates_single_node() {
        let ps = test_participants(1);
        let s = schedule(ps.clone(), 0);
        match s.target_leaders() {
            Recipients::One(leader) => {
                assert_eq!(leader, ps[0]);
            }
            other => panic!("expected One, got {other:?}"),
        }
    }

    #[test]
    fn target_leaders_tracks_view_updates() {
        let ps = test_participants(4);
        let view = Arc::new(AtomicU64::new(0));
        let s = LeaderSchedule::new(ps.clone(), view.clone());

        // At view 0: leaders are ps[0], ps[1]
        match s.target_leaders() {
            Recipients::Some(leaders) => assert_eq!(leaders[0], ps[0]),
            other => panic!("expected Some, got {other:?}"),
        }

        // Advance view to 2: leaders are ps[2], ps[3]
        view.store(2, Ordering::Relaxed);
        match s.target_leaders() {
            Recipients::Some(leaders) => {
                assert_eq!(leaders[0], ps[2]);
                assert_eq!(leaders[1], ps[3]);
            }
            other => panic!("expected Some, got {other:?}"),
        }
    }

    #[test]
    fn view_tracker_handle_shares_atomic() {
        let ps = test_participants(2);
        let s = schedule(ps, 0);
        let tracker = s.view_tracker();
        tracker.store(42, Ordering::Relaxed);
        assert_eq!(s.view.load(Ordering::Relaxed), 42);
    }

    #[test]
    #[should_panic(expected = "no participants")]
    fn leader_schedule_panics_on_empty() {
        schedule(vec![], 0);
    }

    #[test]
    fn target_leaders_wraps_at_boundary() {
        let ps = test_participants(3);
        // view=2: current=ps[2], next=ps[0] (wraps)
        let s = schedule(ps.clone(), 2);
        match s.target_leaders() {
            Recipients::Some(leaders) => {
                assert_eq!(leaders[0], ps[2]);
                assert_eq!(leaders[1], ps[0]);
            }
            other => panic!("expected Some, got {other:?}"),
        }
    }
}
