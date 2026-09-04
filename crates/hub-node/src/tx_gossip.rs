//! Transaction admission and gossip.
//!
//! Every validator forwards admitted transactions to every other validator, so
//! whichever leader builds the next block has them.

use std::sync::{Arc, OnceLock};

use alloy_primitives::Bytes;
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::Spawner;
use hub_consensus::{Mempool as _, components::InMemoryMempool};
use hub_domain::{NativeTx, Tx};
use hub_executor::MempoolValidator;
use hub_modules::native_account::NativeNonceStore;
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

use crate::CommittedState;

/// Mempool validator over committed state, bound once the databases are open.
pub type SharedValidator = Arc<OnceLock<Mutex<MempoolValidator<CommittedState>>>>;

/// Admits transactions locally and forwards them to peers.
pub struct TxGossip<S: Sender> {
    mempool: InMemoryMempool,
    validator: SharedValidator,
    chain_id: u64,
    sender: Arc<Mutex<S>>,
}

impl<S: Sender> Clone for TxGossip<S> {
    fn clone(&self) -> Self {
        Self {
            mempool: self.mempool.clone(),
            validator: self.validator.clone(),
            chain_id: self.chain_id,
            sender: self.sender.clone(),
        }
    }
}

impl<S: Sender> std::fmt::Debug for TxGossip<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxGossip").finish_non_exhaustive()
    }
}

/// Validate and insert one transaction into the mempool.
pub(crate) async fn admit(
    mempool: &InMemoryMempool,
    validator: &SharedValidator,
    chain_id: u64,
    bytes: Bytes,
) -> Result<bool, String> {
    let validator = validator
        .get()
        .ok_or_else(|| "node is still starting".to_string())?;
    let tx = Tx::new(bytes.clone());
    let is_native = !bytes.is_empty() && NativeTx::is_native_tx(bytes[0]);
    if is_native {
        let pre = MempoolValidator::<CommittedState>::pre_validate_native(chain_id, &bytes)
            .map_err(|e| e.to_string())?;
        validator
            .lock()
            .await
            .admit_native(&pre)
            .map_err(|e| e.to_string())?;
    } else {
        validator
            .lock()
            .await
            .validate_tx(&bytes)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(mempool.insert(tx))
}

impl<S: Sender> TxGossip<S> {
    /// Build the gossip handle over the mempool channel sender.
    pub fn new(
        mempool: InMemoryMempool,
        validator: SharedValidator,
        chain_id: u64,
        sender: S,
    ) -> Self {
        Self {
            mempool,
            validator,
            chain_id,
            sender: Arc::new(Mutex::new(sender)),
        }
    }

    /// Admit a locally submitted transaction and forward it to every peer.
    pub async fn submit(&self, bytes: Bytes) -> Result<bool, String> {
        let inserted = admit(&self.mempool, &self.validator, self.chain_id, bytes.clone()).await?;
        if inserted {
            let feedback = self
                .sender
                .lock()
                .await
                .send(Recipients::All, bytes.0, false);
            trace!(?feedback, "forwarded transaction");
        }
        Ok(inserted)
    }
}

/// Reset the validator against fresh committed state after a finalized block
/// and evict transactions that no longer validate.
pub(crate) async fn recheck(
    mempool: &InMemoryMempool,
    validator: &SharedValidator,
    state: CommittedState,
    nonces: NativeNonceStore,
) {
    let Some(validator) = validator.get() else {
        return;
    };
    let mut guard = validator.lock().await;
    guard.reset(state, nonces);
    let pending = mempool.build(usize::MAX, &std::collections::BTreeSet::new());
    let mut evict = Vec::new();
    for tx in &pending {
        if let Err(e) = guard.recheck_tx_stateless(&tx.bytes).await {
            trace!(tx_id = ?tx.id(), error = %e, "evicting stale tx");
            evict.push(tx.id());
        }
    }
    if !evict.is_empty() {
        debug!(count = evict.len(), "evicted stale transactions");
        mempool.prune(&evict);
    }
}

/// Receive gossiped transactions from peers and admit them.
pub fn spawn_tx_receiver<E: Spawner, R: Receiver + Send + 'static>(
    context: E,
    mut receiver: R,
    mempool: InMemoryMempool,
    validator: SharedValidator,
    chain_id: u64,
) {
    context.spawn(move |_| async move {
        loop {
            match receiver.recv().await {
                Ok((peer, message)) => {
                    let bytes = Bytes::copy_from_slice(message.as_ref());
                    match admit(&mempool, &validator, chain_id, bytes).await {
                        Ok(true) => trace!(?peer, "admitted gossiped transaction"),
                        Ok(false) => trace!(?peer, "duplicate gossiped transaction"),
                        Err(e) => debug!(?peer, error = %e, "rejected gossiped transaction"),
                    }
                }
                Err(e) => {
                    warn!(error = ?e, "mempool channel closed");
                    return;
                }
            }
        }
    });
}
