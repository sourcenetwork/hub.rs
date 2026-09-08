//! In-memory mempool implementation.

use std::{collections::BTreeMap, sync::Arc};

use commonware_codec::EncodeSize as _;
use hub_domain::Tx;
use parking_lot::RwLock;

use crate::traits::{Mempool, TxId};

/// Simple in-memory mempool backed by a BTreeMap.
#[derive(Debug, Clone)]
pub struct InMemoryMempool {
    inner: Arc<RwLock<Pending>>,
}

const MAX_PENDING_BYTES: usize = 64 << 20;
const MAX_PENDING_TXS: usize = 4096;

#[derive(Debug, Default)]
struct Pending {
    txs: BTreeMap<TxId, Tx>,
    bytes: usize,
}

impl Pending {
    fn accepts(&self, id: &TxId, tx: &Tx) -> bool {
        tx.bytes.len() <= hub_domain::MAX_TX_BYTES
            && (self.txs.contains_key(id)
                || (self.txs.len() < MAX_PENDING_TXS
                    && tx.bytes.len() <= MAX_PENDING_BYTES - self.bytes))
    }
}

impl InMemoryMempool {
    /// Check capacity while the caller holds the admission validator lock.
    pub fn can_insert(&self, tx: &Tx) -> bool {
        self.inner.read().accepts(&tx.id(), tx)
    }

    /// Select a prefix that fits the encoded transaction budget of one block.
    pub fn build_block(
        &self,
        max_txs: usize,
        excluded: &std::collections::BTreeSet<TxId>,
    ) -> Vec<Tx> {
        let mut remaining = hub_domain::MAX_BLOCK_TX_BYTES - 5;
        self.inner
            .read()
            .txs
            .iter()
            .filter(|(id, _)| !excluded.contains(id))
            .take(max_txs.min(hub_domain::MAX_BLOCK_TXS))
            .take_while(|(_, tx)| {
                if tx.bytes.len() > hub_domain::MAX_TX_BYTES || tx.encode_size() > remaining {
                    return false;
                }
                remaining -= tx.encode_size();
                true
            })
            .map(|(_, tx)| tx.clone())
            .collect()
    }

    /// Create a new empty mempool.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Pending::default())),
        }
    }
}

impl Default for InMemoryMempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Mempool for InMemoryMempool {
    fn insert(&self, tx: Tx) -> bool {
        let id = tx.id();
        let mut inner = self.inner.write();
        if !inner.accepts(&id, &tx) || inner.txs.contains_key(&id) {
            return false;
        }
        inner.bytes += tx.bytes.len();
        inner.txs.insert(id, tx);
        true
    }

    fn build(&self, max_txs: usize, excluded: &std::collections::BTreeSet<TxId>) -> Vec<Tx> {
        let inner = self.inner.read();
        inner
            .txs
            .iter()
            .filter(|(id, _)| !excluded.contains(id))
            .take(max_txs)
            .map(|(_, tx)| tx.clone())
            .collect()
    }

    fn prune(&self, tx_ids: &[TxId]) {
        let mut inner = self.inner.write();
        for id in tx_ids {
            if let Some(tx) = inner.txs.remove(id) {
                inner.bytes -= tx.bytes.len();
            }
        }
    }

    fn len(&self) -> usize {
        self.inner.read().txs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_requests_respect_proposal_and_pending_budgets() {
        let pool = InMemoryMempool::new();
        let txs: Vec<_> = (0..6)
            .map(|i| Tx::new(vec![i; hub_domain::MAX_TX_BYTES].into()))
            .collect();
        for tx in &txs[..5] {
            assert!(pool.insert(tx.clone()));
        }
        assert!(!pool.can_insert(&txs[5]));
        assert!(!pool.insert(txs[5].clone()));
        let block = pool.build_block(64, &Default::default());
        assert_eq!(block.len(), 1);
        assert!(block.encode_size() <= hub_domain::MAX_BLOCK_TX_BYTES);
        pool.prune(&[block[0].id()]);
        assert!(pool.insert(txs[5].clone()));
        let excluded = txs.iter().map(Tx::id).collect();
        assert!(pool.build_block(64, &excluded).is_empty());
    }

    #[test]
    fn mempool_insert_and_build() {
        let mempool = InMemoryMempool::new();

        let tx1 = Tx::new(vec![1, 2, 3].into());
        let tx2 = Tx::new(vec![4, 5, 6].into());

        assert!(mempool.insert(tx1.clone()));
        assert!(mempool.insert(tx2));
        assert!(!mempool.insert(tx1)); // Duplicate

        assert_eq!(mempool.len(), 2);

        let txs = mempool.build(10, &std::collections::BTreeSet::new());
        assert_eq!(txs.len(), 2);
    }

    #[test]
    fn mempool_prune() {
        let mempool = InMemoryMempool::new();

        let tx = Tx::new(vec![1, 2, 3].into());
        let id = tx.id();

        mempool.insert(tx);
        assert_eq!(mempool.len(), 1);

        mempool.prune(&[id]);
        assert_eq!(mempool.len(), 0);
    }

    #[test]
    fn mempool_build_with_exclusions() {
        let mempool = InMemoryMempool::new();

        let tx1 = Tx::new(vec![1, 2, 3].into());
        let tx2 = Tx::new(vec![4, 5, 6].into());
        let id1 = tx1.id();

        mempool.insert(tx1);
        mempool.insert(tx2.clone());

        let mut excluded = std::collections::BTreeSet::new();
        excluded.insert(id1);

        let txs = mempool.build(10, &excluded);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0], tx2);
    }
}
