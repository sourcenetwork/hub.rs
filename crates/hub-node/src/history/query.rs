//! Durable hash lookups over finalized execution history.

use super::*;

/// One retained revision and its execution results.
/// Finality evidence must be obtained and verified separately.
#[derive(Debug)]
pub struct HistoricalExecution {
    /// Canonical retained revision.
    pub block: Block,
    /// Results in execution order.
    pub receipts: Vec<ExecutionReceipt>,
    /// Execution budget committed by the receipt root.
    pub gas_limit: u64,
}

fn hash_key(prefix: u8, hash: &[u8; 32]) -> [u8; 33] {
    let mut key = [prefix; 33];
    key[1..].copy_from_slice(hash);
    key
}

pub(super) fn index_execution(batch: &mut WriteBatch, block: &Block, receipts: &[StoredReceipt]) {
    let height = block.height.to_be_bytes();
    batch.put(hash_key(BLOCK_HASH, &block.id().0.0), height);
    for receipt in receipts {
        batch.put(hash_key(SUBMISSION_HASH, &receipt.hash), height);
    }
}

impl FinalizedHistory {
    /// Assemble complete receipt evidence from durable execution and finality records.
    pub fn receipt_proof(
        &self,
        hash: B256,
        epochs: &LightBlockIndex,
    ) -> Result<Option<hub_domain::ReceiptResponse>> {
        let Some(execution) = self.execution_by_submission(hash)? else {
            return Ok(None);
        };
        let revision = match self.light_block(execution.block.height, epochs) {
            Ok(revision) => revision,
            Err(error)
                if error
                    .to_string()
                    .starts_with("finalization certificate not found for height ") =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        ensure!(
            revision.block_hash.parse::<B256>()? == execution.block.id().0,
            "receipt finality differs from execution record"
        );
        Ok(Some(hub_domain::ReceiptResponse {
            revision,
            gas_limit: execution.gas_limit,
            receipts: execution.receipts,
        }))
    }

    /// Read an execution by revision hash after startup has reconciled history.
    pub fn execution_by_hash(&self, hash: B256) -> Result<Option<HistoricalExecution>> {
        self.query_execution(BLOCK_HASH, hash)
    }

    /// Read the revision containing a submission, including unsuccessful execution.
    pub fn execution_by_submission(&self, hash: B256) -> Result<Option<HistoricalExecution>> {
        self.query_execution(SUBMISSION_HASH, hash)
    }

    fn query_execution(&self, prefix: u8, hash: B256) -> Result<Option<HistoricalExecution>> {
        let snapshot = self.db.snapshot();
        ensure!(
            snapshot.get(transfer::IMPORT)?.is_none(),
            "history import is not published"
        );
        let head = snapshot.get(HEAD)?.context("missing history head")?;
        ensure!(
            snapshot.get(QUERY_HEAD)?.as_deref() == Some(head.as_slice()),
            "history query index requires recovery"
        );
        let Some(height) = snapshot.get(hash_key(prefix, &hash.0))? else {
            return Ok(None);
        };
        let height = u64::from_be_bytes(
            height
                .as_slice()
                .try_into()
                .context("invalid history query height")?,
        );
        let (maximum, _): (u64, [u8; 32]) = borsh::from_slice(&head)?;
        ensure!(
            height > 0 && height <= maximum,
            "history query exceeds published head"
        );
        let bytes = snapshot
            .get_pinned(key(RECORD, height))?
            .context("missing indexed execution record")?;
        let record: Record = borsh::from_slice(&bytes)?;
        let (block, receipts) = record.decode()?;
        ensure!(block.height == height, "indexed execution height mismatch");
        let matches = if prefix == BLOCK_HASH {
            block.id().0 == hash
        } else {
            receipts.iter().any(|receipt| receipt.tx_hash == hash)
        };
        ensure!(matches, "execution record differs from its query key");
        Ok(Some(HistoricalExecution {
            block,
            receipts,
            gas_limit: record.gas_limit,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::tests::block;
    use std::{num::NonZeroU64, sync::Arc};

    #[tokio::test]
    async fn durable_queries_survive_reopen_rebuild_and_rewind() {
        let dir = tempfile::tempdir().unwrap();
        let genesis = block(0, BlockId(B256::ZERO));
        let mut first = block(1, genesis.id());
        first.txs.push(hub_domain::Tx::new(vec![1].into()));
        let receipt = ExecutionReceipt::new(B256::repeat_byte(7), false, 3, 3, vec![], None);
        first.native_targets = Some([hub_domain::DbTarget::default(); 4]);
        first.receipt_commitment = Some(hub_executor::receipt_commitment(
            100,
            std::slice::from_ref(&receipt),
        ));
        let second = block(2, first.id());
        {
            let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
            assert!(
                history
                    .append(&first, std::slice::from_ref(&receipt), 101)
                    .is_err()
            );
            assert!(history.execution_by_hash(first.id().0).unwrap().is_none());
            history
                .append(&first, std::slice::from_ref(&receipt), 100)
                .unwrap();
            history.append(&second, &[], 100).unwrap();
        }
        let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
        let restored = history
            .execution_by_submission(receipt.tx_hash)
            .unwrap()
            .unwrap();
        assert_eq!(restored.block, first);
        assert_eq!(restored.gas_limit, 100);
        assert!(!restored.receipts[0].success());
        assert_eq!(restored.receipts[0].tx_hash, receipt.tx_hash);
        assert_eq!(
            history
                .execution_by_hash(second.id().0)
                .unwrap()
                .unwrap()
                .block,
            second
        );
        assert!(
            history
                .execution_by_submission(B256::ZERO)
                .unwrap()
                .is_none()
        );
        history
            .db
            .put(hash_key(BLOCK_HASH, &first.id().0.0), 2_u64.to_be_bytes())
            .unwrap();
        assert!(
            history
                .execution_by_hash(first.id().0)
                .unwrap_err()
                .to_string()
                .contains("query key")
        );
        history.db.delete(QUERY_HEAD).unwrap();
        assert!(history.execution_by_hash(B256::ZERO).is_err());
        assert!(history.append(&second, &[], 100).is_err());
        let lookup: FinalizationLookup = Arc::new(|_| Box::pin(async { None }));
        let epochs = LightBlockIndex::new(NonZeroU64::new(20).unwrap());
        history
            .recover(&genesis, &second, &BlockIndex::new(), &epochs, &lookup)
            .await
            .unwrap();
        assert_eq!(
            history
                .execution_by_hash(first.id().0)
                .unwrap()
                .unwrap()
                .block,
            first
        );
        history
            .recover(&genesis, &first, &BlockIndex::new(), &epochs, &lookup)
            .await
            .unwrap();
        assert!(history.execution_by_hash(second.id().0).unwrap().is_none());
        assert!(
            history
                .execution_by_submission(receipt.tx_hash)
                .unwrap()
                .is_some()
        );
    }
}
