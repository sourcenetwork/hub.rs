use super::*;
use hub_domain::{DbTargets, StateRoot, Tx};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn block(height: u64, parent: BlockId) -> Block {
    Block {
        context: Block::genesis_context(),
        parent,
        height,
        timestamp: height,
        prevrandao: B256::ZERO,
        state_root: StateRoot(B256::ZERO),
        module_state_root: B256::ZERO,
        txs: Vec::new(),
        payload: None,
        db_targets: DbTargets::default(),
    }
}

fn artifacts(height: u64) -> FinalizationArtifacts {
    FinalizationArtifacts {
        epoch: 0,
        finalization: height.to_be_bytes().to_vec(),
        certificate: Vec::new(),
    }
}

#[tokio::test]
async fn restart_restores_history_and_replaces_the_unprocessed_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let first = block(1, genesis.id());
    let second = block(2, first.id());
    {
        let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
        assert!(history.append(&second, &[], 100).is_err());
        history.append(&first, &[], 100).unwrap();
        history.append(&first, &[], 100).unwrap();
        assert!(history.append(&first, &[], 101).is_err());
        history.append(&second, &[], 100).unwrap();
        history.store_finalization(2, Some(&artifacts(2))).unwrap();
    }
    let calls = Arc::new(AtomicUsize::new(0));
    let lookup: FinalizationLookup = {
        let calls = calls.clone();
        Arc::new(move |height| {
            calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move { Some(artifacts(height)) })
        })
    };
    {
        let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
        let index = BlockIndex::new();
        let light = LightBlockIndex::new();
        history
            .recover(&genesis, &first, &index, &light, &lookup)
            .await
            .unwrap();
        assert_eq!(index.head_block_number(), 1);
        assert_eq!(index.get_block_by_number(1).unwrap().hash, first.id().0);
        assert!(index.get_block_by_number(2).is_none());
        assert_eq!(
            light.get_finalization(&first.digest().0).unwrap().bytes,
            artifacts(1).finalization
        );
        assert!(history.db.get(key(CERTIFICATE, 2)).unwrap().is_none());
        let mut replacement = second.clone();
        replacement.timestamp += 1;
        history.append(&replacement, &[], 100).unwrap();
    }
    {
        let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
        history
            .recover(
                &genesis,
                &first,
                &BlockIndex::new(),
                &LightBlockIndex::new(),
                &lookup,
            )
            .await
            .unwrap();
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "stored certificates should survive restart"
        );
        let mut wrong = first.clone();
        wrong.timestamp += 1;
        assert!(
            history
                .recover(
                    &genesis,
                    &wrong,
                    &BlockIndex::new(),
                    &LightBlockIndex::new(),
                    &lookup
                )
                .await
                .is_err()
        );
        history.db.delete(key(RECORD, 1)).unwrap();
        assert!(
            history
                .recover(
                    &genesis,
                    &first,
                    &BlockIndex::new(),
                    &LightBlockIndex::new(),
                    &lookup
                )
                .await
                .is_err()
        );
    }
    let mut other_genesis = genesis.clone();
    other_genesis.timestamp += 1;
    assert!(FinalizedHistory::open(dir.path(), &other_genesis).is_err());
}

#[test]
fn execution_record_preserves_receipt_fields_and_rejects_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let mut first = block(1, genesis.id());
    first.txs.push(Tx::new(vec![1, 2, 3].into()));
    let log = Log::new_unchecked(
        Address::repeat_byte(7),
        vec![B256::repeat_byte(8)],
        vec![9, 10].into(),
    );
    let receipt = ExecutionReceipt::new(
        B256::repeat_byte(4),
        false,
        17,
        29,
        vec![log.clone()],
        Some(Address::repeat_byte(5)),
    );
    let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
    history
        .append(&first, std::slice::from_ref(&receipt), 31)
        .unwrap();
    let bytes = history.db.get(key(RECORD, 1)).unwrap().unwrap();
    let mut record: Record = borsh::from_slice(&bytes).unwrap();
    let (restored, receipts) = record.decode().unwrap();
    assert_eq!(restored, first);
    let actual = &receipts[0];
    assert_eq!(actual.tx_hash, receipt.tx_hash);
    assert_eq!(actual.contract_address, receipt.contract_address);
    assert_eq!(actual.gas_used, 17);
    assert_eq!(actual.cumulative_gas_used(), 29);
    assert!(!actual.success());
    assert_eq!(actual.logs(), &[log]);
    assert_eq!(record.gas_limit, 31);
    record.receipts[0].logs[0].push(0);
    assert!(record.decode().is_err());
    assert!(borsh::from_slice::<Record>(&bytes[..bytes.len() - 1]).is_err());
}

#[tokio::test]
async fn ancestor_without_a_direct_certificate_remains_queryable() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let first = block(1, genesis.id());
    let unavailable: FinalizationLookup = Arc::new(|_| Box::pin(async { None }));
    {
        let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
        history.append(&first, &[], 100).unwrap();
        history
            .recover(
                &genesis,
                &first,
                &BlockIndex::new(),
                &LightBlockIndex::new(),
                &unavailable,
            )
            .await
            .unwrap();
    }
    let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
    let index = BlockIndex::new();
    let light = LightBlockIndex::new();
    let unexpected: FinalizationLookup = Arc::new(|_| panic!("lookup result must be retained"));
    history
        .recover(&genesis, &first, &index, &light, &unexpected)
        .await
        .unwrap();
    assert_eq!(index.get_block_by_number(1).unwrap().hash, first.id().0);
    assert!(light.get_finalization(&first.digest().0).is_none());
}
