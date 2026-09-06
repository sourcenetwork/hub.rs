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
        native_targets: None,
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

#[tokio::test]
async fn indirect_proof_survives_reopen_and_uses_the_rpc_history_lookup() {
    use commonware_consensus::simplex::types::{Finalization, Finalize, Proposal};
    use commonware_cryptography::{Signer as _, ed25519};
    use commonware_parallel::Sequential;
    use commonware_utils::non_empty;
    use hub_app::ConsensusScheme;
    use hub_domain::{ConsensusDigest, verify_light_block};
    use hub_jsonrpc::{HubApiImpl, HubApiServer, NodeState};

    let public = ed25519::PrivateKey::from_seed(7).public_key();
    let (info, shares) = crate::trusted_setup(7, [public.clone()]).unwrap();
    let material = EpochMaterial::new(info.output.players().clone(), info.output.public().clone());
    let trusted = *material.sharing.public();
    let signer = ConsensusScheme::signer(
        crate::NAMESPACE,
        material.participants.clone(),
        material.sharing.clone(),
        shares.get_value(&public).unwrap().clone(),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let first = block(1, genesis.id());
    let second = block(2, first.id());
    let third = block(3, second.id());
    let proposal = Proposal::new(third.context.round, third.context.parent.0, third.digest());
    let vote = Finalize::sign(&signer, proposal).unwrap();
    let finalization: Finalization<ConsensusScheme, ConsensusDigest> =
        Finalization::from_finalizes(&signer, non_empty![&vote], &Sequential).unwrap();
    let certificate = FinalizationArtifacts {
        epoch: 0,
        finalization: finalization.encode().to_vec(),
        certificate: finalization.certificate.encode().to_vec(),
    };
    let epochs = Arc::new(LightBlockIndex::new());
    epochs.insert_epoch_material(
        0,
        StoredEpochMaterial {
            bytes: material.encode().to_vec(),
        },
    );
    let expected;
    {
        let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
        for block in [&first, &second, &third] {
            history.append(block, &[], 100).unwrap();
            history.store_finalization(block.height, None).unwrap();
        }
        assert!(history.light_block(1, &epochs).is_err());
        history.store_finalization(3, Some(&certificate)).unwrap();
        expected = history.light_block(1, &epochs).unwrap();
        assert_eq!(expected.height, 1);
        assert_eq!(expected.descendants.len(), 2);
        verify_light_block(&expected, &trusted).unwrap();
        assert!(
            history
                .light_block(3, &epochs)
                .unwrap()
                .descendants
                .is_empty()
        );
        assert!(history.light_block(0, &epochs).is_err());
        assert!(history.light_block(4, &epochs).is_err());
    }
    let history = Arc::new(FinalizedHistory::open(dir.path(), &genesis).unwrap());
    let lookup: FinalizationLookup = Arc::new(|_| panic!("persisted artifacts must be reused"));
    let index = Arc::new(BlockIndex::new());
    history
        .recover(&genesis, &third, &index, &epochs, &lookup)
        .await
        .unwrap();
    assert!(epochs.get_finalization(&first.digest().0).is_none());
    let calls = Arc::new(AtomicUsize::new(0));
    let api = HubApiImpl::new(Arc::new(NodeState::new(1, 0, 1)), None)
        .with_index_and_modules(
            index,
            Arc::new(std::sync::RwLock::new(hub_modules::ModuleState::default())),
        )
        .with_light_block_index(epochs.clone())
        .with_light_block_lookup({
            let history = history.clone();
            let epochs = epochs.clone();
            let calls = calls.clone();
            Arc::new(move |height| {
                calls.fetch_add(1, Ordering::Relaxed);
                history
                    .light_block(height, &epochs)
                    .map_err(|error| error.to_string())
            })
        });
    let restored = api
        .get_light_block(alloy_primitives::U64::from(1))
        .await
        .unwrap();
    assert_eq!(restored, expected);
    verify_light_block(&restored, &trusted).unwrap();
    let direct = api
        .get_light_block(alloy_primitives::U64::from(3))
        .await
        .unwrap();
    assert!(direct.descendants.is_empty());
    verify_light_block(&direct, &trusted).unwrap();
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "direct proofs must use the existing index"
    );
    assert!(
        api.get_light_block(alloy_primitives::U64::from(4))
            .await
            .is_err()
    );
    history.db.delete(key(RECORD, 2)).unwrap();
    assert!(
        api.get_light_block(alloy_primitives::U64::from(1))
            .await
            .is_err()
    );
}

#[test]
fn history_proofs_reject_gaps_corruption_and_excessive_work() {
    use hub_domain::{LIGHT_BLOCK_MAX_ARTIFACT_BYTES, LIGHT_BLOCK_MAX_DESCENDANTS};
    let dir = tempfile::tempdir().unwrap();
    let genesis = block(0, BlockId(B256::ZERO));
    let history = FinalizedHistory::open(dir.path(), &genesis).unwrap();
    let epochs = LightBlockIndex::new();
    epochs.insert_epoch_material(0, StoredEpochMaterial { bytes: vec![1] });
    let mut parent = genesis.id();
    for height in 1..=LIGHT_BLOCK_MAX_DESCENDANTS as u64 + 2 {
        let next = block(height, parent);
        history.append(&next, &[], 100).unwrap();
        parent = next.id();
    }
    let last = LIGHT_BLOCK_MAX_DESCENDANTS as u64 + 2;
    history
        .store_finalization(last, Some(&artifacts(last)))
        .unwrap();
    assert!(history.light_block(1, &epochs).is_err());
    assert_eq!(
        history.light_block(2, &epochs).unwrap().descendants.len(),
        LIGHT_BLOCK_MAX_DESCENDANTS
    );
    let bytes = history.db.get(key(RECORD, 3)).unwrap().unwrap();
    let mut record: Record = borsh::from_slice(&bytes).unwrap();
    let mut disconnected = block(3, BlockId(B256::repeat_byte(99)));
    record.block = disconnected.encode().to_vec();
    history
        .db
        .put(key(RECORD, 3), borsh::to_vec(&record).unwrap())
        .unwrap();
    assert!(history.light_block(2, &epochs).is_err());
    disconnected.height = 4;
    record.block = disconnected.encode().to_vec();
    history
        .db
        .put(key(RECORD, 3), borsh::to_vec(&record).unwrap())
        .unwrap();
    assert!(history.light_block(3, &epochs).is_err());
    history
        .db
        .put(
            key(RECORD, 3),
            ((LIGHT_BLOCK_MAX_ARTIFACT_BYTES + 1) as u32).to_le_bytes(),
        )
        .unwrap();
    assert!(
        history
            .light_block(3, &epochs)
            .unwrap_err()
            .to_string()
            .contains("artifact limits")
    );
    history.db.put(key(RECORD, 3), [1, 0, 0, 0]).unwrap();
    assert!(
        history
            .light_block(3, &epochs)
            .unwrap_err()
            .to_string()
            .contains("truncated")
    );
}
