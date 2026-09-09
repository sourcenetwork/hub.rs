use super::*;
use crate::error::codes;
use std::time::Duration;

#[tokio::test]
async fn proof_admission_is_shared_and_released_on_errors() {
    let state = Arc::new(NodeState::new(1, 0, 1));
    let api = HubApiImpl::new(Arc::new(state.as_ref().clone()), None);
    let mut permits: Vec<_> = (0..8).map(|_| state.proof_permit().unwrap()).collect();
    let error = api
        .get_current_record_proof(ModuleId::Acp, Bytes::new(), U64::ZERO)
        .await
        .unwrap_err();
    assert_eq!(error.code(), codes::RESOURCE_UNAVAILABLE);
    assert_eq!(error.data().unwrap().get(), r#"{"retryable":true}"#);
    assert_eq!(
        api.get_receipt_proof(B256::ZERO).await.unwrap_err().code(),
        codes::RESOURCE_UNAVAILABLE
    );
    drop(permits.pop());
    for _ in 0..2 {
        let error = api
            .get_state_proof("acp".into(), String::new(), U64::ZERO)
            .await
            .unwrap_err();
        assert_eq!(error.code(), codes::INTERNAL_ERROR);
    }
    assert!(state.proof_permit().is_ok());
}

#[tokio::test]
async fn cancelled_lookup_keeps_its_permit_until_blocking_work_finishes() {
    let state = Arc::new(NodeState::new(1, 0, 1));
    let _held: Vec<_> = (0..7)
        .map(|_| state.light_lookup_permit().unwrap())
        .collect();
    let (release, receiver) = std::sync::mpsc::channel();
    let receiver = std::sync::Mutex::new(receiver);
    let entered = Arc::new(tokio::sync::Notify::new());
    let signal = entered.clone();
    let api = Arc::new(
        HubApiImpl::new(state.clone(), None).with_light_block_lookup(Arc::new(move |_| {
            signal.notify_one();
            receiver
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            Err("finished".into())
        })),
    );
    let running = api.clone();
    let task = tokio::spawn(async move { running.get_light_block(U64::from(1)).await });
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(
        api.get_light_block(U64::from(1)).await.unwrap_err().code(),
        codes::RESOURCE_UNAVAILABLE
    );
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if state.light_lookup_permit().is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn receipt_poll_does_not_wait_for_a_missing_certificate() {
    use hub_indexer::{IndexedBlock, IndexedReceipt};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let hash = B256::repeat_byte(1);
    let index = Arc::new(BlockIndex::new());
    index.insert_block(
        IndexedBlock {
            hash,
            number: 1,
            parent_hash: B256::ZERO,
            state_root: B256::ZERO,
            module_state_root: B256::ZERO,
            timestamp: 1,
            gas_limit: 100,
            gas_used: 0,
            base_fee_per_gas: None,
            prevrandao: B256::ZERO,
            transaction_hashes: vec![hash],
        },
        vec![],
        vec![IndexedReceipt {
            transaction_hash: hash,
            block_hash: hash,
            block_number: 1,
            transaction_index: 0,
            from: alloy_primitives::Address::ZERO,
            to: None,
            cumulative_gas_used: 0,
            gas_used: 0,
            contract_address: None,
            logs: vec![],
            status: true,
            signer_did: None,
        }],
    );
    let lookups = Arc::new(AtomicUsize::new(0));
    let calls = lookups.clone();
    let state = Arc::new(NodeState::new(1, 0, 1));
    let mut api =
        HubApiImpl::new(state.clone(), None).with_light_block_lookup(Arc::new(move |_| {
            calls.fetch_add(1, Ordering::Relaxed);
            Err("finalization certificate not found".into())
        }));
    api.index = Some(index);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), api.get_receipt_proof(hash))
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
    assert_eq!(lookups.load(Ordering::Relaxed), 1);
    let permits: Vec<_> = (0..8).map(|_| state.proof_permit().unwrap()).collect();
    assert!(api.get_receipt_proof(B256::ZERO).await.unwrap().is_none());
    let busy = api.get_receipt_proof(hash).await.unwrap_err();
    assert_eq!(busy.code(), codes::RESOURCE_UNAVAILABLE);
    assert_eq!(busy.data().unwrap().get(), r#"{"retryable":true}"#);
    assert_eq!(lookups.load(Ordering::Relaxed), 1);
    drop(permits);
    api.light_block_lookup = Some(Arc::new(|_| Err("corrupt certificate".into())));
    assert!(
        api.get_receipt_proof(hash)
            .await
            .unwrap_err()
            .message()
            .contains("corrupt certificate")
    );
}
