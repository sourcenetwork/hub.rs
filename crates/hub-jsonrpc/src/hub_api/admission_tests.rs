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
