use std::{sync::Arc, time::Duration};

use jsonrpsee::core::client::ClientT;
use tokio::sync::{Semaphore, mpsc};

#[tokio::test]
async fn websocket_dispatch_applies_backpressure() {
    let permits = Arc::new(Semaphore::new(0));
    let (entered, mut entries) = mpsc::unbounded_channel();
    let mut module = jsonrpsee::RpcModule::new(());
    let gate = permits.clone();
    module
        .register_async_method("wait", move |_, _, _| {
            let gate = gate.clone();
            let entered = entered.clone();
            async move {
                entered.send(()).unwrap();
                gate.acquire().await.unwrap().forget();
                "done"
            }
        })
        .unwrap();
    let (handle, addr) = crate::JsonRpcServer::new("127.0.0.1:0".parse().unwrap(), 1)
        .with_extra_module(module)
        .start()
        .await
        .unwrap();
    let client = Arc::new(
        jsonrpsee::ws_client::WsClientBuilder::default()
            .build(format!("ws://{addr}"))
            .await
            .unwrap(),
    );
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..9 {
        let client = client.clone();
        requests.spawn(async move {
            client
                .request::<String, _>("wait", jsonrpsee::rpc_params![])
                .await
                .unwrap()
        });
    }
    for _ in 0..8 {
        tokio::time::timeout(Duration::from_secs(5), entries.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), entries.recv())
            .await
            .is_err()
    );
    permits.add_permits(1);
    tokio::time::timeout(Duration::from_secs(5), entries.recv())
        .await
        .unwrap()
        .unwrap();
    permits.add_permits(8);
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(result) = requests.join_next().await {
            assert_eq!(result.unwrap(), "done");
        }
    })
    .await
    .unwrap();
    handle.stop().unwrap();
    tokio::time::timeout(Duration::from_secs(5), handle.stopped())
        .await
        .unwrap();
}
