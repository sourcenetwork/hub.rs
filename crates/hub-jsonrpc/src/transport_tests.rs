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

#[tokio::test]
async fn websocket_non_reader_does_not_hold_shutdown_open() {
    non_reader(true).await;
}

#[tokio::test]
async fn websocket_non_reader_releases_connection_slot() {
    non_reader(false).await;
}

async fn non_reader(stop_before_timeout: bool) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (entered, mut entries) = mpsc::unbounded_channel();
    let mut module = jsonrpsee::RpcModule::new(());
    module
        .register_method("large", move |_, _, _| {
            entered.send(()).unwrap();
            "x".repeat(4 << 20)
        })
        .unwrap();
    let (handle, addr) = crate::JsonRpcServer::new("127.0.0.1:0".parse().unwrap(), 1)
        .with_max_connections(1)
        .with_extra_module(module)
        .start()
        .await
        .unwrap();
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    socket.write_all(format!(
        "GET / HTTP/1.1\r\nHost: {addr}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ).as_bytes()).await.unwrap();
    let mut handshake = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !handshake.ends_with(b"\r\n\r\n") {
            assert!(handshake.len() < 4096);
            handshake.push(socket.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    assert!(handshake.starts_with(b"HTTP/1.1 101"));
    for id in 0..32 {
        let request = format!(r#"{{"jsonrpc":"2.0","method":"large","id":{id}}}"#);
        assert!(request.len() < 126);
        let mask = [1, 2, 3, 4];
        let mut frame = vec![0x81, 0x80 | request.len() as u8];
        frame.extend(mask);
        frame.extend(request.bytes().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        socket.write_all(&frame).await.unwrap();
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        for _ in 0..16 {
            entries.recv().await.unwrap();
        }
    })
    .await
    .unwrap();
    if !stop_before_timeout {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Ok(client) = jsonrpsee::ws_client::WsClientBuilder::default()
                    .build(format!("ws://{addr}"))
                    .await
                {
                    drop(client);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("the timed-out writer must release its connection slot");
    }
    handle.stop().unwrap();
    tokio::time::timeout(Duration::from_secs(15), handle.stopped())
        .await
        .expect("a non-reading socket must not prevent server shutdown");
    drop(socket);
}
