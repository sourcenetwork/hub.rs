use super::*;
use std::sync::Mutex;

#[tokio::test]
async fn rejected_updates_preserve_results_and_stop_dependent_submissions() {
    let server = jsonrpsee_server::ServerBuilder::default()
        .build("127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let mut module = jsonrpsee::RpcModule::new(calls.clone());
    module
        .register_method("hub_sendNativeTx", |params, calls, _| {
            let (raw,): (String,) = params.parse().unwrap();
            let mut calls = calls.lock().unwrap();
            let throttle = raw == "0x00" && !calls.contains(&raw);
            calls.push(raw);
            Err::<String, _>(if throttle {
                jsonrpsee::types::ErrorObjectOwned::owned(
                    -32002,
                    "busy",
                    Some(serde_json::json!({"retryable": true})),
                )
            } else {
                jsonrpsee::types::ErrorObjectOwned::owned(-32602, "invalid", None::<()>)
            })
        })
        .unwrap();
    let handle = server.start(module);
    let keys = KeySet::builder().seed(42).build().unwrap();
    let reads = Arc::new(driver::ReadContext {
        trusted: *keys.epoch_info().output.public().public(),
        policy: String::new(),
        permissions: true,
    });
    let requests = (0..6)
        .map(|index| driver::Request {
            index,
            object_id: (index % 2).to_string(),
            expected_access: false,
            final_registered: Some(false),
            hash: alloy_primitives::B256::ZERO,
            owner: String::new(),
            raw: vec![index as u8],
        })
        .collect();
    let started = Instant::now();
    let observations = updates::run(
        requests,
        2,
        1000,
        started,
        Arc::new(HubClient::new(format!("http://{address}"))),
        reads,
    )
    .await;
    let summary = driver::summary(&observations, started.elapsed());
    assert_eq!(observations.len(), 6);
    assert_eq!(summary["rejected"], 2);
    assert_eq!(summary["not_sent"], 4);
    assert_eq!(summary["submit_throttles"], 1);
    assert_eq!(summary["completed_workflows"], 0);
    let mut actual = calls.lock().unwrap().clone();
    actual.sort();
    assert_eq!(actual, ["0x00", "0x00", "0x01"]);
    handle.stop().unwrap();
    handle.stopped().await;
}
