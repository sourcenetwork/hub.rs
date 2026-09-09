//! Historical query checks outside the measured arrival interval.

use alloy_primitives::B256;
use hub_client::HubClient;
use serde_json::{Value, json};
use std::time::Duration;

pub(super) struct Probe {
    queries: Vec<(&'static str, Value, Value)>,
}

impl Probe {
    pub(super) async fn capture(
        client: &HubClient,
        hash: B256,
        height: u64,
        revision: B256,
    ) -> Self {
        let number = format!("0x{height:x}");
        let requests = [
            ("eth_getBlockByNumber", json!([number, false])),
            ("eth_getBlockByHash", json!([revision, false])),
            ("eth_getTransactionByHash", json!([hash])),
            ("eth_getTransactionReceipt", json!([hash])),
            ("hub_getTransactionReceipt", json!([hash])),
            (
                "eth_getLogs",
                json!([{"fromBlock": number, "toBlock": number}]),
            ),
        ];
        let mut queries = Vec::new();
        for (method, params) in requests {
            let expected: Value = client.rpc_call_typed(method, params.clone()).await.unwrap();
            assert!(!expected.is_null(), "missing initial {method}");
            if method == "eth_getLogs" {
                assert!(
                    !expected.as_array().unwrap().is_empty(),
                    "probe must include logs"
                );
            }
            queries.push((method, params, expected));
        }
        Self { queries }
    }

    pub(super) async fn check(&self, client: &HubClient) {
        for (method, params, expected) in &self.queries {
            let actual: Value = client.rpc_call_typed(method, params.clone()).await.unwrap();
            assert_eq!(&actual, expected, "historical {method} changed");
        }
    }
}

pub(super) async fn wait(clients: &[HubClient], height: u64) {
    tokio::time::timeout(Duration::from_secs(600), async {
        loop {
            let mut ready = true;
            for client in clients {
                ready &= client.block_number().await.unwrap() >= height;
            }
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("historical retention revision deadline");
}
