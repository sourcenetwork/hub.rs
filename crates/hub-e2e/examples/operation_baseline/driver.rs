use std::{sync::Arc, time::Duration};

use alloy_primitives::{B256, FixedBytes};
use hub_client::{ClientError, HubClient, TransactionReceipt};
use hub_e2e::cluster::TestCluster;
use serde_json::{Value, json};
use tokio::{sync::OwnedSemaphorePermit, time::Instant};

pub(super) const POLL_INTERVAL: Duration = Duration::from_millis(50);
pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub(super) struct Request {
    pub(super) index: usize,
    pub(super) hash: B256,
    pub(super) owner: String,
    pub(super) raw: Vec<u8>,
}

#[derive(Debug)]
pub(super) struct Observation {
    pub(super) request: Request,
    outcome: &'static str,
    schedule_lag_ms: f64,
    submit_ms: Option<f64>,
    receipt_ms: Option<f64>,
    receipt: Option<TransactionReceipt>,
    error: Option<String>,
}

impl Observation {
    pub(super) fn json(&self) -> Value {
        json!({
            "kind": "observation", "index": self.request.index, "hash": self.request.hash,
            "outcome": self.outcome, "schedule_lag_ms": self.schedule_lag_ms,
            "submit_rpc_ms": self.submit_ms, "scheduled_to_receipt_ms": self.receipt_ms,
            "height": self.receipt.as_ref().map(|r| r.block_number), "error": self.error,
        })
    }
}

pub(super) async fn observe(
    client: Arc<HubClient>,
    request: Request,
    scheduled: Instant,
    permit: Option<OwnedSemaphorePermit>,
) -> Observation {
    let mut observation = Observation {
        request,
        outcome: "not_sent",
        schedule_lag_ms: scheduled.elapsed().as_secs_f64() * 1000.0,
        submit_ms: None,
        receipt_ms: None,
        receipt: None,
        error: None,
    };
    let Some(_permit) = permit else {
        return observation;
    };
    observation.outcome = "unknown";
    let completed = tokio::time::timeout(REQUEST_TIMEOUT, async {
        let submit_start = Instant::now();
        let result = client.send_native_tx(&observation.request.raw).await;
        observation.submit_ms = Some(submit_start.elapsed().as_secs_f64() * 1000.0);
        match result {
            Ok(hash) => assert_eq!(hash, observation.request.hash, "submission hash mismatch"),
            Err(error) => {
                if matches!(error, ClientError::Rpc { .. }) {
                    observation.outcome = "rejected";
                }
                observation.error = Some(error.to_string());
                return;
            }
        }
        loop {
            match client
                .get_transaction_receipt(observation.request.hash)
                .await
            {
                Ok(Some(receipt)) => {
                    observation.receipt_ms = Some(scheduled.elapsed().as_secs_f64() * 1000.0);
                    observation.outcome = if receipt.status == 1 {
                        "confirmed"
                    } else {
                        "reverted"
                    };
                    observation.receipt = Some(receipt);
                    return;
                }
                Ok(None) => {}
                Err(error) => {
                    observation.error = Some(error.to_string());
                    return;
                }
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await;
    if completed.is_err() {
        observation.error = Some("request deadline elapsed; submission was not retried".into());
    }
    observation
}

fn distribution(mut samples: Vec<f64>) -> Value {
    if samples.is_empty() {
        return Value::Null;
    }
    samples.sort_unstable_by(f64::total_cmp);
    let percentile = |p: usize| samples[(samples.len() * p).div_ceil(100) - 1];
    json!({"count": samples.len(), "p50": percentile(50), "p95": percentile(95), "p99": percentile(99)})
}

pub(super) fn summary(observations: &[Observation], elapsed: Duration) -> Value {
    let count = |status| observations.iter().filter(|o| o.outcome == status).count();
    json!({
        "kind": "summary", "elapsed_seconds": elapsed.as_secs_f64(),
        "offered": observations.len(), "confirmed": count("confirmed"),
        "reverted": count("reverted"), "rejected": count("rejected"),
        "unknown": count("unknown"), "not_sent": count("not_sent"),
        "confirmed_per_second": count("confirmed") as f64 / elapsed.as_secs_f64(),
        "schedule_lag_ms": distribution(observations.iter().map(|o| o.schedule_lag_ms).collect()),
        "submit_rpc_ms": distribution(observations.iter().filter_map(|o| o.submit_ms).collect()),
        "scheduled_to_receipt_ms": distribution(observations.iter().filter_map(|o| o.receipt_ms).collect()),
    })
}

#[derive(Debug)]
pub(super) enum Resolution {
    Verified,
    Unresolved,
}

pub(super) async fn check_recovered(
    origin: &HubClient,
    recovered: &HubClient,
    policy_id: FixedBytes<32>,
    observation: &Observation,
) -> (bool, bool) {
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        let expected = origin
            .get_transaction_receipt(observation.request.hash)
            .await
            .unwrap();
        let actual = recovered
            .get_transaction_receipt(observation.request.hash)
            .await
            .unwrap();
        let receipt_matches = match (&expected, &actual) {
            (None, None) => true,
            (Some(expected), Some(actual)) => {
                expected.block_hash == actual.block_hash
                    && expected.status == actual.status
                    && expected.transaction_hash == actual.transaction_hash
            }
            _ => false,
        };
        let (registered, record) = recovered
            .get_object_owner(policy_id, "file", &observation.request.index.to_string())
            .await
            .unwrap();
        let expected_registration = expected.as_ref().is_some_and(|r| r.status == 1);
        let owner_matches = !registered || {
            let record: Value = serde_json::from_slice(&record).unwrap();
            record["metadata"]["owner_did"] == observation.request.owner
        };
        (
            receipt_matches,
            registered == expected_registration && owner_matches,
        )
    })
    .await
    .expect("recovered state inspection timed out")
}

pub(super) async fn verify(
    cluster: &TestCluster,
    policy_id: FixedBytes<32>,
    observation: &Observation,
) -> Resolution {
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        let origin = HubClient::new(cluster.node(0).rpc_url());
        let receipt = origin
            .get_transaction_receipt(observation.request.hash)
            .await
            .unwrap();
        if observation.outcome == "unknown" && receipt.is_none() {
            return Resolution::Unresolved;
        }
        if matches!(observation.outcome, "not_sent" | "rejected") {
            assert!(receipt.is_none(), "rejected operation has a receipt");
        }
        if let Some(measured) = &observation.receipt {
            let current = receipt.as_ref().expect("measured receipt disappeared");
            assert_eq!(current.block_hash, measured.block_hash);
            assert_eq!(current.status, measured.status);
        }
        for index in 0..cluster.node_count() {
            let client = HubClient::new(cluster.node(index).rpc_url());
            let replica_receipt = if let Some(expected) = &receipt {
                let actual = client
                    .wait_for_receipt(observation.request.hash, POLL_INTERVAL, 600)
                    .await
                    .unwrap();
                assert_eq!(
                    actual.block_hash, expected.block_hash,
                    "replica {index} receipt differs"
                );
                assert_eq!(
                    actual.status, expected.status,
                    "replica {index} status differs"
                );
                Some(actual)
            } else {
                client
                    .get_transaction_receipt(observation.request.hash)
                    .await
                    .unwrap()
            };
            let (registered, record) = client
                .get_object_owner(policy_id, "file", &observation.request.index.to_string())
                .await
                .unwrap();
            let expected_registration = receipt.as_ref().is_some_and(|r| r.status == 1);
            assert_eq!(
                registered, expected_registration,
                "replica {index} ownership differs"
            );
            assert_eq!(replica_receipt.is_some(), receipt.is_some());
            if registered {
                let record: Value = serde_json::from_slice(&record).unwrap();
                assert_eq!(record["metadata"]["owner_did"], observation.request.owner);
            }
        }
        Resolution::Verified
    })
    .await
    .expect("replica verification timed out")
}
