//! Opt-in resource snapshots using existing runtime and storage measurements.

use crate::FinalizedHistory;
use commonware_runtime::{Metrics as _, tokio::Context};
use hub_indexer::BlockIndex;
use std::{sync::Arc, time::Duration};

pub(crate) async fn run(context: Context, history: Arc<FinalizedHistory>, index: Arc<BlockIndex>) {
    let context = Arc::new(context);
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let context = context.clone();
        let history = history.clone();
        let index = index.clone();
        let result = tokio::task::spawn_blocking(move || {
            Ok::<_, anyhow::Error>((context.encode(), history.memory_usage()?, index.stats()))
        })
        .await;
        match result {
            Ok(Ok((metrics, memory, index))) => {
                tracing::debug!(target: "hub_diagnostics", runtime_metrics = %metrics,
                    history_memory_bytes = ?memory, index = ?index, "node resource snapshot");
            }
            Ok(Err(error)) => {
                tracing::warn!(target: "hub_diagnostics", %error, "resource snapshot failed")
            }
            Err(error) => {
                tracing::warn!(target: "hub_diagnostics", %error, "resource snapshot task failed")
            }
        }
    }
}
