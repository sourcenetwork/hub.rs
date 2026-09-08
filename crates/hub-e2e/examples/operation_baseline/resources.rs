use std::{io, path::Path, time::Duration};

use hub_e2e::cluster::TestCluster;
use serde_json::json;
use tokio::{process::Command, sync::oneshot, task::JoinHandle, time::Instant};

pub(super) async fn storage(cluster: &TestCluster, phase: &str) {
    for index in 0..4 {
        let path = cluster.node(index).data_dir.clone();
        let started = Instant::now();
        let result = tokio::task::spawn_blocking(move || logical_bytes(&path))
            .await
            .expect("storage sampler task");
        let (bytes, error) = match result {
            Ok(bytes) => (Some(bytes), None),
            Err(error) => (None, Some(error.to_string())),
        };
        println!(
            "{}",
            json!({
                "kind": "storage", "phase": phase, "node": index,
                "logical_bytes": bytes, "error": error,
                "scan_ms": started.elapsed().as_secs_f64() * 1000.0,
            })
        );
    }
}

fn logical_bytes(path: &Path) -> io::Result<u64> {
    let mut bytes = 0u64;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.path().symlink_metadata()?;
        let size = if metadata.is_dir() {
            logical_bytes(&entry.path())?
        } else if metadata.is_file() {
            metadata.len()
        } else {
            0
        };
        bytes = bytes
            .checked_add(size)
            .ok_or_else(|| io::Error::other("storage size overflow"))?;
    }
    Ok(bytes)
}

pub(super) fn start(cluster: &TestCluster) -> (oneshot::Sender<()>, JoinHandle<()>) {
    let pids: Vec<_> = (0..4)
        .map(|i| cluster.node(i).process.id().expect("running node"))
        .collect();
    println!(
        "{}",
        json!({"kind": "resource_configuration", "node_pids": pids,
        "sample_interval_ms": 1000, "rss_unit": "KiB", "cpu_time": "cumulative ps time"})
    );
    let selection = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let (stop, mut stopped) = oneshot::channel();
    let task = tokio::spawn(async move {
        let started = Instant::now();
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                _ = interval.tick() => {}
            }
            let output = tokio::time::timeout(
                Duration::from_secs(2),
                Command::new("ps")
                    .args(["-p", &selection, "-o", "pid=,rss=,time="])
                    .kill_on_drop(true)
                    .output(),
            )
            .await;
            let sample = match output {
                Ok(Ok(output)) if output.status.success() => match String::from_utf8(output.stdout)
                {
                    Ok(rows) => json!({"rows": rows}),
                    Err(error) => json!({"error": error.to_string()}),
                },
                Ok(Ok(output)) => json!({"error": String::from_utf8_lossy(&output.stderr)}),
                Ok(Err(error)) => json!({"error": error.to_string()}),
                Err(_) => json!({"error": "process sampling timed out"}),
            };
            println!(
                "{}",
                json!({"kind": "resources", "elapsed_seconds": started.elapsed().as_secs_f64(), "sample": sample})
            );
        }
    });
    (stop, task)
}
