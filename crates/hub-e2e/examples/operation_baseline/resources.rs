use std::{io, os::unix::fs::MetadataExt, path::Path, time::Duration};

use hub_e2e::cluster::TestCluster;
use serde_json::json;
use tokio::{process::Command, sync::oneshot, task::JoinHandle, time::Instant};

pub(super) async fn storage(cluster: &TestCluster, phase: &str) {
    for index in 0..4 {
        let path = cluster.node(index).data_dir.clone();
        let started = Instant::now();
        let result = tokio::task::spawn_blocking(move || storage_usage(&path))
            .await
            .expect("storage sampler task");
        let (usage, error) = match result {
            Ok(usage) => (Some(usage), None),
            Err(error) => (None, Some(error.to_string())),
        };
        println!(
            "{}",
            json!({
                "kind": "storage", "phase": phase, "node": index,
                "logical_bytes": usage.as_ref().map(|s| s.logical_bytes),
                "allocated_file_bytes": usage.as_ref().map(|s| s.allocated_file_bytes),
                "regular_files": usage.as_ref().map(|s| s.regular_files),
                "error": error,
                "scan_ms": started.elapsed().as_secs_f64() * 1000.0,
            })
        );
    }
}

#[derive(Default)]
struct StorageUsage {
    logical_bytes: u64,
    allocated_file_bytes: u64,
    regular_files: u64,
}

fn storage_usage(path: &Path) -> io::Result<StorageUsage> {
    let mut total = StorageUsage::default();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.path().symlink_metadata()?;
        let usage = if metadata.is_dir() {
            storage_usage(&entry.path())?
        } else if metadata.is_file() {
            StorageUsage {
                logical_bytes: metadata.len(),
                allocated_file_bytes: metadata
                    .blocks()
                    .checked_mul(512)
                    .ok_or_else(size_overflow)?,
                regular_files: 1,
            }
        } else {
            continue;
        };
        total.logical_bytes = total
            .logical_bytes
            .checked_add(usage.logical_bytes)
            .ok_or_else(size_overflow)?;
        total.allocated_file_bytes = total
            .allocated_file_bytes
            .checked_add(usage.allocated_file_bytes)
            .ok_or_else(size_overflow)?;
        total.regular_files = total
            .regular_files
            .checked_add(usage.regular_files)
            .ok_or_else(size_overflow)?;
    }
    Ok(total)
}

fn size_overflow() -> io::Error {
    io::Error::other("storage size overflow")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_usage_counts_nested_files_without_following_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let nested = root.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let first = root.path().join("record");
        let second = nested.join("journal");
        std::fs::write(&first, b"record").unwrap();
        std::fs::File::create(&second)
            .unwrap()
            .set_len(1 << 20)
            .unwrap();
        std::os::unix::fs::symlink(root.path(), nested.join("cycle")).unwrap();
        std::os::unix::fs::symlink(&first, root.path().join("alias")).unwrap();
        let usage = storage_usage(root.path()).unwrap();
        assert_eq!(usage.logical_bytes, 6 + (1 << 20));
        assert_eq!(usage.regular_files, 2);
        assert_eq!(
            usage.allocated_file_bytes,
            [first, second]
                .iter()
                .map(|path| std::fs::metadata(path).unwrap().blocks() * 512)
                .sum::<u64>()
        );
    }
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
