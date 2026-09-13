//! Rejoin recovery for a restart stranded behind peer retention.
//!
//! A completed state sync permanently skips peer synchronization on later
//! boots. If the node was offline (or crashed) long enough that every peer
//! pruned its floor, that skip strands the node: consensus cannot advance
//! without newer epoch material, and backfill cannot fetch pruned blocks.
//! Recovery re-arms peer state sync by discarding the sync bookkeeping so the
//! node re-synchronizes from a current floor.

use std::path::Path;

use crate::node::PARTITION_PREFIX;

/// Partition holding the stateful syncer's completed-sync marker.
const STATE_SYNC_METADATA: &str = "state_sync_metadata";
/// Partition holding the DKG state-sync transcript.
const DKG_STATE_SYNC: &str = "_dkg_state_sync";

/// Epochs beyond which a restart cannot recover by advancing through
/// reshare ceremonies one epoch at a time.
///
/// A node a few epochs behind follows the gossiped reshare mailboxes forward;
/// a node farther behind can no longer verify any live traffic and must
/// re-engage peer state sync from a current floor.
pub(crate) const REJOIN_EPOCHS: u64 = 3;

/// Whether a restart must re-engage peer state sync: the network is farther
/// ahead than sequential reshare advancement can cover.
pub(crate) const fn stranded(our_epoch: u64, network_epoch: u64) -> bool {
    network_epoch >= our_epoch + REJOIN_EPOCHS
}

/// Discard sync bookkeeping so the next plan initialization re-arms peer
/// state sync. Application databases, marshal archives and durable history
/// are untouched; the syncer supersedes them from a current floor.
pub(crate) fn reset_sync_bookkeeping(data_dir: &Path) {
    let storage = data_dir.join("commonware");
    for suffix in [STATE_SYNC_METADATA, DKG_STATE_SYNC] {
        let partition = storage.join(format!("{PARTITION_PREFIX}{suffix}"));
        match std::fs::remove_dir_all(&partition) {
            Ok(()) => {
                tracing::warn!(partition = %partition.display(), "reset state sync bookkeeping for rejoin")
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::error!(partition = %partition.display(), %error, "failed to reset state sync bookkeeping")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_distant_networks_require_rejoin() {
        assert!(!stranded(4, 5));
        assert!(!stranded(4, 6));
        assert!(stranded(4, 7));
        assert!(stranded(6, 378));
    }

    #[test]
    fn reset_removes_only_sync_partitions() {
        let directory = tempfile::tempdir().unwrap();
        let storage = directory.path().join("commonware");
        let metadata = storage.join(format!("{PARTITION_PREFIX}{STATE_SYNC_METADATA}"));
        let dkg = storage.join(format!("{PARTITION_PREFIX}{DKG_STATE_SYNC}"));
        let history = directory.path().join("history");
        for path in [&metadata, &dkg, &history] {
            std::fs::create_dir_all(path).unwrap();
            std::fs::write(path.join("blob"), [0u8; 8]).unwrap();
        }
        reset_sync_bookkeeping(directory.path());
        assert!(!metadata.exists());
        assert!(!dkg.exists());
        assert!(history.exists());
    }
}
