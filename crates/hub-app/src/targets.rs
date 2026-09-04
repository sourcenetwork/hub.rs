//! Conversions between block-carried [`DbTargets`] and glue sync targets.

use commonware_glue::stateful::db::Merkleized;
use commonware_storage::{
    merkle::{Location, mmr},
    qmdb::sync::Target,
};
use commonware_utils::non_empty_range;
use hub_backend::{HubMerkleized, HubSyncTargets};
use hub_domain::{ConsensusDigest, DbTarget, DbTargets};

type SyncTarget = Target<mmr::Family, ConsensusDigest>;

fn target_from_sync(target: &SyncTarget) -> DbTarget {
    DbTarget {
        root: target.root,
        floor: *target.range.start(),
        tip: *target.range.end(),
    }
}

fn sync_from_target(target: &DbTarget) -> SyncTarget {
    Target::new(
        target.root,
        non_empty_range!(Location::new(target.floor), Location::new(target.tip)),
    )
}

/// Targets recorded by a block, read back from committed sync targets.
pub fn db_targets_from_sync(targets: &HubSyncTargets) -> DbTargets {
    DbTargets {
        accounts: target_from_sync(&targets.0),
        storage: target_from_sync(&targets.1),
        code: target_from_sync(&targets.2),
    }
}

/// Targets recorded by a block, derived from the merkleized batches it produced.
pub fn db_targets_from_merkleized(merkleized: &HubMerkleized) -> DbTargets {
    fn one<M: Merkleized<Digest = ConsensusDigest>>(
        m: &M,
        bounds_floor: u64,
        bounds_tip: u64,
    ) -> DbTarget {
        DbTarget {
            root: m.root(),
            floor: bounds_floor,
            tip: bounds_tip,
        }
    }
    let (a, s, c) = merkleized;
    let ab = a.bounds();
    let sb = s.bounds();
    let cb = c.bounds();
    DbTargets {
        accounts: one(a, u64::from(ab.inactivity_floor), u64::from(ab.tip.size)),
        storage: one(s, u64::from(sb.inactivity_floor), u64::from(sb.tip.size)),
        code: one(c, u64::from(cb.inactivity_floor), u64::from(cb.tip.size)),
    }
}

/// Glue sync targets for a block's recorded [`DbTargets`].
pub fn sync_targets(targets: &DbTargets) -> HubSyncTargets {
    (
        sync_from_target(&targets.accounts),
        sync_from_target(&targets.storage),
        sync_from_target(&targets.code),
    )
}
