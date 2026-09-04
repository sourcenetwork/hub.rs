//! Glue-managed QMDB databases for EVM state: accounts, storage, and code.
//!
//! The three databases form a [`DatabaseSet`] through commonware-glue's tuple
//! implementation; [`combined_root`] gives the EVM state root one definition.

use alloy_primitives::B256;
use commonware_codec::RangeCfg;
use commonware_cryptography::Sha256;
use commonware_glue::stateful::db::ManagedDb;
use commonware_glue::stateful::db::{Reader, Shared};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, tokio};
use commonware_storage::{
    merkle::mmr,
    qmdb::any::{VariableConfig, unordered::variable},
    translator::EightCap,
};
use commonware_utils::{NZU64, NZUsize};
use hub_qmdb::StateRoot;

use crate::types::{AccountKey, AccountValue, CodeKey, StorageKey, StorageValue};

/// Runtime context the state set runs on.
pub type Ctx = tokio::Context;

/// Account partition: 20-byte address keys, fixed 80-byte account records.
pub type AccountsDb =
    variable::Db<mmr::Family, Ctx, AccountKey, AccountValue, Sha256, EightCap, Sequential>;
/// Storage partition: 60-byte (address, generation, slot) keys, 32-byte values.
pub type StorageDb =
    variable::Db<mmr::Family, Ctx, StorageKey, StorageValue, Sha256, EightCap, Sequential>;
/// Code partition: 32-byte code-hash keys, variable-length bytecode.
pub type CodeDb = variable::Db<mmr::Family, Ctx, CodeKey, Vec<u8>, Sha256, EightCap, Sequential>;

/// The tuple that carries glue's blanket [`DatabaseSet`] implementation.
pub type HubDatabases = (Shared<AccountsDb>, Shared<StorageDb>, Shared<CodeDb>);
/// Read-only handles over committed state, in accounts, storage, code order.
pub type HubReaders = (Reader<AccountsDb>, Reader<StorageDb>, Reader<CodeDb>);
/// Pending batches forked from committed or pending state.
pub type HubUnmerkleized = (
    <AccountsDb as ManagedDb<Ctx>>::Unmerkleized,
    <StorageDb as ManagedDb<Ctx>>::Unmerkleized,
    <CodeDb as ManagedDb<Ctx>>::Unmerkleized,
);
/// Merkleized batches ready to apply on finalization.
pub type HubMerkleized = (
    <AccountsDb as ManagedDb<Ctx>>::Merkleized,
    <StorageDb as ManagedDb<Ctx>>::Merkleized,
    <CodeDb as ManagedDb<Ctx>>::Merkleized,
);
/// Per-database sync targets, in accounts, storage, code order.
pub type HubSyncTargets = (
    <AccountsDb as ManagedDb<Ctx>>::SyncTarget,
    <StorageDb as ManagedDb<Ctx>>::SyncTarget,
    <CodeDb as ManagedDb<Ctx>>::SyncTarget,
);
/// Per-database configuration, in accounts, storage, code order.
pub type HubConfig = (
    VariableConfig<EightCap, ((), ()), Sequential>,
    VariableConfig<EightCap, ((), ()), Sequential>,
    VariableConfig<EightCap, ((), (RangeCfg<usize>, ())), Sequential>,
);

/// Build the three partition configs under `prefix`, sharing `page_cache`.
pub fn state_set_config(prefix: &str, page_cache: CacheRef) -> HubConfig {
    (
        store_config(prefix, "accounts", page_cache.clone(), ((), ())),
        store_config(prefix, "storage", page_cache.clone(), ((), ())),
        store_config(prefix, "code", page_cache, ((), (RangeCfg::new(0..), ()))),
    )
}

fn store_config<C>(
    prefix: &str,
    name: &str,
    page_cache: CacheRef,
    log_codec_config: C,
) -> VariableConfig<EightCap, C, Sequential> {
    VariableConfig {
        merkle_config: commonware_storage::merkle::full::Config {
            journal_partition: format!("{prefix}-{name}-mmr"),
            metadata_partition: format!("{prefix}-{name}-mmr-meta"),
            items_per_blob: NZU64!(128),
            write_buffer: NZUsize!(1024 * 1024),
            replay_buffer: NZUsize!(1024 * 1024),
            strategy: Sequential,
            page_cache: page_cache.clone(),
        },
        journal_config: commonware_storage::journal::contiguous::variable::Config {
            partition: format!("{prefix}-{name}-log"),
            items_per_section: NZU64!(128),
            compression: None,
            codec_config: log_codec_config,
            page_cache,
            write_buffer: NZUsize!(1024 * 1024),
            replay_buffer: NZUsize!(1024 * 1024),
        },
        translator: EightCap,
        init_cache_size: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

/// The EVM state backend: glue's tuple [`DatabaseSet`] over the three partitions.
pub type HubStateSet = HubDatabases;

/// Combined EVM state root over merkleized batches.
pub fn combined_root(merkleized: &HubMerkleized) -> B256 {
    let (accounts, storage, code) = merkleized.roots();
    StateRoot::compute(accounts, storage, code)
}

/// Roots of the three merkleized batches as 32-byte values.
pub trait MerkleizedTriple {
    /// Return the accounts, storage, and code roots.
    fn roots(&self) -> (B256, B256, B256);
}

impl<A, S, C> MerkleizedTriple for (A, S, C)
where
    A: commonware_glue::stateful::db::Merkleized,
    S: commonware_glue::stateful::db::Merkleized,
    C: commonware_glue::stateful::db::Merkleized,
{
    fn roots(&self) -> (B256, B256, B256) {
        (
            B256::from_slice(self.0.root().as_ref()),
            B256::from_slice(self.1.root().as_ref()),
            B256::from_slice(self.2.root().as_ref()),
        )
    }
}
