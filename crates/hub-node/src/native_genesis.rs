use std::{fs, io::Write as _, path::Path};

use alloy_primitives::keccak256;
use anyhow::{Context as _, ensure};
use commonware_codec::{Decode as _, Encode as _};
use commonware_glue::stateful::db::DatabaseSet as _;
use commonware_runtime::{Supervisor as _, buffer::paged::CacheRef, tokio};
use hub_backend::{
    HubStateSet,
    native::{self, NativeStateSet},
    state_set_config,
};
use hub_domain::Block;
use hub_genesis::HubGenesis;
use hub_modules::ModuleState;

/// Initialize all seven journals once, with a durable intent for interrupted first boots.
pub(super) async fn load_or_create(
    context: &tokio::Context,
    data_dir: &Path,
    genesis: &HubGenesis,
    cache: &CacheRef,
) -> anyhow::Result<Block> {
    let fingerprint = keccak256(serde_json::to_vec(genesis)?);
    let path = data_dir.join("native-genesis.bin");
    if path.exists() {
        let record = fs::read(&path)?;
        ensure!(
            record.get(..32) == Some(fingerprint.as_slice()),
            "configured genesis differs from persisted native genesis"
        );
        let block = Block::decode_cfg(&record[32..], &crate::node::block_cfg())?;
        ensure!(
            block.native_targets.is_some(),
            "native genesis commitments missing"
        );
        ensure!(
            block.receipt_commitment == Some(hub_executor::receipt_commitment(0, &[])),
            "native genesis predates receipt commitments; an explicit migration is required"
        );
        return Ok(block);
    }
    ensure!(
        !data_dir.join("genesis_block.bin").exists() && !data_dir.join("state").exists(),
        "existing JMT state requires an explicit native-storage migration"
    );
    ensure!(
        !data_dir.join("history").exists(),
        "genesis record missing from a node with finalized history"
    );
    fs::create_dir_all(data_dir)?;
    let intent = data_dir.join("native-genesis.intent");
    let execution = HubStateSet::init(
        context.child("genesis_execution"),
        state_set_config(super::node::PARTITION_PREFIX, cache.clone()),
    )
    .await;
    let native = NativeStateSet::init(
        context.child("genesis_modules"),
        native::state_config(super::node::PARTITION_PREFIX, cache.clone()),
    )
    .await;
    if intent.exists() {
        ensure!(
            fs::read(&intent)? == fingerprint.as_slice(),
            "interrupted genesis has different configuration"
        );
        execution
            .rewind_to_targets(HubStateSet::initial_sync_targets())
            .await;
        native
            .rewind_to_targets(NativeStateSet::initial_sync_targets())
            .await;
    } else {
        ensure!(
            execution.committed_targets().await == HubStateSet::initial_sync_targets()
                && native.committed_targets().await == NativeStateSet::initial_sync_targets(),
            "existing journals have no native genesis or initialization intent"
        );
        persist(&intent, fingerprint.as_slice())?;
    }
    let (root, targets) = hub_app::apply_genesis(&execution, &genesis.to_genesis_state()?).await?;
    let mut modules = ModuleState::default();
    if let Some(policy) = &genesis.operators {
        modules.hub.initialize_administration(policy.clone())?;
    }
    let sealed = native::prepare(
        native.new_batches().await,
        modules.diff_from(&ModuleState::default()),
    )
    .await?;
    let module_root = native::state_root(&sealed);
    native.apply(sealed).await;
    ensure!(
        native.finalize().await.durable().await,
        "native genesis did not become durable"
    );
    let native_targets = native.committed_targets().await;
    let mut block = hub_app::genesis_block(root, targets, module_root);
    block.receipt_commitment = Some(hub_executor::receipt_commitment(0, &[]));
    block.native_targets = Some(
        [
            &native_targets.0,
            &native_targets.1,
            &native_targets.2,
            &native_targets.3,
        ]
        .map(|target| hub_domain::DbTarget {
            root: target.root,
            floor: *target.range.start(),
            tip: *target.range.end(),
        }),
    );
    let mut record = fingerprint.to_vec();
    record.extend_from_slice(&block.encode());
    persist(&path, &record)?;
    fs::remove_file(intent)?;
    fs::File::open(data_dir)?.sync_all()?;
    Ok(block)
}

fn persist(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let temporary = path.with_extension("tmp");
    let mut file = fs::File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(temporary, path)?;
    fs::File::open(path.parent().context("genesis directory missing")?)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[path = "node/genesis_tests.rs"]
mod tests;
