//! Historical membership selections embedded in finalized epoch artifacts.

use super::*;
use commonware_consensus::types::Epoch;
use commonware_utils::ordered::Set;
use hub_domain::PublicKey;
use std::num::NonZeroU64;

impl FinalizedHistory {
    /// Read an older selection after history has been reconciled with execution.
    pub(crate) fn consensus_roster(
        &self,
        epoch: Epoch,
        length: NonZeroU64,
    ) -> Result<Option<Set<PublicKey>>> {
        let Some(boundary_epoch) = epoch.get().checked_sub(1) else {
            return Ok(None);
        };
        let height = boundary_epoch
            .checked_mul(length.get())
            .and_then(|height| height.checked_sub(1))
            .context("consensus roster boundary overflow")?;
        let snapshot = self.db.snapshot();
        ensure!(
            snapshot.get(transfer::IMPORT)?.is_none(),
            "history import is not published"
        );
        let (head, _): (u64, [u8; 32]) =
            borsh::from_slice(&snapshot.get(HEAD)?.context("missing history head")?)?;
        if height > head {
            return Ok(None);
        }
        let record = snapshot
            .get_pinned(key(RECORD, height))?
            .context("missing finalized roster boundary")?;
        let mut encoded = record.as_ref();
        let size = u32::deserialize(&mut encoded)? as usize;
        ensure!(
            size <= hub_domain::MAX_BLOCK_BYTES,
            "oversized roster boundary block"
        );
        let block = Block::decode_cfg(
            encoded
                .get(..size)
                .context("truncated roster boundary block")?,
            &crate::node::block_cfg(),
        )?;
        ensure!(block.height == height, "roster boundary height mismatch");
        let Some(Payload::EpochInfo(info)) = block.payload else {
            anyhow::bail!("roster boundary is missing its epoch artifact");
        };
        ensure!(
            info.epoch.get() == boundary_epoch,
            "roster artifact epoch mismatch"
        );
        ensure!(
            !info.next_players.is_empty(),
            "empty historical consensus roster"
        );
        Ok(Some(info.next_players))
    }
}
