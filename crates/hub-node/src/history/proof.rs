use super::*;
use hub_domain::{LIGHT_BLOCK_MAX_ARTIFACT_BYTES, LIGHT_BLOCK_MAX_DESCENDANTS, LightBlock};

impl FinalizedHistory {
    /// Assemble a bounded ancestry proof from one durable history snapshot.
    pub fn light_block(&self, height: u64, epochs: &LightBlockIndex) -> Result<LightBlock> {
        let snapshot = self.db.snapshot();
        ensure!(
            snapshot.get(transfer::IMPORT)?.is_none(),
            "history import is not published"
        );
        let (head, _): (u64, [u8; 32]) =
            borsh::from_slice(&snapshot.get(HEAD)?.context("missing history head")?)?;
        ensure!(
            height > 0 && height <= head,
            "block not found at height {height}"
        );
        let last = head.min(height.saturating_add(LIGHT_BLOCK_MAX_DESCENDANTS as u64));
        let mut blocks = Vec::new();
        let mut previous = None;
        let mut remaining = LIGHT_BLOCK_MAX_ARTIFACT_BYTES;
        for current in height..=last {
            let record = snapshot
                .get(key(RECORD, current))?
                .context("missing finalized history block")?;
            let mut encoded = record.as_slice();
            let length = u32::deserialize(&mut encoded)? as usize;
            remaining = remaining
                .checked_sub(length)
                .context("light block proof exceeds artifact limits")?;
            let encoded = encoded
                .get(..length)
                .context("truncated finalized history block")?;
            let block = Block::decode_cfg(encoded, &crate::node::block_cfg())?;
            ensure!(block.height == current, "finalized history height mismatch");
            if let Some(parent) = previous {
                ensure!(
                    block.parent == parent,
                    "finalized history ancestry mismatch"
                );
            }
            previous = Some(block.id());
            blocks.push(encoded.to_vec());
            let certificate = snapshot
                .get(key(CERTIFICATE, current))?
                .map(|bytes| borsh::from_slice::<Option<(u64, Vec<u8>)>>(&bytes))
                .transpose()?
                .flatten();
            if let Some((epoch, certificate)) = certificate {
                ensure!(
                    epoch == block.context.round.epoch().get(),
                    "finalized history epoch mismatch"
                );
                let material = epochs
                    .get_epoch_material(epoch)
                    .context("epoch material not found for finalized history")?;
                ensure!(
                    certificate
                        .len()
                        .checked_add(material.bytes.len())
                        .is_some_and(|length| length <= remaining),
                    "light block proof exceeds artifact limits"
                );
                let mut blocks = blocks.into_iter();
                let mut light = LightBlock::from_encoded_block(
                    &blocks.next().expect("requested block is retained"),
                    &certificate,
                    &material.bytes,
                )?;
                light.descendants = blocks
                    .map(|bytes| format!("0x{}", hex::encode(bytes)))
                    .collect();
                light.check_artifact_limits()?;
                return Ok(light);
            }
        }
        anyhow::bail!(
            "finalization certificate not found for height {height} within retained proof limits"
        )
    }
}
