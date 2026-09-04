//! Trusted-dealer bootstrap for local networks: one dealer produces the
//! epoch-0 sharing and every participant's share.

use commonware_codec::Encode as _;
use commonware_consensus::types::Epoch;
use commonware_cryptography::bls12381::{
    dkg::feldman_desmedt::{Output, deal},
    primitives::{group::Share, variant::MinSig},
};
use commonware_glue::dkg::types::{EpochInfo, EpochOutcome};
use commonware_utils::{
    N3f1, TestRng,
    ordered::{Map, Set},
    sequence::Unit,
};
use hub_domain::PublicKey;

use crate::SHARING_MODE;

/// Epoch-0 artifact carried by the genesis block.
pub type GenesisEpochInfo = EpochInfo<MinSig, PublicKey, Unit>;

/// Deal an epoch-0 sharing among `participants` deterministically from `seed`.
pub fn trusted_setup(
    seed: u64,
    participants: impl IntoIterator<Item = PublicKey>,
) -> anyhow::Result<(GenesisEpochInfo, Map<PublicKey, Share>)> {
    let players: Set<PublicKey> = Set::from_iter_dedup(participants);
    let (output, shares): (Output<MinSig, PublicKey>, Map<PublicKey, Share>) =
        deal::<MinSig, _, N3f1>(TestRng::new(seed), SHARING_MODE, players.clone())
            .map_err(|e| anyhow::anyhow!("trusted deal failed: {e:?}"))?;
    let info = EpochInfo {
        outcome: EpochOutcome::Success,
        epoch: Epoch::zero(),
        output,
        players: players.clone(),
        next_players: players,
        directory: Unit,
    };
    Ok((info, shares))
}

/// Hex encoding of `info` as stored in `genesis.json`.
pub fn epoch_info_hex(info: &GenesisEpochInfo) -> String {
    format!("0x{}", hex::encode(info.encode()))
}
