use alloy_primitives::Bytes;
use commonware_consensus::{
    simplex::types::Finalize,
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    Digestible as _, Signer as _, bls12381::dkg::feldman_desmedt::deal, ed25519,
};
use commonware_utils::{N3f1, TestRng, non_empty};

use super::*;
use crate::{BlockId, ConsensusContext, DbTargets, StateRoot};

fn fixture(
    seed: u64,
) -> (
    Vec<LightConsensusScheme>,
    LightConsensusScheme,
    EpochMaterial,
) {
    let keys = Set::from_iter_dedup(
        (0..4).map(|index| ed25519::PrivateKey::from_seed(seed + index).public_key()),
    );
    let mut rng = TestRng::new(seed);
    let (output, shares) = deal::<MinSig, _, N3f1>(
        &mut rng,
        commonware_cryptography::bls12381::primitives::sharing::Mode::NonZeroCounter,
        keys,
    )
    .expect("trusted deal");
    let signers = shares
        .into_iter()
        .map(|(_, share)| {
            LightConsensusScheme::signer(
                LIGHT_BLOCK_NAMESPACE,
                output.players().clone(),
                output.public().clone(),
                share,
            )
            .expect("matching share")
        })
        .collect();
    let verifier = LightConsensusScheme::verifier(
        LIGHT_BLOCK_NAMESPACE,
        output.players().clone(),
        output.public().clone(),
    );
    let material = EpochMaterial::new(output.players().clone(), output.public().clone());
    (signers, verifier, material)
}

fn light_fixture(seed: u64) -> LightBlock {
    let (signers, verifier, material) = fixture(seed);
    let leader = material
        .participants
        .iter()
        .next()
        .expect("participants are non-empty")
        .clone();
    let round = Round::new(Epoch::new(3), View::new(17));
    let block = Block {
        context: ConsensusContext {
            round,
            leader,
            parent: (View::new(16), ConsensusDigest::from([0x44; 32])),
        },
        parent: BlockId(B256::repeat_byte(0x07)),
        height: 100,
        timestamp: 1_700_000_000,
        prevrandao: B256::repeat_byte(0x55),
        state_root: StateRoot(B256::repeat_byte(0x01)),
        module_state_root: B256::repeat_byte(0x02),
        txs: vec![crate::Tx::new(Bytes::from_static(b"light-block"))],
        payload: None,
        native_targets: None,
        receipt_commitment: Some(B256::repeat_byte(9)),
        db_targets: DbTargets::default(),
    };
    let proposal = Proposal::new(round, View::new(16), block.digest());
    let votes: Vec<_> = signers
        .iter()
        .take(3)
        .map(|signer| Finalize::sign(signer, proposal.clone()).expect("sign vote"))
        .collect();
    let finalization =
        Finalization::from_finalizes(&verifier, non_empty![@votes.iter()], &Sequential)
            .expect("assemble quorum");
    LightBlock::from_parts(&block, &finalization.encode(), &material.encode())
}

fn trusted_key() -> ConsensusPublicKey {
    *fixture(42).2.sharing.public()
}

#[test]
fn unrelated_consensus_group_is_rejected() {
    let light = light_fixture(100);
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::UntrustedConsensusKey)
    );
}

#[test]
fn valid_light_block_verifies() {
    let light = light_fixture(42);
    assert_eq!(
        verify_light_block(&light, &trusted_key()).unwrap(),
        (B256::repeat_byte(0x01), B256::repeat_byte(0x02))
    );
}

#[test]
fn displayed_header_tampering_fails() {
    let mut light = light_fixture(42);
    light.module_state_root = encode_hex(B256::repeat_byte(0x99).as_slice());
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::BlockFieldMismatch("module_state_root"))
    );
}

#[test]
fn proposal_payload_tampering_fails() {
    let mut light = light_fixture(42);
    let encoded = decode_hex("finalization", &light.finalization).unwrap();
    let mut finalization: Finalization<LightConsensusScheme, ConsensusDigest> =
        Finalization::decode(encoded.as_slice()).unwrap();
    finalization.proposal.payload = ConsensusDigest::from([0x99; 32]);
    light.finalization = encode_hex(&finalization.encode());
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::ProposalMismatch)
    );
}

#[test]
fn malformed_finalization_fails() {
    let mut light = light_fixture(42);
    light.finalization = "0xdeadbeef".into();
    assert!(matches!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::Codec(_))
    ));
}

#[test]
fn wrong_epoch_material_fails() {
    let mut light = light_fixture(42);
    let (_, _, other) = fixture(100);
    light.epoch_material = encode_hex(&other.encode());
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::UntrustedConsensusKey)
    );
}

#[test]
fn substituted_certificate_is_rejected() {
    let mut light = light_fixture(42);
    let mut finalization: Finalization<LightConsensusScheme, ConsensusDigest> =
        Finalization::decode(
            decode_hex("finalization", &light.finalization)
                .unwrap()
                .as_slice(),
        )
        .unwrap();
    let unrelated: Finalization<LightConsensusScheme, ConsensusDigest> = Finalization::decode(
        decode_hex("finalization", &light_fixture(100).finalization)
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    finalization.certificate = unrelated.certificate;
    light.finalization = encode_hex(&finalization.encode());
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::InvalidCertificate)
    );
}

#[test]
fn json_round_trip_preserves_verifiability() {
    let light = light_fixture(42);
    let json = serde_json::to_string(&light).unwrap();
    let decoded: LightBlock = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, light);
    verify_light_block(&decoded, &trusted_key()).unwrap();
}

fn indirect_fixture(count: usize) -> LightBlock {
    let mut light = light_fixture(42);
    let mut parent = decode_block(&decode_hex("block", &light.block).unwrap()).unwrap();
    for index in 0..count {
        let mut child = parent.clone();
        child.parent = parent.id();
        child.height += 1;
        child.timestamp += 1;
        child.state_root = StateRoot(B256::repeat_byte(0x30));
        child.module_state_root = B256::repeat_byte(0x40);
        child.context.parent = (parent.context.round.view(), parent.digest());
        child.context.round = Round::new(Epoch::new(4), View::new(index as u64 + 1));
        light.descendants.push(encode_hex(&child.encode()));
        parent = child;
    }
    light.finalization = signed_finalization(&parent, 42);
    light
}

fn signed_finalization(block: &Block, seed: u64) -> String {
    let (signers, verifier, _) = fixture(seed);
    let proposal = Proposal::new(block.context.round, block.context.parent.0, block.digest());
    let votes: Vec<_> = signers
        .iter()
        .take(3)
        .map(|signer| Finalize::sign(signer, proposal.clone()).unwrap())
        .collect();
    let finalization =
        Finalization::from_finalizes(&verifier, non_empty![@votes.iter()], &Sequential).unwrap();
    encode_hex(&finalization.encode())
}

#[test]
fn descendant_certificate_authenticates_the_requested_roots_across_epochs() {
    let light = indirect_fixture(3);
    assert_eq!(light.epoch, 3);
    let requested = verify_finalized_block(&light, &trusted_key()).unwrap();
    assert_eq!(requested.height, light.height);
    assert_eq!(requested.context.round.epoch().get(), light.epoch);
    assert_eq!(
        requested,
        decode_block(&decode_hex("block", &light.block).unwrap()).unwrap()
    );
    assert_eq!(
        verify_light_block(&light, &trusted_key()).unwrap(),
        (B256::repeat_byte(1), B256::repeat_byte(2))
    );
    let decoded: LightBlock =
        serde_json::from_str(&serde_json::to_string(&light).unwrap()).unwrap();
    assert_eq!(decoded, light);
    verify_light_block(&decoded, &trusted_key()).unwrap();
    let direct = serde_json::to_value(light_fixture(42)).unwrap();
    assert!(direct.get("descendants").is_none());
    verify_light_block(&serde_json::from_value(direct).unwrap(), &trusted_key()).unwrap();
}

#[test]
fn descendant_omission_reordering_and_substitution_are_rejected() {
    let light = indirect_fixture(3);
    for index in 0..light.descendants.len() {
        let mut missing = light.clone();
        missing.descendants.remove(index);
        assert!(verify_light_block(&missing, &trusted_key()).is_err());
    }
    let mut reversed = light.clone();
    reversed.descendants.reverse();
    assert_eq!(
        verify_light_block(&reversed, &trusted_key()),
        Err(LightBlockError::AncestryMismatch)
    );
    let mut changed = light.clone();
    let mut child =
        decode_block(&decode_hex("descendant", &changed.descendants[0]).unwrap()).unwrap();
    child.module_state_root = B256::repeat_byte(0x99);
    changed.descendants[0] = encode_hex(&child.encode());
    assert_eq!(
        verify_light_block(&changed, &trusted_key()),
        Err(LightBlockError::AncestryMismatch)
    );
    let mut duplicate = light.clone();
    duplicate
        .descendants
        .insert(1, duplicate.descendants[0].clone());
    assert_eq!(
        verify_light_block(&duplicate, &trusted_key()),
        Err(LightBlockError::AncestryMismatch)
    );
    let mut disconnected = light;
    disconnected.block = light_fixture(100).block;
    disconnected.block_hash =
        encode_hex(&keccak256(decode_hex("block", &disconnected.block).unwrap()).0);
    assert_eq!(
        verify_light_block(&disconnected, &trusted_key()),
        Err(LightBlockError::AncestryMismatch)
    );
}

#[test]
fn signed_height_gaps_and_untrusted_descendant_certificates_are_rejected() {
    let mut light = indirect_fixture(1);
    let mut child =
        decode_block(&decode_hex("descendant", &light.descendants[0]).unwrap()).unwrap();
    light.finalization = signed_finalization(&child, 100);
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::InvalidCertificate)
    );
    child.height += 1;
    light.descendants[0] = encode_hex(&child.encode());
    light.finalization = signed_finalization(&child, 42);
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::AncestryMismatch)
    );
}

#[test]
fn proof_limits_apply_before_decoding() {
    let mut light = indirect_fixture(LIGHT_BLOCK_MAX_DESCENDANTS);
    verify_light_block(&light, &trusted_key()).unwrap();
    light.descendants.push("invalid hex".into());
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::LimitExceeded)
    );
    light = light_fixture(42);
    let others = light.finalization.len() - 2 + light.epoch_material.len() - 2;
    light.block = "0".repeat(LIGHT_BLOCK_MAX_ARTIFACT_BYTES * 2 - others);
    light.check_artifact_limits().unwrap();
    light.block.push('0');
    assert_eq!(
        verify_light_block(&light, &trusted_key()),
        Err(LightBlockError::LimitExceeded)
    );
}
