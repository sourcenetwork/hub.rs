//! Self-contained BLS light blocks and standalone finality verification.

use alloy_evm::revm::primitives::{B256, keccak256};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Decode as _, DecodeExt as _, Encode as _, EncodeSize, Error as CodecError, RangeCfg, Read,
    Write,
};
use commonware_consensus::{
    simplex::{
        scheme::bls12381_threshold::vrf,
        types::{Finalization, Proposal},
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{
    Hasher as _, Sha256,
    bls12381::primitives::{
        sharing::{ModeVersion, Sharing},
        variant::{MinSig, Variant},
    },
};
use commonware_parallel::Sequential;
use commonware_utils::{NZU32, ordered::Set};
use serde::{Deserialize, Serialize};

use crate::{Block, BlockCfg, ConsensusDigest, PublicKey, TxCfg};

/// Simplex namespace shared with validator nodes.
pub const LIGHT_BLOCK_NAMESPACE: &[u8] = b"_COMMONWARE_HUB_SIMPLEX";
/// Maximum participant count accepted from an untrusted light-block response.
pub const LIGHT_BLOCK_MAX_PARTICIPANTS: u32 = 64;
const LIGHT_BLOCK_MAX_TXS: usize = 64;
const LIGHT_BLOCK_MAX_TX_BYTES: usize = 65_536;

/// The threshold VRF scheme whose recovered certificate finalizes Hub blocks.
pub type LightConsensusScheme = vrf::Scheme<PublicKey, MinSig>;

/// Public consensus identity, retained across resharing epochs.
pub type ConsensusPublicKey = <MinSig as Variant>::Public;

/// Public verifier material for one consensus epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochMaterial {
    /// Ordered ed25519 peer identities that received shares.
    pub participants: Set<PublicKey>,
    /// Public BLS group polynomial produced by DKG.
    pub sharing: Sharing<MinSig>,
}

impl EpochMaterial {
    /// Construct public material from a DKG output.
    #[must_use]
    pub const fn new(participants: Set<PublicKey>, sharing: Sharing<MinSig>) -> Self {
        Self {
            participants,
            sharing,
        }
    }

    /// Decode verifier material using the protocol's participant and sharing bounds.
    pub fn decode_bounded(bytes: &[u8]) -> Result<Self, LightBlockError> {
        Ok(Self::decode_cfg(
            bytes,
            &(LIGHT_BLOCK_MAX_PARTICIPANTS, ModeVersion::v0()),
        )?)
    }
}

impl Write for EpochMaterial {
    fn write(&self, buf: &mut impl BufMut) {
        self.participants.write(buf);
        self.sharing.write(buf);
    }
}

impl EncodeSize for EpochMaterial {
    fn encode_size(&self) -> usize {
        self.participants.encode_size() + self.sharing.encode_size()
    }
}

impl Read for EpochMaterial {
    type Cfg = (u32, ModeVersion);

    fn read_cfg(
        buf: &mut impl Buf,
        (max_participants, max_mode): &Self::Cfg,
    ) -> Result<Self, CodecError> {
        let participants =
            Set::read_cfg(buf, &(RangeCfg::new(1..=*max_participants as usize), ()))?;
        let sharing = Sharing::read_cfg(buf, &(NZU32!(*max_participants), *max_mode))?;
        Ok(Self {
            participants,
            sharing,
        })
    }
}

/// A finalized block and its certificate; verification requires a trusted consensus key.
///
/// Binary fields use `0x`-prefixed hex so the type remains directly usable over JSON-RPC.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightBlock {
    /// EVM block ID: keccak256 of the canonical Hub block encoding.
    pub block_hash: String,
    /// Parent EVM block ID.
    pub parent_hash: String,
    /// Block height.
    pub height: u64,
    /// Unix timestamp in seconds.
    pub timestamp: u64,
    /// EVM/QMDB state root.
    pub state_root: String,
    /// Combined native-module state root.
    pub module_state_root: String,
    /// Consensus epoch.
    pub epoch: u64,
    /// Consensus view.
    pub view: u64,
    /// Consensus view of the parent proposal.
    pub parent_view: u64,
    /// Canonical encoded [`Block`], which binds every displayed header field.
    pub block: String,
    /// Canonical encoded `Finalization<LightConsensusScheme, ConsensusDigest>`.
    pub finalization: String,
    /// Canonical encoded [`EpochMaterial`].
    pub epoch_material: String,
}

impl LightBlock {
    /// Construct the JSON-facing light block from canonical node artifacts.
    #[must_use]
    pub fn from_parts(block: &Block, finalization: &[u8], epoch_material: &[u8]) -> Self {
        Self {
            block_hash: encode_hex(block.id().0.as_slice()),
            parent_hash: encode_hex(block.parent.0.as_slice()),
            height: block.height,
            timestamp: block.timestamp,
            state_root: encode_hex(block.state_root.0.as_slice()),
            module_state_root: encode_hex(block.module_state_root.as_slice()),
            epoch: block.context.round.epoch().get(),
            view: block.context.round.view().get(),
            parent_view: block.context.parent.0.get(),
            block: encode_hex(&block.encode()),
            finalization: encode_hex(finalization),
            epoch_material: encode_hex(epoch_material),
        }
    }

    /// Construct from canonical block bytes retained alongside the finalization.
    pub fn from_encoded_block(
        block: &[u8],
        finalization: &[u8],
        epoch_material: &[u8],
    ) -> Result<Self, LightBlockError> {
        let decoded = decode_block(block)?;
        Ok(Self::from_parts(&decoded, finalization, epoch_material))
    }
}

/// Errors returned by [`verify_light_block`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LightBlockError {
    /// A JSON hex field could not be decoded.
    #[error("invalid {field} hex: {message}")]
    Hex {
        /// Name of the malformed JSON field.
        field: &'static str,
        /// Decoder detail.
        message: String,
    },
    /// A Commonware or Hub artifact could not be decoded.
    #[error("artifact decode failed: {0}")]
    Codec(String),
    /// Canonical block bytes do not hash to the advertised block ID.
    #[error("canonical block bytes do not match block_hash")]
    BlockHashMismatch,
    /// A displayed field differs from the authenticated canonical block.
    #[error("authenticated block field does not match: {0}")]
    BlockFieldMismatch(&'static str),
    /// Finalization proposal metadata or payload differs from the block.
    #[error("finalization proposal does not match the authenticated block")]
    ProposalMismatch,
    /// Epoch material is structurally inconsistent.
    #[error("invalid epoch material: {0}")]
    EpochMaterial(String),
    /// The response names a different consensus identity from the trusted deployment.
    #[error("light block consensus key does not match the trusted key")]
    UntrustedConsensusKey,
    /// The aggregate threshold finalization certificate is invalid.
    #[error("BLS threshold finalization certificate verification failed")]
    InvalidCertificate,
}

impl From<CodecError> for LightBlockError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error.to_string())
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn decode_hex(field: &'static str, value: &str) -> Result<Vec<u8>, LightBlockError> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value)).map_err(|error| LightBlockError::Hex {
        field,
        message: error.to_string(),
    })
}

fn decode_b256(field: &'static str, value: &str) -> Result<B256, LightBlockError> {
    let bytes = decode_hex(field, value)?;
    B256::try_from(bytes.as_slice()).map_err(|_| LightBlockError::Hex {
        field,
        message: format!("expected 32 bytes, got {}", bytes.len()),
    })
}

fn decode_block(bytes: &[u8]) -> Result<Block, LightBlockError> {
    Ok(Block::decode_cfg(
        bytes,
        &BlockCfg {
            max_txs: LIGHT_BLOCK_MAX_TXS,
            tx: TxCfg {
                max_tx_bytes: LIGHT_BLOCK_MAX_TX_BYTES,
            },
        },
    )?)
}

/// Verify a block's finalization against an independently trusted consensus key.
///
/// Obtain `trusted_key` from the deployment's authenticated bootstrap configuration,
/// never from the response being verified. The identity remains constant across
/// resharing epochs. Epoch material in the response cannot establish trust.
/// Returns the authenticated `(state_root, module_state_root)` on success.
pub fn verify_light_block(
    light: &LightBlock,
    trusted_key: &ConsensusPublicKey,
) -> Result<(B256, B256), LightBlockError> {
    let block_hash = decode_b256("block_hash", &light.block_hash)?;
    let block_bytes = decode_hex("block", &light.block)?;
    if keccak256(&block_bytes) != block_hash {
        return Err(LightBlockError::BlockHashMismatch);
    }
    let block = decode_block(&block_bytes)?;

    let checks = [
        (
            block.parent.0 == decode_b256("parent_hash", &light.parent_hash)?,
            "parent_hash",
        ),
        (block.height == light.height, "height"),
        (block.timestamp == light.timestamp, "timestamp"),
        (
            block.state_root.0 == decode_b256("state_root", &light.state_root)?,
            "state_root",
        ),
        (
            block.module_state_root == decode_b256("module_state_root", &light.module_state_root)?,
            "module_state_root",
        ),
        (block.context.round.epoch().get() == light.epoch, "epoch"),
        (block.context.round.view().get() == light.view, "view"),
        (
            block.context.parent.0.get() == light.parent_view,
            "parent_view",
        ),
    ];
    if let Some((_, field)) = checks.into_iter().find(|(matches, _)| !matches) {
        return Err(LightBlockError::BlockFieldMismatch(field));
    }

    let material_bytes = decode_hex("epoch_material", &light.epoch_material)?;
    let material = EpochMaterial::decode_bounded(&material_bytes)?;
    if material.participants.is_empty()
        || material.sharing.total().get() as usize != material.participants.len()
    {
        return Err(LightBlockError::EpochMaterial(
            "participant set and sharing polynomial disagree".into(),
        ));
    }

    if material.sharing.public() != trusted_key {
        return Err(LightBlockError::UntrustedConsensusKey);
    }

    let expected = Proposal::new(
        Round::new(Epoch::new(light.epoch), View::new(light.view)),
        View::new(light.parent_view),
        Sha256::hash(&[block_hash.as_slice()]),
    );
    let finalization_bytes = decode_hex("finalization", &light.finalization)?;
    let finalization: Finalization<LightConsensusScheme, ConsensusDigest> =
        Finalization::decode(finalization_bytes.as_slice())?;
    if finalization.proposal != expected {
        return Err(LightBlockError::ProposalMismatch);
    }

    let verifier = LightConsensusScheme::certificate_verifier(LIGHT_BLOCK_NAMESPACE, *trusted_key);
    if !finalization.verify(&mut commonware_utils::test_rng(), &verifier, &Sequential) {
        return Err(LightBlockError::InvalidCertificate);
    }

    Ok((block.state_root.0, block.module_state_root))
}

#[cfg(test)]
mod tests {
    use alloy_primitives::Bytes;
    use commonware_consensus::simplex::types::Finalize;
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
}
