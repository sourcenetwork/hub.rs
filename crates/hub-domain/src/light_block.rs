//! Light block type for header verification and standalone verification logic.

use alloy_evm::revm::primitives::B256;
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    simplex::types::Proposal,
    types::{Epoch, Round, View},
};
use commonware_cryptography::{Hasher as _, Sha256, Verifier as _, ed25519};
use serde::{Deserialize, Serialize};

use crate::ConsensusDigest;

const SIMPLEX_NAMESPACE: &[u8] = b"_COMMONWARE_HUB_SIMPLEX";
const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

/// A self-contained block snapshot for light client verification.
///
/// All binary fields are hex-encoded with `0x` prefix.
/// Returned by the `hub_getLightBlock` RPC endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightBlock {
    /// Block hash (hex 32 bytes).
    pub block_hash: String,
    /// Parent block hash (hex 32 bytes).
    pub parent_hash: String,
    /// Block height.
    pub height: u64,
    /// Block timestamp (unix seconds).
    pub timestamp: u64,
    /// EVM state root (hex 32 bytes).
    pub state_root: String,
    /// Combined module state root (hex 32 bytes).
    pub module_state_root: String,

    /// Consensus epoch.
    pub epoch: u64,
    /// View in which the block was finalized.
    pub view: u64,
    /// View of the parent proposal.
    pub parent_view: u64,
    /// SHA-256 of block_hash — the consensus payload digest (hex 32 bytes).
    pub proposal_payload: String,

    /// Indices of validators that signed the finalization certificate.
    pub signer_indices: Vec<u32>,
    /// Ed25519 signatures (hex 64 bytes each), ordered by signer index.
    pub signatures: Vec<String>,

    /// Ordered ed25519 validator public keys (hex 32 bytes each).
    pub validators: Vec<String>,
}

/// Errors from light block verification.
#[derive(Debug, thiserror::Error)]
pub enum LightBlockError {
    /// Hex decoding failed.
    #[error("failed to decode hex field '{0}': {1}")]
    HexDecode(&'static str, String),

    /// SHA-256(block_hash) does not match proposal_payload.
    #[error("SHA256(block_hash) does not match proposal_payload")]
    PayloadMismatch,

    /// A signer index exceeds the validator set size.
    #[error("signer index {0} out of range for validator set of size {1}")]
    SignerIndexOutOfRange(u32, usize),

    /// An ed25519 public key failed to decode.
    #[error("failed to decode validator public key at index {0}")]
    InvalidPublicKey(usize),

    /// An ed25519 signature failed to decode.
    #[error("failed to decode signature at index {0}")]
    InvalidSignature(usize),

    /// The signer_indices and signatures arrays differ in length.
    #[error("signer_indices and signatures have different lengths ({0} vs {1})")]
    LengthMismatch(usize, usize),

    /// Not enough valid signatures for a 2/3+1 quorum.
    #[error("insufficient valid signatures: got {got}, need {need}")]
    InsufficientSignatures {
        /// Valid signature count.
        got: usize,
        /// Required signature count.
        need: usize,
    },
}

fn decode_hex(field: &'static str, s: &str) -> Result<Vec<u8>, LightBlockError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| LightBlockError::HexDecode(field, e.to_string()))
}

fn decode_hex_32(field: &'static str, s: &str) -> Result<[u8; 32], LightBlockError> {
    let bytes = decode_hex(field, s)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        LightBlockError::HexDecode(field, format!("expected 32 bytes, got {}", bytes.len()))
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Verify a light block's finalization certificate against the embedded validator set.
///
/// Returns `(state_root, module_state_root)` on success.
///
/// Verification steps:
/// 1. `SHA256(block_hash) == proposal_payload`
/// 2. Reconstruct Simplex `Proposal` and encode it
/// 3. Verify each ed25519 signature against the finalize namespace
/// 4. Check quorum: `valid_sigs >= (2 * validators.len() / 3) + 1`
pub fn verify_light_block(block: &LightBlock) -> Result<(B256, B256), LightBlockError> {
    let block_hash_bytes = decode_hex_32("block_hash", &block.block_hash)?;
    let proposal_payload_bytes = decode_hex_32("proposal_payload", &block.proposal_payload)?;

    let mut hasher = Sha256::default();
    hasher.update(&block_hash_bytes);
    let computed_payload = hasher.finalize();
    if computed_payload.0 != proposal_payload_bytes {
        return Err(LightBlockError::PayloadMismatch);
    }

    if block.signer_indices.len() != block.signatures.len() {
        return Err(LightBlockError::LengthMismatch(
            block.signer_indices.len(),
            block.signatures.len(),
        ));
    }

    let mut finalize_ns = Vec::with_capacity(SIMPLEX_NAMESPACE.len() + FINALIZE_SUFFIX.len());
    finalize_ns.extend_from_slice(SIMPLEX_NAMESPACE);
    finalize_ns.extend_from_slice(FINALIZE_SUFFIX);

    let proposal = Proposal::new(
        Round::new(Epoch::new(block.epoch), View::new(block.view)),
        View::new(block.parent_view),
        ConsensusDigest::from(proposal_payload_bytes),
    );
    let proposal_bytes = proposal.encode();

    let mut validator_keys = Vec::with_capacity(block.validators.len());
    for (i, hex_pk) in block.validators.iter().enumerate() {
        let pk_bytes = decode_hex_32("validators", hex_pk)?;
        let pk = ed25519::PublicKey::decode(pk_bytes.as_ref())
            .map_err(|_| LightBlockError::InvalidPublicKey(i))?;
        validator_keys.push(pk);
    }

    let mut valid_sigs = 0usize;
    for (i, signer_index) in block.signer_indices.iter().enumerate() {
        let idx = *signer_index as usize;
        if idx >= validator_keys.len() {
            return Err(LightBlockError::SignerIndexOutOfRange(
                *signer_index,
                validator_keys.len(),
            ));
        }

        let sig_bytes = decode_hex("signatures", &block.signatures[i])?;
        if sig_bytes.len() != 64 {
            return Err(LightBlockError::InvalidSignature(i));
        }
        let sig = ed25519::Signature::decode(sig_bytes.as_ref())
            .map_err(|_| LightBlockError::InvalidSignature(i))?;

        if validator_keys[idx].verify(&finalize_ns, &proposal_bytes, &sig) {
            valid_sigs += 1;
        }
    }

    let required = (2 * block.validators.len() / 3) + 1;
    if valid_sigs < required {
        return Err(LightBlockError::InsufficientSignatures {
            got: valid_sigs,
            need: required,
        });
    }

    let state_root = B256::from(decode_hex_32("state_root", &block.state_root)?);
    let module_state_root = B256::from(decode_hex_32(
        "module_state_root",
        &block.module_state_root,
    )?);
    Ok((state_root, module_state_root))
}

impl LightBlock {
    /// Construct a `LightBlock` from raw components (used by the RPC handler).
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        block_hash: B256,
        parent_hash: B256,
        height: u64,
        timestamp: u64,
        state_root: B256,
        module_state_root: B256,
        epoch: u64,
        view: u64,
        parent_view: u64,
        payload: [u8; 32],
        signer_indices: Vec<u32>,
        signatures: Vec<[u8; 64]>,
        validators: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            block_hash: encode_hex(block_hash.as_slice()),
            parent_hash: encode_hex(parent_hash.as_slice()),
            height,
            timestamp,
            state_root: encode_hex(state_root.as_slice()),
            module_state_root: encode_hex(module_state_root.as_slice()),
            epoch,
            view,
            parent_view,
            proposal_payload: encode_hex(&payload),
            signer_indices,
            signatures: signatures.iter().map(|s| encode_hex(s)).collect(),
            validators: validators.iter().map(|v| encode_hex(v)).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::Signer as _;

    fn make_test_setup(
        n: usize,
    ) -> (
        Vec<ed25519::PrivateKey>,
        Vec<ed25519::PublicKey>,
        B256,
        [u8; 32],
    ) {
        let private_keys: Vec<_> = (0..n)
            .map(|i| ed25519::PrivateKey::from_seed(i as u64))
            .collect();
        let mut pubkeys: Vec<_> = private_keys.iter().map(|k| k.public_key()).collect();
        pubkeys.sort();

        let block_hash = B256::repeat_byte(0xAB);
        let mut hasher = Sha256::default();
        hasher.update(block_hash.as_slice());
        let payload = hasher.finalize();

        (private_keys, pubkeys, block_hash, payload.0)
    }

    fn sign_proposal(
        private_key: &ed25519::PrivateKey,
        finalize_ns: &[u8],
        proposal_bytes: &[u8],
    ) -> [u8; 64] {
        let sig = private_key.sign(finalize_ns, proposal_bytes);
        let encoded = sig.encode();
        let mut out = [0u8; 64];
        out.copy_from_slice(&encoded);
        out
    }

    fn build_valid_light_block(
        n: usize,
        signer_count: usize,
    ) -> (
        LightBlock,
        Vec<ed25519::PrivateKey>,
        Vec<ed25519::PublicKey>,
    ) {
        let (private_keys, pubkeys, block_hash, payload) = make_test_setup(n);

        let epoch = 0u64;
        let view = 1u64;
        let parent_view = 0u64;

        let proposal = Proposal::new(
            Round::new(Epoch::new(epoch), View::new(view)),
            View::new(parent_view),
            ConsensusDigest::from(payload),
        );
        let proposal_bytes = proposal.encode();

        let mut finalize_ns = Vec::with_capacity(SIMPLEX_NAMESPACE.len() + FINALIZE_SUFFIX.len());
        finalize_ns.extend_from_slice(SIMPLEX_NAMESPACE);
        finalize_ns.extend_from_slice(FINALIZE_SUFFIX);

        // Match private keys to sorted pubkey order for signing.
        let ordered_privkeys: Vec<_> = pubkeys
            .iter()
            .map(|pk| {
                private_keys
                    .iter()
                    .find(|sk| sk.public_key() == *pk)
                    .unwrap()
            })
            .collect();

        let mut signer_indices = Vec::new();
        let mut signatures = Vec::new();
        for i in 0..signer_count {
            let sig = sign_proposal(ordered_privkeys[i], &finalize_ns, &proposal_bytes);
            signer_indices.push(i as u32);
            signatures.push(sig);
        }

        let validators: Vec<[u8; 32]> = pubkeys
            .iter()
            .map(|pk| {
                let bytes: &[u8] = pk.as_ref();
                let mut out = [0u8; 32];
                out.copy_from_slice(bytes);
                out
            })
            .collect();

        let lb = LightBlock::from_parts(
            block_hash,
            B256::repeat_byte(0x01),
            42,
            1_700_000_000,
            B256::repeat_byte(0xCC),
            B256::repeat_byte(0xDD),
            epoch,
            view,
            parent_view,
            payload,
            signer_indices,
            signatures,
            validators,
        );

        (lb, private_keys, pubkeys)
    }

    #[test]
    fn valid_light_block_roundtrip() {
        let (lb, _, _) = build_valid_light_block(4, 3);
        let (state_root, module_state_root) = verify_light_block(&lb).unwrap();
        assert_eq!(state_root, B256::repeat_byte(0xCC));
        assert_eq!(module_state_root, B256::repeat_byte(0xDD));
    }

    #[test]
    fn rejects_tampered_block_hash() {
        let (mut lb, _, _) = build_valid_light_block(4, 3);
        lb.block_hash = encode_hex(&[0xFF; 32]);
        let err = verify_light_block(&lb).unwrap_err();
        assert!(matches!(err, LightBlockError::PayloadMismatch));
    }

    #[test]
    fn rejects_bad_signature() {
        let (mut lb, _, _) = build_valid_light_block(4, 3);
        lb.signatures[0] = encode_hex(&[0x00; 64]);
        // With 3 signers and 1 bad, only 2 valid. Need 3 for quorum of 4.
        let err = verify_light_block(&lb).unwrap_err();
        assert!(matches!(
            err,
            LightBlockError::InsufficientSignatures { .. }
        ));
    }

    #[test]
    fn rejects_insufficient_quorum() {
        let (lb, _, _) = build_valid_light_block(4, 2);
        let err = verify_light_block(&lb).unwrap_err();
        assert!(matches!(
            err,
            LightBlockError::InsufficientSignatures { got: 2, need: 3 }
        ));
    }

    #[test]
    fn serde_roundtrip() {
        let (lb, _, _) = build_valid_light_block(4, 3);
        let json = serde_json::to_string(&lb).unwrap();
        let deserialized: LightBlock = serde_json::from_str(&json).unwrap();
        let result = verify_light_block(&deserialized);
        assert!(result.is_ok());
    }
}
