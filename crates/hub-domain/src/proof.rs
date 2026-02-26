//! Merkle inclusion/exclusion proofs for module state, verifiable against
//! the `module_state_root` committed in signed block headers.

use alloy_evm::revm::primitives::{B256, keccak256};
use borsh::BorshDeserialize;
use jmt::{KeyHash, RootHash, proof::SparseMerkleProof};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const MODULE_ROOT_NAMESPACE: &[u8] = b"_HUB_MODULE_ROOT";

/// Identifies which module tree a proof targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleId {
    /// Access control policy module.
    Acp = 0,
    /// Bulletin board module.
    Bulletin = 1,
    /// Hub identity module.
    Hub = 2,
    /// Native BLS nonce tracking.
    NativeNonce = 3,
}

impl ModuleId {
    /// Parse a module name string into a `ModuleId`.
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s {
            "acp" => Some(Self::Acp),
            "bulletin" => Some(Self::Bulletin),
            "hub" => Some(Self::Hub),
            "native_nonce" | "nonces" => Some(Self::NativeNonce),
            _ => None,
        }
    }

    /// Returns the index of this module in the roots array.
    pub const fn index(self) -> usize {
        self as usize
    }
}

/// Proof that a key-value pair exists (or doesn't exist) in a module's state,
/// verifiable against the block's `module_state_root`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleStateProof {
    /// Which module this proof targets.
    pub module: ModuleId,
    /// Block height this proof was generated at.
    pub height: u64,
    /// The key being proved (hex-encoded).
    pub key: String,
    /// The value at the key (hex-encoded), or null for non-existence proofs.
    pub value: Option<String>,
    /// JMT sparse Merkle proof (borsh-serialized, hex-encoded).
    pub jmt_proof: String,
    /// Root hash of this module's JMT.
    pub module_root: String,
    /// Root hashes of all 4 module trees (hex-encoded, order: acp, bulletin, hub, nonces).
    pub all_module_roots: [String; 4],
}

/// Errors from proof verification.
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    /// Hex decoding of the JMT proof bytes failed.
    #[error("failed to decode jmt_proof from hex: {0}")]
    JmtProofHex(String),
    /// Borsh deserialization of the JMT proof failed.
    #[error("failed to deserialize jmt_proof: {0}")]
    JmtProofDeserialize(String),
    /// Hex decoding of the module root failed.
    #[error("failed to decode module_root from hex: {0}")]
    ModuleRootHex(String),
    /// Hex decoding of one of the all_module_roots entries failed.
    #[error("failed to decode all_module_roots[{0}] from hex: {1}")]
    AllModuleRootsHex(usize, String),
    /// Hex decoding of the key failed.
    #[error("failed to decode key from hex: {0}")]
    KeyHex(String),
    /// Hex decoding of the value failed.
    #[error("failed to decode value from hex: {0}")]
    ValueHex(String),
    /// The module_root field doesn't match its slot in all_module_roots.
    #[error("module_root does not match all_module_roots[{0}]")]
    ModuleRootMismatch(usize),
    /// Recomputed module_state_root doesn't match the expected value.
    #[error("recomputed module_state_root does not match expected")]
    StateRootMismatch,
    /// The JMT sparse Merkle proof failed cryptographic verification.
    #[error("JMT proof verification failed: {0}")]
    JmtVerification(String),
}

fn decode_hex_32(s: &str) -> Result<[u8; 32], String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| e.to_string())?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("expected 32 bytes, got {}", bytes.len()))
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| e.to_string())
}

fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Recompute the combined module state root from 4 per-module JMT roots.
fn recompute_state_root(roots: &[[u8; 32]; 4]) -> B256 {
    let mut buf = Vec::with_capacity(MODULE_ROOT_NAMESPACE.len() + 128);
    buf.extend_from_slice(MODULE_ROOT_NAMESPACE);
    for root in roots {
        buf.extend_from_slice(root);
    }
    keccak256(buf)
}

impl ModuleStateProof {
    /// Construct a proof from raw components (used by the RPC handler).
    pub fn new(
        module: ModuleId,
        height: u64,
        key: &[u8],
        value: Option<&[u8]>,
        jmt_proof: &SparseMerkleProof<Sha256>,
        module_root: [u8; 32],
        all_module_roots: [[u8; 32]; 4],
    ) -> Self {
        let jmt_bytes = borsh::to_vec(jmt_proof).expect("borsh serialization is infallible");
        Self {
            module,
            height,
            key: encode_hex(key),
            value: value.map(encode_hex),
            jmt_proof: encode_hex(&jmt_bytes),
            module_root: encode_hex(&module_root),
            all_module_roots: [
                encode_hex(&all_module_roots[0]),
                encode_hex(&all_module_roots[1]),
                encode_hex(&all_module_roots[2]),
                encode_hex(&all_module_roots[3]),
            ],
        }
    }
}

/// Verify a module state proof against a `module_state_root`.
///
/// Performs cheap cross-module checks first (root consistency, state root
/// recomputation), then deserializes and cryptographically verifies the
/// JMT sparse Merkle proof.
pub fn verify_module_state_proof(
    module_state_root: B256,
    proof: &ModuleStateProof,
) -> Result<(), ProofError> {
    let module_root = decode_hex_32(&proof.module_root).map_err(ProofError::ModuleRootHex)?;

    let mut all_roots = [[0u8; 32]; 4];
    for (i, hex_root) in proof.all_module_roots.iter().enumerate() {
        all_roots[i] = decode_hex_32(hex_root).map_err(|e| ProofError::AllModuleRootsHex(i, e))?;
    }

    let idx = proof.module.index();
    if all_roots[idx] != module_root {
        return Err(ProofError::ModuleRootMismatch(idx));
    }

    let recomputed = recompute_state_root(&all_roots);
    if recomputed != module_state_root {
        return Err(ProofError::StateRootMismatch);
    }

    let jmt_proof_bytes = decode_hex(&proof.jmt_proof).map_err(ProofError::JmtProofHex)?;
    let jmt_proof: SparseMerkleProof<Sha256> =
        BorshDeserialize::try_from_slice(&jmt_proof_bytes)
            .map_err(|e| ProofError::JmtProofDeserialize(e.to_string()))?;

    let key_bytes = decode_hex(&proof.key).map_err(ProofError::KeyHex)?;
    let key_hash = KeyHash::with::<Sha256>(&key_bytes);

    let value_bytes = match &proof.value {
        Some(hex_val) => Some(decode_hex(hex_val).map_err(ProofError::ValueHex)?),
        None => None,
    };

    jmt_proof
        .verify(RootHash(module_root), key_hash, value_bytes)
        .map_err(|e| ProofError::JmtVerification(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jmt::{Sha256Jmt, mock::MockTreeStore};

    fn make_jmt_proof(
        key: &[u8],
        value: &[u8],
    ) -> (SparseMerkleProof<Sha256>, [u8; 32], Option<Vec<u8>>) {
        let store = MockTreeStore::default();
        let tree = Sha256Jmt::new(&store);
        let key_hash = KeyHash::with::<Sha256>(key);
        let (root, batch) = tree
            .put_value_set([(key_hash, Some(value.to_vec()))], 1)
            .unwrap();
        store.write_tree_update_batch(batch).unwrap();
        let (val, proof) = tree.get_with_proof(key_hash, 1).unwrap();
        (proof, root.0, val)
    }

    fn make_nonexistence_proof(
        existing_key: &[u8],
        existing_val: &[u8],
        absent_key: &[u8],
    ) -> (SparseMerkleProof<Sha256>, [u8; 32]) {
        let store = MockTreeStore::default();
        let tree = Sha256Jmt::new(&store);
        let key_hash = KeyHash::with::<Sha256>(existing_key);
        let (root, batch) = tree
            .put_value_set([(key_hash, Some(existing_val.to_vec()))], 1)
            .unwrap();
        store.write_tree_update_batch(batch).unwrap();
        let absent_hash = KeyHash::with::<Sha256>(absent_key);
        let (val, proof) = tree.get_with_proof(absent_hash, 1).unwrap();
        assert!(val.is_none());
        (proof, root.0)
    }

    #[test]
    fn module_id_from_str() {
        assert_eq!(ModuleId::from_str_name("acp"), Some(ModuleId::Acp));
        assert_eq!(
            ModuleId::from_str_name("bulletin"),
            Some(ModuleId::Bulletin)
        );
        assert_eq!(ModuleId::from_str_name("hub"), Some(ModuleId::Hub));
        assert_eq!(
            ModuleId::from_str_name("native_nonce"),
            Some(ModuleId::NativeNonce)
        );
        assert_eq!(
            ModuleId::from_str_name("nonces"),
            Some(ModuleId::NativeNonce)
        );
        assert_eq!(ModuleId::from_str_name("unknown"), None);
    }

    #[test]
    fn module_id_index() {
        assert_eq!(ModuleId::Acp.index(), 0);
        assert_eq!(ModuleId::Bulletin.index(), 1);
        assert_eq!(ModuleId::Hub.index(), 2);
        assert_eq!(ModuleId::NativeNonce.index(), 3);
    }

    #[test]
    fn recompute_state_root_deterministic() {
        let roots = [[0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32], [0xDDu8; 32]];
        let r1 = recompute_state_root(&roots);
        let r2 = recompute_state_root(&roots);
        assert_eq!(r1, r2);
        assert_ne!(r1, B256::ZERO);
    }

    #[test]
    fn recompute_state_root_sensitive_to_order() {
        let roots_a = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let roots_b = [[2u8; 32], [1u8; 32], [3u8; 32], [4u8; 32]];
        assert_ne!(
            recompute_state_root(&roots_a),
            recompute_state_root(&roots_b)
        );
    }

    #[test]
    fn encode_decode_hex_roundtrip() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = encode_hex(&data);
        assert_eq!(encoded, "0xdeadbeef");
        let decoded = decode_hex(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn existence_proof_roundtrip() {
        let key = b"relationship/policy-1/resource:doc1:reader:did:key:z6Mk";
        let value = b"exists";
        let (jmt_proof, module_root, val) = make_jmt_proof(key, value);
        assert_eq!(val, Some(value.to_vec()));

        let all_roots = [module_root, [0xBBu8; 32], [0xCCu8; 32], [0xDDu8; 32]];
        let module_state_root = recompute_state_root(&all_roots);

        let proof = ModuleStateProof::new(
            ModuleId::Acp,
            42,
            key,
            Some(value),
            &jmt_proof,
            module_root,
            all_roots,
        );

        assert!(verify_module_state_proof(module_state_root, &proof).is_ok());
    }

    #[test]
    fn nonexistence_proof_roundtrip() {
        let (jmt_proof, module_root) =
            make_nonexistence_proof(b"existing-key", b"val", b"absent-key");

        let all_roots = [module_root, [0xBBu8; 32], [0xCCu8; 32], [0xDDu8; 32]];
        let module_state_root = recompute_state_root(&all_roots);

        let proof = ModuleStateProof::new(
            ModuleId::Acp,
            42,
            b"absent-key",
            None,
            &jmt_proof,
            module_root,
            all_roots,
        );

        assert!(verify_module_state_proof(module_state_root, &proof).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_value() {
        let key = b"policy/objs/policy-1";
        let value = b"correct-value";
        let (jmt_proof, module_root, _) = make_jmt_proof(key, value);

        let all_roots = [module_root, [0xBBu8; 32], [0xCCu8; 32], [0xDDu8; 32]];
        let module_state_root = recompute_state_root(&all_roots);

        let proof = ModuleStateProof::new(
            ModuleId::Acp,
            42,
            key,
            Some(b"tampered-value"),
            &jmt_proof,
            module_root,
            all_roots,
        );

        let result = verify_module_state_proof(module_state_root, &proof);
        assert!(matches!(result, Err(ProofError::JmtVerification(_))));
    }

    #[test]
    fn verify_rejects_module_root_mismatch() {
        let proof = ModuleStateProof {
            module: ModuleId::Acp,
            height: 1,
            key: encode_hex(b"test"),
            value: Some(encode_hex(b"val")),
            jmt_proof: encode_hex(&[0]),
            module_root: encode_hex(&[0xAAu8; 32]),
            all_module_roots: [
                encode_hex(&[0xBBu8; 32]),
                encode_hex(&[0x00u8; 32]),
                encode_hex(&[0x00u8; 32]),
                encode_hex(&[0x00u8; 32]),
            ],
        };
        let result = verify_module_state_proof(B256::ZERO, &proof);
        assert!(matches!(result, Err(ProofError::ModuleRootMismatch(0))));
    }

    #[test]
    fn verify_rejects_state_root_mismatch() {
        let module_root = [0xAAu8; 32];
        let proof = ModuleStateProof {
            module: ModuleId::Acp,
            height: 1,
            key: encode_hex(b"test"),
            value: Some(encode_hex(b"val")),
            jmt_proof: encode_hex(&[0]),
            module_root: encode_hex(&module_root),
            all_module_roots: [
                encode_hex(&module_root),
                encode_hex(&[0x00u8; 32]),
                encode_hex(&[0x00u8; 32]),
                encode_hex(&[0x00u8; 32]),
            ],
        };
        let wrong_state_root = B256::repeat_byte(0xFF);
        let result = verify_module_state_proof(wrong_state_root, &proof);
        assert!(matches!(result, Err(ProofError::StateRootMismatch)));
    }

    #[test]
    fn verify_different_modules() {
        let key = b"bulletin/ns/test";
        let value = b"post-data";
        let (jmt_proof, bulletin_root, _) = make_jmt_proof(key, value);

        let all_roots = [[0xAAu8; 32], bulletin_root, [0xCCu8; 32], [0xDDu8; 32]];
        let module_state_root = recompute_state_root(&all_roots);

        let proof = ModuleStateProof::new(
            ModuleId::Bulletin,
            10,
            key,
            Some(value),
            &jmt_proof,
            bulletin_root,
            all_roots,
        );

        assert!(verify_module_state_proof(module_state_root, &proof).is_ok());
    }

    #[test]
    fn proof_serde_roundtrip() {
        let key = b"test-key";
        let value = b"test-value";
        let (jmt_proof, module_root, _) = make_jmt_proof(key, value);

        let all_roots = [module_root, [0xBBu8; 32], [0xCCu8; 32], [0xDDu8; 32]];
        let proof = ModuleStateProof::new(
            ModuleId::Acp,
            42,
            key,
            Some(value),
            &jmt_proof,
            module_root,
            all_roots,
        );

        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: ModuleStateProof = serde_json::from_str(&json).unwrap();

        let module_state_root = recompute_state_root(&all_roots);
        assert!(verify_module_state_proof(module_state_root, &deserialized).is_ok());
    }
}
