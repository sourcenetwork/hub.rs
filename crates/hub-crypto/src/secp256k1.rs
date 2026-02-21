//! secp256k1 public key recovery and `did:key:` derivation.
//!
//! Parallel to [`bls`](super::bls) — provides DID derivation for EVM transaction signers
//! by recovering the secp256k1 public key from ECDSA signatures.

use alloy_primitives::{B256, Signature as AlloySig};
use k256::ecdsa::{RecoveryId, Signature as K256Sig, VerifyingKey};

/// secp256k1 multicodec prefix (`secp256k1-pub`, 0xe7).
const SECP256K1_PUB_MULTICODEC: u64 = 0xe7;

/// Errors from secp256k1 operations.
#[derive(Debug, thiserror::Error)]
pub enum Secp256k1Error {
    /// Compressed public key must be exactly 33 bytes.
    #[error("invalid compressed pubkey length: expected 33 bytes, got {0}")]
    InvalidPubkeyLength(usize),
    /// ECDSA public key recovery failed.
    #[error("pubkey recovery failed: {0}")]
    Recovery(String),
}

/// Derive a `did:key:` identifier from a compressed secp256k1 public key (33 bytes).
///
/// Encoding: `did:key:` + multibase(Base58Btc, varint(0xe7) || compressed_pubkey).
pub fn did_from_secp256k1_pubkey(compressed_pubkey: &[u8]) -> Result<String, Secp256k1Error> {
    if compressed_pubkey.len() != 33 {
        return Err(Secp256k1Error::InvalidPubkeyLength(compressed_pubkey.len()));
    }

    let mut varint_buf = [0u8; 10];
    let varint = unsigned_varint::encode::u64(SECP256K1_PUB_MULTICODEC, &mut varint_buf);

    let mut codec_bytes = Vec::with_capacity(varint.len() + compressed_pubkey.len());
    codec_bytes.extend_from_slice(varint);
    codec_bytes.extend_from_slice(compressed_pubkey);

    let encoded = multibase::encode(multibase::Base::Base58Btc, &codec_bytes);
    Ok(format!("did:key:{encoded}"))
}

/// Recover the compressed secp256k1 public key (33 bytes) from an ECDSA signature.
pub fn recover_pubkey(signature: &AlloySig, sighash: &B256) -> Result<Vec<u8>, Secp256k1Error> {
    let r_bytes: [u8; 32] = signature.r().to_be_bytes();
    let s_bytes: [u8; 32] = signature.s().to_be_bytes();

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r_bytes);
    sig_bytes[32..].copy_from_slice(&s_bytes);

    let k256_sig = K256Sig::from_bytes((&sig_bytes).into())
        .map_err(|e| Secp256k1Error::Recovery(e.to_string()))?;

    let recovery_id = RecoveryId::new(signature.v(), false);

    let verifying_key =
        VerifyingKey::recover_from_prehash(sighash.as_ref(), &k256_sig, recovery_id)
            .map_err(|e| Secp256k1Error::Recovery(e.to_string()))?;

    Ok(verifying_key.to_encoded_point(true).as_bytes().to_vec())
}

/// Recover a `did:key:` identifier from an ECDSA signature and signing hash.
///
/// Combines [`recover_pubkey`] and [`did_from_secp256k1_pubkey`].
pub fn recover_did(signature: &AlloySig, sighash: &B256) -> Result<String, Secp256k1Error> {
    let pubkey = recover_pubkey(signature, sighash)?;
    did_from_secp256k1_pubkey(&pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn test_keypair() -> (SigningKey, Vec<u8>) {
        let secret = [42u8; 32];
        let signing_key = SigningKey::from_bytes((&secret).into()).unwrap();
        let compressed = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        (signing_key, compressed)
    }

    #[test]
    fn did_from_secp256k1_pubkey_valid_format() {
        let (_sk, pubkey) = test_keypair();
        let did = did_from_secp256k1_pubkey(&pubkey).unwrap();

        assert!(
            did.starts_with("did:key:zQ3s"),
            "secp256k1 did:key should start with zQ3s, got: {did}"
        );

        let multibase_part = &did["did:key:".len()..];
        let (_base, decoded) = multibase::decode(multibase_part).unwrap();

        let mut varint_buf = [0u8; 10];
        let expected_prefix =
            unsigned_varint::encode::u64(SECP256K1_PUB_MULTICODEC, &mut varint_buf);
        assert_eq!(&decoded[..expected_prefix.len()], expected_prefix);
        assert_eq!(&decoded[expected_prefix.len()..], pubkey.as_slice());
    }

    #[test]
    fn did_is_deterministic() {
        let (_sk, pubkey) = test_keypair();
        let did1 = did_from_secp256k1_pubkey(&pubkey).unwrap();
        let did2 = did_from_secp256k1_pubkey(&pubkey).unwrap();
        assert_eq!(did1, did2);
    }

    #[test]
    fn did_rejects_wrong_length_pubkey() {
        assert!(did_from_secp256k1_pubkey(&[0u8; 32]).is_err());
        assert!(did_from_secp256k1_pubkey(&[0u8; 65]).is_err());
        assert!(did_from_secp256k1_pubkey(&[]).is_err());
    }

    #[test]
    fn recover_did_roundtrip() {
        use k256::ecdsa::signature::hazmat::PrehashSigner;

        let (signing_key, pubkey) = test_keypair();
        let expected_did = did_from_secp256k1_pubkey(&pubkey).unwrap();

        let msg_hash = B256::from([0xAB; 32]);
        let (sig, recovery_id): (K256Sig, RecoveryId) = signing_key
            .sign_prehash_recoverable(msg_hash.as_ref())
            .unwrap();

        let sig_bytes = sig.to_bytes();
        let r = alloy_primitives::U256::from_be_slice(&sig_bytes[..32]);
        let s = alloy_primitives::U256::from_be_slice(&sig_bytes[32..]);
        let alloy_sig = AlloySig::new(r, s, recovery_id.is_y_odd());

        let recovered_did = recover_did(&alloy_sig, &msg_hash).unwrap();
        assert_eq!(recovered_did, expected_did);
    }
}
