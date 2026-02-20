//! BLS12-381 signing, verification, and `did:key:` derivation.
//!
//! Matches orbis-rs conventions: G1 pubkeys (48 bytes), G2 signatures (96 bytes),
//! IETF-standard hash-to-curve DST.

use ark_bls12_381::{Bls12_381, G1Affine, G2Affine, G2Projective, g2::Config as G2Config};
use ark_ec::{
    AffineRepr, CurveGroup,
    hashing::{HashToCurve, curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher},
    pairing::Pairing,
};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::Sha256;

/// IETF-standard BLS signature DST (matches orbis-rs `sign.rs:27`).
const BLS_SIG_DOMAIN: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// BLS multicodec prefix for `bls12_381-g1-pub`.
const BLS_G1_MULTICODEC: u64 = 0xea;

/// Errors from BLS operations.
#[derive(Debug, thiserror::Error)]
pub enum BlsError {
    /// Hash-to-curve failed.
    #[error("hash-to-curve failed")]
    HashToCurve,
    /// Point serialization failed.
    #[error("serialization failed")]
    Serialize,
    /// Point deserialization failed.
    #[error("deserialization failed")]
    Deserialize,
    /// Signature verification failed (pairing mismatch).
    #[error("invalid signature")]
    InvalidSignature,
}

/// Hash a message to a G2 point using the IETF hash-to-curve suite.
///
/// Ported from orbis-rs `sign.rs:201-223`.
pub fn hash_to_g2(msg: &[u8]) -> Result<G2Affine, BlsError> {
    type G2Hasher =
        MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256>, WBMap<G2Config>>;
    let hasher = G2Hasher::new(BLS_SIG_DOMAIN).map_err(|_| BlsError::HashToCurve)?;
    let point: G2Affine = hasher.hash(msg).map_err(|_| BlsError::HashToCurve)?;
    if point.is_zero() {
        return Err(BlsError::HashToCurve);
    }
    Ok(point)
}

/// Sign a message with a BLS secret key, producing a compressed G2 signature (96 bytes).
pub fn sign(secret_key: &ark_bls12_381::Fr, msg: &[u8]) -> Result<Vec<u8>, BlsError> {
    let h_msg = hash_to_g2(msg)?;
    let sig: G2Affine = (G2Projective::from(h_msg) * secret_key).into_affine();
    let mut bytes = Vec::with_capacity(96);
    sig.serialize_compressed(&mut bytes)
        .map_err(|_| BlsError::Serialize)?;
    Ok(bytes)
}

/// Verify a BLS signature against a G1 public key and message.
///
/// Rejects identity points for both the public key and signature to prevent
/// trivial forgery via degenerate pairing (matches orbis-rs `sign.rs:157-190`).
pub fn verify(pubkey: &G1Affine, msg: &[u8], sig_bytes: &[u8]) -> Result<(), BlsError> {
    if pubkey.is_zero() {
        return Err(BlsError::InvalidSignature);
    }

    let sig = G2Affine::deserialize_compressed(sig_bytes).map_err(|_| BlsError::Deserialize)?;
    if sig.is_zero() {
        return Err(BlsError::InvalidSignature);
    }

    let h_msg = hash_to_g2(msg)?;
    let g1_gen = G1Affine::generator();

    let lhs = Bls12_381::pairing(*pubkey, h_msg);
    let rhs = Bls12_381::pairing(g1_gen, sig);

    if lhs != rhs {
        return Err(BlsError::InvalidSignature);
    }
    Ok(())
}

/// Deserialize a compressed BLS G1 public key (48 bytes).
pub fn deserialize_pubkey(bytes: &[u8]) -> Result<G1Affine, BlsError> {
    G1Affine::deserialize_compressed(bytes).map_err(|_| BlsError::Deserialize)
}

/// Derive a `did:key:` identifier from a BLS G1 public key.
///
/// Encoding: `did:key:` + multibase(Base58Btc, varint(0xea) || compressed_pubkey).
pub fn did_from_bls_pubkey(pubkey: &G1Affine) -> Result<String, BlsError> {
    let mut varint_buf = [0u8; 10];
    let varint = unsigned_varint::encode::u64(BLS_G1_MULTICODEC, &mut varint_buf);

    let mut pubkey_bytes = Vec::with_capacity(48);
    pubkey
        .serialize_compressed(&mut pubkey_bytes)
        .map_err(|_| BlsError::Serialize)?;

    let mut codec_bytes = Vec::with_capacity(varint.len() + pubkey_bytes.len());
    codec_bytes.extend_from_slice(varint);
    codec_bytes.extend_from_slice(&pubkey_bytes);

    let encoded = multibase::encode(multibase::Base::Base58Btc, &codec_bytes);
    Ok(format!("did:key:{encoded}"))
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::UniformRand;
    use ark_serialize::CanonicalSerialize;
    use ark_std::test_rng;

    use super::*;

    fn generate_keypair() -> (Fr, G1Affine) {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let pk = (G1Projective::from(G1Affine::generator()) * sk).into_affine();
        (sk, pk)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (sk, pk) = generate_keypair();
        let msg = b"test message";
        let sig = sign(&sk, msg).expect("sign");
        verify(&pk, msg, &sig).expect("verify");
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let (sk, pk) = generate_keypair();
        let sig = sign(&sk, b"correct message").expect("sign");
        let result = verify(&pk, b"wrong message", &sig);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (sk, _pk) = generate_keypair();
        let msg = b"test message";
        let sig = sign(&sk, msg).expect("sign");

        let mut rng = test_rng();
        // Use a different seed to get a different key.
        let _ = Fr::rand(&mut rng);
        let sk2 = Fr::rand(&mut rng);
        let pk2 = (G1Projective::from(G1Affine::generator()) * sk2).into_affine();

        let result = verify(&pk2, msg, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn did_derivation_valid_format() {
        let (_sk, pk) = generate_keypair();
        let did = did_from_bls_pubkey(&pk).expect("did");
        assert!(
            did.starts_with("did:key:z"),
            "DID should start with did:key:z, got: {did}"
        );

        let multibase_part = &did["did:key:".len()..];
        let (_base, decoded) = multibase::decode(multibase_part).expect("multibase decode");

        let mut varint_buf = [0u8; 10];
        let expected_prefix = unsigned_varint::encode::u64(BLS_G1_MULTICODEC, &mut varint_buf);
        assert_eq!(&decoded[..expected_prefix.len()], expected_prefix);

        let recovered_pk =
            G1Affine::deserialize_compressed(&decoded[expected_prefix.len()..]).expect("deser pk");
        assert_eq!(recovered_pk, pk);
    }

    #[test]
    fn did_is_deterministic() {
        let (_sk, pk) = generate_keypair();
        let did1 = did_from_bls_pubkey(&pk).expect("did1");
        let did2 = did_from_bls_pubkey(&pk).expect("did2");
        assert_eq!(did1, did2);
    }

    #[test]
    fn verify_rejects_identity_pubkey() {
        let (sk, _pk) = generate_keypair();
        let msg = b"test message";
        let sig = sign(&sk, msg).expect("sign");
        let identity = G1Affine::zero();
        assert!(verify(&identity, msg, &sig).is_err());
    }

    #[test]
    fn verify_rejects_identity_signature() {
        let (_sk, pk) = generate_keypair();
        let msg = b"test message";
        let mut sig_bytes = Vec::new();
        G2Affine::zero()
            .serialize_compressed(&mut sig_bytes)
            .expect("serialize identity");
        assert!(verify(&pk, msg, &sig_bytes).is_err());
    }

    #[test]
    fn pubkey_serialization_roundtrip() {
        let (_sk, pk) = generate_keypair();
        let mut bytes = Vec::with_capacity(48);
        pk.serialize_compressed(&mut bytes).expect("serialize");
        assert_eq!(bytes.len(), 48);
        let recovered = deserialize_pubkey(&bytes).expect("deserialize");
        assert_eq!(recovered, pk);
    }
}
