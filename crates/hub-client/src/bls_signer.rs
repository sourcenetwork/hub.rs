//! BLS12-381 signer for native transactions.

use std::sync::atomic::{AtomicU64, Ordering};

use alloy_primitives::{Address, Bytes, FixedBytes};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use hub_crypto::bls;
use hub_domain::NativeTx;

use crate::error::ClientError;

/// BLS12-381 signer for native hub transactions.
///
/// Wraps a single BLS keypair with a chain ID. Tracks nonces locally
/// since there is no RPC endpoint to query native nonces.
///
/// In production, orbis-rs produces threshold BLS signatures via DKG,
/// but the wire format is identical. This signer enables testing
/// without a full orbis cluster.
#[derive(Debug)]
pub struct BlsSigner {
    secret_key: Fr,
    pubkey_bytes: FixedBytes<48>,
    did: String,
    chain_id: u64,
    nonce: AtomicU64,
}

impl BlsSigner {
    /// Create a signer from a BLS secret key scalar and chain ID.
    pub fn new(secret_key: Fr, chain_id: u64) -> Result<Self, ClientError> {
        let public_key = (G1Projective::from(G1Affine::generator()) * secret_key).into_affine();

        let mut pk_bytes = Vec::with_capacity(48);
        public_key
            .serialize_compressed(&mut pk_bytes)
            .map_err(|e| ClientError::Bls(format!("pubkey serialize: {e}")))?;
        let pubkey_bytes = FixedBytes::from_slice(&pk_bytes);

        let did =
            bls::did_from_bls_pubkey(&public_key).map_err(|e| ClientError::Bls(e.to_string()))?;

        Ok(Self {
            secret_key,
            pubkey_bytes,
            did,
            chain_id,
            nonce: AtomicU64::new(0),
        })
    }

    /// Generate a random BLS keypair for testing.
    pub fn random(chain_id: u64) -> Result<Self, ClientError> {
        let mut rng = rand::thread_rng();
        let sk = Fr::rand(&mut rng);
        Self::new(sk, chain_id)
    }

    /// Return the `did:key:` identifier derived from this signer's public key.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Return the compressed G1 public key bytes (48 bytes).
    pub const fn pubkey_bytes(&self) -> &FixedBytes<48> {
        &self.pubkey_bytes
    }

    /// Return the chain ID this signer targets.
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Return the current local nonce counter.
    pub fn nonce(&self) -> u64 {
        self.nonce.load(Ordering::SeqCst)
    }

    /// Build, sign, and encode a native transaction in wire format.
    ///
    /// Increments the local nonce counter on success.
    pub fn sign_native_tx(&self, target: Address, calldata: Bytes) -> Result<Vec<u8>, ClientError> {
        let nonce = self.nonce.load(Ordering::SeqCst);

        let mut tx = NativeTx {
            chain_id: self.chain_id,
            nonce,
            bls_pubkey: self.pubkey_bytes,
            target,
            calldata,
            signature: FixedBytes::from([0u8; 96]),
        };

        let signing_data = tx.signing_data();
        let sig_bytes = bls::sign(&self.secret_key, &signing_data)
            .map_err(|e| ClientError::Bls(e.to_string()))?;
        tx.signature = FixedBytes::from_slice(&sig_bytes);

        let wire = tx.encode_wire();
        self.nonce.fetch_add(1, Ordering::SeqCst);
        Ok(wire)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use hub_domain::NativeTx;

    use super::*;

    fn test_signer() -> BlsSigner {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        BlsSigner::new(sk, 1337).unwrap()
    }

    #[test]
    fn new_valid_key() {
        let signer = test_signer();
        assert!(signer.did().starts_with("did:key:z"));
        assert_eq!(signer.chain_id(), 1337);
    }

    #[test]
    fn random_produces_valid_signer() {
        let signer = BlsSigner::random(42).unwrap();
        assert!(signer.did().starts_with("did:key:z"));
        assert_eq!(signer.chain_id(), 42);
    }

    #[test]
    fn random_produces_different_signers() {
        let s1 = BlsSigner::random(1).unwrap();
        let s2 = BlsSigner::random(1).unwrap();
        assert_ne!(s1.did(), s2.did());
    }

    #[test]
    fn pubkey_bytes_length() {
        let signer = test_signer();
        assert_eq!(signer.pubkey_bytes().len(), 48);
    }

    #[test]
    fn did_is_deterministic() {
        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let s1 = BlsSigner::new(sk, 1).unwrap();
        let s2 = BlsSigner::new(sk, 1).unwrap();
        assert_eq!(s1.did(), s2.did());
    }

    #[test]
    fn sign_native_tx_produces_valid_wire_format() {
        let signer = test_signer();
        let target = Address::from([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x08, 0x10,
        ]);
        let calldata = Bytes::from(vec![0xde, 0xad]);

        let wire = signer.sign_native_tx(target, calldata).unwrap();
        assert_eq!(wire[0], 0x45);

        let decoded = NativeTx::decode_wire(&wire).unwrap();
        assert_eq!(decoded.chain_id, 1337);
        assert_eq!(decoded.nonce, 0);
        assert_eq!(decoded.bls_pubkey, *signer.pubkey_bytes());
        assert_eq!(decoded.target, target);
    }

    #[test]
    fn sign_native_tx_signature_verifies() {
        let signer = test_signer();
        let target = Address::ZERO;
        let calldata = Bytes::from(vec![0x01, 0x02]);

        let wire = signer.sign_native_tx(target, calldata).unwrap();
        let decoded = NativeTx::decode_wire(&wire).unwrap();

        let signing_data = decoded.signing_data();
        let pk = bls::deserialize_pubkey(decoded.bls_pubkey.as_slice()).unwrap();
        bls::verify(&pk, &signing_data, decoded.signature.as_slice()).unwrap();
    }

    #[test]
    fn nonce_increments() {
        let signer = test_signer();
        let target = Address::ZERO;

        let wire1 = signer.sign_native_tx(target, Bytes::new()).unwrap();
        let tx1 = NativeTx::decode_wire(&wire1).unwrap();
        assert_eq!(tx1.nonce, 0);

        let wire2 = signer.sign_native_tx(target, Bytes::new()).unwrap();
        let tx2 = NativeTx::decode_wire(&wire2).unwrap();
        assert_eq!(tx2.nonce, 1);
    }

    #[test]
    fn different_calldata_produces_different_wire() {
        let target = Address::ZERO;

        let mut rng = test_rng();
        let sk = Fr::rand(&mut rng);
        let s1 = BlsSigner::new(sk, 1).unwrap();
        let s2 = BlsSigner::new(sk, 1).unwrap();

        let wire1 = s1.sign_native_tx(target, Bytes::from(vec![0x01])).unwrap();
        let wire2 = s2.sign_native_tx(target, Bytes::from(vec![0x02])).unwrap();
        assert_ne!(wire1, wire2);
    }
}
