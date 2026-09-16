//! Verification of the threshold signatures used by Orbis service rings.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha512};

/// Signature formats supported by existing Orbis rings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdScheme {
    /// BLS with a compressed G1 public key and G2 signature, using the basic NUL suite.
    #[serde(rename = "bls12_381_g1_pk_g2_sig_nul")]
    Bls12381,
    /// Orbis FROST over decaf377 with its existing challenge domain.
    #[serde(rename = "decaf377_frost")]
    Decaf377Frost,
}

/// The encoding, group element or signature equation is invalid.
#[derive(Debug, thiserror::Error)]
#[error("invalid threshold signature")]
pub struct InvalidThresholdSignature;

/// Verify an aggregate signature against the existing ring key.
pub fn verify(
    scheme: ThresholdScheme,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidThresholdSignature> {
    let valid = match scheme {
        ThresholdScheme::Bls12381 => {
            if public_key.len() != 48 || signature.len() != 96 {
                return Err(InvalidThresholdSignature);
            }
            let key = blst::min_pk::PublicKey::from_bytes(public_key)
                .map_err(|_| InvalidThresholdSignature)?;
            let signature = blst::min_pk::Signature::from_bytes(signature)
                .map_err(|_| InvalidThresholdSignature)?;
            signature.verify(
                true,
                message,
                b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
                &[],
                &key,
                true,
            ) == blst::BLST_ERROR::BLST_SUCCESS
        }
        ThresholdScheme::Decaf377Frost => {
            use decaf377::{Element, Encoding, Fr};
            if public_key.len() != 32 || signature.len() != 64 {
                return Err(InvalidThresholdSignature);
            }
            let key = Encoding(
                public_key
                    .try_into()
                    .map_err(|_| InvalidThresholdSignature)?,
            )
            .vartime_decompress()
            .map_err(|_| InvalidThresholdSignature)?;
            let r = Encoding(
                signature[..32]
                    .try_into()
                    .map_err(|_| InvalidThresholdSignature)?,
            )
            .vartime_decompress()
            .map_err(|_| InvalidThresholdSignature)?;
            let z = Fr::from_bytes_checked(
                signature[32..]
                    .try_into()
                    .map_err(|_| InvalidThresholdSignature)?,
            )
            .map_err(|_| InvalidThresholdSignature)?;
            if key == Element::default() {
                return Err(InvalidThresholdSignature);
            }
            let mut challenge = Sha512::new();
            challenge.update(b"FROST-decaf377-challenge");
            challenge.update(&signature[..32]);
            challenge.update(public_key);
            challenge.update(message);
            let c = Fr::from_le_bytes_mod_order(&challenge.finalize());
            Element::GENERATOR * z == r + key * c
        }
    };
    if valid {
        Ok(())
    } else {
        Err(InvalidThresholdSignature)
    }
}

#[cfg(test)]
mod tests;
