use commonware_consensus::simplex::scheme::ed25519::Scheme;
use commonware_cryptography::{Signer as _, ed25519};
use commonware_utils::{TryCollect as _, ordered::Set};

/// Ed25519 multisig signing scheme used for consensus.
pub type Ed25519Scheme = Scheme;

pub(crate) const SIMPLEX_NAMESPACE: &[u8] = b"_COMMONWARE_HUB_SIMPLEX";

/// Generate deterministic ed25519 signing schemes from a seed.
///
/// Derives ed25519 participant keys from `seed + i` and builds `Scheme::signer()` for each.
/// Returns `(participants, schemes)` where both vectors share the same ordering
/// (the `Set`-sorted participant order).
pub fn generate_ed25519_schemes(
    seed: u64,
    n: usize,
) -> anyhow::Result<(Vec<ed25519::PublicKey>, Vec<Ed25519Scheme>)> {
    let private_keys: Vec<ed25519::PrivateKey> = (0..n)
        .map(|i| ed25519::PrivateKey::from_seed(seed.wrapping_add(i as u64)))
        .collect();

    let participants: Set<ed25519::PublicKey> = private_keys
        .iter()
        .map(|k| k.public_key())
        .try_collect()
        .expect("participant public keys are unique");

    let ordered_pks: Vec<ed25519::PublicKey> = participants.iter().cloned().collect();

    let mut schemes = Vec::with_capacity(n);
    for pk in participants.iter() {
        let private_key = private_keys
            .iter()
            .find(|k| k.public_key() == *pk)
            .expect("private key exists for participant")
            .clone();
        let scheme = Scheme::signer(SIMPLEX_NAMESPACE, participants.clone(), private_key)
            .ok_or_else(|| anyhow::anyhow!("failed to create signer"))?;
        schemes.push(scheme);
    }

    Ok((ordered_pks, schemes))
}

/// Generate an ed25519 scheme for a specific validator identified by its identity key.
///
/// Returns `(scheme, validator_index)`.
pub fn generate_for_validator(
    seed: u64,
    n: usize,
    identity_key: &ed25519::PrivateKey,
) -> anyhow::Result<(Ed25519Scheme, u32)> {
    let (participants, schemes) = generate_ed25519_schemes(seed, n)?;

    let my_pk = identity_key.public_key();
    let validator_index = participants
        .iter()
        .position(|pk| *pk == my_pk)
        .ok_or_else(|| {
            anyhow::anyhow!("identity key not found in participants derived from seed {seed}")
        })?;

    let scheme = schemes.into_iter().nth(validator_index).unwrap();

    Ok((scheme, validator_index as u32))
}
