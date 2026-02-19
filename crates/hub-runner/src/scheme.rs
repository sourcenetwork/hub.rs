use anyhow::Context as _;
use commonware_consensus::simplex::scheme::bls12381_threshold::vrf;
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg,
        primitives::{sharing::Mode, variant::MinSig},
    },
    ed25519,
};
use commonware_utils::{N3f1, TryCollect as _, ordered::Set};
use rand::{SeedableRng as _, rngs::StdRng};

/// BLS12-381 threshold signature scheme used for consensus.
pub type ThresholdScheme = vrf::Scheme<ed25519::PublicKey, MinSig>;

const SIMPLEX_NAMESPACE: &[u8] = b"_COMMONWARE_HUB_SIMPLEX";

/// Generate deterministic threshold BLS signing schemes using trusted-dealer mode.
///
/// Derives ed25519 participant keys from `seed + i` and calls `dkg::deal()`.
/// Returns `(participants, schemes)` where both vectors share the same ordering
/// (the `Set`-sorted participant order).
pub fn generate_threshold_schemes(
    seed: u64,
    n: usize,
) -> anyhow::Result<(Vec<ed25519::PublicKey>, Vec<ThresholdScheme>)> {
    let participants: Set<ed25519::PublicKey> = (0..n)
        .map(|i| ed25519::PrivateKey::from_seed(seed.wrapping_add(i as u64)).public_key())
        .try_collect()
        .expect("participant public keys are unique");

    let mut rng = StdRng::seed_from_u64(seed);
    let (output, shares) =
        dkg::deal::<MinSig, _, N3f1>(&mut rng, Mode::default(), participants.clone())
            .context("dkg deal failed")?;

    let mut schemes = Vec::with_capacity(n);
    for pk in participants.iter() {
        let share = shares.get_value(pk).expect("share exists").clone();
        let scheme = vrf::Scheme::signer(
            SIMPLEX_NAMESPACE,
            participants.clone(),
            output.public().clone(),
            share,
        )
        .context("failed to create signer")?;
        schemes.push(scheme);
    }

    Ok((participants.into(), schemes))
}

/// Generate a threshold scheme for a specific validator identified by its identity key.
///
/// Returns `(scheme, group_public_key_bytes, validator_index)`.
pub fn generate_for_validator(
    seed: u64,
    n: usize,
    identity_key: &ed25519::PrivateKey,
) -> anyhow::Result<(ThresholdScheme, Vec<u8>, u32)> {
    let (participants, schemes) = generate_threshold_schemes(seed, n)?;

    let my_pk = identity_key.public_key();
    let validator_index = participants
        .iter()
        .position(|pk| *pk == my_pk)
        .ok_or_else(|| {
            anyhow::anyhow!("identity key not found in participants derived from seed {seed}")
        })?;

    let scheme = schemes.into_iter().nth(validator_index).unwrap();

    let mut group_pub_key = Vec::new();
    commonware_codec::Write::write(scheme.identity(), &mut group_pub_key);

    Ok((scheme, group_pub_key, validator_index as u32))
}
