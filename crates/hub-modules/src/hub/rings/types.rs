#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{Result, invalid};

pub const MAX_RING_REQUEST_BYTES: usize = 48 * 1024;
pub const MAX_RING_RECORD_BYTES: usize = 128 * 1024;
pub const MAX_RING_MEMBERS: usize = 256;

/// Creation parameters retained independently of subsequent ring state.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingConfig {
    pub policy_id: String,
    pub peer_node_keys: Vec<String>,
    pub threshold: u32,
    pub pss_interval: u64,
    pub current_version: u64,
    pub nonce: [u8; 32],
    /// None permanently disables relays; Some allows a bounded canonical set.
    pub trusted_auth_relay_dids: Option<Vec<String>>,
    pub reporting: ReportingConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportingConfig {
    pub node_offline_demerits: u64,
    pub invalid_crypto_response_demerits: u64,
    pub unauthorized_request_demerits: u64,
    pub reset_interval_seconds: u64,
    pub kick_threshold: u64,
    pub backup_node_keys: Vec<String>,
}

impl Default for ReportingConfig {
    fn default() -> Self {
        Self {
            node_offline_demerits: 1,
            invalid_crypto_response_demerits: 1,
            unauthorized_request_demerits: 1,
            reset_interval_seconds: 86400,
            kick_threshold: 3,
            backup_node_keys: Vec::new(),
        }
    }
}

impl RingConfig {
    pub fn validate(&self) -> Result<()> {
        if self.policy_id.len() != 64
            || hex::decode(&self.policy_id).is_err()
            || self.policy_id.bytes().any(|b| b.is_ascii_uppercase())
        {
            return Err(invalid("invalid ring policy identifier"));
        }
        keys(&self.peer_node_keys, false)?;
        keys(&self.reporting.backup_node_keys, true)?;
        if self.threshold == 0
            || self.threshold as usize > self.peer_node_keys.len()
            || self.pss_interval < 86400
            || self.reporting.reset_interval_seconds == 0
            || self.reporting.kick_threshold == 0
            || self.reporting.node_offline_demerits == 0
            || self.reporting.invalid_crypto_response_demerits == 0
            || self.reporting.unauthorized_request_demerits == 0
        {
            return Err(invalid(
                "invalid ring threshold, refresh interval or reporting bounds",
            ));
        }
        if let Some(relays) = &self.trusted_auth_relay_dids {
            if relays.len() > MAX_RING_MEMBERS || !sorted(relays) {
                return Err(invalid("relay set must be bounded, sorted and unique"));
            }
            for did in relays {
                if did.len() > 256 {
                    return Err(invalid("relay identity exceeds byte limit"));
                }
                let encoded = did
                    .strip_prefix("did:key:z")
                    .ok_or_else(|| invalid("relay must be an Ed25519 key DID"))?;
                let bytes = bs58::decode(encoded).into_vec().map_err(invalid)?;
                if bytes.len() != 34
                    || !bytes.starts_with(&[0xed, 0x01])
                    || bs58::encode(&bytes).into_string() != encoded
                {
                    return Err(invalid("relay must be a canonical Ed25519 key DID"));
                }
            }
        }
        Ok(())
    }

    /// Bind the immutable identity to the deployment, creator and all creation parameters.
    pub fn id(&self, deployment_root: [u8; 32], creator: &str) -> Result<String> {
        self.validate()?;
        identity::Did::new(creator).map_err(invalid)?;
        let bytes = borsh::to_vec(&(deployment_root, creator, self)).map_err(invalid)?;
        if bytes.len() > MAX_RING_REQUEST_BYTES {
            return Err(invalid("ring configuration exceeds byte limit"));
        }
        let mut hash = Sha256::new();
        hash.update(b"vera/orbis/ring/v1\0");
        hash.update(bytes);
        Ok(hex::encode(hash.finalize()))
    }
}

/// Confirmation requires every configured participant, matching the fresh-DKG protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RingState {
    Pending {
        public_key: Option<String>,
        confirmations: Vec<String>,
    },
    Active {
        public_key: String,
    },
    Cancelled {
        by: String,
    },
    Conflict {
        first_key: String,
        conflicting_key: String,
        by: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingRecord {
    pub id: String,
    pub deployment_root: [u8; 32],
    pub creator: String,
    pub config: RingConfig,
    pub state: RingState,
    pub revision: crate::types::Timestamp,
}

impl RingRecord {
    pub fn validate(&self, expected: &str) -> Result<()> {
        if self.id != expected
            || self.config.id(self.deployment_root, &self.creator)? != expected
            || self.revision.block_height == 0
            || self.revision.seconds == 0
        {
            return Err(invalid("ring record identity or revision mismatch"));
        }
        match &self.state {
            RingState::Pending {
                public_key,
                confirmations,
            } => {
                keys(confirmations, true)?;
                if confirmations.len() >= self.config.peer_node_keys.len()
                    || confirmations
                        .iter()
                        .any(|key| self.config.peer_node_keys.binary_search(key).is_err())
                    || public_key.is_some() == confirmations.is_empty()
                {
                    return Err(invalid("invalid pending confirmations"));
                }
                if let Some(key) = public_key {
                    public_key_value(key)?;
                }
            }
            RingState::Active { public_key } => public_key_value(public_key)?,
            RingState::Cancelled { by } => {
                identity::Did::new(by).map_err(invalid)?;
            }
            RingState::Conflict {
                first_key,
                conflicting_key,
                by,
            } => {
                public_key_value(first_key)?;
                public_key_value(conflicting_key)?;
                if first_key == conflicting_key
                    || self.config.peer_node_keys.binary_search(by).is_err()
                {
                    return Err(invalid("invalid conflicting confirmation"));
                }
            }
        }
        Ok(())
    }
}

/// Commands requiring an actor's delegation and ACP authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RingCommand {
    Create(RingConfig),
    Cancel { ring_id: String },
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RingParticipantCommand {
    Confirm(String),
    Cancel,
}

/// Participant confirmation, independent of the submission worker's identity and sequence.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RingParticipantRequest {
    pub deployment_root: [u8; 32],
    pub deployment_id: u64,
    pub ring_id: String,
    pub node_key: String,
    pub command: RingParticipantCommand,
    pub expires_at: u64,
}

impl RingParticipantRequest {
    pub fn signing_digest(&self) -> Result<[u8; 32]> {
        let bytes = borsh::to_vec(self).map_err(invalid)?;
        if bytes.len() > MAX_RING_REQUEST_BYTES {
            return Err(invalid("confirmation exceeds byte limit"));
        }
        let mut hash = Sha256::new();
        hash.update(b"vera/orbis/ring-participant/v1\0");
        hash.update(bytes);
        Ok(hash.finalize().into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRingParticipantRequest {
    pub request: RingParticipantRequest,
    pub signature: String,
}

pub(super) fn sorted(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn keys(values: &[String], empty: bool) -> Result<()> {
    if (!empty && values.is_empty()) || values.len() > MAX_RING_MEMBERS || !sorted(values) {
        return Err(invalid("node set must be bounded, sorted and unique"));
    }
    for key in values {
        super::super::nodes::node_key(key).map_err(invalid)?;
    }
    Ok(())
}

pub(super) fn public_key_value(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 8192
        || hex::decode(value).is_err()
        || value.bytes().any(|b| b.is_ascii_uppercase())
    {
        return Err(invalid("invalid public key declaration"));
    }
    Ok(())
}
