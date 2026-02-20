//! ACP module key prefixes and builders.
//!
//! Matches Go `x/acp/types/keys.go`. Auto-increment stores use
//! `objs/` and `counter/` sub-prefixes as defined by the mod.rs
//! storage spec.

/// Access decision prefix (string-keyed objects).
pub const ACCESS_DECISION_PREFIX: &[u8] = b"access_decision/";
/// Registration commitment prefix (auto-increment objects).
pub const COMMITMENT_PREFIX: &[u8] = b"commitment/";
/// Amendment event prefix (auto-increment objects).
pub const AMENDMENT_EVENT_PREFIX: &[u8] = b"amendment_event/";
/// Signed policy command replay cache prefix.
pub const SIGNED_POLICY_CMD_SEEN_PREFIX: &[u8] = b"spc_seen/";
/// Module parameters key.
pub const PARAMS_KEY: &[u8] = b"p_acp";

/// Object storage sub-prefix (within auto-increment stores).
pub const OBJS_SUBPREFIX: &[u8] = b"objs/";
/// Counter sub-prefix (within auto-increment stores).
pub const COUNTER_SUBPREFIX: &[u8] = b"counter/";

/// Access decision key: `prefix + decision_id`.
pub fn access_decision_key(decision_id: &str) -> Vec<u8> {
    let mut key = Vec::from(ACCESS_DECISION_PREFIX);
    key.extend_from_slice(decision_id.as_bytes());
    key
}

/// Commitment object key: `"commitment/objs/" + BE(id)`.
pub fn commitment_key(id: u64) -> Vec<u8> {
    let mut key = Vec::from(COMMITMENT_PREFIX);
    key.extend_from_slice(OBJS_SUBPREFIX);
    key.extend_from_slice(&id.to_be_bytes());
    key
}

/// Commitment counter key: `"commitment/counter/id"`.
pub fn commitment_counter_key() -> Vec<u8> {
    let mut key = Vec::from(COMMITMENT_PREFIX);
    key.extend_from_slice(COUNTER_SUBPREFIX);
    key.extend_from_slice(b"id");
    key
}

/// Amendment event object key: `"amendment_event/objs/" + BE(id)`.
pub fn amendment_event_key(id: u64) -> Vec<u8> {
    let mut key = Vec::from(AMENDMENT_EVENT_PREFIX);
    key.extend_from_slice(OBJS_SUBPREFIX);
    key.extend_from_slice(&id.to_be_bytes());
    key
}

/// Amendment event counter key: `"amendment_event/counter/id"`.
pub fn amendment_event_counter_key() -> Vec<u8> {
    let mut key = Vec::from(AMENDMENT_EVENT_PREFIX);
    key.extend_from_slice(COUNTER_SUBPREFIX);
    key.extend_from_slice(b"id");
    key
}

/// Signed policy command replay cache key: `prefix + payload_id`.
pub fn signed_policy_cmd_key(payload_id: &[u8]) -> Vec<u8> {
    let mut key = Vec::from(SIGNED_POLICY_CMD_SEEN_PREFIX);
    key.extend_from_slice(payload_id);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_decision_key_format() {
        let key = access_decision_key("ABCDEF123");
        assert!(key.starts_with(ACCESS_DECISION_PREFIX));
        assert_eq!(&key[ACCESS_DECISION_PREFIX.len()..], b"ABCDEF123");
    }

    #[test]
    fn commitment_key_big_endian() {
        let key = commitment_key(42);
        let id_bytes = &key[key.len() - 8..];
        assert_eq!(u64::from_be_bytes(id_bytes.try_into().unwrap()), 42);
    }

    #[test]
    fn commitment_key_includes_objs_subprefix() {
        let key = commitment_key(1);
        let prefix_len = COMMITMENT_PREFIX.len() + OBJS_SUBPREFIX.len();
        let key_str = String::from_utf8_lossy(&key[..prefix_len]);
        assert_eq!(key_str, "commitment/objs/");
    }

    #[test]
    fn counter_keys_are_stable() {
        let ck = commitment_counter_key();
        assert_eq!(ck, b"commitment/counter/id");

        let ak = amendment_event_counter_key();
        assert_eq!(ak, b"amendment_event/counter/id");
    }

    #[test]
    fn amendment_event_key_big_endian() {
        let key = amendment_event_key(256);
        let id_bytes = &key[key.len() - 8..];
        assert_eq!(u64::from_be_bytes(id_bytes.try_into().unwrap()), 256);
    }

    #[test]
    fn signed_policy_cmd_key_format() {
        let payload_id = [0xAA; 32];
        let key = signed_policy_cmd_key(&payload_id);
        assert!(key.starts_with(SIGNED_POLICY_CMD_SEEN_PREFIX));
        assert_eq!(&key[SIGNED_POLICY_CMD_SEEN_PREFIX.len()..], &payload_id);
    }

    #[test]
    fn borsh_roundtrip_access_decision() {
        use borsh::BorshDeserialize;

        use crate::acp::types::{AccessDecision, DecisionParams, Object, Operation};
        use crate::types::Timestamp;

        let decision = AccessDecision {
            id: "DECISION123".into(),
            policy_id: "pol1".into(),
            creator: "did:key:z6Mk".into(),
            creator_acc_sequence: 5,
            operations: vec![Operation {
                object: Object {
                    resource: "namespace".into(),
                    id: "ns1".into(),
                },
                permission: "create_post".into(),
            }],
            actor: "did:key:z6Mk".into(),
            params: DecisionParams {
                decision_expiration_delta: 100,
                proof_expiration_delta: 50,
                ticket_expiration_delta: 100,
            },
            creation_time: Timestamp {
                seconds: 1000,
                block_height: 42,
            },
            issued_height: 42,
        };
        let encoded = borsh::to_vec(&decision).unwrap();
        let decoded = AccessDecision::try_from_slice(&encoded).unwrap();
        assert_eq!(decision, decoded);
    }

    #[test]
    fn borsh_roundtrip_registrations_commitment() {
        use borsh::BorshDeserialize;

        use crate::acp::types::{RecordMetadata, RegistrationsCommitment};
        use crate::types::{Duration, Timestamp};

        let commitment = RegistrationsCommitment {
            id: 1,
            policy_id: "pol1".into(),
            commitment: vec![0xAB; 32],
            expired: false,
            validity: Duration::Seconds(600),
            metadata: RecordMetadata {
                creation_ts: Timestamp {
                    seconds: 500,
                    block_height: 10,
                },
                tx_hash: vec![0xCD; 32],
                tx_signer: "0x1234".into(),
                owner_did: "did:key:z6Mk".into(),
            },
        };
        let encoded = borsh::to_vec(&commitment).unwrap();
        let decoded = RegistrationsCommitment::try_from_slice(&encoded).unwrap();
        assert_eq!(commitment, decoded);
    }

    #[test]
    fn borsh_roundtrip_amendment_event() {
        use borsh::BorshDeserialize;
        use identity::Did;

        use crate::acp::types::{Actor, AmendmentEvent, Object, RecordMetadata};
        use crate::types::Timestamp;

        let event = AmendmentEvent {
            id: 7,
            policy_id: "pol1".into(),
            object: Object {
                resource: "namespace".into(),
                id: "obj1".into(),
            },
            new_owner: Actor(
                Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap(),
            ),
            previous_owner: Actor(
                Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap(),
            ),
            commitment_id: 1,
            hijack_flag: false,
            metadata: RecordMetadata {
                creation_ts: Timestamp {
                    seconds: 500,
                    block_height: 10,
                },
                tx_hash: vec![0xEF; 32],
                tx_signer: "0x5678".into(),
                owner_did: "did:key:z6Mk".into(),
            },
        };
        let encoded = borsh::to_vec(&event).unwrap();
        let decoded = AmendmentEvent::try_from_slice(&encoded).unwrap();
        assert_eq!(event, decoded);
    }
}
