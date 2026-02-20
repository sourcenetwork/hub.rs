//! Bulletin module key prefixes and builders.
//!
//! Matches Go `x/bulletin/types/keys.go`. Composite keys use `/`-sanitization
//! to prevent path collisions when namespace IDs or DIDs contain `/`.

use sha2::{Digest, Sha256};

use crate::key_encoding::{sanitize_key_part, unsanitize_key_part};

/// Singleton key for the module's ACP policy ID.
pub const POLICY_ID_KEY: &[u8] = b"policy_id";
/// Post storage prefix.
pub const POST_PREFIX: &[u8] = b"post/";
/// Namespace storage prefix.
pub const NAMESPACE_PREFIX: &[u8] = b"namespace/";
/// Collaborator storage prefix.
pub const COLLABORATOR_PREFIX: &[u8] = b"collaborator/";
/// Module parameters key.
pub const PARAMS_KEY: &[u8] = b"p_bulletin";

/// Post key: `prefix + sanitize(namespace_id) + "/" + sanitize(post_id)`.
pub fn post_key(namespace_id: &str, post_id: &str) -> Vec<u8> {
    let mut key = Vec::from(POST_PREFIX);
    key.extend_from_slice(sanitize_key_part(namespace_id).as_bytes());
    key.push(b'/');
    key.extend_from_slice(sanitize_key_part(post_id).as_bytes());
    key
}

/// Collaborator key: `prefix + sanitize(namespace_id) + "/" + sanitize(did)`.
pub fn collaborator_key(namespace_id: &str, collaborator_did: &str) -> Vec<u8> {
    let mut key = Vec::from(COLLABORATOR_PREFIX);
    key.extend_from_slice(sanitize_key_part(namespace_id).as_bytes());
    key.push(b'/');
    key.extend_from_slice(sanitize_key_part(collaborator_did).as_bytes());
    key
}

/// Namespace key: `prefix + namespace_id`.
pub fn namespace_key(namespace_id: &str) -> Vec<u8> {
    let mut key = Vec::from(NAMESPACE_PREFIX);
    key.extend_from_slice(namespace_id.as_bytes());
    key
}

/// Parse a post key back into `(namespace_id, post_id)`.
///
/// Expects the key to start with `POST_PREFIX`. Reverses sanitization.
///
/// # Panics
///
/// Panics if the key does not start with `POST_PREFIX` or contains
/// no separator after the prefix.
pub fn parse_post_key(key: &[u8]) -> (String, String) {
    let suffix = &key[POST_PREFIX.len()..];
    let suffix_str = std::str::from_utf8(suffix).expect("post key is valid UTF-8");
    let (ns, id) = suffix_str
        .split_once('/')
        .expect("post key contains separator");
    (unsanitize_key_part(ns), unsanitize_key_part(id))
}

/// Parse a collaborator key back into `(namespace_id, collaborator_did)`.
///
/// Expects the key to start with `COLLABORATOR_PREFIX`. Reverses sanitization.
///
/// # Panics
///
/// Panics if the key does not start with `COLLABORATOR_PREFIX` or contains
/// no separator after the prefix.
pub fn parse_collaborator_key(key: &[u8]) -> (String, String) {
    let suffix = &key[COLLABORATOR_PREFIX.len()..];
    let suffix_str = std::str::from_utf8(suffix).expect("collaborator key is valid UTF-8");
    let (ns, did) = suffix_str
        .split_once('/')
        .expect("collaborator key contains separator");
    (unsanitize_key_part(ns), unsanitize_key_part(did))
}

/// Deterministic post ID: `hex(SHA-256(namespace_id + payload))`.
pub fn generate_post_id(namespace_id: &str, payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(namespace_id.as_bytes());
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_key_roundtrip() {
        let ns = "bulletin/my-ns";
        let pid = "abc123";
        let key = post_key(ns, pid);
        let (parsed_ns, parsed_pid) = parse_post_key(&key);
        assert_eq!(parsed_ns, ns);
        assert_eq!(parsed_pid, pid);
    }

    #[test]
    fn collaborator_key_roundtrip() {
        let ns = "bulletin/my-ns";
        let did = "did:key:z6Mk123";
        let key = collaborator_key(ns, did);
        let (parsed_ns, parsed_did) = parse_collaborator_key(&key);
        assert_eq!(parsed_ns, ns);
        assert_eq!(parsed_did, did);
    }

    #[test]
    fn sanitization_prevents_collision() {
        let key_a = post_key("ns/a", "post1");
        let key_b = post_key("ns", "a/post1");
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn namespace_key_format() {
        let key = namespace_key("bulletin/test");
        assert_eq!(key, b"namespace/bulletin/test");
    }

    #[test]
    fn generate_post_id_deterministic() {
        let a = generate_post_id("bulletin/ns1", b"payload");
        let b = generate_post_id("bulletin/ns1", b"payload");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn generate_post_id_changes_with_input() {
        let a = generate_post_id("bulletin/ns1", b"payload-a");
        let b = generate_post_id("bulletin/ns1", b"payload-b");
        assert_ne!(a, b);

        let c = generate_post_id("bulletin/ns1", b"payload-a");
        let d = generate_post_id("bulletin/ns2", b"payload-a");
        assert_ne!(c, d);
    }

    #[test]
    fn borsh_roundtrip_namespace() {
        use borsh::BorshDeserialize;

        use crate::bulletin::types::Namespace;
        use crate::types::Timestamp;

        let ns = Namespace {
            id: "bulletin/test".into(),
            creator: "0xABCD".into(),
            owner_did: "did:key:z6Mk".into(),
            created_at: Timestamp {
                seconds: 100,
                block_height: 10,
            },
        };
        let encoded = borsh::to_vec(&ns).unwrap();
        let decoded = Namespace::try_from_slice(&encoded).unwrap();
        assert_eq!(ns, decoded);
    }

    #[test]
    fn borsh_roundtrip_post() {
        use borsh::BorshDeserialize;

        use crate::bulletin::types::Post;

        let post = Post {
            id: "abc123".into(),
            namespace: "bulletin/ns1".into(),
            creator_did: "did:key:z6Mk".into(),
            payload: vec![1, 2, 3],
            proof: vec![4, 5, 6],
        };
        let encoded = borsh::to_vec(&post).unwrap();
        let decoded = Post::try_from_slice(&encoded).unwrap();
        assert_eq!(post, decoded);
    }

    #[test]
    fn borsh_roundtrip_bulletin_actor() {
        use borsh::BorshDeserialize;
        use identity::Did;

        use crate::bulletin::types::BulletinActor;

        let actor = BulletinActor(
            Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap(),
        );
        let encoded = borsh::to_vec(&actor).unwrap();
        let decoded = BulletinActor::try_from_slice(&encoded).unwrap();
        assert_eq!(actor, decoded);
    }
}
