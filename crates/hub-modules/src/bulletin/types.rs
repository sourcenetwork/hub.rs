//! Bulletin domain types — namespaces, posts, collaborators, and native tx operations.

#![allow(missing_docs)]

use identity::Did;
use serde::{Deserialize, Serialize};

/// A registered namespace for organizing posts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Namespace {
    pub id: String,
    pub creator: String,
    pub owner_did: String,
    pub created_at: u64,
}

/// A post within a namespace (payload + optional proof).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Post {
    pub id: String,
    pub namespace: String,
    pub creator_did: String,
    pub payload: Vec<u8>,
    pub proof: Vec<u8>,
}

/// A collaborator on a namespace.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Collaborator {
    pub address: String,
    pub did: String,
    pub namespace: String,
}

/// Native BLS transaction operations for the Bulletin module.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BulletinOp {
    RegisterNamespace {
        namespace: String,
    },
    CreatePost {
        namespace: String,
        payload: Vec<u8>,
        proof: Vec<u8>,
    },
    AddCollaborator {
        namespace: String,
        collaborator: String,
    },
    RemoveCollaborator {
        namespace: String,
        collaborator: String,
    },
}

/// Module-level parameters (governance-controlled).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BulletinParams {}

/// Actor identity for Bulletin operations (wraps a DID).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BulletinActor(pub Did);
