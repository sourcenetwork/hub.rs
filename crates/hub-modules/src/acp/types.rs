//! ACP domain types — request/response structs, native tx operations, and policy commands.

#![allow(missing_docs)]

use acp::{Policy, Relationship, Subject};
use identity::Did;
use serde::{Deserialize, Serialize};

/// Policy serialization format.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PolicyMarshalingType {
    Yaml,
    ShortYaml,
}

/// Reference to an object within a policy resource.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Object {
    pub resource: String,
    pub id: String,
}

/// An actor identity (wraps a DID).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Actor(pub Did);

/// A request to check whether an actor has a permission on an object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessRequest {
    pub resource: String,
    pub object_id: String,
    pub permission: String,
    pub actor: Actor,
}

/// The result of evaluating an access check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessDecision {
    pub id: String,
    pub policy_id: String,
    pub request: AccessRequest,
    pub granted: bool,
}

/// A command to execute against a policy's relation graph.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PolicyCmd {
    SetRelationship(Relationship),
    DeleteRelationship(Relationship),
    RegisterObject(Object),
    ArchiveObject(Object),
    UnarchiveObject(Object),
    CommitRegistrations {
        commitment: Vec<u8>,
    },
    RevealRegistration {
        commitment_id: u64,
        proof: RegistrationProof,
    },
    FlagHijackAttempt {
        event_id: u64,
    },
}

/// The result of executing a policy command.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyCmdResult {
    pub record_existed: bool,
}

/// A stored policy with metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub id: String,
    pub policy: Policy,
    pub creator: Actor,
    pub creation_time: u64,
}

/// Proof that an object was included in a registration commitment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationProof {
    pub object: Object,
    pub proof_data: Vec<u8>,
}

/// Status of a registration commitment.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CommitmentStatus {
    Pending,
    Revealed,
    Expired,
}

/// A batch registration commitment submitted by an actor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistrationsCommitment {
    pub id: u64,
    pub policy_id: String,
    pub actor: Actor,
    pub commitment: Vec<u8>,
    pub status: CommitmentStatus,
}

/// Record of a hijack attempt on a registered object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AmendmentEvent {
    pub id: u64,
    pub policy_id: String,
    pub object: Object,
}

/// Filter for querying relationships.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RelationshipSelector {
    pub resource: Option<String>,
    pub object_id: Option<String>,
    pub relation: Option<String>,
    pub subject: Option<Subject>,
}

/// A relationship associated with its policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelationshipRecord {
    pub policy_id: String,
    pub relationship: Relationship,
}

/// Native BLS transaction operations for the ACP module.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AcpOp {
    CreatePolicy {
        yaml: Vec<u8>,
    },
    EditPolicy {
        policy_id: String,
        yaml: Vec<u8>,
    },
    CheckAccess {
        policy_id: String,
        access_request: AccessRequest,
    },
    DirectCmd {
        policy_id: String,
        cmd: PolicyCmd,
    },
}

/// Module-level parameters (governance-controlled).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AcpParams {}
