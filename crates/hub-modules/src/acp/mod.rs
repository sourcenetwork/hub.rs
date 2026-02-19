//! ACP module — Zanzibar-style access control policies.

/// Solidity ABI interface for the ACP precompile.
pub mod abi;
/// ACP error types.
pub mod error;
/// ACP domain types.
pub mod types;

use error::AcpError;
use identity::Did;
use types::{
    AccessDecision, AccessRequest, AcpParams, AmendmentEvent, Object, PolicyCmd, PolicyCmdResult,
    PolicyMarshalingType, PolicyRecord, RegistrationProof, RegistrationsCommitment,
    RelationshipRecord, RelationshipSelector,
};

type Result<T> = std::result::Result<T, AcpError>;

/// Access Control Policy module.
///
/// Manages Zanzibar-style relation tuples, policy CRUD, object registration,
/// and access checks. Business logic lives here; precompile and native-tx
/// shims are thin wrappers that decode arguments and forward to these methods.
#[derive(Debug)]
pub struct AcpModule {
    _private: (),
}

impl AcpModule {
    // ── Msg handlers ────────────────────────────────────────────────────

    /// Parse and store a new policy from YAML.
    #[allow(unused_variables)]
    pub fn create_policy(
        &mut self,
        creator: &Did,
        policy_yaml: &[u8],
        marshal_type: PolicyMarshalingType,
    ) -> Result<PolicyRecord> {
        todo!()
    }

    /// Replace a policy's definition, returning the count of removed relationships.
    #[allow(unused_variables)]
    pub fn edit_policy(
        &mut self,
        creator: &Did,
        policy_id: &str,
        policy_yaml: &[u8],
        marshal_type: PolicyMarshalingType,
    ) -> Result<(u64, PolicyRecord)> {
        todo!()
    }

    /// Evaluate an access check and record the decision.
    #[allow(unused_variables)]
    pub fn check_access(
        &self,
        creator: &Did,
        policy_id: &str,
        access_request: &AccessRequest,
    ) -> Result<AccessDecision> {
        todo!()
    }

    /// Execute a policy command authenticated by the tx signer's DID.
    #[allow(unused_variables)]
    pub fn direct_policy_cmd(
        &mut self,
        creator: &Did,
        policy_id: &str,
        cmd: PolicyCmd,
    ) -> Result<PolicyCmdResult> {
        todo!()
    }

    /// Execute a policy command authenticated by a JWS payload signature.
    #[allow(unused_variables)]
    pub fn signed_policy_cmd(
        &mut self,
        creator: &Did,
        payload_jws: &str,
    ) -> Result<PolicyCmdResult> {
        todo!()
    }

    /// Execute a policy command authenticated by a bearer JWT token.
    #[allow(unused_variables)]
    pub fn bearer_policy_cmd(
        &mut self,
        creator: &Did,
        bearer_token: &str,
        policy_id: &str,
        cmd: PolicyCmd,
    ) -> Result<PolicyCmdResult> {
        todo!()
    }

    /// Update governance-controlled module parameters.
    #[allow(unused_variables)]
    pub fn update_params(&mut self, authority: &Did, params: AcpParams) -> Result<()> {
        todo!()
    }

    // ── Query handlers ──────────────────────────────────────────────────

    /// Look up a policy by ID.
    #[allow(unused_variables)]
    pub fn query_policy(&self, id: &str) -> Result<PolicyRecord> {
        todo!()
    }

    /// List all stored policy IDs.
    pub fn query_policy_ids(&self) -> Result<Vec<String>> {
        todo!()
    }

    /// Filter relationships within a policy by resource, object, relation, or subject.
    #[allow(unused_variables)]
    pub fn query_filter_relationships(
        &self,
        policy_id: &str,
        selector: &RelationshipSelector,
    ) -> Result<Vec<RelationshipRecord>> {
        todo!()
    }

    /// Verify an access request without recording a decision.
    #[allow(unused_variables)]
    pub fn query_verify_access_request(
        &self,
        policy_id: &str,
        access_request: &AccessRequest,
    ) -> Result<bool> {
        todo!()
    }

    /// Validate policy YAML without storing it.
    #[allow(unused_variables)]
    pub fn query_validate_policy(
        &self,
        policy_yaml: &[u8],
        marshal_type: PolicyMarshalingType,
    ) -> Result<(bool, String)> {
        todo!()
    }

    /// Look up a previously recorded access decision.
    #[allow(unused_variables)]
    pub fn query_access_decision(&self, id: &str) -> Result<AccessDecision> {
        todo!()
    }

    /// Find the owner of a registered object.
    #[allow(unused_variables)]
    pub fn query_object_owner(
        &self,
        policy_id: &str,
        object: &Object,
    ) -> Result<(bool, Option<RelationshipRecord>)> {
        todo!()
    }

    /// Look up a registration commitment by ID.
    #[allow(unused_variables)]
    pub fn query_registrations_commitment(&self, id: u64) -> Result<RegistrationsCommitment> {
        todo!()
    }

    /// Find registration commitments by their commitment value.
    #[allow(unused_variables)]
    pub fn query_registrations_commitment_by_commitment(
        &self,
        commitment: &[u8],
    ) -> Result<Vec<RegistrationsCommitment>> {
        todo!()
    }

    /// Generate a commitment and proofs for a set of objects.
    #[allow(unused_variables)]
    pub fn query_generate_commitment(
        &self,
        policy_id: &str,
        objects: &[Object],
        actor: &types::Actor,
    ) -> Result<(Vec<u8>, Vec<RegistrationProof>)> {
        todo!()
    }

    /// List hijack attempts for a policy.
    #[allow(unused_variables)]
    pub fn query_hijack_attempts_by_policy(&self, policy_id: &str) -> Result<Vec<AmendmentEvent>> {
        todo!()
    }

    /// Query current module parameters.
    pub fn query_params(&self) -> Result<AcpParams> {
        todo!()
    }
}
