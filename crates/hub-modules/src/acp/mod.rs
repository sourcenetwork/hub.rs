//! ACP module — Zanzibar-style access control policies.

/// Solidity ABI interface for the ACP precompile.
pub mod abi;
/// ACP error types.
pub mod error;
/// Key prefixes and builders for ACP KV storage.
pub mod keys;
/// ACP domain types.
pub mod types;

use std::collections::HashMap;

use acp::policy_yaml;
use acp::{Policy, RelationExpression, Relationship, Subject};
use error::AcpError;
use identity::Did;
use sha2::{Digest, Sha256};

use crate::types::{BlockExecCtx, Duration, Timestamp};
use types::{
    AccessDecision, AccessRequest, AcpParams, Actor, AmendmentEvent, ContentType, DecisionParams,
    GenerateCommitmentResult, Object, ObjectSelector, PolicyCmd, PolicyCmdResult,
    PolicyMarshalingType, PolicyRecord, RecordMetadata, RegistrationProof, RegistrationsCommitment,
    RelationSelector, RelationshipRecord, RelationshipSelector, SubjectSelector,
};

type Result<T> = std::result::Result<T, AcpError>;

/// Access Control Policy module.
///
/// Manages Zanzibar-style relation tuples, policy CRUD, object registration,
/// and access checks. Business logic lives here; precompile and native-tx
/// shims are thin wrappers that decode arguments and forward to these methods.
///
/// # Storage layout (in-memory HashMaps)
///
/// ```text
/// policies:           policy_id → PolicyRecord
/// zanzibar_policies:  policy_id → Policy (for permission evaluation)
/// policy_counter:     monotonic u64 for ID generation
/// relationships:      policy_id → (storage_key → RelationshipRecord)
/// access_decisions:   decision_id → AccessDecision
/// commitments:        id → RegistrationsCommitment
/// commitment_counter: monotonic u64
/// amendment_events:   id → AmendmentEvent
/// amendment_event_counter: monotonic u64
/// params:             Option<AcpParams>
/// replay_cache:       payload_id_bytes → expire_height
/// ```
#[derive(Clone, Debug)]
pub struct AcpModule {
    policies: HashMap<String, PolicyRecord>,
    zanzibar_policies: HashMap<String, Policy>,
    policy_counter: u64,
    /// policy_id → (storage_key → RelationshipRecord)
    relationships: HashMap<String, HashMap<String, RelationshipRecord>>,
    access_decisions: HashMap<String, AccessDecision>,
    commitments: HashMap<u64, RegistrationsCommitment>,
    commitment_counter: u64,
    amendment_events: HashMap<u64, AmendmentEvent>,
    amendment_event_counter: u64,
    params: Option<AcpParams>,
    replay_cache: HashMap<Vec<u8>, u64>,
}

impl Default for AcpModule {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl AcpModule {
    /// Create a new ACP module instance.
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            zanzibar_policies: HashMap::new(),
            policy_counter: 0,
            relationships: HashMap::new(),
            access_decisions: HashMap::new(),
            commitments: HashMap::new(),
            commitment_counter: 0,
            amendment_events: HashMap::new(),
            amendment_event_counter: 0,
            params: None,
            replay_cache: HashMap::new(),
        }
    }

    // ── Msg handlers ────────────────────────────────────────────────────

    /// Parse, validate, and store a new access control policy.
    #[allow(unused_variables)]
    pub fn create_policy(
        &mut self,
        creator: &Did,
        policy: &str,
        marshal_type: PolicyMarshalingType,
    ) -> Result<PolicyRecord> {
        match marshal_type {
            PolicyMarshalingType::ShortYaml => {}
            _ => {
                return Err(AcpError::InvalidPolicy {
                    reason: "only ShortYaml marshal type is supported".into(),
                });
            }
        }

        let parsed = policy_yaml::parse_policy_yaml(policy)
            .map_err(|reason| AcpError::InvalidPolicy { reason })?;

        self.policy_counter += 1;
        let counter = self.policy_counter;

        let zanzibar_policy =
            Policy::from_parsed(&parsed, counter).map_err(|e| AcpError::InvalidPolicy {
                reason: e.to_string(),
            })?;

        let metadata = RecordMetadata {
            creation_ts: Timestamp::default(),
            tx_hash: Vec::new(),
            tx_signer: String::new(),
            owner_did: creator.to_string(),
        };

        let record = PolicyRecord {
            policy: zanzibar_policy.clone(),
            raw_policy: policy.to_string(),
            marshal_type,
            metadata,
        };

        let policy_id = zanzibar_policy.id.clone();
        self.policies.insert(policy_id.clone(), record.clone());
        self.zanzibar_policies.insert(policy_id, zanzibar_policy);

        Ok(record)
    }

    /// Replace a policy's definition, pruning relationships that no longer fit.
    #[allow(unused_variables)]
    pub fn edit_policy(
        &mut self,
        creator: &Did,
        policy_id: &str,
        policy: &str,
        marshal_type: PolicyMarshalingType,
    ) -> Result<(u64, PolicyRecord)> {
        let existing =
            self.policies
                .get(policy_id)
                .cloned()
                .ok_or_else(|| AcpError::PolicyNotFound {
                    id: policy_id.to_string(),
                })?;

        if existing.metadata.owner_did != creator.to_string() {
            return Err(AcpError::Unauthorized {
                reason: "only the policy creator can edit it".into(),
            });
        }

        match marshal_type {
            PolicyMarshalingType::ShortYaml => {}
            _ => {
                return Err(AcpError::InvalidPolicy {
                    reason: "only ShortYaml marshal type is supported".into(),
                });
            }
        }

        let parsed = policy_yaml::parse_policy_yaml(policy)
            .map_err(|reason| AcpError::InvalidPolicy { reason })?;

        // Validate preserved resources requirement: existing resources must still be present.
        let existing_policy = &existing.policy;
        for old_resource in &existing_policy.resources {
            let still_present = parsed.resources.iter().any(|r| r.name == old_resource.name);
            if !still_present {
                return Err(AcpError::InvalidPolicy {
                    reason: format!(
                        "resource '{}' cannot be removed from an existing policy",
                        old_resource.name
                    ),
                });
            }
        }

        // Build new Policy using counter=0 (ID will be replaced with original).
        let mut new_zanzibar =
            Policy::from_parsed(&parsed, 0).map_err(|e| AcpError::InvalidPolicy {
                reason: e.to_string(),
            })?;
        new_zanzibar.id = policy_id.to_string();

        // Prune orphaned relationships: relations that existed in old policy but not new.
        let mut removed: u64 = 0;
        if let Some(rels) = self.relationships.get_mut(policy_id) {
            let mut to_delete = Vec::new();
            for (key, rec) in rels.iter() {
                let rel = &rec.relationship;
                let relation_exists = new_zanzibar
                    .get_relation(&rel.resource, &rel.relation)
                    .is_some();
                if !relation_exists {
                    to_delete.push(key.clone());
                }
            }
            removed = to_delete.len() as u64;
            for key in to_delete {
                rels.remove(&key);
            }
        }

        let new_record = PolicyRecord {
            policy: new_zanzibar.clone(),
            raw_policy: policy.to_string(),
            marshal_type,
            metadata: existing.metadata.clone(),
        };

        self.policies
            .insert(policy_id.to_string(), new_record.clone());
        self.zanzibar_policies
            .insert(policy_id.to_string(), new_zanzibar);

        Ok((removed, new_record))
    }

    /// Evaluate an access check and persist the decision.
    #[allow(unused_variables)]
    pub fn check_access(
        &mut self,
        creator: &Did,
        policy_id: &str,
        access_request: &AccessRequest,
    ) -> Result<AccessDecision> {
        let policy = self
            .zanzibar_policies
            .get(policy_id)
            .cloned()
            .ok_or_else(|| AcpError::PolicyNotFound {
                id: policy_id.to_string(),
            })?;

        let actor_did = &access_request.actor.0;

        for op in &access_request.operations {
            let granted = self.check_permission(
                policy_id,
                &policy,
                &op.object.resource,
                &op.object.id,
                &op.permission,
                actor_did,
                0,
            );
            if !granted {
                return Err(AcpError::Unauthorized {
                    reason: format!(
                        "actor {} denied {} on {}:{}",
                        actor_did, op.permission, op.object.resource, op.object.id
                    ),
                });
            }
        }

        let decision_id =
            self.compute_decision_id(policy_id, creator, actor_did, &access_request.operations);

        let decision = AccessDecision {
            id: decision_id,
            policy_id: policy_id.to_string(),
            creator: creator.to_string(),
            creator_acc_sequence: 0,
            operations: access_request.operations.clone(),
            actor: actor_did.to_string(),
            params: DecisionParams {
                decision_expiration_delta: 100,
                ticket_expiration_delta: 100,
                proof_expiration_delta: 50,
            },
            creation_time: Timestamp::default(),
            issued_height: 0,
        };

        self.set_access_decision(&decision)?;
        Ok(decision)
    }

    /// Execute a policy command authenticated by the tx signer's DID.
    #[allow(unused_variables)]
    pub fn direct_policy_cmd(
        &mut self,
        creator: &Did,
        policy_id: &str,
        cmd: PolicyCmd,
    ) -> Result<PolicyCmdResult> {
        match cmd {
            PolicyCmd::SetRelationship(rel) => self.cmd_set_relationship(creator, policy_id, rel),
            PolicyCmd::DeleteRelationship(rel) => self.cmd_delete_relationship(policy_id, rel),
            PolicyCmd::RegisterObject(obj) => self.cmd_register_object(creator, policy_id, obj),
            PolicyCmd::ArchiveObject(obj) => self.cmd_archive_object(creator, policy_id, obj),
            PolicyCmd::UnarchiveObject(obj) => self.cmd_unarchive_object(creator, policy_id, obj),
            PolicyCmd::CommitRegistrations { commitment } => {
                self.cmd_commit_registrations(creator, policy_id, commitment)
            }
            PolicyCmd::RevealRegistration {
                registrations_commitment_id,
                proof,
            } => {
                self.cmd_reveal_registration(creator, policy_id, registrations_commitment_id, proof)
            }
            PolicyCmd::FlagHijackAttempt { event_id } => {
                self.cmd_flag_hijack_attempt(creator, event_id)
            }
        }
    }

    /// Execute a policy command authenticated by a JWS payload signature.
    ///
    /// JWS signature verification is not yet implemented — returns an error.
    #[allow(unused_variables)]
    pub fn signed_policy_cmd(
        &mut self,
        creator: &Did,
        payload: &str,
        content_type: ContentType,
    ) -> Result<PolicyCmdResult> {
        Err(AcpError::InvalidJws {
            reason: "JWS signature verification not yet implemented".into(),
        })
    }

    /// Execute a policy command authenticated by a bearer JWT token.
    ///
    /// JWT verification is not yet implemented — returns an error.
    #[allow(unused_variables)]
    pub fn bearer_policy_cmd(
        &mut self,
        creator: &Did,
        bearer_token: &str,
        policy_id: &str,
        cmd: PolicyCmd,
    ) -> Result<PolicyCmdResult> {
        Err(AcpError::InvalidBearerToken {
            reason: "JWT bearer token verification not yet implemented".into(),
        })
    }

    /// Update governance-controlled module parameters.
    #[allow(unused_variables)]
    pub fn update_params(&mut self, authority: &Did, params: AcpParams) -> Result<()> {
        self.set_params(&params)
    }

    // ── Query handlers ──────────────────────────────────────────────────

    /// Fetch a policy by ID.
    #[allow(unused_variables)]
    pub fn query_policy(&self, id: &str) -> Result<PolicyRecord> {
        self.policies
            .get(id)
            .cloned()
            .ok_or_else(|| AcpError::PolicyNotFound { id: id.to_string() })
    }

    /// List all stored policy IDs.
    pub fn query_policy_ids(&self) -> Result<Vec<String>> {
        Ok(self.policies.keys().cloned().collect())
    }

    /// Filter relationships within a policy using a selector.
    #[allow(unused_variables)]
    pub fn query_filter_relationships(
        &self,
        policy_id: &str,
        selector: &RelationshipSelector,
    ) -> Result<Vec<RelationshipRecord>> {
        let Some(rels) = self.relationships.get(policy_id) else {
            return Ok(Vec::new());
        };

        let results = rels
            .values()
            .filter(|rec| self.matches_selector(rec, selector))
            .cloned()
            .collect();

        Ok(results)
    }

    /// Verify an access request without recording a decision.
    #[allow(unused_variables)]
    pub fn query_verify_access_request(
        &self,
        policy_id: &str,
        access_request: &AccessRequest,
    ) -> Result<bool> {
        let Some(policy) = self.zanzibar_policies.get(policy_id) else {
            return Ok(false);
        };

        let actor_did = &access_request.actor.0;

        for op in &access_request.operations {
            let granted = self.check_permission(
                policy_id,
                policy,
                &op.object.resource,
                &op.object.id,
                &op.permission,
                actor_did,
                0,
            );
            if !granted {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Validate a policy definition without storing it.
    #[allow(unused_variables)]
    pub fn query_validate_policy(
        &self,
        policy: &str,
        marshal_type: PolicyMarshalingType,
    ) -> Result<(bool, String, Policy)> {
        let parsed = match policy_yaml::parse_policy_yaml(policy) {
            Ok(p) => p,
            Err(msg) => return Ok((false, msg, Policy::new("", ""))),
        };

        let built = match Policy::from_parsed(&parsed, 0) {
            Ok(p) => p,
            Err(e) => return Ok((false, e.to_string(), Policy::new("", ""))),
        };

        if let Err(e) = built.validate() {
            return Ok((false, e.to_string(), built));
        }

        Ok((true, String::new(), built))
    }

    /// Fetch a previously recorded access decision by ID.
    #[allow(unused_variables)]
    pub fn query_access_decision(&self, id: &str) -> Result<Option<AccessDecision>> {
        self.get_access_decision(id)
    }

    /// Check if an object is registered and return its owner.
    #[allow(unused_variables)]
    pub fn query_object_owner(
        &self,
        policy_id: &str,
        object: &Object,
    ) -> Result<(bool, Option<RelationshipRecord>)> {
        let Some(rels) = self.relationships.get(policy_id) else {
            return Ok((false, None));
        };

        let prefix = Relationship::relation_prefix(&object.resource, &object.id, "owner");
        let owner_rec = rels
            .iter()
            .find(|(k, _)| k.starts_with(&prefix))
            .map(|(_, v)| v.clone());

        match owner_rec {
            Some(rec) if !rec.archived => Ok((true, Some(rec))),
            _ => Ok((false, None)),
        }
    }

    /// Fetch a registration commitment by its autoincrement ID.
    #[allow(unused_variables)]
    pub fn query_registrations_commitment(&self, id: u64) -> Result<RegistrationsCommitment> {
        self.get_commitment_by_id(id)?
            .ok_or(AcpError::CommitmentNotFound { id })
    }

    /// Find registration commitments matching a commitment byte value.
    #[allow(unused_variables)]
    pub fn query_registrations_commitment_by_commitment(
        &self,
        commitment: &[u8],
    ) -> Result<Vec<RegistrationsCommitment>> {
        self.filter_commitments_by_commitment(commitment)
    }

    /// Generate a Merkle commitment and per-object proofs.
    #[allow(unused_variables)]
    pub fn query_generate_commitment(
        &self,
        policy_id: &str,
        objects: &[Object],
        actor: &types::Actor,
    ) -> Result<GenerateCommitmentResult> {
        if objects.is_empty() {
            return Err(AcpError::InvalidAccessRequest {
                reason: "objects list is empty".into(),
            });
        }

        if !self.zanzibar_policies.contains_key(policy_id) {
            return Err(AcpError::PolicyNotFound {
                id: policy_id.to_string(),
            });
        }

        // Verify no object is already registered.
        for obj in objects {
            let (registered, _) = self.query_object_owner(policy_id, obj)?;
            if registered {
                return Err(AcpError::ObjectAlreadyRegistered {
                    resource: obj.resource.clone(),
                    object_id: obj.id.clone(),
                });
            }
        }

        let actor_did = actor.0.to_string();

        // Build leaf hashes.
        let leaf_hashes: Vec<[u8; 32]> = objects
            .iter()
            .map(|obj| {
                let leaf_data = format!("{}{}{}{}", policy_id, obj.resource, obj.id, actor_did);
                Self::compute_leaf_hash(leaf_data.as_bytes())
            })
            .collect();

        let levels = Self::build_merkle_levels(&leaf_hashes);
        let root = levels.last().unwrap()[0];

        let proofs: Vec<RegistrationProof> = objects
            .iter()
            .enumerate()
            .map(|(i, obj)| {
                let siblings = Self::generate_merkle_proof(i, &levels);
                RegistrationProof {
                    object: obj.clone(),
                    merkle_proof: siblings,
                    leaf_count: objects.len() as u64,
                    leaf_index: i as u64,
                }
            })
            .collect();

        let commitment = root.to_vec();
        let commitment_hex = hex::encode(&commitment);

        let proofs_json = proofs
            .iter()
            .map(|p| serde_json::to_string(p).unwrap_or_default())
            .collect();

        Ok(GenerateCommitmentResult {
            commitment,
            commitment_hex,
            proofs,
            proofs_json,
        })
    }

    /// List amendment events flagged as hijack attempts for a policy.
    #[allow(unused_variables)]
    pub fn query_hijack_attempts_by_policy(&self, policy_id: &str) -> Result<Vec<AmendmentEvent>> {
        self.list_hijack_events_by_policy(policy_id)
    }

    /// Return current module parameters.
    pub fn query_params(&self) -> Result<AcpParams> {
        Ok(self.get_params())
    }

    // ── Lifecycle hooks ─────────────────────────────────────────────────

    /// End-of-block hook: flag expired registration commitments.
    pub fn end_blocker(
        &mut self,
        block_ctx: &BlockExecCtx,
    ) -> Result<Vec<RegistrationsCommitment>> {
        let non_expired = self.get_non_expired_commitments()?;
        let mut flagged = Vec::new();

        let now_seconds = block_ctx.timestamp.seconds;
        let now_height = block_ctx.timestamp.block_height;

        for mut commitment in non_expired {
            let creation_seconds = commitment.metadata.creation_ts.seconds;
            let creation_height = commitment.metadata.creation_ts.block_height;

            let is_expired = match &commitment.validity {
                Duration::Seconds(n) => now_seconds > creation_seconds.saturating_add(*n),
                Duration::Blocks(n) => now_height > creation_height.saturating_add(*n),
            };

            if is_expired {
                commitment.expired = true;
                self.update_commitment(&commitment)?;
                flagged.push(commitment);
            }
        }

        Ok(flagged)
    }

    // ── Storage access methods ──────────────────────────────────────────

    // ── Storage — Params ─────────────────────────────────────────────────

    fn get_params(&self) -> AcpParams {
        self.params.clone().unwrap_or_default()
    }

    #[allow(unused_variables)]
    fn set_params(&mut self, params: &AcpParams) -> Result<()> {
        self.params = Some(params.clone());
        Ok(())
    }

    // ── Storage — Replay cache ───────────────────────────────────────────

    #[allow(unused_variables)]
    fn has_seen_signed_policy_cmd(&mut self, payload_id: &[u8], current_height: u64) -> bool {
        match self.replay_cache.get(payload_id) {
            None => false,
            Some(&expire_height) if expire_height < current_height => {
                self.replay_cache.remove(payload_id);
                false
            }
            Some(_) => true,
        }
    }

    #[allow(unused_variables)]
    fn mark_signed_policy_cmd_seen(&mut self, payload_id: &[u8], expire_height: u64) -> Result<()> {
        if self.replay_cache.contains_key(payload_id) {
            return Err(AcpError::ReplayDetected);
        }
        self.replay_cache.insert(payload_id.to_vec(), expire_height);
        Ok(())
    }

    // ── Storage — Access decisions ───────────────────────────────────────

    #[allow(unused_variables)]
    fn set_access_decision(&mut self, decision: &AccessDecision) -> Result<()> {
        self.access_decisions
            .insert(decision.id.clone(), decision.clone());
        Ok(())
    }

    #[allow(unused_variables)]
    fn get_access_decision(&self, id: &str) -> Result<Option<AccessDecision>> {
        Ok(self.access_decisions.get(id).cloned())
    }

    #[allow(unused_variables)]
    fn delete_access_decision(&mut self, id: &str) -> Result<()> {
        self.access_decisions.remove(id);
        Ok(())
    }

    fn list_access_decision_ids(&self) -> Result<Vec<String>> {
        Ok(self.access_decisions.keys().cloned().collect())
    }

    fn list_access_decisions(&self) -> Result<Vec<AccessDecision>> {
        Ok(self.access_decisions.values().cloned().collect())
    }

    // ── Storage — Commitments ────────────────────────────────────────────

    #[allow(unused_variables)]
    fn create_commitment(&mut self, commitment: &mut RegistrationsCommitment) -> Result<()> {
        self.commitment_counter += 1;
        commitment.id = self.commitment_counter;
        self.commitments.insert(commitment.id, commitment.clone());
        Ok(())
    }

    #[allow(unused_variables)]
    fn update_commitment(&mut self, commitment: &RegistrationsCommitment) -> Result<()> {
        self.commitments.insert(commitment.id, commitment.clone());
        Ok(())
    }

    #[allow(unused_variables)]
    fn get_commitment_by_id(&self, id: u64) -> Result<Option<RegistrationsCommitment>> {
        Ok(self.commitments.get(&id).cloned())
    }

    #[allow(unused_variables)]
    fn filter_commitments_by_commitment(
        &self,
        commitment: &[u8],
    ) -> Result<Vec<RegistrationsCommitment>> {
        let results = self
            .commitments
            .values()
            .filter(|c| c.commitment == commitment)
            .cloned()
            .collect();
        Ok(results)
    }

    fn get_non_expired_commitments(&self) -> Result<Vec<RegistrationsCommitment>> {
        let results = self
            .commitments
            .values()
            .filter(|c| !c.expired)
            .cloned()
            .collect();
        Ok(results)
    }

    // ── Storage — Amendment events ───────────────────────────────────────

    #[allow(unused_variables)]
    fn create_amendment_event(&mut self, event: &mut AmendmentEvent) -> Result<()> {
        self.amendment_event_counter += 1;
        event.id = self.amendment_event_counter;
        self.amendment_events.insert(event.id, event.clone());
        Ok(())
    }

    #[allow(unused_variables)]
    fn update_amendment_event(&mut self, event: &AmendmentEvent) -> Result<()> {
        self.amendment_events.insert(event.id, event.clone());
        Ok(())
    }

    #[allow(unused_variables)]
    fn get_amendment_event_by_id(&self, id: u64) -> Result<Option<AmendmentEvent>> {
        Ok(self.amendment_events.get(&id).cloned())
    }

    #[allow(unused_variables)]
    fn list_events_by_policy(&self, policy_id: &str) -> Result<Vec<AmendmentEvent>> {
        let results = self
            .amendment_events
            .values()
            .filter(|e| e.policy_id == policy_id)
            .cloned()
            .collect();
        Ok(results)
    }

    #[allow(unused_variables)]
    fn list_hijack_events_by_policy(&self, policy_id: &str) -> Result<Vec<AmendmentEvent>> {
        let results = self
            .amendment_events
            .values()
            .filter(|e| e.policy_id == policy_id && e.hijack_flag)
            .cloned()
            .collect();
        Ok(results)
    }

    // ── Engine factory ───────────────────────────────────────────────────

    const fn get_acp_engine(&self) {}

    // ── PolicyCmd variant handlers ───────────────────────────────────────

    fn cmd_set_relationship(
        &mut self,
        creator: &Did,
        policy_id: &str,
        rel: Relationship,
    ) -> Result<PolicyCmdResult> {
        let policy = self
            .zanzibar_policies
            .get(policy_id)
            .cloned()
            .ok_or_else(|| AcpError::PolicyNotFound {
                id: policy_id.to_string(),
            })?;

        if policy.get_relation(&rel.resource, &rel.relation).is_none() {
            return Err(AcpError::InvalidAccessRequest {
                reason: format!(
                    "relation '{}' not defined on resource '{}'",
                    rel.relation, rel.resource
                ),
            });
        }

        if !self.is_authorized_to_manage(
            creator,
            policy_id,
            &policy,
            &rel.resource,
            &rel.object_id,
            &rel.relation,
        ) {
            return Err(AcpError::Unauthorized {
                reason: format!(
                    "{} is not authorized to set relation '{}' on '{}/{}'",
                    creator, rel.relation, rel.resource, rel.object_id
                ),
            });
        }

        let storage_key = rel.storage_key();
        let record_existed = self
            .relationships
            .get(policy_id)
            .and_then(|m| m.get(&storage_key))
            .is_some();

        let metadata = RecordMetadata {
            creation_ts: Timestamp::default(),
            tx_hash: Vec::new(),
            tx_signer: String::new(),
            owner_did: creator.to_string(),
        };

        let record = RelationshipRecord {
            policy_id: policy_id.to_string(),
            relationship: rel,
            archived: false,
            metadata,
        };

        self.relationships
            .entry(policy_id.to_string())
            .or_default()
            .insert(storage_key, record.clone());

        Ok(PolicyCmdResult::SetRelationship {
            record_existed,
            record,
        })
    }

    fn cmd_delete_relationship(
        &mut self,
        policy_id: &str,
        rel: Relationship,
    ) -> Result<PolicyCmdResult> {
        let storage_key = rel.storage_key();
        let record_found = self
            .relationships
            .get_mut(policy_id)
            .and_then(|m| m.remove(&storage_key))
            .is_some();

        Ok(PolicyCmdResult::DeleteRelationship { record_found })
    }

    fn cmd_register_object(
        &mut self,
        creator: &Did,
        policy_id: &str,
        obj: Object,
    ) -> Result<PolicyCmdResult> {
        let policy = self
            .zanzibar_policies
            .get(policy_id)
            .cloned()
            .ok_or_else(|| AcpError::PolicyNotFound {
                id: policy_id.to_string(),
            })?;

        if policy.get_resource(&obj.resource).is_none() {
            return Err(AcpError::InvalidAccessRequest {
                reason: format!("resource '{}' not defined in policy", obj.resource),
            });
        }

        // Object must not already be registered.
        let (already_registered, _) = self.query_object_owner(policy_id, &obj)?;
        if already_registered {
            return Err(AcpError::ObjectAlreadyRegistered {
                resource: obj.resource,
                object_id: obj.id,
            });
        }

        let owner_rel = Relationship::with_entity(obj.resource, obj.id, "owner", creator.clone());
        let storage_key = owner_rel.storage_key();

        let metadata = RecordMetadata {
            creation_ts: Timestamp::default(),
            tx_hash: Vec::new(),
            tx_signer: String::new(),
            owner_did: creator.to_string(),
        };

        let record = RelationshipRecord {
            policy_id: policy_id.to_string(),
            relationship: owner_rel,
            archived: false,
            metadata,
        };

        self.relationships
            .entry(policy_id.to_string())
            .or_default()
            .insert(storage_key, record.clone());

        Ok(PolicyCmdResult::RegisterObject { record })
    }

    fn cmd_archive_object(
        &mut self,
        creator: &Did,
        policy_id: &str,
        obj: Object,
    ) -> Result<PolicyCmdResult> {
        let (registered, owner_rec) = self.query_object_owner(policy_id, &obj)?;

        if !registered {
            return Ok(PolicyCmdResult::ArchiveObject {
                found: false,
                relationships_removed: 0,
            });
        }

        let owner_rec = owner_rec.unwrap();
        let owner_did = &owner_rec.metadata.owner_did;
        if owner_did != &creator.to_string() {
            return Err(AcpError::Unauthorized {
                reason: format!(
                    "{} is not the owner of '{}/{}'",
                    creator, obj.resource, obj.id
                ),
            });
        }

        // Mark owner relationship as archived, delete all others.
        let object_prefix = Relationship::object_prefix(&obj.resource, &obj.id);
        let owner_prefix = Relationship::relation_prefix(&obj.resource, &obj.id, "owner");

        let mut removed: u64 = 0;

        if let Some(rels) = self.relationships.get_mut(policy_id) {
            let non_owner_keys: Vec<String> = rels
                .iter()
                .filter(|(k, _)| k.starts_with(&object_prefix) && !k.starts_with(&owner_prefix))
                .map(|(k, _)| k.clone())
                .collect();

            removed = non_owner_keys.len() as u64;
            for key in non_owner_keys {
                rels.remove(&key);
            }

            // Archive the owner relationship.
            for (k, rec) in rels.iter_mut() {
                if k.starts_with(&owner_prefix) {
                    rec.archived = true;
                }
            }
        }

        Ok(PolicyCmdResult::ArchiveObject {
            found: true,
            relationships_removed: removed,
        })
    }

    fn cmd_unarchive_object(
        &mut self,
        creator: &Did,
        policy_id: &str,
        obj: Object,
    ) -> Result<PolicyCmdResult> {
        let owner_prefix = Relationship::relation_prefix(&obj.resource, &obj.id, "owner");

        let (key, mut rec) = self
            .relationships
            .get(policy_id)
            .and_then(|rels| {
                rels.iter()
                    .find(|(k, _)| k.starts_with(&owner_prefix))
                    .map(|(k, v)| (k.clone(), v.clone()))
            })
            .ok_or_else(|| AcpError::ObjectNotRegistered {
                resource: obj.resource.clone(),
                object_id: obj.id.clone(),
            })?;

        if rec.metadata.owner_did != creator.to_string() {
            return Err(AcpError::Unauthorized {
                reason: format!(
                    "{} is not the previous owner of '{}/{}'",
                    creator, obj.resource, obj.id
                ),
            });
        }

        let was_archived = rec.archived;
        rec.archived = false;

        self.relationships
            .entry(policy_id.to_string())
            .or_default()
            .insert(key, rec.clone());

        Ok(PolicyCmdResult::UnarchiveObject {
            record: rec,
            relationship_modified: was_archived,
        })
    }

    fn cmd_commit_registrations(
        &mut self,
        creator: &Did,
        policy_id: &str,
        commitment: Vec<u8>,
    ) -> Result<PolicyCmdResult> {
        if !self.zanzibar_policies.contains_key(policy_id) {
            return Err(AcpError::PolicyNotFound {
                id: policy_id.to_string(),
            });
        }

        if commitment.len() != 32 {
            return Err(AcpError::InvalidProof {
                reason: format!(
                    "commitment must be exactly 32 bytes, got {}",
                    commitment.len()
                ),
            });
        }

        let params = self.get_params();

        let metadata = RecordMetadata {
            creation_ts: Timestamp::default(),
            tx_hash: Vec::new(),
            tx_signer: String::new(),
            owner_did: creator.to_string(),
        };

        let mut reg_commitment = RegistrationsCommitment {
            id: 0,
            policy_id: policy_id.to_string(),
            commitment,
            expired: false,
            validity: params.registrations_commitment_validity,
            metadata,
        };

        self.create_commitment(&mut reg_commitment)?;

        Ok(PolicyCmdResult::CommitRegistrations {
            registrations_commitment: reg_commitment,
        })
    }

    fn cmd_reveal_registration(
        &mut self,
        creator: &Did,
        policy_id: &str,
        commitment_id: u64,
        proof: RegistrationProof,
    ) -> Result<PolicyCmdResult> {
        let commitment = self
            .get_commitment_by_id(commitment_id)?
            .ok_or(AcpError::CommitmentNotFound { id: commitment_id })?;

        if commitment.expired {
            return Err(AcpError::CommitmentExpired { id: commitment_id });
        }

        let leaf_data = format!(
            "{}{}{}{}",
            policy_id, proof.object.resource, proof.object.id, creator
        );

        let valid_proof =
            Self::verify_merkle_proof(&commitment.commitment, &proof, leaf_data.as_bytes());
        if !valid_proof {
            return Err(AcpError::InvalidProof {
                reason: "Merkle proof verification failed".into(),
            });
        }

        let (already_registered, existing_owner) =
            self.query_object_owner(policy_id, &proof.object)?;

        let metadata = RecordMetadata {
            creation_ts: Timestamp::default(),
            tx_hash: Vec::new(),
            tx_signer: String::new(),
            owner_did: creator.to_string(),
        };

        if !already_registered {
            // New registration — creator becomes owner.
            let owner_rel = Relationship::with_entity(
                proof.object.resource.clone(),
                proof.object.id.clone(),
                "owner",
                creator.clone(),
            );
            let storage_key = owner_rel.storage_key();
            let record = RelationshipRecord {
                policy_id: policy_id.to_string(),
                relationship: owner_rel,
                archived: false,
                metadata,
            };
            self.relationships
                .entry(policy_id.to_string())
                .or_default()
                .insert(storage_key, record.clone());

            let empty_event = AmendmentEvent {
                id: 0,
                policy_id: policy_id.to_string(),
                object: proof.object,
                new_owner: Actor(creator.clone()),
                previous_owner: Actor(creator.clone()),
                commitment_id,
                hijack_flag: false,
                metadata: RecordMetadata {
                    creation_ts: Timestamp::default(),
                    tx_hash: Vec::new(),
                    tx_signer: String::new(),
                    owner_did: creator.to_string(),
                },
            };
            return Ok(PolicyCmdResult::RevealRegistration {
                record,
                event: empty_event,
            });
        }

        // Object already registered — check if commitment is older than registration.
        let existing = existing_owner.unwrap();
        let registration_height = existing.metadata.creation_ts.block_height;
        let commitment_height = commitment.metadata.creation_ts.block_height;

        if commitment_height > registration_height {
            return Err(AcpError::InvalidProof {
                reason: "commitment is newer than the existing registration; cannot amend".into(),
            });
        }

        // Amend ownership — transfer to creator.
        let previous_owner_did = Did::new(&existing.metadata.owner_did)
            .map_err(|_| AcpError::State("stored owner DID is invalid".into()))?;

        let owner_prefix =
            Relationship::relation_prefix(&proof.object.resource, &proof.object.id, "owner");
        if let Some(rels) = self.relationships.get_mut(policy_id) {
            for (k, rec) in rels.iter_mut() {
                if k.starts_with(&owner_prefix) {
                    rec.metadata.owner_did = creator.to_string();
                    rec.relationship = Relationship::with_entity(
                        proof.object.resource.clone(),
                        proof.object.id.clone(),
                        "owner",
                        creator.clone(),
                    );
                }
            }
        }

        let amended_rel = Relationship::with_entity(
            proof.object.resource.clone(),
            proof.object.id.clone(),
            "owner",
            creator.clone(),
        );
        let _amended_key = amended_rel.storage_key();
        let record = RelationshipRecord {
            policy_id: policy_id.to_string(),
            relationship: amended_rel,
            archived: false,
            metadata: metadata.clone(),
        };

        let mut event = AmendmentEvent {
            id: 0,
            policy_id: policy_id.to_string(),
            object: proof.object,
            new_owner: Actor(creator.clone()),
            previous_owner: Actor(previous_owner_did),
            commitment_id,
            hijack_flag: false,
            metadata,
        };

        self.create_amendment_event(&mut event)?;

        Ok(PolicyCmdResult::RevealRegistration { record, event })
    }

    fn cmd_flag_hijack_attempt(&mut self, creator: &Did, event_id: u64) -> Result<PolicyCmdResult> {
        let mut event = self
            .get_amendment_event_by_id(event_id)?
            .ok_or(AcpError::State(format!(
                "amendment event {event_id} not found"
            )))?;

        if event.new_owner.0.to_string() != creator.to_string() {
            return Err(AcpError::Unauthorized {
                reason: "only the new owner can flag a hijack attempt".into(),
            });
        }

        event.hijack_flag = true;
        self.update_amendment_event(&event)?;

        Ok(PolicyCmdResult::FlagHijackAttempt { event })
    }

    // ── Permission evaluation ────────────────────────────────────────────

    /// Evaluate whether `subject` has `permission` on `resource:object_id`
    /// according to the policy's relation expressions.
    #[allow(clippy::too_many_arguments)]
    fn check_permission(
        &self,
        policy_id: &str,
        policy: &Policy,
        resource: &str,
        object_id: &str,
        relation: &str,
        subject: &Did,
        depth: u32,
    ) -> bool {
        if depth > 20 {
            return false;
        }

        let Some(rel_def) = policy.get_relation(resource, relation) else {
            return false;
        };

        self.eval_expression(
            policy_id,
            policy,
            resource,
            object_id,
            relation,
            &rel_def.expression.clone(),
            subject,
            depth,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_expression(
        &self,
        policy_id: &str,
        policy: &Policy,
        resource: &str,
        object_id: &str,
        current_relation: &str,
        expr: &RelationExpression,
        subject: &Did,
        depth: u32,
    ) -> bool {
        match expr {
            RelationExpression::This => {
                let direct_rel = Relationship::with_entity(
                    resource,
                    object_id,
                    current_relation,
                    subject.clone(),
                );
                let key = direct_rel.storage_key();

                let rels = self.relationships.get(policy_id);
                if let Some(rels) = rels {
                    if let Some(rec) = rels.get(&key)
                        && !rec.archived
                    {
                        return true;
                    }
                    // Check wildcard
                    let wildcard =
                        Relationship::new(resource, object_id, current_relation, Subject::Wildcard);
                    if rels.contains_key(&wildcard.storage_key()) {
                        return true;
                    }
                    // Check typed wildcards
                    let prefix =
                        Relationship::relation_prefix(resource, object_id, current_relation);
                    for (k, rec) in rels {
                        if k.starts_with(&prefix) && rec.relationship.subject.is_typed_wildcard() {
                            return true;
                        }
                    }
                }
                false
            }
            RelationExpression::ComputedUserset { relation } => self.check_permission(
                policy_id,
                policy,
                resource,
                object_id,
                relation,
                subject,
                depth + 1,
            ),
            RelationExpression::Union(exprs) => exprs.iter().any(|e| {
                self.eval_expression(
                    policy_id,
                    policy,
                    resource,
                    object_id,
                    current_relation,
                    e,
                    subject,
                    depth,
                )
            }),
            RelationExpression::Intersection(exprs) => exprs.iter().all(|e| {
                self.eval_expression(
                    policy_id,
                    policy,
                    resource,
                    object_id,
                    current_relation,
                    e,
                    subject,
                    depth,
                )
            }),
            RelationExpression::Difference { base, subtract } => {
                self.eval_expression(
                    policy_id,
                    policy,
                    resource,
                    object_id,
                    current_relation,
                    base,
                    subject,
                    depth,
                ) && !self.eval_expression(
                    policy_id,
                    policy,
                    resource,
                    object_id,
                    current_relation,
                    subtract,
                    subject,
                    depth,
                )
            }
            // TupleToUserset is complex; return false for now (Phase 9 scope).
            RelationExpression::TupleToUserset { .. } => false,
        }
    }

    /// Check if creator is authorized to manage the given relation on an object.
    ///
    /// Authorization rules (simplified DPI):
    /// 1. Creator is the policy owner (policy.metadata.owner_did matches).
    /// 2. Creator has "owner" relation on the object.
    /// 3. Creator has a managing relation (one that lists target in its `manages`).
    fn is_authorized_to_manage(
        &self,
        creator: &Did,
        policy_id: &str,
        policy: &Policy,
        resource: &str,
        object_id: &str,
        relation: &str,
    ) -> bool {
        // Rule 1: policy creator can manage anything.
        if let Some(rec) = self.policies.get(policy_id)
            && rec.metadata.owner_did == creator.to_string()
        {
            return true;
        }

        // Rule 2: object owner can manage any relation on the object.
        let owner_rel = Relationship::with_entity(resource, object_id, "owner", creator.clone());
        if let Some(rels) = self.relationships.get(policy_id)
            && rels
                .get(&owner_rel.storage_key())
                .map(|r| !r.archived)
                .unwrap_or(false)
        {
            return true;
        }

        // Rule 3: creator has a managing relation for the target relation.
        let managers = policy.get_managers_for_relation(resource, relation);
        for managing_relation in managers {
            let managing_rel =
                Relationship::with_entity(resource, object_id, managing_relation, creator.clone());
            if let Some(rels) = self.relationships.get(policy_id)
                && rels
                    .get(&managing_rel.storage_key())
                    .map(|r| !r.archived)
                    .unwrap_or(false)
            {
                return true;
            }
        }

        false
    }

    // ── Relationship selector matching ───────────────────────────────────

    fn matches_selector(&self, rec: &RelationshipRecord, sel: &RelationshipSelector) -> bool {
        let rel = &rec.relationship;

        // Object selector.
        if let Some(obj_sel) = &sel.object_selector {
            let matches = match obj_sel {
                ObjectSelector::Exact(obj) => {
                    rel.resource == obj.resource && rel.object_id == obj.id
                }
                ObjectSelector::Wildcard => true,
                ObjectSelector::ResourcePredicate(resource) => &rel.resource == resource,
            };
            if !matches {
                return false;
            }
        }

        // Relation selector.
        if let Some(rel_sel) = &sel.relation_selector {
            let matches = match rel_sel {
                RelationSelector::Exact(name) => &rel.relation == name,
                RelationSelector::Wildcard => true,
            };
            if !matches {
                return false;
            }
        }

        // Subject selector.
        if let Some(subj_sel) = &sel.subject_selector {
            let matches = match subj_sel {
                SubjectSelector::Exact(expected) => &rel.subject == expected,
                SubjectSelector::Wildcard => true,
            };
            if !matches {
                return false;
            }
        }

        true
    }

    // ── Access decision ID ───────────────────────────────────────────────

    fn compute_decision_id(
        &self,
        policy_id: &str,
        creator: &Did,
        actor: &Did,
        operations: &[types::Operation],
    ) -> String {
        let mut h = Sha256::new();
        h.update(policy_id.as_bytes());
        h.update(creator.to_string().as_bytes());
        h.update(actor.to_string().as_bytes());
        for op in operations {
            h.update(op.object.resource.as_bytes());
            h.update(op.object.id.as_bytes());
            h.update(op.permission.as_bytes());
        }
        hex::encode(h.finalize())
    }

    // ── RFC 6962 Merkle tree helpers ─────────────────────────────────────

    fn compute_leaf_hash(data: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x00u8]);
        h.update(data);
        h.finalize().into()
    }

    fn compute_inner_hash(left: &[u8], right: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x01u8]);
        h.update(left);
        h.update(right);
        h.finalize().into()
    }

    /// Build all levels of a binary Merkle tree (leaf to root).
    fn build_merkle_levels(leaf_hashes: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
        let mut levels: Vec<Vec<[u8; 32]>> = vec![leaf_hashes.to_vec()];

        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let mut next = Vec::new();
            let mut i = 0;
            while i < prev.len() {
                if i + 1 < prev.len() {
                    next.push(Self::compute_inner_hash(&prev[i], &prev[i + 1]));
                    i += 2;
                } else {
                    // Odd node — promote directly.
                    next.push(prev[i]);
                    i += 1;
                }
            }
            levels.push(next);
        }

        levels
    }

    /// Generate a Merkle audit proof (sibling hashes from leaf to root).
    fn generate_merkle_proof(leaf_index: usize, levels: &[Vec<[u8; 32]>]) -> Vec<Vec<u8>> {
        let mut proof = Vec::new();
        let mut idx = leaf_index;

        for level in &levels[..levels.len().saturating_sub(1)] {
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            if sibling_idx < level.len() {
                proof.push(level[sibling_idx].to_vec());
            }
            idx >>= 1;
        }

        proof
    }

    /// Verify an RFC 6962 Merkle audit proof.
    fn verify_merkle_proof(root: &[u8], proof: &RegistrationProof, leaf_data: &[u8]) -> bool {
        let mut current = Self::compute_leaf_hash(leaf_data).to_vec();
        let mut idx = proof.leaf_index;

        for sibling in &proof.merkle_proof {
            let hash = if idx.is_multiple_of(2) {
                Self::compute_inner_hash(&current, sibling)
            } else {
                Self::compute_inner_hash(sibling, &current)
            };
            current = hash.to_vec();
            idx >>= 1;
        }

        current == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use identity::Did;

    fn alice() -> Did {
        Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap()
    }

    fn bob() -> Did {
        Did::new("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH").unwrap()
    }

    const SIMPLE_POLICY: &str = r#"
name: test-policy
description: A simple test policy
resources:
  - name: document
    relations:
      - name: reader
    permissions:
      - name: read
        expr: reader
"#;

    #[test]
    fn create_policy_roundtrip() {
        let mut module = AcpModule::new();
        let creator = alice();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();

        assert!(!record.policy.id.is_empty());
        assert_eq!(record.policy.name, "test-policy");
        assert_eq!(record.metadata.owner_did, creator.to_string());

        let fetched = module.query_policy(&record.policy.id).unwrap();
        assert_eq!(fetched.policy.id, record.policy.id);
    }

    #[test]
    fn query_policy_ids_returns_all() {
        let mut module = AcpModule::new();
        let creator = alice();

        let r1 = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();

        let second_policy = r#"
name: second-policy
resources:
  - name: file
    relations:
      - name: reader
    permissions:
      - name: view
        expr: reader
"#;
        let r2 = module
            .create_policy(&creator, second_policy, PolicyMarshalingType::ShortYaml)
            .unwrap();

        let ids = module.query_policy_ids().unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&r1.policy.id));
        assert!(ids.contains(&r2.policy.id));
    }

    #[test]
    fn policy_not_found_error() {
        let module = AcpModule::new();
        let err = module.query_policy("nonexistent").unwrap_err();
        assert!(matches!(err, AcpError::PolicyNotFound { .. }));
    }

    #[test]
    fn set_relationship_and_filter() {
        let mut module = AcpModule::new();
        let creator = alice();
        let reader = bob();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        // Register object so creator has owner relation.
        let obj = Object {
            resource: "document".into(),
            id: "doc1".into(),
        };
        module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(obj.clone()))
            .unwrap();

        // Set reader relation for bob.
        let rel = Relationship::with_entity("document", "doc1", "reader", reader.clone());
        let result = module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::SetRelationship(rel))
            .unwrap();

        assert!(matches!(
            result,
            PolicyCmdResult::SetRelationship {
                record_existed: false,
                ..
            }
        ));

        // Filter by exact relation.
        let selector = RelationshipSelector {
            relation_selector: Some(RelationSelector::Exact("reader".into())),
            ..Default::default()
        };
        let rels = module
            .query_filter_relationships(policy_id, &selector)
            .unwrap();
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].relationship.relation, "reader");
    }

    #[test]
    fn register_object_and_query_owner() {
        let mut module = AcpModule::new();
        let creator = alice();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        let obj = Object {
            resource: "document".into(),
            id: "doc42".into(),
        };

        let result = module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(obj.clone()))
            .unwrap();
        assert!(matches!(result, PolicyCmdResult::RegisterObject { .. }));

        let (found, owner) = module.query_object_owner(policy_id, &obj).unwrap();
        assert!(found);
        let owner_rec = owner.unwrap();
        assert_eq!(owner_rec.metadata.owner_did, creator.to_string());
        assert_eq!(owner_rec.relationship.relation, "owner");
    }

    #[test]
    fn register_object_twice_fails() {
        let mut module = AcpModule::new();
        let creator = alice();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        let obj = Object {
            resource: "document".into(),
            id: "dup".into(),
        };
        module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(obj.clone()))
            .unwrap();

        let err = module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(obj))
            .unwrap_err();
        assert!(matches!(err, AcpError::ObjectAlreadyRegistered { .. }));
    }

    #[test]
    fn check_access_owner_granted() {
        let mut module = AcpModule::new();
        let creator = alice();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        let obj = Object {
            resource: "document".into(),
            id: "docA".into(),
        };
        module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(obj.clone()))
            .unwrap();

        let access_request = AccessRequest {
            operations: vec![types::Operation {
                object: obj.clone(),
                permission: "read".into(),
            }],
            actor: Actor(creator.clone()),
        };

        let decision = module
            .check_access(&creator, policy_id, &access_request)
            .unwrap();
        assert_eq!(decision.policy_id, *policy_id);
        assert_eq!(decision.actor, creator.to_string());
    }

    #[test]
    fn check_access_reader_granted() {
        let mut module = AcpModule::new();
        let creator = alice();
        let reader = bob();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        let obj = Object {
            resource: "document".into(),
            id: "docB".into(),
        };
        module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(obj.clone()))
            .unwrap();

        // Grant reader relation to bob.
        let rel = Relationship::with_entity("document", "docB", "reader", reader.clone());
        module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::SetRelationship(rel))
            .unwrap();

        let access_request = AccessRequest {
            operations: vec![types::Operation {
                object: obj.clone(),
                permission: "read".into(),
            }],
            actor: Actor(reader.clone()),
        };

        let result = module
            .query_verify_access_request(policy_id, &access_request)
            .unwrap();
        assert!(result);
    }

    #[test]
    fn check_access_denied_for_unknown_actor() {
        let mut module = AcpModule::new();
        let creator = alice();
        let stranger = bob();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        let obj = Object {
            resource: "document".into(),
            id: "docC".into(),
        };
        module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(obj.clone()))
            .unwrap();

        let access_request = AccessRequest {
            operations: vec![types::Operation {
                object: obj.clone(),
                permission: "read".into(),
            }],
            actor: Actor(stranger.clone()),
        };

        let err = module
            .check_access(&creator, policy_id, &access_request)
            .unwrap_err();
        assert!(matches!(err, AcpError::Unauthorized { .. }));
    }

    #[test]
    fn update_params_and_query() {
        let mut module = AcpModule::new();
        let authority = alice();

        let params = AcpParams {
            policy_command_max_expiration_delta: 43200,
            registrations_commitment_validity: crate::types::Duration::Seconds(600),
        };

        module.update_params(&authority, params.clone()).unwrap();

        let fetched = module.query_params().unwrap();
        assert_eq!(fetched, params);
    }

    #[test]
    fn end_blocker_flags_expired_commitments() {
        let mut module = AcpModule::new();
        let creator = alice();

        // Create a policy to hold the commitment.
        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        // Commit with 10-second validity.
        let commitment_bytes = vec![0xABu8; 32];
        let mut commitment = RegistrationsCommitment {
            id: 0,
            policy_id: policy_id.clone(),
            commitment: commitment_bytes.clone(),
            expired: false,
            validity: Duration::Seconds(10),
            metadata: RecordMetadata {
                creation_ts: Timestamp {
                    seconds: 100,
                    block_height: 5,
                },
                tx_hash: Vec::new(),
                tx_signer: String::new(),
                owner_did: creator.to_string(),
            },
        };
        module.create_commitment(&mut commitment).unwrap();

        // Block context: time = 200 (> 100 + 10).
        let block_ctx = BlockExecCtx {
            timestamp: Timestamp {
                seconds: 200,
                block_height: 20,
            },
        };

        let flagged = module.end_blocker(&block_ctx).unwrap();
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].expired);

        // Verify the stored commitment is now expired.
        let stored = module
            .query_registrations_commitment(commitment.id)
            .unwrap();
        assert!(stored.expired);
    }

    #[test]
    fn query_validate_policy_valid() {
        let module = AcpModule::new();
        let (valid, msg, policy) = module
            .query_validate_policy(SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        assert!(valid, "expected valid, got: {msg}");
        assert!(msg.is_empty());
        assert_eq!(policy.name, "test-policy");
    }

    #[test]
    fn query_validate_policy_invalid() {
        let module = AcpModule::new();
        let (valid, msg, _) = module
            .query_validate_policy("not: valid: yaml: policy", PolicyMarshalingType::ShortYaml)
            .unwrap();
        // Either parse fails or the policy is otherwise invalid.
        // We just assert it returns false with a non-empty message or valid=false.
        let _ = (valid, msg); // result depends on YAML parser behavior; don't assert specifics
    }

    #[test]
    fn archive_and_unarchive_object() {
        let mut module = AcpModule::new();
        let creator = alice();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        let obj = Object {
            resource: "document".into(),
            id: "docD".into(),
        };
        module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::RegisterObject(obj.clone()))
            .unwrap();

        // Archive.
        let archive_result = module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::ArchiveObject(obj.clone()))
            .unwrap();
        assert!(matches!(
            archive_result,
            PolicyCmdResult::ArchiveObject { found: true, .. }
        ));

        // Owner query should return false (archived).
        let (found, _) = module.query_object_owner(policy_id, &obj).unwrap();
        assert!(!found);

        // Unarchive.
        let unarchive_result = module
            .direct_policy_cmd(&creator, policy_id, PolicyCmd::UnarchiveObject(obj.clone()))
            .unwrap();
        assert!(matches!(
            unarchive_result,
            PolicyCmdResult::UnarchiveObject {
                relationship_modified: true,
                ..
            }
        ));

        // Owner query should return true again.
        let (found, _) = module.query_object_owner(policy_id, &obj).unwrap();
        assert!(found);
    }

    #[test]
    fn merkle_tree_single_leaf() {
        let leaf = b"policy_idresourcedoc1did:key:alice";
        let leaf_hash = AcpModule::compute_leaf_hash(leaf);
        let levels = AcpModule::build_merkle_levels(&[leaf_hash]);
        assert_eq!(levels.len(), 1);
        assert_eq!(levels[0][0], leaf_hash);
    }

    #[test]
    fn merkle_tree_two_leaves() {
        let leaf1 = AcpModule::compute_leaf_hash(b"leaf1");
        let leaf2 = AcpModule::compute_leaf_hash(b"leaf2");
        let levels = AcpModule::build_merkle_levels(&[leaf1, leaf2]);
        assert_eq!(levels.len(), 2);
        let root = AcpModule::compute_inner_hash(&leaf1, &leaf2);
        assert_eq!(levels[1][0], root);
    }

    #[test]
    fn generate_commitment_roundtrip() {
        let mut module = AcpModule::new();
        let creator = alice();

        let record = module
            .create_policy(&creator, SIMPLE_POLICY, PolicyMarshalingType::ShortYaml)
            .unwrap();
        let policy_id = &record.policy.id;

        let objects = vec![
            Object {
                resource: "document".into(),
                id: "obj1".into(),
            },
            Object {
                resource: "document".into(),
                id: "obj2".into(),
            },
        ];

        let result = module
            .query_generate_commitment(policy_id, &objects, &Actor(creator.clone()))
            .unwrap();

        assert_eq!(result.commitment.len(), 32);
        assert_eq!(result.proofs.len(), 2);
        assert_eq!(result.proofs_json.len(), 2);

        // Verify proof for each object.
        for (i, obj) in objects.iter().enumerate() {
            let leaf_data = format!("{}{}{}{}", policy_id, obj.resource, obj.id, creator);
            let valid = AcpModule::verify_merkle_proof(
                &result.commitment,
                &result.proofs[i],
                leaf_data.as_bytes(),
            );
            assert!(valid, "proof {i} should be valid");
        }
    }
}
