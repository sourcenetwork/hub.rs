//! ACP precompile dispatch — ABI decode/encode for all IAcp selectors.

use alloy_primitives::{B256, Bytes};
use alloy_sol_types::SolCall;
use hub_modules::acp::AcpModule;
use hub_modules::acp::abi::IAcp;
use hub_modules::acp::types::{
    AccessRequest, AcpParams, Actor, ContentType, Object, Operation, PolicyCmd,
    PolicyMarshalingType, RelationshipSelector,
};
use hub_modules::types::{BlockExecCtx, TxExecCtx};
use identity::Did;
use revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};

/// Flat gas cost for read operations (real metering is Phase 10).
const READ_GAS: u64 = 1000;
/// Flat gas cost for write operations (real metering is Phase 10).
const WRITE_GAS: u64 = 5000;

fn did_from_signer(signer: &str) -> Result<Did, PrecompileError> {
    let did_str = if signer.starts_with("did:") {
        signer.to_owned()
    } else {
        format!("did:key:z{signer}")
    };
    Did::new(did_str).map_err(|e| PrecompileError::Other(format!("DID construction: {e}").into()))
}

fn did_from_actor(actor: &str) -> Result<Did, PrecompileError> {
    Did::new(actor).map_err(|e| PrecompileError::Other(format!("actor DID: {e}").into()))
}

fn policy_id_to_string(b: &B256) -> String {
    hex::encode(b.as_slice())
}

fn decode_error(e: alloy_sol_types::Error) -> PrecompileError {
    PrecompileError::Other(format!("ABI decode: {e}").into())
}

fn module_error(e: impl core::fmt::Display) -> PrecompileOutput {
    PrecompileOutput {
        gas_used: 0,
        gas_refunded: 0,
        bytes: Bytes::from(e.to_string().into_bytes()),
        reverted: true,
    }
}

fn json_bytes(v: &impl serde::Serialize) -> Bytes {
    Bytes::from(serde_json::to_vec(v).unwrap_or_default())
}

const fn marshal_type_from_u8(v: u8) -> PolicyMarshalingType {
    match v {
        1 => PolicyMarshalingType::ShortYaml,
        2 => PolicyMarshalingType::ShortJson,
        _ => PolicyMarshalingType::Unknown,
    }
}

const fn content_type_from_u8(v: u8) -> ContentType {
    match v {
        1 => ContentType::Jws,
        _ => ContentType::Unknown,
    }
}

fn build_operations(
    resources: &[String],
    object_ids: &[String],
    permissions: &[String],
) -> Result<Vec<Operation>, PrecompileError> {
    if resources.len() != object_ids.len() || resources.len() != permissions.len() {
        return Err(PrecompileError::Other("array length mismatch".into()));
    }
    Ok(resources
        .iter()
        .zip(object_ids)
        .zip(permissions)
        .map(|((r, o), p)| Operation {
            object: Object {
                resource: r.clone(),
                id: o.clone(),
            },
            permission: p.clone(),
        })
        .collect())
}

fn ok_output(gas: u64, ret: Vec<u8>) -> PrecompileOutput {
    PrecompileOutput {
        gas_used: gas,
        gas_refunded: 0,
        bytes: ret.into(),
        reverted: false,
    }
}

/// Dispatch an ABI-encoded call to the ACP module by selector.
#[allow(clippy::too_many_lines)]
pub(super) fn dispatch(
    module: &mut AcpModule,
    _block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    input: &[u8],
    gas_limit: u64,
) -> PrecompileResult {
    if input.len() < 4 {
        return Err(PrecompileError::Other(
            "input too short for selector".into(),
        ));
    }
    let selector: [u8; 4] = input[..4].try_into().expect("checked length above");

    match selector {
        // ── Write methods ────────────────────────────────────────────
        IAcp::createPolicyCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::createPolicyCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let policy_str = String::from_utf8(call.policy.to_vec())
                .map_err(|_| PrecompileError::Other("invalid UTF-8 in policy".into()))?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let marshal_type = marshal_type_from_u8(call.marshalType);

            let record = match module.create_policy(&creator, &policy_str, marshal_type) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IAcp::createPolicyCall::abi_encode_returns(&json_bytes(&record));
            Ok(ok_output(WRITE_GAS, ret))
        }

        IAcp::editPolicyCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::editPolicyCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let policy_str = String::from_utf8(call.policy.to_vec())
                .map_err(|_| PrecompileError::Other("invalid UTF-8 in policy".into()))?;
            let marshal_type = marshal_type_from_u8(call.marshalType);

            let (relationships_removed, record) =
                match module.edit_policy(&creator, &policy_id, &policy_str, marshal_type) {
                    Ok(r) => r,
                    Err(e) => return Ok(module_error(e)),
                };

            let ret = IAcp::editPolicyCall::abi_encode_returns(&IAcp::editPolicyReturn {
                relationshipsRemoved: relationships_removed,
                record: json_bytes(&record),
            });
            Ok(ok_output(WRITE_GAS, ret))
        }

        IAcp::setRelationshipCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::setRelationshipCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let actor_did = did_from_actor(&call.actor)?;
            let cmd = PolicyCmd::SetRelationship(acp::Relationship::new(
                &call.resource,
                &call.objectId,
                &call.relation,
                acp::Subject::entity(actor_did),
            ));

            let result = match module.direct_policy_cmd(&creator, &policy_id, cmd) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let (record_existed, record) = match result {
                hub_modules::acp::types::PolicyCmdResult::SetRelationship {
                    record_existed,
                    record,
                } => (record_existed, record),
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let ret = IAcp::setRelationshipCall::abi_encode_returns(&IAcp::setRelationshipReturn {
                recordExisted: record_existed,
                record: json_bytes(&record),
            });
            Ok(ok_output(WRITE_GAS, ret))
        }

        IAcp::deleteRelationshipCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IAcp::deleteRelationshipCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let actor_did = did_from_actor(&call.actor)?;
            let cmd = PolicyCmd::DeleteRelationship(acp::Relationship::new(
                &call.resource,
                &call.objectId,
                &call.relation,
                acp::Subject::entity(actor_did),
            ));

            let result = match module.direct_policy_cmd(&creator, &policy_id, cmd) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let record_found = match result {
                hub_modules::acp::types::PolicyCmdResult::DeleteRelationship { record_found } => {
                    record_found
                }
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let ret = IAcp::deleteRelationshipCall::abi_encode_returns(&record_found);
            Ok(ok_output(WRITE_GAS, ret))
        }

        IAcp::registerObjectCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::registerObjectCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let cmd = PolicyCmd::RegisterObject(Object {
                resource: call.resource,
                id: call.objectId,
            });

            let result = match module.direct_policy_cmd(&creator, &policy_id, cmd) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let record = match result {
                hub_modules::acp::types::PolicyCmdResult::RegisterObject { record } => record,
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let ret = IAcp::registerObjectCall::abi_encode_returns(&json_bytes(&record));
            Ok(ok_output(WRITE_GAS, ret))
        }

        IAcp::archiveObjectCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::archiveObjectCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let cmd = PolicyCmd::ArchiveObject(Object {
                resource: call.resource,
                id: call.objectId,
            });

            let result = match module.direct_policy_cmd(&creator, &policy_id, cmd) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let (found, relationships_removed) = match result {
                hub_modules::acp::types::PolicyCmdResult::ArchiveObject {
                    found,
                    relationships_removed,
                } => (found, relationships_removed),
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let ret = IAcp::archiveObjectCall::abi_encode_returns(&IAcp::archiveObjectReturn {
                found,
                relationshipsRemoved: relationships_removed,
            });
            Ok(ok_output(WRITE_GAS, ret))
        }

        IAcp::unarchiveObjectCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::unarchiveObjectCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let cmd = PolicyCmd::UnarchiveObject(Object {
                resource: call.resource,
                id: call.objectId,
            });

            let result = match module.direct_policy_cmd(&creator, &policy_id, cmd) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let (record, relationship_modified) = match result {
                hub_modules::acp::types::PolicyCmdResult::UnarchiveObject {
                    record,
                    relationship_modified,
                } => (record, relationship_modified),
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let ret = IAcp::unarchiveObjectCall::abi_encode_returns(&IAcp::unarchiveObjectReturn {
                record: json_bytes(&record),
                relationshipModified: relationship_modified,
            });
            Ok(ok_output(WRITE_GAS, ret))
        }

        IAcp::commitRegistrationsCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IAcp::commitRegistrationsCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let cmd = PolicyCmd::CommitRegistrations {
                commitment: call.commitment.to_vec(),
            };

            let result = match module.direct_policy_cmd(&creator, &policy_id, cmd) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let commitment_id = match result {
                hub_modules::acp::types::PolicyCmdResult::CommitRegistrations {
                    registrations_commitment,
                } => registrations_commitment.id,
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let ret = IAcp::commitRegistrationsCall::abi_encode_returns(&commitment_id);
            Ok(ok_output(WRITE_GAS, ret))
        }

        IAcp::revealRegistrationCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IAcp::revealRegistrationCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let proof: hub_modules::acp::types::RegistrationProof =
                serde_json::from_slice(&call.proof).map_err(|e| {
                    PrecompileError::Other(format!("proof JSON decode: {e}").into())
                })?;
            let cmd = PolicyCmd::RevealRegistration {
                registrations_commitment_id: call.commitmentId,
                proof,
            };

            // policy_id is not needed — the commitment record carries it.
            let result = match module.direct_policy_cmd(&creator, "", cmd) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let encoded = serde_json::to_vec(&result).unwrap_or_default();
            let ret_bytes = Bytes::from(encoded);
            let ret = IAcp::revealRegistrationCall::abi_encode_returns(&ret_bytes);
            Ok(ok_output(WRITE_GAS, ret))
        }

        IAcp::flagHijackAttemptCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IAcp::flagHijackAttemptCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let cmd = PolicyCmd::FlagHijackAttempt {
                event_id: call.eventId,
            };

            // policy_id is empty — FlagHijackAttempt looks up the amendment
            // event by event_id; the event record itself carries the policy_id.
            // The module implementation must ignore policy_id for this variant.
            let result = match module.direct_policy_cmd(&creator, "", cmd) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let event = match result {
                hub_modules::acp::types::PolicyCmdResult::FlagHijackAttempt { event } => event,
                _ => return Err(PrecompileError::Other("unexpected result variant".into())),
            };

            let ret = IAcp::flagHijackAttemptCall::abi_encode_returns(&json_bytes(&event));
            Ok(ok_output(WRITE_GAS, ret))
        }

        IAcp::checkAccessCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::checkAccessCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let actor_did = did_from_actor(&call.actor)?;
            let operations = build_operations(&call.resources, &call.objectIds, &call.permissions)?;
            let access_request = AccessRequest {
                operations,
                actor: Actor(actor_did),
            };

            let decision = match module.check_access(&creator, &policy_id, &access_request) {
                Ok(d) => d,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IAcp::checkAccessCall::abi_encode_returns(&json_bytes(&decision));
            Ok(ok_output(WRITE_GAS, ret))
        }

        IAcp::verifyAccessRequestCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IAcp::verifyAccessRequestCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let actor_did = did_from_actor(&call.actor)?;
            let operations = build_operations(&call.resources, &call.objectIds, &call.permissions)?;
            let access_request = AccessRequest {
                operations,
                actor: Actor(actor_did),
            };

            let allowed = match module.query_verify_access_request(&policy_id, &access_request) {
                Ok(v) => v,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IAcp::verifyAccessRequestCall::abi_encode_returns(&allowed);
            Ok(ok_output(READ_GAS, ret))
        }

        IAcp::signedPolicyCmdCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::signedPolicyCmdCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let payload_str = String::from_utf8(call.payload.to_vec())
                .map_err(|_| PrecompileError::Other("invalid UTF-8 in payload".into()))?;
            let content_type = content_type_from_u8(call.contentType);

            let result = match module.signed_policy_cmd(&creator, &payload_str, content_type) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IAcp::signedPolicyCmdCall::abi_encode_returns(&json_bytes(&result));
            Ok(ok_output(WRITE_GAS, ret))
        }

        IAcp::bearerPolicyCmdCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::bearerPolicyCmdCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let cmd: PolicyCmd = serde_json::from_slice(&call.cmd)
                .map_err(|e| PrecompileError::Other(format!("cmd JSON decode: {e}").into()))?;

            let result =
                match module.bearer_policy_cmd(&creator, &call.bearerToken, &policy_id, cmd) {
                    Ok(r) => r,
                    Err(e) => return Ok(module_error(e)),
                };

            let ret = IAcp::bearerPolicyCmdCall::abi_encode_returns(&json_bytes(&result));
            Ok(ok_output(WRITE_GAS, ret))
        }

        IAcp::updateParamsCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::updateParamsCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let authority = did_from_signer(&tx_ctx.signer)?;
            let params: AcpParams = serde_json::from_slice(&call.params)
                .map_err(|e| PrecompileError::Other(format!("params JSON decode: {e}").into()))?;

            match module.update_params(&authority, params) {
                Ok(()) => {}
                Err(e) => return Ok(module_error(e)),
            }

            Ok(ok_output(WRITE_GAS, Vec::new()))
        }

        // ── Read methods ─────────────────────────────────────────────
        IAcp::hasRelationshipCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::hasRelationshipCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let actor_did = did_from_actor(&call.actor)?;

            let selector = RelationshipSelector {
                object_selector: Some(hub_modules::acp::types::ObjectSelector::Exact(Object {
                    resource: call.resource,
                    id: call.objectId,
                })),
                relation_selector: Some(hub_modules::acp::types::RelationSelector::Exact(
                    call.relation,
                )),
                subject_selector: Some(hub_modules::acp::types::SubjectSelector::Exact(
                    acp::Subject::entity(actor_did),
                )),
            };

            let rels = match module.query_filter_relationships(&policy_id, &selector) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            // Phase 9: verify that query_filter_relationships excludes archived
            // records. If it doesn't, add `.iter().any(|r| !r.archived)` here.
            let has = !rels.is_empty();
            let ret = IAcp::hasRelationshipCall::abi_encode_returns(&has);
            Ok(ok_output(READ_GAS, ret))
        }

        IAcp::getPolicyCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::getPolicyCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let policy_id = policy_id_to_string(&call.policyId);

            let record = match module.query_policy(&policy_id) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IAcp::getPolicyCall::abi_encode_returns(&json_bytes(&record));
            Ok(ok_output(READ_GAS, ret))
        }

        IAcp::getObjectOwnerCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::getObjectOwnerCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let object = Object {
                resource: call.resource,
                id: call.objectId,
            };

            let (registered, record) = match module.query_object_owner(&policy_id, &object) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IAcp::getObjectOwnerCall::abi_encode_returns(&IAcp::getObjectOwnerReturn {
                registered,
                record: json_bytes(&record),
            });
            Ok(ok_output(READ_GAS, ret))
        }

        IAcp::getPolicyIdsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            // Zero-parameter function — no ABI decoding needed.
            let ids = match module.query_policy_ids() {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IAcp::getPolicyIdsCall::abi_encode_returns(&ids);
            Ok(ok_output(READ_GAS, ret))
        }

        IAcp::filterRelationshipsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IAcp::filterRelationshipsCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let policy_id = policy_id_to_string(&call.policyId);

            let selector = build_relationship_selector(
                &call.resource,
                &call.objectId,
                &call.relation,
                &call.actor,
            )?;

            let rels = match module.query_filter_relationships(&policy_id, &selector) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IAcp::filterRelationshipsCall::abi_encode_returns(&json_bytes(&rels));
            Ok(ok_output(READ_GAS, ret))
        }

        IAcp::validatePolicyCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::validatePolicyCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let policy_str = String::from_utf8(call.policy.to_vec())
                .map_err(|_| PrecompileError::Other("invalid UTF-8 in policy".into()))?;
            let marshal_type = marshal_type_from_u8(call.marshalType);

            let (valid, reason, _policy) =
                match module.query_validate_policy(&policy_str, marshal_type) {
                    Ok(r) => r,
                    Err(e) => return Ok(module_error(e)),
                };

            let ret = IAcp::validatePolicyCall::abi_encode_returns(&IAcp::validatePolicyReturn {
                valid,
                reason,
            });
            Ok(ok_output(READ_GAS, ret))
        }

        IAcp::getAccessDecisionCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IAcp::getAccessDecisionCall::abi_decode(&input[4..]).map_err(decode_error)?;

            let decision = match module.query_access_decision(&call.decisionId) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IAcp::getAccessDecisionCall::abi_encode_returns(&json_bytes(&decision));
            Ok(ok_output(READ_GAS, ret))
        }

        IAcp::getRegistrationsCommitmentCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::getRegistrationsCommitmentCall::abi_decode(&input[4..])
                .map_err(decode_error)?;

            let commitment = match module.query_registrations_commitment(call.commitmentId) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let ret =
                IAcp::getRegistrationsCommitmentCall::abi_encode_returns(&json_bytes(&commitment));
            Ok(ok_output(READ_GAS, ret))
        }

        IAcp::getRegistrationsCommitmentByValueCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::getRegistrationsCommitmentByValueCall::abi_decode(&input[4..])
                .map_err(decode_error)?;

            let commitments =
                match module.query_registrations_commitment_by_commitment(&call.commitment) {
                    Ok(r) => r,
                    Err(e) => return Ok(module_error(e)),
                };

            let ret = IAcp::getRegistrationsCommitmentByValueCall::abi_encode_returns(&json_bytes(
                &commitments,
            ));
            Ok(ok_output(READ_GAS, ret))
        }

        IAcp::getHijackAttemptsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IAcp::getHijackAttemptsCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let policy_id = policy_id_to_string(&call.policyId);

            let events = match module.query_hijack_attempts_by_policy(&policy_id) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IAcp::getHijackAttemptsCall::abi_encode_returns(&json_bytes(&events));
            Ok(ok_output(READ_GAS, ret))
        }

        IAcp::generateCommitmentCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IAcp::generateCommitmentCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let actor_did = did_from_actor(&call.actor)?;

            if call.resources.len() != call.objectIds.len() {
                return Err(PrecompileError::Other("array length mismatch".into()));
            }
            let objects: Vec<Object> = call
                .resources
                .iter()
                .zip(&call.objectIds)
                .map(|(r, o)| Object {
                    resource: r.clone(),
                    id: o.clone(),
                })
                .collect();

            let result =
                match module.query_generate_commitment(&policy_id, &objects, &Actor(actor_did)) {
                    Ok(r) => r,
                    Err(e) => return Ok(module_error(e)),
                };

            let ret = IAcp::generateCommitmentCall::abi_encode_returns(&json_bytes(&result));
            Ok(ok_output(READ_GAS, ret))
        }

        IAcp::getParamsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            // Zero-parameter function — no ABI decoding needed.
            let params = match module.query_params() {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IAcp::getParamsCall::abi_encode_returns(&json_bytes(&params));
            Ok(ok_output(READ_GAS, ret))
        }

        _ => Err(PrecompileError::Other(
            format!("unknown ACP selector: 0x{}", hex::encode(selector)).into(),
        )),
    }
}

fn build_relationship_selector(
    resource: &str,
    object_id: &str,
    relation: &str,
    actor: &str,
) -> Result<RelationshipSelector, PrecompileError> {
    use hub_modules::acp::types::{ObjectSelector, RelationSelector, SubjectSelector};

    let object_selector = if resource.is_empty() && object_id.is_empty() {
        None
    } else {
        Some(ObjectSelector::Exact(Object {
            resource: resource.to_owned(),
            id: object_id.to_owned(),
        }))
    };

    let relation_selector = if relation.is_empty() {
        None
    } else {
        Some(RelationSelector::Exact(relation.to_owned()))
    };

    let subject_selector = if actor.is_empty() {
        None
    } else {
        let actor_did = did_from_actor(actor)?;
        Some(SubjectSelector::Exact(acp::Subject::entity(actor_did)))
    };

    Ok(RelationshipSelector {
        object_selector,
        relation_selector,
        subject_selector,
    })
}
