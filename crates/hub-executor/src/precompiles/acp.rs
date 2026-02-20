//! ACP precompile dispatch — ABI decode/encode for all IAcp selectors.

use alloy_primitives::{B256, Bytes};
use alloy_sol_types::SolCall;
use hub_modules::acp::AcpModule;
use hub_modules::acp::abi::IAcp;
use hub_modules::acp::types::{
    AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyMarshalingType, RelationshipSelector,
};
use hub_modules::types::{BlockExecCtx, TxExecCtx};
use identity::Did;
use revm::precompile::{PrecompileError, PrecompileOutput, PrecompileResult};

/// Flat gas cost for read operations (real metering is Phase 10).
const READ_GAS: u64 = 1000;
/// Flat gas cost for write operations (real metering is Phase 10).
const WRITE_GAS: u64 = 5000;

fn did_from_signer(signer: &str) -> Result<Did, PrecompileError> {
    Did::new(format!("did:key:z{signer}"))
        .map_err(|e| PrecompileError::Other(format!("DID construction: {e}").into()))
}

fn did_from_actor(actor: &str) -> Result<Did, PrecompileError> {
    Did::new(actor).map_err(|e| PrecompileError::Other(format!("actor DID: {e}").into()))
}

fn policy_id_to_string(b: &B256) -> String {
    hex::encode(b.as_slice())
}

fn policy_id_from_string(s: &str) -> Result<B256, PrecompileError> {
    let bytes = hex::decode(s)
        .map_err(|e| PrecompileError::Other(format!("policy ID encode: {e}").into()))?;
    if bytes.len() != 32 {
        return Err(PrecompileError::Other(
            format!("policy ID is {} bytes, expected 32", bytes.len()).into(),
        ));
    }
    Ok(B256::from_slice(&bytes))
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
            let yaml_str = String::from_utf8(call.yaml.to_vec())
                .map_err(|_| PrecompileError::Other("invalid UTF-8 in yaml".into()))?;
            let creator = did_from_signer(&tx_ctx.signer)?;

            let record =
                match module.create_policy(&creator, &yaml_str, PolicyMarshalingType::ShortYaml) {
                    Ok(r) => r,
                    Err(e) => return Ok(module_error(e)),
                };

            let policy_id = policy_id_from_string(&record.policy.id)?;
            let ret = IAcp::createPolicyCall::abi_encode_returns(&policy_id);
            Ok(PrecompileOutput {
                gas_used: WRITE_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        IAcp::editPolicyCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::editPolicyCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let yaml_str = String::from_utf8(call.yaml.to_vec())
                .map_err(|_| PrecompileError::Other("invalid UTF-8 in yaml".into()))?;

            match module.edit_policy(
                &creator,
                &policy_id,
                &yaml_str,
                PolicyMarshalingType::ShortYaml,
            ) {
                Ok(_) => {}
                Err(e) => return Ok(module_error(e)),
            }

            Ok(PrecompileOutput {
                gas_used: WRITE_GAS,
                gas_refunded: 0,
                bytes: Bytes::new(),
                reverted: false,
            })
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

            match module.direct_policy_cmd(&creator, &policy_id, cmd) {
                Ok(_) => {}
                Err(e) => return Ok(module_error(e)),
            }

            Ok(PrecompileOutput {
                gas_used: WRITE_GAS,
                gas_refunded: 0,
                bytes: Bytes::new(),
                reverted: false,
            })
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

            match module.direct_policy_cmd(&creator, &policy_id, cmd) {
                Ok(_) => {}
                Err(e) => return Ok(module_error(e)),
            }

            Ok(PrecompileOutput {
                gas_used: WRITE_GAS,
                gas_refunded: 0,
                bytes: Bytes::new(),
                reverted: false,
            })
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

            match module.direct_policy_cmd(&creator, &policy_id, cmd) {
                Ok(_) => {}
                Err(e) => return Ok(module_error(e)),
            }

            Ok(PrecompileOutput {
                gas_used: WRITE_GAS,
                gas_refunded: 0,
                bytes: Bytes::new(),
                reverted: false,
            })
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

            match module.direct_policy_cmd(&creator, &policy_id, cmd) {
                Ok(_) => {}
                Err(e) => return Ok(module_error(e)),
            }

            Ok(PrecompileOutput {
                gas_used: WRITE_GAS,
                gas_refunded: 0,
                bytes: Bytes::new(),
                reverted: false,
            })
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

            match module.direct_policy_cmd(&creator, &policy_id, cmd) {
                Ok(_) => {}
                Err(e) => return Ok(module_error(e)),
            }

            Ok(PrecompileOutput {
                gas_used: WRITE_GAS,
                gas_refunded: 0,
                bytes: Bytes::new(),
                reverted: false,
            })
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
            Ok(PrecompileOutput {
                gas_used: WRITE_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        IAcp::revealRegistrationCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let _call =
                IAcp::revealRegistrationCall::abi_decode(&input[4..]).map_err(decode_error)?;
            // revealRegistration takes (uint64 commitmentId, bytes proof).
            // The proof needs to be deserialized into RegistrationProof — this
            // requires a serialization format decision. For now, the module
            // method will todo!() before we reach return encoding.
            Err(PrecompileError::Other(
                "revealRegistration proof deserialization not yet wired".into(),
            ))
        }

        IAcp::flagHijackAttemptCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IAcp::flagHijackAttemptCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            // flagHijackAttempt uses a fixed policy_id="" — the event_id
            // references a stored event that already has the policy_id.
            let cmd = PolicyCmd::FlagHijackAttempt {
                event_id: call.eventId,
            };

            match module.direct_policy_cmd(&creator, "", cmd) {
                Ok(_) => {}
                Err(e) => return Ok(module_error(e)),
            }

            Ok(PrecompileOutput {
                gas_used: WRITE_GAS,
                gas_refunded: 0,
                bytes: Bytes::new(),
                reverted: false,
            })
        }

        // ── Read methods ─────────────────────────────────────────────
        IAcp::checkAccessCall::SELECTOR => {
            // check_access persists a decision — it's a write
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::checkAccessCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let actor_did = did_from_actor(&call.actor)?;
            let access_request = AccessRequest {
                operations: vec![Operation {
                    object: Object {
                        resource: call.resource,
                        id: call.objectId,
                    },
                    permission: call.permission,
                }],
                actor: Actor(actor_did),
            };

            let _decision = match module.check_access(&creator, &policy_id, &access_request) {
                Ok(d) => d,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IAcp::checkAccessCall::abi_encode_returns(&true);
            Ok(PrecompileOutput {
                gas_used: WRITE_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        IAcp::verifyAccessRequestCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IAcp::verifyAccessRequestCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let policy_id = policy_id_to_string(&call.policyId);
            let actor_did = did_from_actor(&call.actor)?;
            let access_request = AccessRequest {
                operations: vec![Operation {
                    object: Object {
                        resource: call.resource,
                        id: call.objectId,
                    },
                    permission: call.permission,
                }],
                actor: Actor(actor_did),
            };

            let allowed = match module.query_verify_access_request(&policy_id, &access_request) {
                Ok(v) => v,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IAcp::verifyAccessRequestCall::abi_encode_returns(&allowed);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

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

            let has = !rels.is_empty();
            let ret = IAcp::hasRelationshipCall::abi_encode_returns(&has);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
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

            let ret_bytes = Bytes::from(record.raw_policy.into_bytes());
            let ret = IAcp::getPolicyCall::abi_encode_returns(&ret_bytes);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
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

            let owner = if registered {
                record.map(|r| r.metadata.owner_did).unwrap_or_default()
            } else {
                String::new()
            };

            let ret = IAcp::getObjectOwnerCall::abi_encode_returns(&owner);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        IAcp::getPolicyIdsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let _call = IAcp::getPolicyIdsCall::abi_decode(&input[4..]).map_err(decode_error)?;

            let ids = match module.query_policy_ids() {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IAcp::getPolicyIdsCall::abi_encode_returns(&ids);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
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

            let encoded = serde_json::to_vec(&rels).unwrap_or_default();
            let ret_bytes = Bytes::from(encoded);
            let ret = IAcp::filterRelationshipsCall::abi_encode_returns(&ret_bytes);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        IAcp::validatePolicyCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::validatePolicyCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let policy_str = String::from_utf8(call.policy.to_vec())
                .map_err(|_| PrecompileError::Other("invalid UTF-8 in policy".into()))?;

            let (valid, reason, _policy) =
                match module.query_validate_policy(&policy_str, PolicyMarshalingType::ShortYaml) {
                    Ok(r) => r,
                    Err(e) => return Ok(module_error(e)),
                };

            let ret = IAcp::validatePolicyCall::abi_encode_returns(&IAcp::validatePolicyReturn {
                valid,
                reason,
            });
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        IAcp::getAccessDecisionCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IAcp::getAccessDecisionCall::abi_decode(&input[4..]).map_err(decode_error)?;

            let decision = match module.query_access_decision(&call.decisionId.to_string()) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let encoded = serde_json::to_vec(&decision).unwrap_or_default();
            let ret_bytes = Bytes::from(encoded);
            let ret = IAcp::getAccessDecisionCall::abi_encode_returns(&ret_bytes);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
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

            let encoded = serde_json::to_vec(&commitment).unwrap_or_default();
            let ret_bytes = Bytes::from(encoded);
            let ret = IAcp::getRegistrationsCommitmentCall::abi_encode_returns(&ret_bytes);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        IAcp::getRegistrationsCommitmentByValueCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IAcp::getRegistrationsCommitmentByValueCall::abi_decode(&input[4..])
                .map_err(decode_error)?;
            let _policy_id = policy_id_to_string(&call.policyId);

            let commitments =
                match module.query_registrations_commitment_by_commitment(&call.commitment) {
                    Ok(r) => r,
                    Err(e) => return Ok(module_error(e)),
                };

            let encoded = serde_json::to_vec(&commitments).unwrap_or_default();
            let ret_bytes = Bytes::from(encoded);
            let ret = IAcp::getRegistrationsCommitmentByValueCall::abi_encode_returns(&ret_bytes);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
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

            let encoded = serde_json::to_vec(&events).unwrap_or_default();
            let ret_bytes = Bytes::from(encoded);
            let ret = IAcp::getHijackAttemptsCall::abi_encode_returns(&ret_bytes);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
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
