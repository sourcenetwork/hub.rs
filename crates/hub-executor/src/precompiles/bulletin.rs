//! Bulletin precompile dispatch — ABI decode/encode for all IBulletin selectors.

use alloy_primitives::B256;
use alloy_sol_types::SolCall;
use hub_modules::acp::AcpModule;
use hub_modules::bulletin::BulletinModule;
use hub_modules::bulletin::abi::IBulletin;
use hub_modules::types::{BlockExecCtx, TxExecCtx};
use revm::precompile::PrecompileError;

use super::{
    BULLETIN_ADDRESS, DispatchReturn, decode_error, did_from_signer, err_dispatch, event_log,
    json_bytes, ok_dispatch,
};

/// Flat gas cost for read operations (real metering is Phase 10).
const READ_GAS: u64 = 1000;
/// Flat gas cost for write operations (real metering is Phase 10).
const WRITE_GAS: u64 = 5000;

/// Dispatch an ABI-encoded call to the Bulletin module by selector.
pub(super) fn dispatch(
    module: &mut BulletinModule,
    acp: &mut AcpModule,
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    input: &[u8],
    gas_limit: u64,
) -> DispatchReturn {
    if input.len() < 4 {
        return Err(PrecompileError::Other(
            "input too short for selector".into(),
        ));
    }
    let selector: [u8; 4] = input[..4].try_into().expect("checked length above");

    match selector {
        // ── Write methods ────────────────────────────────────────────
        IBulletin::registerNamespaceCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IBulletin::registerNamespaceCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;

            let ns = match module.register_namespace(
                acp,
                block_ctx,
                tx_ctx,
                &creator,
                &call.namespace,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let event = IBulletin::NamespaceCreated {
                namespace: alloy_primitives::keccak256(call.namespace.as_bytes()),
                owner: tx_ctx.signer.clone(),
            };
            let ret = IBulletin::registerNamespaceCall::abi_encode_returns(&json_bytes(&ns));
            Ok(ok_dispatch(
                WRITE_GAS,
                ret,
                vec![event_log(BULLETIN_ADDRESS, &event)],
            ))
        }

        IBulletin::createPostCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IBulletin::createPostCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;

            match module.create_post(
                acp,
                tx_ctx,
                &creator,
                &call.namespace,
                &call.payload,
                &call.proof,
                &call.artifact,
            ) {
                Ok(()) => {}
                Err(e) => return Ok(err_dispatch(e)),
            }

            let event = IBulletin::PostCreated {
                namespace: alloy_primitives::keccak256(call.namespace.as_bytes()),
                postId: B256::ZERO,
            };
            let ret = IBulletin::createPostCall::abi_encode_returns(&B256::ZERO);
            Ok(ok_dispatch(
                WRITE_GAS,
                ret,
                vec![event_log(BULLETIN_ADDRESS, &event)],
            ))
        }

        IBulletin::addCollaboratorCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IBulletin::addCollaboratorCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let collaborator_str = format!("{}", call.collaborator);

            let collaborator_did = match module.add_collaborator(
                acp,
                tx_ctx,
                &creator,
                &call.namespace,
                &collaborator_str,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let event = IBulletin::CollaboratorAdded {
                namespace: alloy_primitives::keccak256(call.namespace.as_bytes()),
                collaborator: collaborator_did.clone(),
            };
            let ret = IBulletin::addCollaboratorCall::abi_encode_returns(&collaborator_did);
            Ok(ok_dispatch(
                WRITE_GAS,
                ret,
                vec![event_log(BULLETIN_ADDRESS, &event)],
            ))
        }

        IBulletin::removeCollaboratorCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IBulletin::removeCollaboratorCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let collaborator_str = format!("{}", call.collaborator);

            let collaborator_did = match module.remove_collaborator(
                acp,
                tx_ctx,
                &creator,
                &call.namespace,
                &collaborator_str,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let event = IBulletin::CollaboratorRemoved {
                namespace: alloy_primitives::keccak256(call.namespace.as_bytes()),
                collaborator: collaborator_did.clone(),
            };
            let ret = IBulletin::removeCollaboratorCall::abi_encode_returns(&collaborator_did);
            Ok(ok_dispatch(
                WRITE_GAS,
                ret,
                vec![event_log(BULLETIN_ADDRESS, &event)],
            ))
        }

        IBulletin::updateParamsCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IBulletin::updateParamsCall::abi_decode(input).map_err(decode_error)?;
            let authority = did_from_signer(&tx_ctx.signer)?;
            let params: hub_modules::bulletin::types::BulletinParams =
                serde_json::from_slice(&call.params).map_err(|e| {
                    PrecompileError::Other(format!("params JSON decode: {e}").into())
                })?;

            match module.update_params(&authority, params) {
                Ok(()) => {}
                Err(e) => return Ok(err_dispatch(e)),
            }

            Ok(ok_dispatch(WRITE_GAS, Vec::new(), vec![]))
        }

        // ── Read methods ─────────────────────────────────────────────
        IBulletin::getPostCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IBulletin::getPostCall::abi_decode(input).map_err(decode_error)?;

            let post = match module.query_post(&call.namespace, &call.postId) {
                Ok(p) => p,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IBulletin::getPostCall::abi_encode_returns(&json_bytes(&post));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IBulletin::getNamespaceCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IBulletin::getNamespaceCall::abi_decode(input).map_err(decode_error)?;

            let ns = match module.query_namespace(&call.namespace) {
                Ok(n) => n,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IBulletin::getNamespaceCall::abi_encode_returns(&json_bytes(&ns));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IBulletin::getNamespacesCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }

            let namespaces = match module.query_namespaces() {
                Ok(ns) => ns,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IBulletin::getNamespacesCall::abi_encode_returns(&json_bytes(&namespaces));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IBulletin::getNamespaceCollaboratorsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IBulletin::getNamespaceCollaboratorsCall::abi_decode(input)
                .map_err(decode_error)?;

            let collaborators = match module.query_namespace_collaborators(&call.namespace) {
                Ok(c) => c,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IBulletin::getNamespaceCollaboratorsCall::abi_encode_returns(&json_bytes(
                &collaborators,
            ));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IBulletin::getNamespacePostsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IBulletin::getNamespacePostsCall::abi_decode(input).map_err(decode_error)?;

            let posts = match module.query_namespace_posts(&call.namespace) {
                Ok(p) => p,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IBulletin::getNamespacePostsCall::abi_encode_returns(&json_bytes(&posts));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IBulletin::getPostsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }

            let posts = match module.query_posts() {
                Ok(p) => p,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IBulletin::getPostsCall::abi_encode_returns(&json_bytes(&posts));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IBulletin::iterateGlobCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IBulletin::iterateGlobCall::abi_decode(input).map_err(decode_error)?;

            let posts = match module.query_iterate_glob(&call.namespace, &call.glob) {
                Ok(p) => p,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IBulletin::iterateGlobCall::abi_encode_returns(&json_bytes(&posts));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IBulletin::getParamsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }

            let params = match module.query_params() {
                Ok(p) => p,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IBulletin::getParamsCall::abi_encode_returns(&json_bytes(&params));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        _ => Err(PrecompileError::Other(
            format!("unknown Bulletin selector: 0x{}", hex::encode(selector)).into(),
        )),
    }
}
