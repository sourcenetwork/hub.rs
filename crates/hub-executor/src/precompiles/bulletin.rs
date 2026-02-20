//! Bulletin precompile dispatch — ABI decode/encode for all IBulletin selectors.

use alloy_primitives::{B256, Bytes};
use alloy_sol_types::SolCall;
use hub_modules::acp::AcpModule;
use hub_modules::bulletin::BulletinModule;
use hub_modules::bulletin::abi::IBulletin;
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

/// Dispatch an ABI-encoded call to the Bulletin module by selector.
pub(super) fn dispatch(
    module: &mut BulletinModule,
    acp: &mut AcpModule,
    block_ctx: &BlockExecCtx,
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
        IBulletin::registerNamespaceCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IBulletin::registerNamespaceCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;

            match module.register_namespace(acp, block_ctx, tx_ctx, &creator, &call.namespace) {
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

        IBulletin::createPostCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IBulletin::createPostCall::abi_decode(&input[4..]).map_err(decode_error)?;
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
                Err(e) => return Ok(module_error(e)),
            }

            // Post ID is sha256(namespace_id + payload), computed inside module.
            // The ABI returns bytes32 postId but create_post returns ().
            // When Phase 9 implements the module, create_post should return
            // the post ID. For now, return zeroed bytes32.
            let ret = IBulletin::createPostCall::abi_encode_returns(&B256::ZERO);
            Ok(PrecompileOutput {
                gas_used: WRITE_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        IBulletin::addCollaboratorCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IBulletin::addCollaboratorCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let collaborator_str = format!("{:?}", call.collaborator);

            match module.add_collaborator(acp, tx_ctx, &creator, &call.namespace, &collaborator_str)
            {
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

        IBulletin::removeCollaboratorCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IBulletin::removeCollaboratorCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let collaborator_str = format!("{:?}", call.collaborator);

            match module.remove_collaborator(
                acp,
                tx_ctx,
                &creator,
                &call.namespace,
                &collaborator_str,
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

        IBulletin::updateParamsCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IBulletin::updateParamsCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let authority = did_from_signer(&tx_ctx.signer)?;
            let params: hub_modules::bulletin::types::BulletinParams =
                serde_json::from_slice(&call.params).unwrap_or_default();

            match module.update_params(&authority, params) {
                Ok(()) => {}
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
        IBulletin::getPostCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IBulletin::getPostCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let post_id = hex::encode(call.postId.as_slice());

            let post = match module.query_post(&call.namespace, &post_id) {
                Ok(p) => p,
                Err(e) => return Ok(module_error(e)),
            };

            let encoded = serde_json::to_vec(&post).unwrap_or_default();
            let ret_bytes = Bytes::from(encoded);
            let ret = IBulletin::getPostCall::abi_encode_returns(&ret_bytes);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        IBulletin::getNamespaceCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IBulletin::getNamespaceCall::abi_decode(&input[4..]).map_err(decode_error)?;

            let ns = match module.query_namespace(&call.namespace) {
                Ok(n) => n,
                Err(e) => return Ok(module_error(e)),
            };

            let encoded = serde_json::to_vec(&ns).unwrap_or_default();
            let ret_bytes = Bytes::from(encoded);
            let ret = IBulletin::getNamespaceCall::abi_encode_returns(&ret_bytes);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        IBulletin::getNamespacesCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }

            let namespaces = match module.query_namespaces() {
                Ok(ns) => ns,
                Err(e) => return Ok(module_error(e)),
            };

            let encoded = serde_json::to_vec(&namespaces).unwrap_or_default();
            let ret_bytes = Bytes::from(encoded);
            let ret = IBulletin::getNamespacesCall::abi_encode_returns(&ret_bytes);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        IBulletin::getNamespaceCollaboratorsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IBulletin::getNamespaceCollaboratorsCall::abi_decode(&input[4..])
                .map_err(decode_error)?;

            let collaborators = match module.query_namespace_collaborators(&call.namespace) {
                Ok(c) => c,
                Err(e) => return Ok(module_error(e)),
            };

            let encoded = serde_json::to_vec(&collaborators).unwrap_or_default();
            let ret_bytes = Bytes::from(encoded);
            let ret = IBulletin::getNamespaceCollaboratorsCall::abi_encode_returns(&ret_bytes);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        IBulletin::getNamespacePostsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IBulletin::getNamespacePostsCall::abi_decode(&input[4..]).map_err(decode_error)?;

            let posts = match module.query_namespace_posts(&call.namespace) {
                Ok(p) => p,
                Err(e) => return Ok(module_error(e)),
            };

            let encoded = serde_json::to_vec(&posts).unwrap_or_default();
            let ret_bytes = Bytes::from(encoded);
            let ret = IBulletin::getNamespacePostsCall::abi_encode_returns(&ret_bytes);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        IBulletin::getPostsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }

            let posts = match module.query_posts() {
                Ok(p) => p,
                Err(e) => return Ok(module_error(e)),
            };

            let encoded = serde_json::to_vec(&posts).unwrap_or_default();
            let ret_bytes = Bytes::from(encoded);
            let ret = IBulletin::getPostsCall::abi_encode_returns(&ret_bytes);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        IBulletin::iterateGlobCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IBulletin::iterateGlobCall::abi_decode(&input[4..]).map_err(decode_error)?;

            let posts = match module.query_iterate_glob(&call.namespace, &call.glob) {
                Ok(p) => p,
                Err(e) => return Ok(module_error(e)),
            };

            let encoded = serde_json::to_vec(&posts).unwrap_or_default();
            let ret_bytes = Bytes::from(encoded);
            let ret = IBulletin::iterateGlobCall::abi_encode_returns(&ret_bytes);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        IBulletin::getParamsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }

            let params = match module.query_params() {
                Ok(p) => p,
                Err(e) => return Ok(module_error(e)),
            };

            let encoded = serde_json::to_vec(&params).unwrap_or_default();
            let ret_bytes = Bytes::from(encoded);
            let ret = IBulletin::getParamsCall::abi_encode_returns(&ret_bytes);
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        _ => Err(PrecompileError::Other(
            format!("unknown Bulletin selector: 0x{}", hex::encode(selector)).into(),
        )),
    }
}
