//! Hub precompile dispatch — ABI decode/encode for all IHub selectors.

use alloy_primitives::Bytes;
use alloy_sol_types::SolCall;
use hub_modules::acp::AcpModule;
use hub_modules::hub::HubModule;
use hub_modules::hub::abi::IHub;
use hub_modules::hub::administration::SignedAdministrativeRequest;
use hub_modules::types::{BlockExecCtx, TxExecCtx};
use identity::Did;
use revm::precompile::PrecompileError;

use super::{
    DispatchReturn, HUB_ADDRESS, decode_error, did_from_signer, err_dispatch, event_log,
    json_bytes, ok_dispatch,
};

/// Flat gas cost for read operations (real metering is Phase 10).
const READ_GAS: u64 = 1000;
/// Flat gas cost for write operations (real metering is Phase 10).
const WRITE_GAS: u64 = 5000;

/// Dispatch an ABI-encoded call to the Hub module by selector.
pub(super) fn dispatch(
    module: &mut HubModule,
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
        IHub::applyRingCommandCall::SELECTOR => {
            if gas_limit < 500_000 {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IHub::applyRingCommandCall::abi_decode(input).map_err(decode_error)?;
            if call.request.len() > hub_modules::hub::rings::MAX_RING_REQUEST_BYTES {
                return Err(PrecompileError::Other("ring command is too large".into()));
            }
            let command = serde_json::from_slice(&call.request)
                .map_err(|error| PrecompileError::Other(error.to_string().into()))?;
            match module.apply_ring_command(acp, block_ctx, tx_ctx, &call.bearerToken, &command) {
                Ok(record) => Ok(ok_dispatch(
                    500_000,
                    IHub::applyRingCommandCall::abi_encode_returns(&json_bytes(&record)),
                    vec![],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        IHub::applyRingParticipantRequestCall::SELECTOR => {
            if gas_limit < 100_000 {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IHub::applyRingParticipantRequestCall::abi_decode(input).map_err(decode_error)?;
            if call.request.len() > hub_modules::hub::rings::MAX_RING_REQUEST_BYTES {
                return Err(PrecompileError::Other("ring request is too large".into()));
            }
            let signed = serde_json::from_slice(&call.request)
                .map_err(|error| PrecompileError::Other(error.to_string().into()))?;
            match module.apply_ring_participant_request(block_ctx, &signed) {
                Ok(record) => Ok(ok_dispatch(
                    100_000,
                    IHub::applyRingParticipantRequestCall::abi_encode_returns(&json_bytes(&record)),
                    vec![],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        IHub::finalizeRingReshareCall::SELECTOR => {
            if gas_limit < 500_000 {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IHub::finalizeRingReshareCall::abi_decode(input).map_err(decode_error)?;
            if call.request.len() > hub_modules::hub::rings::MAX_RING_REQUEST_BYTES {
                return Err(PrecompileError::Other("ring request is too large".into()));
            }
            let signed = serde_json::from_slice(&call.request)
                .map_err(|error| PrecompileError::Other(error.to_string().into()))?;
            match module.finalize_ring_reshare(block_ctx, &signed) {
                Ok(record) => Ok(ok_dispatch(
                    500_000,
                    IHub::finalizeRingReshareCall::abi_encode_returns(&json_bytes(&record)),
                    vec![],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        IHub::applyNodeRequestCall::SELECTOR => {
            if gas_limit < 100_000 {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IHub::applyNodeRequestCall::abi_decode(input).map_err(decode_error)?;
            if call.request.len() > hub_modules::hub::nodes::MAX_NODE_BYTES {
                return Err(PrecompileError::Other("node request is too large".into()));
            }
            let signed = serde_json::from_slice(&call.request)
                .map_err(|error| PrecompileError::Other(error.to_string().into()))?;
            match module.apply_node_request(block_ctx, &signed) {
                Ok(record) => Ok(ok_dispatch(
                    100_000,
                    IHub::applyNodeRequestCall::abi_encode_returns(&json_bytes(&record)),
                    vec![],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        IHub::applyAdministrationCall::SELECTOR => {
            if gas_limit < 500_000 {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IHub::applyAdministrationCall::abi_decode(input).map_err(decode_error)?;
            if call.request.len() > 32_768 {
                return Err(PrecompileError::Other(
                    "administrative request is too large".into(),
                ));
            }
            let signed: SignedAdministrativeRequest = serde_json::from_slice(&call.request)
                .map_err(|error| PrecompileError::Other(error.to_string().into()))?;
            match module.apply_administrative_request(
                acp,
                block_ctx.genesis_id,
                block_ctx.timestamp.seconds,
                &signed,
            ) {
                Ok(()) => Ok(ok_dispatch(500_000, Vec::new(), vec![])),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        IHub::getAdministrationCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            match module.administration() {
                Ok(state) => Ok(ok_dispatch(
                    READ_GAS,
                    IHub::getAdministrationCall::abi_encode_returns(&json_bytes(&state)),
                    vec![],
                )),
                Err(error) => Ok(err_dispatch(error)),
            }
        }
        // ── Write methods ────────────────────────────────────────────
        IHub::revokeDelegationCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IHub::revokeDelegationCall::abi_decode(input).map_err(decode_error)?;
            let caller = did_from_signer(&tx_ctx.signer)?;
            let record = match module.revoke_delegation(block_ctx, &caller, &call.token) {
                Ok(record) => record,
                Err(error) => return Ok(err_dispatch(error)),
            };
            let event = IHub::JWSTokenInvalidated {
                tokenHash: alloy_primitives::keccak256(record.token_hash.as_bytes()),
                issuerDid: record.issuer_did,
            };
            Ok(ok_dispatch(
                WRITE_GAS,
                Vec::new(),
                vec![event_log(HUB_ADDRESS, &event)],
            ))
        }
        IHub::invalidateJWSCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IHub::invalidateJWSCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;

            match module.invalidate_jws(block_ctx, tx_ctx, &creator, &call.tokenHash) {
                Ok(_) => {}
                Err(e) => return Ok(err_dispatch(e)),
            }

            let event = IHub::JWSTokenInvalidated {
                tokenHash: alloy_primitives::keccak256(call.tokenHash.as_bytes()),
                issuerDid: tx_ctx.signer.clone(),
            };
            Ok(ok_dispatch(
                WRITE_GAS,
                Vec::new(),
                vec![event_log(HUB_ADDRESS, &event)],
            ))
        }

        IHub::updateParamsCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IHub::updateParamsCall::abi_decode(input).map_err(decode_error)?;
            let authority = did_from_signer(&tx_ctx.signer)?;
            let params: hub_modules::hub::types::HubParams = serde_json::from_slice(&call.params)
                .map_err(|e| {
                PrecompileError::Other(format!("params JSON decode: {e}").into())
            })?;

            match module.update_params(&authority, params) {
                Ok(()) => {}
                Err(e) => return Ok(err_dispatch(e)),
            }

            Ok(ok_dispatch(WRITE_GAS, Vec::new(), vec![]))
        }

        // ── Read methods ─────────────────────────────────────────────
        IHub::getJWSTokenCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IHub::getJWSTokenCall::abi_decode(input).map_err(decode_error)?;

            let record = match module.get_jws_token(&call.tokenHash) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let (found, record_bytes) = record
                .as_ref()
                .map_or_else(|| (false, Bytes::new()), |r| (true, json_bytes(r)));

            let ret = IHub::getJWSTokenCall::abi_encode_returns(&IHub::getJWSTokenReturn {
                found,
                record: record_bytes,
            });
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IHub::getJWSTokensByDidCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IHub::getJWSTokensByDidCall::abi_decode(input).map_err(decode_error)?;
            let did = Did::new(&call.did)
                .map_err(|e| PrecompileError::Other(format!("DID parse: {e}").into()))?;

            let tokens = match module.get_jws_tokens_by_did(&did) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IHub::getJWSTokensByDidCall::abi_encode_returns(&json_bytes(&tokens));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IHub::getJWSTokensByAccountCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IHub::getJWSTokensByAccountCall::abi_decode(input).map_err(decode_error)?;
            let account_str = format!("{}", call.account);

            let tokens = match module.get_jws_tokens_by_account(&account_str) {
                Ok(r) => r,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IHub::getJWSTokensByAccountCall::abi_encode_returns(&json_bytes(&tokens));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IHub::getDelegationsBySubmitterCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call =
                IHub::getDelegationsBySubmitterCall::abi_decode(input).map_err(decode_error)?;
            let tokens = match module.get_jws_tokens_by_account(&call.submitter) {
                Ok(tokens) => tokens,
                Err(error) => return Ok(err_dispatch(error)),
            };
            let ret = IHub::getDelegationsBySubmitterCall::abi_encode_returns(&json_bytes(&tokens));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IHub::getChainConfigCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            // Zero-parameter function — no ABI decoding needed.
            let config = match module.get_chain_config() {
                Ok(c) => c,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IHub::getChainConfigCall::abi_encode_returns(&json_bytes(&config));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        IHub::getParamsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            // Zero-parameter function — no ABI decoding needed.
            let params = match module.query_params() {
                Ok(p) => p,
                Err(e) => return Ok(err_dispatch(e)),
            };

            let ret = IHub::getParamsCall::abi_encode_returns(&json_bytes(&params));
            Ok(ok_dispatch(READ_GAS, ret, vec![]))
        }

        _ => Err(PrecompileError::Other(
            format!("unknown Hub selector: 0x{}", hex::encode(selector)).into(),
        )),
    }
}
