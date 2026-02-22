//! Hub precompile dispatch — ABI decode/encode for all IHub selectors.

use alloy_primitives::Bytes;
use alloy_sol_types::SolCall;
use hub_modules::hub::HubModule;
use hub_modules::hub::abi::IHub;
use hub_modules::types::{BlockExecCtx, TxExecCtx};
use identity::Did;
use revm::precompile::{PrecompileError, PrecompileResult};

use super::{decode_error, did_from_signer, json_bytes, module_error, ok_output};

/// Flat gas cost for read operations (real metering is Phase 10).
const READ_GAS: u64 = 1000;
/// Flat gas cost for write operations (real metering is Phase 10).
const WRITE_GAS: u64 = 5000;

/// Dispatch an ABI-encoded call to the Hub module by selector.
pub(super) fn dispatch(
    module: &mut HubModule,
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
        IHub::invalidateJWSCall::SELECTOR => {
            if gas_limit < WRITE_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IHub::invalidateJWSCall::abi_decode(input).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;

            match module.invalidate_jws(block_ctx, tx_ctx, &creator, &call.tokenHash) {
                Ok(_) => {}
                Err(e) => return Ok(module_error(e)),
            }

            Ok(ok_output(WRITE_GAS, Vec::new()))
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
                Err(e) => return Ok(module_error(e)),
            }

            Ok(ok_output(WRITE_GAS, Vec::new()))
        }

        // ── Read methods ─────────────────────────────────────────────
        IHub::getJWSTokenCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IHub::getJWSTokenCall::abi_decode(input).map_err(decode_error)?;

            let record = match module.get_jws_token(&call.tokenHash) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let (found, record_bytes) = record
                .as_ref()
                .map_or_else(|| (false, Bytes::new()), |r| (true, json_bytes(r)));

            let ret = IHub::getJWSTokenCall::abi_encode_returns(&IHub::getJWSTokenReturn {
                found,
                record: record_bytes,
            });
            Ok(ok_output(READ_GAS, ret))
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
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IHub::getJWSTokensByDidCall::abi_encode_returns(&json_bytes(&tokens));
            Ok(ok_output(READ_GAS, ret))
        }

        IHub::getJWSTokensByAccountCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IHub::getJWSTokensByAccountCall::abi_decode(input).map_err(decode_error)?;
            let account_str = format!("{}", call.account);

            let tokens = match module.get_jws_tokens_by_account(&account_str) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IHub::getJWSTokensByAccountCall::abi_encode_returns(&json_bytes(&tokens));
            Ok(ok_output(READ_GAS, ret))
        }

        IHub::getChainConfigCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            // Zero-parameter function — no ABI decoding needed.
            let config = match module.get_chain_config() {
                Ok(c) => c,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IHub::getChainConfigCall::abi_encode_returns(&json_bytes(&config));
            Ok(ok_output(READ_GAS, ret))
        }

        IHub::getParamsCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            // Zero-parameter function — no ABI decoding needed.
            let params = match module.query_params() {
                Ok(p) => p,
                Err(e) => return Ok(module_error(e)),
            };

            let ret = IHub::getParamsCall::abi_encode_returns(&json_bytes(&params));
            Ok(ok_output(READ_GAS, ret))
        }

        _ => Err(PrecompileError::Other(
            format!("unknown Hub selector: 0x{}", hex::encode(selector)).into(),
        )),
    }
}
