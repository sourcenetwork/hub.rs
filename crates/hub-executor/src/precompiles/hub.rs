//! Hub precompile dispatch — ABI decode/encode for all IHub selectors.

use alloy_primitives::Bytes;
use alloy_sol_types::SolCall;
use hub_modules::hub::HubModule;
use hub_modules::hub::abi::IHub;
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
            let call = IHub::invalidateJWSCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let creator = did_from_signer(&tx_ctx.signer)?;
            let token_hash = hex::encode(call.tokenHash.as_slice());

            match module.invalidate_jws(block_ctx, tx_ctx, &creator, &token_hash) {
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
        IHub::getJWSTokenCall::SELECTOR => {
            if gas_limit < READ_GAS {
                return Err(PrecompileError::OutOfGas);
            }
            let call = IHub::getJWSTokenCall::abi_decode(&input[4..]).map_err(decode_error)?;
            let token_hash = hex::encode(call.tokenHash.as_slice());

            let record = match module.get_jws_token(&token_hash) {
                Ok(r) => r,
                Err(e) => return Ok(module_error(e)),
            };

            let (valid, issued_at, expires_at) = match record {
                Some(r) => (
                    r.status == hub_modules::hub::types::JWSTokenStatus::Valid,
                    r.issued_at.seconds,
                    r.expires_at.seconds,
                ),
                None => (false, 0, 0),
            };

            let ret = IHub::getJWSTokenCall::abi_encode_returns(&IHub::getJWSTokenReturn {
                valid,
                issuedAt: issued_at,
                expiresAt: expires_at,
            });
            Ok(PrecompileOutput {
                gas_used: READ_GAS,
                gas_refunded: 0,
                bytes: ret.into(),
                reverted: false,
            })
        }

        _ => Err(PrecompileError::Other(
            format!("unknown Hub selector: 0x{}", hex::encode(selector)).into(),
        )),
    }
}
