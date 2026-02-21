//! Hub precompiles — ABI dispatch for ACP, Bulletin, and Hub modules.
//!
//! L2-convention addresses:
//! - `0x0810` — ACP (access control policies)
//! - `0x0811` — Bulletin (coordination / DKG messages)
//! - `0x0812` — Hub (identity / JWS token lifecycle)

mod acp;
mod bulletin;
mod hub;

use alloy_primitives::{Address, B256, Bytes};
use hub_modules::acp::AcpModule;
use hub_modules::bulletin::BulletinModule;
use hub_modules::hub::HubModule;
use hub_modules::types::{BlockExecCtx, Timestamp, TxExecCtx};
use identity::Did;
use revm::{
    context::Cfg,
    context_interface::{Block, ContextTr},
    handler::{EthPrecompiles, PrecompileProvider},
    interpreter::{CallInputs, InterpreterResult},
    precompile::{
        Precompile, PrecompileError, PrecompileId, PrecompileOutput, PrecompileResult, Precompiles,
    },
    primitives::hardfork::SpecId,
};

/// ACP precompile address.
pub const ACP_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x10);

/// Bulletin precompile address.
pub const BULLETIN_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x11);

/// Hub precompile address.
pub const HUB_ADDRESS: Address = address_from_last_two_bytes(0x08, 0x12);

const fn address_from_last_two_bytes(hi: u8, lo: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[18] = hi;
    bytes[19] = lo;
    Address::new(bytes)
}

pub(super) fn did_from_signer(signer: &str) -> Result<Did, PrecompileError> {
    Did::new(signer).map_err(|e| PrecompileError::Other(format!("DID: {e}").into()))
}

pub(super) fn decode_error(e: alloy_sol_types::Error) -> PrecompileError {
    PrecompileError::Other(format!("ABI decode: {e}").into())
}

pub(super) fn module_error(e: impl core::fmt::Display) -> PrecompileOutput {
    PrecompileOutput {
        gas_used: 0,
        gas_refunded: 0,
        bytes: Bytes::from(e.to_string().into_bytes()),
        reverted: true,
    }
}

pub(super) fn json_bytes(v: &impl serde::Serialize) -> Bytes {
    Bytes::from(serde_json::to_vec(v).unwrap_or_default())
}

pub(super) fn ok_output(gas: u64, ret: Vec<u8>) -> PrecompileOutput {
    PrecompileOutput {
        gas_used: gas,
        gas_refunded: 0,
        bytes: ret.into(),
        reverted: false,
    }
}

const fn stub_precompile(_input: &[u8], _gas_limit: u64) -> PrecompileResult {
    Ok(PrecompileOutput {
        gas_used: 0,
        gas_refunded: 0,
        bytes: revm::primitives::Bytes::new(),
        reverted: true,
    })
}

/// Hub precompile provider that extends standard Ethereum precompiles
/// with ABI-dispatching precompiles for ACP, Bulletin, and Hub modules.
#[derive(Clone, Debug)]
pub struct HubPrecompiles {
    eth: EthPrecompiles,
    custom: Precompiles,
    acp_module: AcpModule,
    bulletin_module: BulletinModule,
    hub_module: HubModule,
    current_tx_hash: B256,
    current_signer_did: String,
}

/// Route calldata to the appropriate module based on the target precompile address.
///
/// Used by both the EVM precompile path and the native BLS tx path to ensure
/// both converge on the same module methods.
pub fn dispatch_to_module(
    acp: &mut AcpModule,
    bulletin: &mut BulletinModule,
    hub: &mut HubModule,
    target: Address,
    calldata: &[u8],
    block_ctx: &BlockExecCtx,
    tx_ctx: &TxExecCtx,
    gas_limit: u64,
) -> Option<PrecompileResult> {
    if target == ACP_ADDRESS {
        Some(acp::dispatch(acp, block_ctx, tx_ctx, calldata, gas_limit))
    } else if target == BULLETIN_ADDRESS {
        Some(bulletin::dispatch(
            bulletin, acp, block_ctx, tx_ctx, calldata, gas_limit,
        ))
    } else if target == HUB_ADDRESS {
        Some(hub::dispatch(hub, block_ctx, tx_ctx, calldata, gas_limit))
    } else {
        None
    }
}

fn new_custom_precompiles() -> Precompiles {
    let mut custom = Precompiles::default();
    custom.extend([
        Precompile::new(PrecompileId::custom("acp"), ACP_ADDRESS, stub_precompile),
        Precompile::new(
            PrecompileId::custom("bulletin"),
            BULLETIN_ADDRESS,
            stub_precompile,
        ),
        Precompile::new(PrecompileId::custom("hub"), HUB_ADDRESS, stub_precompile),
    ]);
    custom
}

impl HubPrecompiles {
    /// Create a new hub precompile provider for the given spec.
    pub fn new(spec: SpecId) -> Self {
        Self {
            eth: EthPrecompiles::new(spec),
            custom: new_custom_precompiles(),
            acp_module: AcpModule::new(),
            bulletin_module: BulletinModule::new(),
            hub_module: HubModule::new(),
            current_tx_hash: B256::ZERO,
            current_signer_did: String::new(),
        }
    }

    /// Create a hub precompile provider with pre-built module instances.
    pub fn with_modules(
        spec: SpecId,
        acp_module: AcpModule,
        bulletin_module: BulletinModule,
        hub_module: HubModule,
    ) -> Self {
        Self {
            eth: EthPrecompiles::new(spec),
            custom: new_custom_precompiles(),
            acp_module,
            bulletin_module,
            hub_module,
            current_tx_hash: B256::ZERO,
            current_signer_did: String::new(),
        }
    }

    /// Set the tx hash for the current EVM transaction being executed.
    pub fn set_tx_hash(&mut self, tx_hash: B256) {
        self.current_tx_hash = tx_hash;
    }

    /// Set the signer DID for the current EVM transaction being executed.
    pub fn set_signer_did(&mut self, did: String) {
        self.current_signer_did = did;
    }
}

impl<CTX: ContextTr> PrecompileProvider<CTX> for HubPrecompiles {
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        <EthPrecompiles as PrecompileProvider<CTX>>::set_spec(&mut self.eth, spec)
    }

    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<Self::Output>, String> {
        if self.custom.contains(&inputs.bytecode_address) {
            let block = context.block();
            let block_ctx = BlockExecCtx {
                timestamp: Timestamp {
                    seconds: block.timestamp().as_limbs()[0],
                    block_height: block.number().as_limbs()[0],
                },
            };
            let tx_ctx = TxExecCtx {
                tx_hash: self.current_tx_hash.to_vec(),
                signer: self.current_signer_did.clone(),
            };
            let calldata = inputs.input.bytes(context);
            return self.run_custom(inputs, &calldata, &block_ctx, &tx_ctx);
        }
        self.eth.run(context, inputs)
    }

    fn warm_addresses(&self) -> Box<impl Iterator<Item = Address>> {
        let eth_addrs: Vec<Address> = self.eth.warm_addresses().collect();
        let custom_addrs: Vec<Address> = self.custom.addresses().cloned().collect();
        Box::new(eth_addrs.into_iter().chain(custom_addrs))
    }

    fn contains(&self, address: &Address) -> bool {
        self.eth.contains(address) || self.custom.contains(address)
    }
}

impl HubPrecompiles {
    fn run_custom(
        &mut self,
        inputs: &CallInputs,
        calldata: &[u8],
        block_ctx: &BlockExecCtx,
        tx_ctx: &TxExecCtx,
    ) -> Result<Option<InterpreterResult>, String> {
        use revm::interpreter::{Gas, InstructionResult};

        let precompile_result = match dispatch_to_module(
            &mut self.acp_module,
            &mut self.bulletin_module,
            &mut self.hub_module,
            inputs.bytecode_address,
            calldata,
            block_ctx,
            tx_ctx,
            inputs.gas_limit,
        ) {
            Some(r) => r,
            None => return Ok(None),
        };

        let mut result = InterpreterResult {
            result: InstructionResult::Return,
            gas: Gas::new(inputs.gas_limit),
            output: revm::primitives::Bytes::new(),
        };
        match precompile_result {
            Ok(output) => {
                result.gas.record_refund(output.gas_refunded);
                if !result.gas.record_cost(output.gas_used) {
                    result.result = InstructionResult::PrecompileOOG;
                    return Ok(Some(result));
                }
                result.result = if output.reverted {
                    InstructionResult::Revert
                } else {
                    InstructionResult::Return
                };
                result.output = output.bytes;
            }
            Err(revm::precompile::PrecompileError::Fatal(e)) => return Err(e),
            Err(e) => {
                result.result = if e.is_oog() {
                    InstructionResult::PrecompileOOG
                } else {
                    InstructionResult::PrecompileError
                };
            }
        }
        Ok(Some(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::{database::EmptyDB, handler::MainnetContext};

    type TestCtx = MainnetContext<EmptyDB>;

    fn test_precompiles() -> HubPrecompiles {
        HubPrecompiles::new(SpecId::CANCUN)
    }

    #[test]
    fn precompile_addresses_are_nonzero() {
        assert_ne!(ACP_ADDRESS, Address::ZERO);
        assert_ne!(BULLETIN_ADDRESS, Address::ZERO);
        assert_ne!(HUB_ADDRESS, Address::ZERO);
    }

    #[test]
    fn precompile_addresses_are_distinct() {
        assert_ne!(ACP_ADDRESS, BULLETIN_ADDRESS);
        assert_ne!(ACP_ADDRESS, HUB_ADDRESS);
        assert_ne!(BULLETIN_ADDRESS, HUB_ADDRESS);
    }

    #[test]
    fn precompile_addresses_are_l2_convention() {
        assert_eq!(
            ACP_ADDRESS,
            "0x0000000000000000000000000000000000000810"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(
            BULLETIN_ADDRESS,
            "0x0000000000000000000000000000000000000811"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(
            HUB_ADDRESS,
            "0x0000000000000000000000000000000000000812"
                .parse::<Address>()
                .unwrap()
        );
    }

    #[test]
    fn hub_precompiles_contains_custom() {
        let precompiles = test_precompiles();
        assert!(<HubPrecompiles as PrecompileProvider<TestCtx>>::contains(
            &precompiles,
            &ACP_ADDRESS
        ));
        assert!(<HubPrecompiles as PrecompileProvider<TestCtx>>::contains(
            &precompiles,
            &BULLETIN_ADDRESS
        ));
        assert!(<HubPrecompiles as PrecompileProvider<TestCtx>>::contains(
            &precompiles,
            &HUB_ADDRESS
        ));
    }

    #[test]
    fn hub_precompiles_contains_standard() {
        let ecrecover = "0x0000000000000000000000000000000000000001"
            .parse::<Address>()
            .unwrap();
        let precompiles = test_precompiles();
        assert!(<HubPrecompiles as PrecompileProvider<TestCtx>>::contains(
            &precompiles,
            &ecrecover
        ));
    }

    #[test]
    fn hub_precompiles_warm_addresses_include_custom() {
        let precompiles = test_precompiles();
        let warm: Vec<Address> =
            <HubPrecompiles as PrecompileProvider<TestCtx>>::warm_addresses(&precompiles).collect();
        assert!(warm.contains(&ACP_ADDRESS));
        assert!(warm.contains(&BULLETIN_ADDRESS));
        assert!(warm.contains(&HUB_ADDRESS));
    }
}
