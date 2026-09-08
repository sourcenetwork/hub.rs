//! Emit native access-decision commitments and call encoding for gateway interoperability.

use alloy_primitives::B256;
use alloy_sol_types::SolCall as _;
use hub_modules::acp::{
    abi::IAcp,
    delegated_operation::DelegatedOperation,
    types::{AccessRequest, Actor, Object, Operation},
};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy_id = "ab".repeat(32);
    let request = AccessRequest {
        actor: Actor(format!("did:opk:{}", "cd".repeat(32)).parse()?),
        operations: vec![
            Operation {
                object: Object {
                    resource: "document".into(),
                    id: "report-雪<>&\u{2028}\u{2029}\n\"".into(),
                },
                permission: "read".into(),
            },
            Operation {
                object: Object {
                    resource: "document".into(),
                    id: "second".into(),
                },
                permission: "write".into(),
            },
        ],
    };
    let operation = DelegatedOperation::CheckAccess(&policy_id, &request);
    let encoded = serde_json::to_vec(&request)?;
    let call = IAcp::bearerCheckAccessCall {
        bearerToken: "fixture-token".into(),
        policyId: B256::repeat_byte(0xab),
        request: encoded.clone().into(),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "policy_id": policy_id, "request": String::from_utf8(encoded)?,
            "digest": hex::encode(operation.digest()?), "token": "fixture-token", "call": hex::encode(call.abi_encode()),
        }))?
    );
    Ok(())
}
