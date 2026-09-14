//! Emit the policy-edit commitment and call encoding for gateway interoperability.

use alloy_primitives::B256;
use alloy_sol_types::SolCall as _;
use hub_modules::acp::{
    abi::IAcp, delegated_operation::DelegatedOperation, types::PolicyMarshalingType,
};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let policy_id = "ab".repeat(32);
    let definition = "name: edits\n# 雪<>&\u{2028}\u{2029}\\u2028\nresources:\n  - name: file\n";
    let operation =
        DelegatedOperation::EditPolicy(&policy_id, definition, &PolicyMarshalingType::ShortYaml);
    let call = IAcp::bearerEditPolicyCall {
        bearerToken: "fixture-token".into(),
        policyId: B256::repeat_byte(0xab),
        policy: definition.as_bytes().to_vec().into(),
        marshalType: 1,
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "policy_id": policy_id, "definition": definition, "digest": hex::encode(operation.digest()?),
            "token": "fixture-token", "call": hex::encode(call.abi_encode()),
        }))?
    );
    Ok(())
}
