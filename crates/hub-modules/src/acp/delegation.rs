use hub_crypto::jwt::DelegationScope;
use identity::Did;

use super::delegated_operation::DelegatedOperation;
use super::{AcpError, AcpModule, Result};
use crate::acp::types::{
    PolicyCmd, PolicyCmdResult, PolicyMarshalingType, PolicyRecord, RecordMetadata,
};
use crate::hub::HubModule;
use crate::types::{BlockExecCtx, Timestamp, TxExecCtx};

impl AcpModule {
    /// Create a policy owned by the actor authorizing the submitting worker.
    pub fn bearer_create_policy(
        &mut self,
        hub: &mut HubModule,
        context: &BlockExecCtx,
        submission: &TxExecCtx,
        token: &str,
        policy: &str,
        marshal_type: PolicyMarshalingType,
    ) -> Result<PolicyRecord> {
        if submission.tx_hash.len() != 32 {
            return Err(AcpError::State(
                "missing authenticated submission identifier".into(),
            ));
        }
        let caller =
            Did::new(&submission.signer).map_err(|error| AcpError::InvalidBearerToken {
                reason: error.to_string(),
            })?;
        self.with_delegation(
            hub,
            context,
            &caller,
            token,
            (
                DelegationScope::CreatePolicy,
                DelegatedOperation::CreatePolicy(policy, &marshal_type).digest()?,
            ),
            |module, actor| {
                module.create_policy_with_metadata(
                    policy,
                    marshal_type,
                    RecordMetadata {
                        creation_ts: context.timestamp.clone(),
                        tx_hash: submission.tx_hash.clone(),
                        tx_signer: submission.signer.clone(),
                        owner_did: actor.to_string(),
                    },
                )
            },
        )
    }

    /// Edit a policy using the actor's ownership and the worker's delegation.
    #[allow(clippy::too_many_arguments)]
    pub fn bearer_edit_policy(
        &mut self,
        hub: &mut HubModule,
        context: &BlockExecCtx,
        caller: &Did,
        token: &str,
        policy_id: &str,
        policy: &str,
        marshal_type: PolicyMarshalingType,
    ) -> Result<(u64, PolicyRecord)> {
        self.with_delegation(
            hub,
            context,
            caller,
            token,
            (
                DelegationScope::EditPolicy,
                DelegatedOperation::EditPolicy(policy_id, policy, &marshal_type).digest()?,
            ),
            |module, actor| module.edit_policy(actor, policy_id, policy, marshal_type),
        )
    }

    /// Execute a caller-bound delegation and record usage only on success.
    pub fn bearer_policy_cmd(
        &mut self,
        hub: &mut HubModule,
        context: &BlockExecCtx,
        caller: &Did,
        token: &str,
        policy_id: &str,
        cmd: PolicyCmd,
    ) -> Result<PolicyCmdResult> {
        self.with_delegation(
            hub,
            context,
            caller,
            token,
            (
                DelegationScope::PolicyCommands,
                DelegatedOperation::PolicyCommand(policy_id, &cmd).digest()?,
            ),
            |module, actor| module.direct_policy_cmd(actor, policy_id, cmd),
        )
    }

    fn with_delegation<T>(
        &mut self,
        hub: &mut HubModule,
        context: &BlockExecCtx,
        caller: &Did,
        token: &str,
        delegated: (DelegationScope, [u8; 32]),
        operation: impl FnOnce(&mut Self, &Did) -> Result<T>,
    ) -> Result<T> {
        let invalid = |error: crate::hub::error::HubError| AcpError::InvalidBearerToken {
            reason: error.to_string(),
        };
        let claims = hub
            .authorize_delegation(context, caller, token, delegated.0, delegated.1)
            .map_err(invalid)?;
        let actor = Did::new(claims.actor()).map_err(|error| AcpError::InvalidBearerToken {
            reason: error.to_string(),
        })?;
        let issuer = Did::new(&claims.iss).map_err(|error| AcpError::InvalidBearerToken {
            reason: error.to_string(),
        })?;
        let before = self.clone();
        let result = operation(self, &actor).and_then(|result| {
            hub.store_or_update_jws_token(
                context,
                token,
                &issuer,
                &claims.sub,
                Timestamp {
                    seconds: claims.iat,
                    block_height: 0,
                },
                Timestamp {
                    seconds: claims.exp,
                    block_height: 0,
                },
            )
            .map_err(invalid)?;
            Ok(result)
        });
        if result.is_err() {
            *self = before;
        }
        result
    }
}
