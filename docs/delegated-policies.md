# Delegated policy creation and editing

A policy actor can authorize a signing worker to create or edit policies. The
worker signs the native submission; the actor remains the policy owner. Each
worker has its own submission sequence.

Delegations use signed ES256K tokens with a worker DID in `sub`, deployment in
`aud`, and explicit validity times. The supported scopes are separate:

| Scope | Authorized operations |
|---|---|
| `acp:policy` | Existing object registration, archival and relationship commands |
| `acp:policy:create` | Create policies owned by the token issuer |
| `acp:policy:edit` | Edit policies already owned by the token issuer |

`create_bearer_token` retains the existing command scope.
`create_scoped_bearer_token` accepts `DelegationScope::CreatePolicy` or
`DelegationScope::EditPolicy` for lifecycle operations. A creation token cannot
edit policies, and an existing command token cannot create or edit them.

The shared ACP interface accepts:

```text
bearerCreatePolicy(bearerToken, policy, marshalType)
bearerEditPolicy(bearerToken, policyId, policy, marshalType)
```

`marshalType = 1` selects the supported YAML policy format. These calls can be
encoded as native submission payloads and sent through `hub_sendNativeTx`.
Every consensus member must run a version supporting the new calls and scopes
before operators enable their use.

Creation returns a policy record and emits `DelegatedPolicyCreated`, containing
the actual 32-byte policy ID and actor DID. The stored policy metadata records
the actor as owner, the authenticated worker as signer, the signed submission
ID, and the creation revision and timestamp. Editing preserves that creation
metadata and enforces the actor's ownership and existing policy-edit rules.

The creation receipt provides a lookup hint. To verify the result, obtain the
policy record from `hub_getCurrentRecordProof` using `policy/objs/<policy-id>` in
the ACP namespace. Verify its certificate against configured trust and its
record proof, then compare the policy ID, owner, worker, signed submission ID,
definition and creation revision with the request. The receipt alone does not
authenticate the result. This lets concurrent creators identify their own
policies without scanning the policy list.

Execution checks the exact scope, caller, deployment, validity interval and
revocation before applying a change. Failed operations do not record delegation
usage. The actor or the bound worker can revoke a token through
`revokeDelegation`; revocation applies to that token, including after restart.
