# Caller operation identities

Delegated ACP creation, editing and graph commands accept an optional signed
`request` claim. It binds a caller operation ID, exact semantic operation digest
and genesis identity. Direct key delegations and operator-authorized relay
assertions use the same execution path. All members must support this claim
before clients use it; older members reject unknown claims.

An operation ID contains 32 bytes: an eight-byte big-endian Unix expiry followed
by 24 bytes of caller-generated entropy. Expiry is exclusive and can be at most
600 seconds ahead of execution time. Empty entropy is rejected. The full ID,
including its expiry, must be persisted before submission and retained across
workers, gateway instances and retries. Identical arguments with different IDs
are independent operations.

The signed `request` object contains `id`, `digest` and `genesis_id`, each encoded
as a JSON array of exactly 32 byte values. `digest` uses the typed operation
encoding in [delegated-policies.md](delegated-policies.md). Token expiry cannot
exceed the ID's deadline. Normal caller, deployment, scope, relay grant and
revocation checks run before an existing outcome can be returned. The ID does
not bypass authorization.

The first successful execution stores its exact typed result, semantic digest,
actor, original worker, submission ID and creation revision atomically with its
effects and token usage. A later authorized request with the same actor, ID and
digest returns that original result without applying the effect again. Different
arguments under a completed ID are rejected. A result describes the completed
operation; it does not establish current ownership or permission after later
changes. Equivalent compressed and uncompressed secp256k1 actor encodings share
one operation namespace.

Failed execution, result encoding, storage-budget checks and enclosing batch
reverts leave no completion record or partial effect. Only successful effects
claim an ID: failed requests can be corrected or retried within the deadline.
An expired ID always rejects execution, including after its record is removed.
Clients must never replace an expired or uncertain ID automatically to retry the
same intended operation.

Outcome records are at most 1 MiB. The total encoded outcome budget defaults to
64 MiB and is changed through the existing operator quorum with
`{"SetOperationBudget":268435456}` in an administrative request. A budget below
1 MiB or below currently retained usage is rejected without advancing the
administrative sequence. New outcomes exceeding the budget revert atomically;
existing outcomes remain available. Keys and index structures add memory and
storage overhead beyond this encoded-value budget.

End-of-block cleanup removes at most 128 expired records, in deadline order.
It verifies each index's immutable ID deadline and updates the byte counter with
the deletions. Cleanup may lag expiration under pressure; it never permits an
expired ID to execute again. This lifetime applies to operation outcomes, not
historical authorization-state retention.

`acp::operation::operation_key(actor, id)` derives the native ACP key:
`operation/v1/ || SHA256("vera/operation-actor/v1\0" || canonical_actor) || id`.
`hub_getCurrentRecordProof` serves its membership or absence with certified state.
The budget and encoded-byte counter use `operation-budget/v1` and
`operation-bytes/v1`, respectively, as eight-byte big-endian integers.

Clients verify the certificate, exact key, actor, ID, digest, original execution
metadata and typed result. Lookup can recover an outcome without the original
worker's submission ID. A missing record after expiry is not proof that the
operation never ran. Receipt verification establishes the submitted attempt's
result; retries can have different submission IDs while referring to the same
original outcome. Neither a missing receipt nor a transport timeout establishes
rejection.
