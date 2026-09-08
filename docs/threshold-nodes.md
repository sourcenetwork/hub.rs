# Threshold-service node registration

The native Hub service stores Orbis node identities under `orbis/node/v1/` in
the certified Hub partition. Registration proves possession of the compressed
secp256k1 node key and selects its controller. Subsequent peer, controller and
allowed-policy/ring changes require the current controller's signature. These
records advertise threshold-service participants; they do not admit consensus
members or initiate DKG.

`hub_client::nodes::sign_node_request` signs a `NodeRequest`, and
`HubClient::submit_node_request` relays it through an independent BLS worker.
The request binds the initial deployment state, deployment ID, node identity, sequence, expiry
and command. The digest is SHA-256 over `vera/orbis/node/v1` followed by a zero
byte and the Borsh request. Keys are canonical lowercase compressed public keys;
signatures are canonical compact low-S ECDSA. Registration uses sequence zero;
each successful mutation advances the node's sequence. Rejected commands leave
both metadata and sequence unchanged. Controller transfer immediately revokes
the previous controller for later commands, including after restart.

Peer identifiers are bounded to 256 printable ASCII bytes. Each allowed list is
sorted, unique, contains at most 256 identifiers, and bounds each identifier to
128 printable ASCII bytes. A ring is permitted by its own ID or its policy ID.
Requests and stored records are limited to 48 KiB. Allowed entries need not
already exist; they are declarations for subsequent ring admission checks.

`read_threshold_node` verifies current record membership or absence against the
caller's consensus key and minimum revision, then validates the record identity
and metadata. Callers supply any additional freshness policy. Submission returns
a locally checked identifier; retain it and use `read_receipt` to verify the
execution outcome. Reusing a completed authorization through another worker
fails its per-node sequence check.

For durable submission, open `NativeWorker` with the application's encrypted key
store callbacks, encode the command with `encode_node_request`, and call
`prepare(HUB_ADDRESS, calldata)` before sending. The journal retains exact signed
bytes across restarts and refuses a different pending request. Use `acknowledge`
with a certified receipt to advance the worker sequence after either successful
or rejected execution. Missing receipts and transport errors leave it pending.
The journal format is shared with DefraDB's existing native worker; keys remain
in the caller's secret store. Opening and mutating the journal perform blocking
filesystem IO.

This preserves the node-registration/controller behavior needed by the Orbis
consumer. Ring creation/finalization, reporting, document/key-derivation storage
and threshold cryptography are separate service workflows.
