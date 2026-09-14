# Consensus membership

Consensus membership changes accept native signed submissions. They use the
existing registry rules and storage, including ACP authorization, through the
shared command dispatcher. Admission and proposal rechecking accept the registry
target. A rejected command consumes its submission sequence and leaves membership
unchanged. A storage failure aborts proposal execution; it cannot become a
certified rejection or leave a partial member entry.

The registry holds at most 64 entries, matching the current protocol's DKG
participant bound. Inactive entries count toward that limit. A consensus public
key can belong to only one registered entry, including inactive entries. Stored
counts, indexes and route lengths are checked at their full encoded width;
malformed values and inconsistent array/record links are errors.

The active committee is also bounded by the configured epoch length. Commonware
requires its dealer quorum to fit between the dealing phase and the final epoch
artifact. For example, 20 revisions per epoch permit 13 active members; 87 permit
the protocol maximum of 64. Additions and reactivations that exceed this capacity
are rejected during command execution. Inactive entries do not use active
committee capacity. Startup rejects a genesis committee that exceeds it.

Removing or deactivating the last active participant is rejected. Inactive
entries may still be removed.

Operators first approve `InitializeMembershipPolicy` using the configured
approval quorum. That ACP policy controls `manage` on the `registry` resource's
`registry` object. Membership requests require that permission for the native
signer's DID. Registration, status changes and removal use the same permission
check. An independent native worker can submit the operator approvals; those
approvals bind the deployment root, administrative sequence, expiry and command.

Execution records the active roster at the last revision of each epoch `e` for
selection in epoch `e + 3`. Commonware reads that immutable record while preparing
the end of epoch `e + 1`, which gives every replica the same finalized cutoff.
Changes after the cutoff enter a later selection. Genesis supplies the initial
lookahead through epoch 2. A selected roster does not guarantee admission:
the corresponding resharing ceremony must also succeed.

These records participate in the native state commitment, proposal verification,
recovery and state synchronization. The provider reads them under the committed
module lock and retains no separate epoch cache. Live state retains three recent
rosters. Older selections are read from their finalized epoch artifacts in the
existing history store, including after restart. A missing or inconsistent
historical artifact is an error; it never substitutes a newer roster. This bounds
live roster records without adding another historical index. General finalized
history retention is separate.

This changes execution commitments at epoch boundaries and requires a fresh
deployment; it is not a rolling upgrade for existing data.

Membership writes use `VALIDATOR_REGISTRY_ADDRESS` with the request bindings in
`hub_modules::validator_registry::abi`. Persist the signed submission before sending, retain its identifier,
and use `read_receipt` with independently provisioned consensus trust to verify
the result. A successful receipt records the registry update. The effective
committee changes after successful distributed resharing, so inspect verified
revision evidence and its `EpochMaterial.participants` before treating admission
as complete.

For an incoming process:

1. Provision the same deployment genesis and an independent participant identity.
2. Include that public identity and its reachable route in the incoming process's
   peer configuration, with existing members as bootstrappers.
3. Start with an empty threshold-secret store. The process initially verifies
   consensus evidence using the public genesis material.
4. Submit the authorized membership registration and wait for its certified result.
5. Wait for verified evidence that includes the incoming identity in the effective
   committee. The new share is received through resharing and persisted locally.

The consensus public key remains stable through this transition. The public
sharing polynomial changes. A member's service address and its consensus identity
remain distinct configuration values.

The `native_membership` process fixture starts four members, admits a fifth with
no initial share, verifies its new committee evidence, and stops an original
member. A subsequent native write finalizes with the incoming member needed for
quorum. It then kills and restarts the admitted process using its persisted share,
deactivates and removes the unavailable original member, and verifies the reduced
committee under the same consensus identity. Finalization continues after a
second original process stops. Interruption during the admission ceremony,
power-loss behavior and broader network/storage faults require additional
qualification.

```sh
HUBD_BINARY=/path/to/hubd cargo test -p hub-e2e --test native_membership
```

`HubClient::read_administration` verifies the current operator configuration and
next administrative sequence against independently configured consensus trust.
It returns the selected revision, timestamp and decoded state, or certified
absence if administration is not initialized. Decoding rejects malformed operator
policies and incomplete or trailing record bytes. Use a minimum revision from a
certified administrative receipt to observe its resulting configuration.

The existing `administration` convenience method does not authenticate its RPC
response. Use the certified read when selecting an operator policy or checking
rotation recovery. A certified operator configuration does not grant authority to
an unlisted signer; execution still requires the configured approval threshold.

`HubClient::read_acp_parameters` authenticates the ACP parameter record separately
from operator configuration. Its value is absent until parameters are explicitly
stored; execution then uses `AcpParams::default()`. Malformed stored bytes are
errors and never select defaults. Parameter-dependent registration commitments
also reject malformed configuration before changing state. After an approved
parameter update, use its certified revision as the minimum for the read.
