# Threshold-service rings

A ring starts with an ACP-authorized creation request. The actor must have
`create_ring` on `ring_policy/<policy_id>`. Creation registers the corresponding
`ring/<ring_id>` ACP object for that actor and stores the pending ring atomically.
All committee and reporting-backup node keys must already be registered.

`RingConfig::id` binds the initial deployment state, creator and complete creation
configuration, including a caller-generated nonce. Node and relay sets must be
sorted and unique. Reporting settings are explicit; `ReportingConfig::default`
uses one demerit per report, a daily reset and a kick threshold of three. Ring
configuration retains these settings for the reporting service.

| Current state | Authorized action | Result |
|---|---|---|
| Absent | Actor with ACP creation permission | Pending ring and registered ACP object |
| Pending | First confirmation from a participant | Record that participant's public-key declaration |
| Pending | All participants confirm the same key | Active ring |
| Pending | Different participant confirms a conflicting key | Terminal conflict record |
| Pending | Creator or participant cancels | Terminal cancellation record |
| Active, cancelled or conflicting | Fresh-DKG confirmation/cancellation | Rejected |

Duplicate confirmations are rejected before checking for a conflicting key, so a
participant cannot reverse its own accepted declaration to abort the ring. Every
participant must confirm; the configured cryptographic threshold does not replace
this fresh-DKG unanimity rule. Confirmation also checks the node controller's
current allowed-policy/ring set. Participant cancellation remains available if
the controller withdraws that permission.

Cancelled and conflicting records remain stored. Their identifiers cannot be
reused, preventing old signed confirmations from applying to a recreated ring.
Creation retries with the same authenticated operation identity return the
original recorded outcome; read the ring again to obtain its current state.

## Native client

Use `hub_client::rings::encode_ring_command` with an `orbis:ring` delegation for
creation, administration or creator cancellation. Delegations use the existing expiry,
revocation, relay authorization and optional exact-operation binding checks.
`DelegatedOperation::RingCommand` supplies the digest for a relay assertion or
operation-bound delegation. Failed admission, including outcome-storage budget
exhaustion, rolls back both Hub and ACP changes.

Participants use `sign_ring_participant_request` and
`encode_ring_participant_request`. These signatures bind the deployment root and
ID, ring, node identity, command and expiry. A controller or submission worker
cannot confirm using the node's authority. Public-key declarations use lowercase
hex; the ring lifecycle records participant agreement on those bytes. It does
not validate a DKG transcript or select a threshold cryptographic scheme.

Pass the encoded command to `NativeWorker::prepare(HUB_ADDRESS, calldata)` before
submission. Recover the exact pending bytes after interruption and acknowledge
only a verified receipt. `read_threshold_ring` verifies inclusion or absence
against caller-provisioned consensus trust and a minimum revision, then validates
the record's identity, configuration and state. Callers enforce their freshness
requirements.

Requests are limited to 48 KiB; records to 128 KiB; each node/relay set to 256
entries; public-key declarations to 8 KiB of hex. The refresh interval must be at
least one day. Reporting counters and thresholds must be positive.

## Administration

`RingCommand::Update` requires ACP `update_ring` permission on `ring/<ring_id>`
and the current `expected_sequence`. Every ring mutation increments this sequence,
including writes within one finalized revision. An outdated command fails without
changing either the ring or delegation outcome storage. Creation parameters remain
immutable, so administrative changes preserve the ring identifier.

Active rings support refresh-interval changes, reporting configuration, scheduled
upgrades and resharing announcements. Upgrades must increase the version and allow
at least 600 seconds before activation. Consumers can resolve the effective version
at a certified timestamp; later service updates materialize an activated upgrade.
Cancellation requires an upgrade whose activation time has not arrived.

Relay additions/removals also work while fresh DKG is pending. Creation with relays
disabled is permanent. Reporting backup nodes and resharing target nodes must be
registered and their controllers must permit the ring or its policy. A resharing
announcement records the target committee and threshold while the current committee
continues serving; a second announcement is rejected while one is pending.

Threshold-signed resharing finalization, report processing, document and
key-derivation services are separate pending work. This API does not import
existing rings or choose an encrypted-record migration policy.
