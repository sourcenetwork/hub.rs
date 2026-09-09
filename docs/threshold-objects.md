# Encrypted documents and signing derivations

Native threshold objects bind an encrypted document or a signing derivation to
an active ring and a policy resource/permission. Register them through
`hub_client::threshold_objects::encode_threshold_object` and a durable
`NativeWorker`. The actor delegates `orbis:object:store` to the worker; the
registered creator is the actor, not the submission key. Ring-management and ACP
policy scopes cannot authorize registration.

`ThresholdObject::Document` retains the ciphertext, encryption proof, policy
binding and optional tier/timestamp. `ThresholdObject::KeyDerivation` retains the
derivation string and policy binding. Registration requires a finalized active
ring in the same deployment. It does not grant ACP permission, register an ACP
object, verify the encryption proof or derive a private key. Orbis must verify
the encryption proof and the requesting actor's policy authorization before use.
Storing a historical timestamp does not establish historical authorization.

The request ceiling is 512 KiB of encoded JSON; stored records are bounded to
1 MiB. Proof JSON and derivation strings are limited to 4 KiB. Ciphertext and
proof fields must be present and nonempty. Unknown or duplicate JSON fields are
rejected. Resource, permission and optional tier strings are bounded to 256 bytes.
Records are immutable and retained; pruning and sustained storage growth remain
release qualification work.

Document IDs use the canonical encoding consumed by current Rust Orbis: ring
ID, decoded ciphertext/proof byte fields, policy binding and optional metadata
are length-prefixed and hashed. JSON whitespace or field order does not change
the ID. This differs from the inspected Go checkout, which hashes the raw
ciphertext and proof strings. Native registration does not migrate those older
IDs or encrypted records. Derivation IDs retain Orbis's length-prefixed string
encoding. The native ring ID already binds its creation deployment.

An object identity can be registered only once. A retry with an authenticated
operation identity returns the original retained outcome after rechecking the
current delegation; another registration fails instead of replacing the creator
or payload. Failed registration or outcome retention rolls back the object and
delegation state together.

`read_threshold_object` verifies presence or absence at a requested minimum
revision using caller-provisioned consensus trust. It validates the returned
kind, content-derived ID, creator and revision. Document and derivation keys use
separate namespaces. Orbis's native adapter preserves the payload shapes used by
its existing PRE and signing protocols, with durable preparation and certified
reads. The native distributed threshold workflow covers startup, signing, encrypted
secret recovery, revocation and membership changes. See
[the capability comparison](threshold-capabilities.md) for the boundary between
Commonware consensus keys and Orbis application protocols.
