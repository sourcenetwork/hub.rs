//! Bulletin module — namespace-scoped posts for DKG coordination and messaging.

/// Solidity ABI interface for the Bulletin precompile.
pub mod abi;
/// Bulletin error types.
pub mod error;
/// Key prefixes and builders for Bulletin KV storage.
pub mod keys;
/// Bulletin domain types.
pub mod types;

use error::BulletinError;
use identity::Did;
use types::{BulletinParams, Collaborator, Namespace, Post};

use crate::types::{BlockExecCtx, TxExecCtx};

type Result<T> = std::result::Result<T, BulletinError>;

/// Bulletin module.
///
/// Manages namespaces, posts, and collaborator access. Authorization
/// flows through ACP — a lazy policy is created on first namespace
/// registration. Business logic lives here; precompile and native-tx
/// shims are thin wrappers that decode arguments and forward to these methods.
///
/// # ACP integration
///
/// The module lazily creates a single ACP policy on the first
/// `register_namespace` call (stored as `"policy_id"` in the KV store).
/// The policy defines one resource type `namespace` with one relation
/// `collaborator` and one permission `create_post = collaborator`.
///
/// Cross-module calls use direct parameter passing — the caller
/// (application/executor) passes `&mut AcpModule` to methods that
/// need it. Rust's partial borrow rules allow this since modules
/// are disjoint fields in the parent struct.
///
/// | Bulletin method | ACP method | Mutability |
/// |---|---|---|
/// | `register_namespace` | `acp.create_policy()` (first call), `acp.direct_policy_cmd(RegisterObject)` | `&mut AcpModule` |
/// | `create_post` | `acp.query_verify_access_request()` | `&AcpModule` |
/// | `add_collaborator` | `acp.direct_policy_cmd(SetRelationship)` | `&mut AcpModule` |
/// | `remove_collaborator` | `acp.direct_policy_cmd(DeleteRelationship)` | `&mut AcpModule` |
///
/// # KV store layout
///
/// ```text
/// "policy_id"                                          → policy ID string
/// "namespace/" + namespaceId                           → Namespace
/// "collaborator/" + sanitize(namespaceId) + "/" + sanitize(did) → Collaborator
/// "post/" + sanitize(namespaceId) + "/" + sanitize(postId)     → Post
/// "p_bulletin"                                         → BulletinParams
/// ```
///
/// Key sanitization: `/` in component parts is replaced with `|`.
/// Namespace IDs are always prefixed: user `"ns1"` → stored `"bulletin/ns1"`.
/// Post IDs are deterministic: `hex(sha256(namespaceId + payload))`.
#[derive(Clone, Debug)]
pub struct BulletinModule {
    _private: (),
}

impl Default for BulletinModule {
    fn default() -> Self {
        Self::new()
    }
}

impl BulletinModule {
    /// Create a new Bulletin module instance.
    pub const fn new() -> Self {
        Self { _private: () }
    }

    // ── Msg handlers ────────────────────────────────────────────────────

    /// Register a new namespace owned by the creator.
    ///
    /// # Flow
    ///
    /// 1. Call `ensure_policy(acp)` — on first call, invokes
    ///    `acp.create_module_policy(BULLETIN_POLICY_YAML,
    ///    PolicyMarshalingType_YAML, "bulletin")` and stores the
    ///    returned policy ID under `"policy_id"` key. Subsequent
    ///    calls read the stored ID.
    /// 2. Compute `namespace_id = "bulletin/" + namespace`.
    /// 3. Read `"namespace/" + namespace_id` — if present, return
    ///    `NamespaceAlreadyExists`.
    /// 4. Resolve `owner_did` from `tx_ctx.signer` via
    ///    `acp.get_actor_did(msg.Creator)` (Go: `GetActorDID`).
    ///    The shim layer pre-resolves this and passes it as `creator`.
    /// 5. Call `acp.module_policy_cmd(policy_cap, RegisterObject(
    ///    Object { resource: "namespace", id: namespace_id }),
    ///    owner_did, signer)` (Go: `ModulePolicyCmdForActorDID` —
    ///    requires both the DID and the original signer address,
    ///    plus a policy capability fetched from the scoped keeper).
    ///    This registers the namespace as an ACP object with the creator
    ///    as owner (granting implicit manager rights over `collaborator`).
    /// 6. Build `Namespace`:
    ///    ```text
    ///    id           = namespace_id
    ///    creator      = tx_ctx.signer
    ///    owner_did    = creator.to_string()
    ///    created_at   = block_ctx.timestamp
    ///    ```
    /// 7. Write namespace to `"namespace/" + namespace_id`.
    /// 8. Return the created `Namespace`.
    ///
    /// # Reads
    /// - `"policy_id"` (ensure_policy check)
    /// - `"namespace/" + namespace_id` (existence check)
    ///
    /// # Writes
    /// - `"policy_id"` (first call only — ensure_policy)
    /// - `"namespace/" + namespace_id`
    /// - ACP via `acp.create_module_policy()` (first call) + `acp.module_policy_cmd(RegisterObject)`
    ///
    /// # Ctx
    /// `block_ctx.timestamp` for created_at, `tx_ctx.signer` for creator.
    /// Go resolves `owner_did` from `msg.Creator` via `GetActorDID` —
    /// hub.rs expects the shim layer to pre-resolve and pass as `creator`.
    ///
    /// # Errors
    /// - `PolicyInitFailed` — ACP policy creation failed
    /// - `NamespaceAlreadyExists` — namespace already registered
    /// - ACP errors from `module_policy_cmd`
    #[allow(unused_variables)]
    pub fn register_namespace(
        &mut self,
        acp: &mut super::acp::AcpModule,
        block_ctx: &BlockExecCtx,
        tx_ctx: &TxExecCtx,
        creator: &Did,
        namespace: &str,
    ) -> Result<Namespace> {
        todo!()
    }

    /// Create a post in a namespace (requires collaborator permission via ACP).
    ///
    /// # Flow
    ///
    /// 1. Read `"policy_id"`. Return `PolicyNotInitialized` if empty.
    /// 2. Compute `namespace_id = "bulletin/" + namespace`.
    /// 3. Read `"namespace/" + namespace_id` — return `NamespaceNotFound`
    ///    if absent.
    /// 4. Validate payload is non-empty → `InvalidPostPayload`.
    ///    (Go: this check lives in `MsgCreatePost.ValidateBasic()`,
    ///    not in the keeper handler. Relocated here since hub.rs has
    ///    no `ValidateBasic` equivalent.)
    /// 5. Validate proof is non-empty → `InvalidPostProof`.
    ///    (Same relocation from `ValidateBasic`.)
    /// 6. Call `acp.query_verify_access_request(policy_id, &AccessRequest { operations: vec![Operation { object: Object { resource: "namespace", id: namespace_id }, permission: "create_post" }], actor: Actor { id: creator.to_string() } })`.
    ///    This is a **read-only** query (Go: `VerifyAccessRequest`), NOT `check_access`.
    ///    Return `NotCollaborator` if the engine denies access.
    /// 7. Compute `post_id = hex(sha256(namespace_id + payload))`.
    /// 8. Read `"post/" + sanitize(namespace_id) + "/" + sanitize(post_id)` —
    ///    return `PostAlreadyExists` if present.
    /// 9. Build `Post`:
    ///    ```text
    ///    id          = post_id
    ///    namespace   = namespace_id
    ///    creator_did = creator.to_string()
    ///    payload     = payload bytes
    ///    proof       = proof bytes
    ///    ```
    /// 10. Write post to `"post/" + sanitize(namespace_id) + "/" + sanitize(post_id)`.
    /// 11. Return `Ok(())`. The `artifact` parameter is for event emission
    ///     only — it is NOT stored in the `Post` struct.
    ///
    /// # Reads
    /// - `"policy_id"`
    /// - `"namespace/" + namespace_id`
    /// - `"post/" + sanitize(namespace_id) + "/" + sanitize(post_id)`
    ///
    /// # Writes
    /// - `"post/" + sanitize(namespace_id) + "/" + sanitize(post_id)`
    ///
    /// # Ctx
    /// `tx_ctx.signer` for DID resolution.
    ///
    /// # Errors
    /// - `PolicyNotInitialized` — module policy not yet created
    /// - `NamespaceNotFound` — namespace does not exist
    /// - `InvalidPostPayload` — empty payload
    /// - `InvalidPostProof` — empty proof
    /// - `NotCollaborator` — ACP denies create_post permission
    /// - `PostAlreadyExists` — duplicate content hash
    #[allow(unused_variables, clippy::too_many_arguments)]
    pub fn create_post(
        &mut self,
        acp: &super::acp::AcpModule,
        tx_ctx: &TxExecCtx,
        creator: &Did,
        namespace: &str,
        payload: &[u8],
        proof: &[u8],
        artifact: &str,
    ) -> Result<()> {
        todo!()
    }

    /// Add a collaborator to a namespace.
    ///
    /// # Flow
    ///
    /// 1. Read `"policy_id"`. Return `PolicyNotInitialized` if empty.
    /// 2. Compute `namespace_id = "bulletin/" + namespace`.
    /// 3. Read `"namespace/" + namespace_id` — return `NamespaceNotFound`
    ///    if absent.
    /// 4. Resolve collaborator DID from the `collaborator` address string
    ///    (always derived from account address, never from bearer token).
    /// 5. Read `"collaborator/" + sanitize(namespace_id) + "/" + sanitize(collab_did)` —
    ///    return `CollaboratorAlreadyExists` if present.
    /// 6. Call `acp.direct_policy_cmd(creator, policy_id, SetRelationship(Relationship { resource: "namespace", object: namespace_id, relation: "collaborator", actor: collab_did }))`.
    ///    ACP enforces that creator is the object owner (manager of relation).
    /// 7. Build `Collaborator`:
    ///    ```text
    ///    address   = collaborator (original address string)
    ///    did       = collab_did
    ///    namespace = namespace_id
    ///    ```
    /// 8. Write to `"collaborator/" + sanitize(namespace_id) + "/" + sanitize(collab_did)`.
    /// 9. Return the collaborator DID string.
    ///
    /// # Reads
    /// - `"policy_id"`
    /// - `"namespace/" + namespace_id`
    /// - `"collaborator/" + sanitize(namespace_id) + "/" + sanitize(collab_did)`
    ///
    /// # Writes
    /// - `"collaborator/" + sanitize(namespace_id) + "/" + sanitize(collab_did)`
    /// - ACP via `acp.direct_policy_cmd(SetRelationship)`
    ///
    /// # Ctx
    /// `creator` DID is pre-resolved by the caller (shim layer).
    /// Go resolves the owner via `GetActorDID` (bearer-token-aware)
    /// and the collaborator via `IssueDIDFromAccountAddr` (address-only).
    ///
    /// # Errors
    /// - `PolicyNotInitialized` — module policy not yet created
    /// - `NamespaceNotFound` — namespace does not exist
    /// - `CollaboratorAlreadyExists` — already a collaborator
    /// - `Unauthorized` — ACP: creator is not the object owner
    ///
    /// # Return
    /// Go returns an empty response. Rust returns the collaborator DID
    /// string (deliberate API enrichment — the proto field exists but
    /// Go never populates it).
    #[allow(unused_variables)]
    pub fn add_collaborator(
        &mut self,
        acp: &mut super::acp::AcpModule,
        tx_ctx: &TxExecCtx,
        creator: &Did,
        namespace: &str,
        collaborator: &str,
    ) -> Result<String> {
        todo!()
    }

    /// Remove a collaborator from a namespace.
    ///
    /// # Flow
    ///
    /// 1. Read `"policy_id"`. Return `PolicyNotInitialized` if empty.
    /// 2. Compute `namespace_id = "bulletin/" + namespace`.
    /// 3. Read `"namespace/" + namespace_id` — return `NamespaceNotFound`
    ///    if absent.
    /// 4. Resolve collaborator DID from the `collaborator` address string.
    /// 5. Read `"collaborator/" + sanitize(namespace_id) + "/" + sanitize(collab_did)` —
    ///    return `CollaboratorNotFound` if absent.
    /// 6. Call `acp.direct_policy_cmd(creator, policy_id, DeleteRelationship(Relationship { resource: "namespace", object: namespace_id, relation: "collaborator", actor: collab_did }))`.
    ///    ACP enforces that creator is the object owner.
    /// 7. Delete `"collaborator/" + sanitize(namespace_id) + "/" + sanitize(collab_did)`.
    /// 8. Return the collaborator DID string.
    ///
    /// # Reads
    /// - `"policy_id"`
    /// - `"namespace/" + namespace_id`
    /// - `"collaborator/" + sanitize(namespace_id) + "/" + sanitize(collab_did)`
    ///
    /// # Writes (deletes)
    /// - `"collaborator/" + sanitize(namespace_id) + "/" + sanitize(collab_did)`
    /// - ACP via `acp.direct_policy_cmd(DeleteRelationship)`
    ///
    /// # Ctx
    /// `creator` DID is pre-resolved by the caller (shim layer).
    /// Same resolution asymmetry as `add_collaborator`.
    ///
    /// # Errors
    /// - `PolicyNotInitialized` — module policy not yet created
    /// - `NamespaceNotFound` — namespace does not exist
    /// - `CollaboratorNotFound` — not currently a collaborator
    /// - `Unauthorized` — ACP: creator is not the object owner
    ///
    /// # Return
    /// Go returns an empty response. Rust returns the collaborator DID
    /// string (same enrichment as `add_collaborator`).
    #[allow(unused_variables)]
    pub fn remove_collaborator(
        &mut self,
        acp: &mut super::acp::AcpModule,
        tx_ctx: &TxExecCtx,
        creator: &Did,
        namespace: &str,
        collaborator: &str,
    ) -> Result<String> {
        todo!()
    }

    /// Update governance-controlled module parameters.
    ///
    /// # Flow
    ///
    /// 1. Verify `authority` matches the governance module address.
    ///    Return `Unauthorized` if not.
    /// 2. Write `params` to `"p_bulletin"` key.
    /// 3. Return `Ok(())`.
    ///
    /// # Reads
    /// None (authority check is against a known constant).
    ///
    /// # Writes
    /// - `"p_bulletin"`
    ///
    /// # Errors
    /// - `Unauthorized` — caller is not the governance authority
    #[allow(unused_variables)]
    pub fn update_params(&mut self, authority: &Did, params: BulletinParams) -> Result<()> {
        todo!()
    }

    // ── Query handlers ──────────────────────────────────────────────────

    /// Look up a namespace by name.
    ///
    /// # Flow
    ///
    /// 1. Compute `namespace_id = "bulletin/" + namespace`.
    /// 2. Read `"namespace/" + namespace_id`.
    /// 3. Return the `Namespace` or `NamespaceNotFound`.
    ///
    /// # Reads
    /// - `"namespace/" + namespace_id`
    #[allow(unused_variables)]
    pub fn query_namespace(&self, namespace: &str) -> Result<Namespace> {
        todo!()
    }

    /// List all namespaces.
    ///
    /// # Flow
    ///
    /// 1. Iterate all entries under the `"namespace/"` prefix.
    /// 2. Deserialize each value as `Namespace`.
    /// 3. Return the collected list.
    ///
    /// # Reads
    /// - All keys under `"namespace/"` prefix
    pub fn query_namespaces(&self) -> Result<Vec<Namespace>> {
        todo!()
    }

    /// List collaborators on a namespace.
    ///
    /// # Flow
    ///
    /// 1. Compute `namespace_id = "bulletin/" + namespace`.
    /// 2. Verify namespace exists — read `"namespace/" + namespace_id`,
    ///    return `NamespaceNotFound` if absent.
    /// 3. Iterate all entries under `"collaborator/"` prefix.
    /// 4. Filter to keys starting with `sanitize(namespace_id) + "/"`.
    /// 5. Deserialize matching values as `Collaborator`.
    /// 6. Return the collected list.
    ///
    /// # Reads
    /// - `"namespace/" + namespace_id` (existence check)
    /// - Keys under `"collaborator/"` prefix, filtered by namespace
    ///
    /// # Errors
    /// - `NamespaceNotFound` — namespace does not exist
    ///
    /// # Implementation notes
    /// Go uses a full-table scan with in-callback filtering.
    /// A cleaner approach is to use a sub-prefix iterator:
    /// `"collaborator/" + sanitize(namespace_id) + "/"`.
    #[allow(unused_variables)]
    pub fn query_namespace_collaborators(&self, namespace: &str) -> Result<Vec<Collaborator>> {
        todo!()
    }

    /// List posts in a namespace.
    ///
    /// # Flow
    ///
    /// 1. Compute `namespace_id = "bulletin/" + namespace`.
    /// 2. Verify namespace exists — read `"namespace/" + namespace_id`,
    ///    return `NamespaceNotFound` if absent.
    /// 3. Iterate all entries under `"post/"` prefix.
    /// 4. Filter to keys starting with `sanitize(namespace_id) + "/"`.
    /// 5. Deserialize matching values as `Post`.
    /// 6. Return the collected list.
    ///
    /// # Reads
    /// - `"namespace/" + namespace_id` (existence check)
    /// - Keys under `"post/"` prefix, filtered by namespace
    ///
    /// # Errors
    /// - `NamespaceNotFound` — namespace does not exist
    ///
    /// # Implementation notes
    /// Same full-table-scan pattern as collaborators. Prefer sub-prefix
    /// iterator: `"post/" + sanitize(namespace_id) + "/"`.
    #[allow(unused_variables)]
    pub fn query_namespace_posts(&self, namespace: &str) -> Result<Vec<Post>> {
        todo!()
    }

    /// Look up a post by namespace and ID.
    ///
    /// # Flow
    ///
    /// 1. Compute `namespace_id = "bulletin/" + namespace`.
    /// 2. Verify namespace exists — read `"namespace/" + namespace_id`,
    ///    return `NamespaceNotFound` if absent.
    /// 3. Read `"post/" + sanitize(namespace_id) + "/" + sanitize(id)`.
    /// 4. Return the `Post` or `PostNotFound`.
    ///
    /// # Reads
    /// - `"namespace/" + namespace_id`
    /// - `"post/" + sanitize(namespace_id) + "/" + sanitize(id)`
    ///
    /// # Errors
    /// - `NamespaceNotFound` — namespace does not exist
    /// - `PostNotFound` — post not found at that key
    #[allow(unused_variables)]
    pub fn query_post(&self, namespace: &str, id: &str) -> Result<Post> {
        todo!()
    }

    /// List all posts across all namespaces.
    ///
    /// # Flow
    ///
    /// 1. Iterate all entries under the `"post/"` prefix.
    /// 2. Deserialize each value as `Post`.
    /// 3. Return the collected list.
    ///
    /// # Reads
    /// - All keys under `"post/"` prefix
    pub fn query_posts(&self) -> Result<Vec<Post>> {
        todo!()
    }

    /// Query posts matching a glob pattern within a namespace.
    ///
    /// # Flow
    ///
    /// 1. Compute `namespace_id = "bulletin/" + namespace`.
    ///    Note: unlike other namespace-scoped queries, this does NOT
    ///    validate namespace existence. If the namespace has no posts,
    ///    an empty list is returned.
    /// 2. Open a sub-prefix iterator scoped to
    ///    `"post/" + sanitize(namespace_id)`.
    /// 3. For each entry, extract the post ID portion of the key:
    ///    strip any leading `|` or `/` separator, strip any trailing `/`,
    ///    then unsanitize (restore `|` → `/`).
    /// 4. Apply glob matching against the cleaned, unsanitized post ID.
    ///    Glob supports `*` as a wildcard that matches across `/`.
    /// 5. Collect matching entries, deserialize as `Post`.
    /// 6. Return the matched posts.
    ///
    /// # Reads
    /// - Keys under `"post/" + sanitize(namespace_id)` sub-prefix
    ///
    /// # Errors
    /// - Empty `namespace` → Go returns `InvalidArgument` at the gRPC layer.
    ///   Validate non-empty namespace before iterating.
    ///
    /// The glob function itself (`utils.Glob`) accepts any pattern
    /// and returns a bool; it never fails. The Rust implementation may
    /// choose to validate patterns if using a stricter glob library.
    ///
    /// # Implementation notes
    /// The Go implementation uses a tighter prefix store scoped to the
    /// namespace (unlike other post queries). This is the correct approach.
    /// `*` matches across path separators (not single-segment like shell glob).
    #[allow(unused_variables)]
    pub fn query_iterate_glob(&self, namespace: &str, glob: &str) -> Result<Vec<Post>> {
        todo!()
    }

    /// Query current module parameters.
    ///
    /// # Flow
    ///
    /// 1. Read `"p_bulletin"` from the KV store.
    /// 2. Deserialize and return `BulletinParams`.
    ///    If not set, return `BulletinParams::default()`.
    ///
    /// # Reads
    /// - `"p_bulletin"`
    pub fn query_params(&self) -> Result<BulletinParams> {
        todo!()
    }

    // ── Storage access methods ──────────────────────────────────────────
    //
    // Bulletin uses raw Cosmos SDK prefix stores — no raccoondb, no
    // secondary indexes. Three prefix namespaces (`namespace/`,
    // `collaborator/`, `post/`), one singleton (`policy_id`), and one
    // params key (`p_bulletin`).
    //
    // Key sanitization: `/` in component parts is replaced with `|` to
    // prevent path collisions. Reversed on read (`|` → `/`).

    // ── Storage — Policy ID (singleton) ────────────────────────────────

    /// Read the module's ACP policy ID.
    ///
    /// Flow:
    ///   1. Read value at raw KV key `"policy_id"` (no prefix store)
    ///   2. If key absent → return `None`
    ///   3. Value is raw string bytes (NOT protobuf-encoded)
    ///
    /// Key: `"policy_id"` (fixed, raw store)
    /// Value: UTF-8 policy ID string bytes
    /// Direction: read-only
    fn get_policy_id(&self) -> Option<String> {
        todo!()
    }

    /// Write the module's ACP policy ID.
    ///
    /// Flow:
    ///   1. Store `policy_id` as raw string bytes at KV key `"policy_id"`
    ///      (upsert — overwrites any existing value)
    ///
    /// Key: `"policy_id"` (fixed, raw store)
    /// Value: UTF-8 policy ID string bytes (NOT protobuf)
    /// Direction: write
    ///
    /// Called once during `ensure_policy` on the first namespace
    /// registration. Never updated after initial write.
    #[allow(unused_variables)]
    fn set_policy_id(&mut self, policy_id: &str) {
        todo!()
    }

    /// Check if the module's ACP policy has been initialized.
    ///
    /// Flow:
    ///   1. Read value at raw KV key `"policy_id"`
    ///   2. Return `true` if key exists (non-nil bytes)
    ///
    /// Equivalent to `get_policy_id().is_some()`.
    fn has_policy(&self) -> bool {
        todo!()
    }

    /// Lazily initialize the module's ACP policy.
    ///
    /// Flow:
    ///   1. Call `has_policy()` — if true, return the stored policy ID
    ///      via `get_policy_id()`
    ///   2. Call `acp.create_module_policy(BULLETIN_POLICY_YAML,
    ///      PolicyMarshalingType_YAML, "bulletin")` — the creator is
    ///      the bulletin module itself (Go derives a module DID from
    ///      the module name via `did.IssueModuleDID("bulletin")`).
    ///      No external creator DID is involved.
    ///   3. Extract the returned policy ID (and policy capability in Go)
    ///   4. Claim the policy capability (Go:
    ///      `PolicyCapabilityManager.Claim(ctx, polCap)` via the
    ///      scoped keeper). hub.rs may not use Cosmos capabilities —
    ///      this step may be replaced by a different authorization
    ///      mechanism.
    ///   5. Call `set_policy_id(policy_id)` to persist it
    ///   6. Return the new policy ID
    ///
    /// The YAML policy defines one resource type `namespace` with one
    /// relation `collaborator` and one permission
    /// `create_post = collaborator`.
    ///
    /// Errors:
    ///   - ACP `create_module_policy` failure → `PolicyInitFailed`
    ///   - Capability claim failure → `PolicyInitFailed`
    #[allow(unused_variables)]
    fn ensure_policy(&mut self, acp: &mut super::acp::AcpModule) -> Result<String> {
        todo!()
    }

    // ── Storage — Params ───────────────────────────────────────────────

    /// Read module parameters from the KV store.
    ///
    /// Flow:
    ///   1. Read value at raw KV key `"p_bulletin"` (no prefix store)
    ///   2. If key absent → return default `BulletinParams`
    ///      (currently an empty struct — no tunable parameters)
    ///   3. Deserialize stored bytes as `BulletinParams` (protobuf
    ///      encoding in Go; hub.rs serialization format TBD)
    ///
    /// Key: `"p_bulletin"` (fixed, raw store)
    /// Value: serialized `BulletinParams`
    /// Direction: read-only
    ///
    /// Panics on corrupt stored data (Go: `MustUnmarshal`).
    fn get_params(&self) -> BulletinParams {
        todo!()
    }

    /// Write module parameters to the KV store.
    ///
    /// Flow:
    ///   1. Serialize `params` as `BulletinParams`
    ///   2. Store at raw KV key `"p_bulletin"` (upsert)
    ///
    /// Key: `"p_bulletin"` (fixed, raw store)
    /// Value: serialized `BulletinParams`
    /// Direction: write
    ///
    /// This is the only storage method in Bulletin that returns an
    /// error in Go (`cdc.Marshal` can fail). All other writes use
    /// `MustMarshal` which panics on failure.
    #[allow(unused_variables)]
    fn set_params(&mut self, params: &BulletinParams) -> Result<()> {
        todo!()
    }

    // ── Storage — Namespaces ───────────────────────────────────────────

    /// Write a namespace to the KV store.
    ///
    /// Flow:
    ///   1. Serialize `namespace` as protobuf
    ///   2. Store at prefix store `"namespace/"` with key
    ///      `namespace.id` (raw bytes, no sanitization needed —
    ///      namespace IDs are already prefixed with `"bulletin/"`)
    ///
    /// Key: `"namespace/" + namespace.id`
    /// Value: protobuf-serialized `Namespace`
    /// Direction: write (upsert)
    ///
    /// Panics on serialization failure (Go: `MustMarshal`).
    #[allow(unused_variables)]
    fn set_namespace(&mut self, namespace: &Namespace) {
        todo!()
    }

    /// Read a namespace by ID.
    ///
    /// Flow:
    ///   1. Read from prefix store `"namespace/"` with key
    ///      `namespace_id`
    ///   2. If key absent → return `None`
    ///   3. Deserialize as `Namespace`
    ///
    /// Key: `"namespace/" + namespace_id`
    /// Direction: read-only
    ///
    /// Panics on corrupt stored data (Go: `MustUnmarshal`).
    #[allow(unused_variables)]
    fn get_namespace(&self, namespace_id: &str) -> Option<Namespace> {
        todo!()
    }

    /// Check if a namespace exists.
    ///
    /// Flow:
    ///   1. Read from prefix store `"namespace/"` with key
    ///      `namespace_id`
    ///   2. Return `true` if key exists (non-nil bytes)
    ///
    /// Equivalent to `get_namespace(id).is_some()`.
    #[allow(unused_variables)]
    fn has_namespace(&self, namespace_id: &str) -> bool {
        todo!()
    }

    /// List all namespaces.
    ///
    /// Flow:
    ///   1. Open prefix iterator over `"namespace/"` with empty
    ///      sub-prefix (iterates all entries)
    ///   2. Deserialize each value as `Namespace`
    ///   3. Collect and return
    ///
    /// Go: `mustIterateNamespaces` + `KVStorePrefixIterator(store, []byte{})`.
    /// Panics on deserialization failure.
    fn get_all_namespaces(&self) -> Vec<Namespace> {
        todo!()
    }

    // ── Storage — Collaborators ────────────────────────────────────────

    /// Write a collaborator to the KV store.
    ///
    /// Flow:
    ///   1. Serialize `collaborator` as protobuf
    ///   2. Compute key: `sanitize(collaborator.namespace) + "/"
    ///      + sanitize(collaborator.did)`
    ///   3. Store at prefix store `"collaborator/"` with that key
    ///
    /// Key: `"collaborator/" + sanitize(namespace) + "/" + sanitize(did)`
    /// Value: protobuf-serialized `Collaborator`
    /// Direction: write (upsert)
    ///
    /// Panics on serialization failure (Go: `MustMarshal`).
    #[allow(unused_variables)]
    fn set_collaborator(&mut self, collaborator: &Collaborator) {
        todo!()
    }

    /// Read a collaborator by namespace and DID.
    ///
    /// Flow:
    ///   1. Compute key: `sanitize(namespace_id) + "/"
    ///      + sanitize(collaborator_did)`
    ///   2. Read from prefix store `"collaborator/"`
    ///   3. If key absent → return `None`
    ///   4. Deserialize as `Collaborator`
    ///
    /// Key: `"collaborator/" + sanitize(namespace_id) + "/" + sanitize(did)`
    /// Direction: read-only
    ///
    /// Panics on corrupt stored data (Go: `MustUnmarshal`).
    #[allow(unused_variables)]
    fn get_collaborator(&self, namespace_id: &str, collaborator_did: &str) -> Option<Collaborator> {
        todo!()
    }

    /// Delete a collaborator from the KV store.
    ///
    /// Flow:
    ///   1. Compute key: `sanitize(namespace_id) + "/"
    ///      + sanitize(collaborator_did)`
    ///   2. Delete from prefix store `"collaborator/"`
    ///
    /// Key: `"collaborator/" + sanitize(namespace_id) + "/" + sanitize(did)`
    /// Direction: delete
    ///
    /// No-op if key does not exist (Go: `store.Delete` on missing
    /// key is silent).
    #[allow(unused_variables)]
    fn delete_collaborator(&mut self, namespace_id: &str, collaborator_did: &str) {
        todo!()
    }

    /// List all collaborators across all namespaces.
    ///
    /// Flow:
    ///   1. Open prefix iterator over `"collaborator/"` with empty
    ///      sub-prefix (iterates all entries)
    ///   2. Deserialize each value as `Collaborator`
    ///   3. Collect and return
    ///
    /// Go: `mustIterateCollaborators` + `KVStorePrefixIterator(store, []byte{})`.
    /// Panics on deserialization failure.
    fn get_all_collaborators(&self) -> Vec<Collaborator> {
        todo!()
    }

    // ── Storage — Posts ────────────────────────────────────────────────

    /// Write a post to the KV store.
    ///
    /// Flow:
    ///   1. Serialize `post` as protobuf
    ///   2. Compute key: `sanitize(post.namespace) + "/"
    ///      + sanitize(post.id)`
    ///   3. Store at prefix store `"post/"` with that key
    ///
    /// Key: `"post/" + sanitize(namespace) + "/" + sanitize(id)`
    /// Value: protobuf-serialized `Post`
    /// Direction: write (upsert)
    ///
    /// Panics on serialization failure (Go: `MustMarshal`).
    #[allow(unused_variables)]
    fn set_post(&mut self, post: &Post) {
        todo!()
    }

    /// Read a post by namespace and post ID.
    ///
    /// Flow:
    ///   1. Compute key: `sanitize(namespace_id) + "/"
    ///      + sanitize(post_id)`
    ///   2. Read from prefix store `"post/"`
    ///   3. If key absent → return `None`
    ///   4. Deserialize as `Post`
    ///
    /// Key: `"post/" + sanitize(namespace_id) + "/" + sanitize(post_id)`
    /// Direction: read-only
    ///
    /// Panics on corrupt stored data (Go: `MustUnmarshal`).
    #[allow(unused_variables)]
    fn get_post(&self, namespace_id: &str, post_id: &str) -> Option<Post> {
        todo!()
    }

    /// List all posts in a specific namespace.
    ///
    /// Flow:
    ///   1. Open prefix iterator over `"post/"` with sub-prefix
    ///      `sanitize(namespace_id) + "/"`
    ///   2. Deserialize each value as `Post`
    ///   3. Collect and return
    ///
    /// Go: `mustIterateNamespacePosts` — uses a scoped prefix
    /// iterator (more efficient than full scan + filter).
    /// Panics on deserialization failure.
    #[allow(unused_variables)]
    fn get_namespace_posts(&self, namespace_id: &str) -> Vec<Post> {
        todo!()
    }

    /// List all posts across all namespaces.
    ///
    /// Flow:
    ///   1. Open prefix iterator over `"post/"` with empty
    ///      sub-prefix (iterates all entries)
    ///   2. Deserialize each value as `Post`
    ///   3. Collect and return
    ///
    /// Go: `mustIteratePosts` + `KVStorePrefixIterator(store, []byte{})`.
    /// Panics on deserialization failure.
    fn get_all_posts(&self) -> Vec<Post> {
        todo!()
    }

    // ── Storage — Utility ──────────────────────────────────────────────

    /// Sanitize a key component by replacing `/` with `|`.
    ///
    /// Prevents path collisions when key components (namespace IDs,
    /// DIDs, post IDs) contain `/` characters. The `"bulletin/"` prefix
    /// in namespace IDs becomes `"bulletin|"` after sanitization.
    ///
    /// Reversible via `unsanitize_key_part`.
    #[allow(unused_variables)]
    fn sanitize_key_part(part: &str) -> String {
        todo!()
    }

    /// Reverse key sanitization: replace `|` with `/`.
    #[allow(unused_variables)]
    fn unsanitize_key_part(part: &str) -> String {
        todo!()
    }

    /// Generate a deterministic post ID from namespace and payload.
    ///
    /// Formula: `hex(sha256(namespace_id + payload))`
    ///
    /// The namespace_id includes the `"bulletin/"` prefix, so posts
    /// in different namespaces with identical payloads get different
    /// IDs. The hex encoding is lowercase.
    #[allow(unused_variables)]
    fn generate_post_id(namespace_id: &str, payload: &[u8]) -> String {
        todo!()
    }
}
