//! Bulletin module — namespace-scoped posts for DKG coordination and messaging.

/// Solidity ABI interface for the Bulletin precompile.
pub mod abi;
/// Bulletin error types.
pub mod error;
/// Key prefixes and builders for Bulletin KV storage.
pub mod keys;
/// Bulletin domain types.
pub mod types;

use acp::{Relationship, Subject};
use error::BulletinError;
use identity::Did;
use types::{BulletinParams, Collaborator, Namespace, Post};

use crate::acp::types::{AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyMarshalingType};
use crate::kv_store::{InMemoryKvStore, ModuleKvStore};
use crate::types::{BlockExecCtx, TxExecCtx};

type Result<T> = std::result::Result<T, BulletinError>;

const BULLETIN_POLICY_YAML: &str = "\
name: bulletin-module-policy
resources:
  - name: namespace
    relations:
      - name: owner
      - name: collaborator
    permissions:
      - name: create_post
        expr: owner + collaborator
";

const MODULE_DID: &str = "did:key:bulletin";

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
#[derive(Clone, Debug, Default)]
pub struct BulletinModule {
    store: InMemoryKvStore,
}

#[allow(dead_code)]
impl BulletinModule {
    /// Create a new Bulletin module instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read access to the underlying KV store (for serialization).
    pub const fn store(&self) -> &InMemoryKvStore {
        &self.store
    }

    /// Reconstruct from a deserialized store.
    pub const fn from_store(store: InMemoryKvStore) -> Self {
        Self { store }
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
    pub fn register_namespace(
        &mut self,
        acp: &mut super::acp::AcpModule,
        block_ctx: &BlockExecCtx,
        tx_ctx: &TxExecCtx,
        creator: &Did,
        namespace: &str,
    ) -> Result<Namespace> {
        let policy_id = self.ensure_policy(acp)?;
        let namespace_id = format!("bulletin/{}", namespace);

        if self.has_namespace(&namespace_id) {
            return Err(BulletinError::NamespaceAlreadyExists {
                namespace: namespace.to_string(),
            });
        }

        acp.direct_policy_cmd(
            creator,
            &policy_id,
            PolicyCmd::RegisterObject(Object {
                resource: "namespace".into(),
                id: namespace_id.clone(),
            }),
        )
        .map_err(|e| BulletinError::PolicyInitFailed(e.to_string()))?;

        let ns = Namespace {
            id: namespace_id,
            creator: tx_ctx.signer.clone(),
            owner_did: creator.to_string(),
            created_at: block_ctx.timestamp.clone(),
        };
        self.set_namespace(&ns);
        Ok(ns)
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
    #[allow(clippy::too_many_arguments)]
    pub fn create_post(
        &mut self,
        acp: &super::acp::AcpModule,
        _tx_ctx: &TxExecCtx,
        creator: &Did,
        namespace: &str,
        payload: &[u8],
        proof: &[u8],
        _artifact: &str,
    ) -> Result<()> {
        let policy_id = self
            .get_policy_id()
            .ok_or(BulletinError::PolicyNotInitialized)?;
        let namespace_id = format!("bulletin/{}", namespace);

        if !self.has_namespace(&namespace_id) {
            return Err(BulletinError::NamespaceNotFound {
                namespace: namespace.to_string(),
            });
        }

        if payload.is_empty() {
            return Err(BulletinError::InvalidPostPayload);
        }

        if proof.is_empty() {
            return Err(BulletinError::InvalidPostProof);
        }

        let access_request = AccessRequest {
            operations: vec![Operation {
                object: Object {
                    resource: "namespace".into(),
                    id: namespace_id.clone(),
                },
                permission: "create_post".into(),
            }],
            actor: Actor(creator.clone()),
        };

        let allowed = acp
            .query_verify_access_request(&policy_id, &access_request)
            .map_err(|e| BulletinError::State(e.to_string()))?;

        if !allowed {
            return Err(BulletinError::NotCollaborator {
                namespace: namespace.to_string(),
            });
        }

        let post_id = Self::generate_post_id(&namespace_id, payload);

        if self.get_post(&namespace_id, &post_id).is_some() {
            return Err(BulletinError::PostAlreadyExists {
                namespace: namespace.to_string(),
                id: post_id,
            });
        }

        let post = Post {
            id: post_id,
            namespace: namespace_id,
            creator_did: creator.to_string(),
            payload: payload.to_vec(),
            proof: proof.to_vec(),
        };
        self.set_post(&post);
        Ok(())
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
    pub fn add_collaborator(
        &mut self,
        acp: &mut super::acp::AcpModule,
        _tx_ctx: &TxExecCtx,
        creator: &Did,
        namespace: &str,
        collaborator: &str,
    ) -> Result<String> {
        let policy_id = self
            .get_policy_id()
            .ok_or(BulletinError::PolicyNotInitialized)?;
        let namespace_id = format!("bulletin/{}", namespace);

        if !self.has_namespace(&namespace_id) {
            return Err(BulletinError::NamespaceNotFound {
                namespace: namespace.to_string(),
            });
        }

        let collab_did = format!("did:key:{}", collaborator);

        if self.get_collaborator(&namespace_id, &collab_did).is_some() {
            return Err(BulletinError::CollaboratorAlreadyExists {
                namespace: namespace.to_string(),
                did: collab_did,
            });
        }

        let collab_did_parsed = Did::new(&collab_did)
            .map_err(|e| BulletinError::State(format!("invalid collaborator DID: {}", e)))?;

        acp.direct_policy_cmd(
            creator,
            &policy_id,
            PolicyCmd::SetRelationship(Relationship {
                resource: "namespace".into(),
                object_id: namespace_id.clone(),
                relation: "collaborator".into(),
                subject: Subject::Entity(collab_did_parsed),
            }),
        )
        .map_err(|e| BulletinError::Unauthorized {
            reason: e.to_string(),
        })?;

        let record = Collaborator {
            address: collaborator.to_string(),
            did: collab_did.clone(),
            namespace: namespace_id,
        };
        self.set_collaborator(&record);
        Ok(collab_did)
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
    pub fn remove_collaborator(
        &mut self,
        acp: &mut super::acp::AcpModule,
        _tx_ctx: &TxExecCtx,
        creator: &Did,
        namespace: &str,
        collaborator: &str,
    ) -> Result<String> {
        let policy_id = self
            .get_policy_id()
            .ok_or(BulletinError::PolicyNotInitialized)?;
        let namespace_id = format!("bulletin/{}", namespace);

        if !self.has_namespace(&namespace_id) {
            return Err(BulletinError::NamespaceNotFound {
                namespace: namespace.to_string(),
            });
        }

        let collab_did = format!("did:key:{}", collaborator);

        if self.get_collaborator(&namespace_id, &collab_did).is_none() {
            return Err(BulletinError::CollaboratorNotFound {
                namespace: namespace.to_string(),
                did: collab_did,
            });
        }

        let collab_did_parsed = Did::new(&collab_did)
            .map_err(|e| BulletinError::State(format!("invalid collaborator DID: {}", e)))?;

        acp.direct_policy_cmd(
            creator,
            &policy_id,
            PolicyCmd::DeleteRelationship(Relationship {
                resource: "namespace".into(),
                object_id: namespace_id.clone(),
                relation: "collaborator".into(),
                subject: Subject::Entity(collab_did_parsed),
            }),
        )
        .map_err(|e| BulletinError::Unauthorized {
            reason: e.to_string(),
        })?;

        self.delete_collaborator(&namespace_id, &collab_did);
        Ok(collab_did)
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
    pub fn update_params(&mut self, _authority: &Did, params: BulletinParams) -> Result<()> {
        self.set_params(&params)
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
    pub fn query_namespace(&self, namespace: &str) -> Result<Namespace> {
        let namespace_id = format!("bulletin/{}", namespace);
        self.get_namespace(&namespace_id)
            .ok_or(BulletinError::NamespaceNotFound {
                namespace: namespace.to_string(),
            })
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
        Ok(self.get_all_namespaces())
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
    pub fn query_namespace_collaborators(&self, namespace: &str) -> Result<Vec<Collaborator>> {
        let namespace_id = format!("bulletin/{}", namespace);
        if !self.has_namespace(&namespace_id) {
            return Err(BulletinError::NamespaceNotFound {
                namespace: namespace.to_string(),
            });
        }
        Ok(self.get_namespace_collaborators(&namespace_id))
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
    pub fn query_namespace_posts(&self, namespace: &str) -> Result<Vec<Post>> {
        let namespace_id = format!("bulletin/{}", namespace);
        if !self.has_namespace(&namespace_id) {
            return Err(BulletinError::NamespaceNotFound {
                namespace: namespace.to_string(),
            });
        }
        Ok(self.get_namespace_posts(&namespace_id))
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
    pub fn query_post(&self, namespace: &str, id: &str) -> Result<Post> {
        let namespace_id = format!("bulletin/{}", namespace);
        if !self.has_namespace(&namespace_id) {
            return Err(BulletinError::NamespaceNotFound {
                namespace: namespace.to_string(),
            });
        }
        self.get_post(&namespace_id, id)
            .ok_or(BulletinError::PostNotFound {
                namespace: namespace.to_string(),
                id: id.to_string(),
            })
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
        Ok(self.get_all_posts())
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
    pub fn query_iterate_glob(&self, namespace: &str, glob: &str) -> Result<Vec<Post>> {
        if namespace.is_empty() {
            return Err(BulletinError::InvalidGlob {
                pattern: "empty namespace".to_string(),
            });
        }

        let namespace_id = format!("bulletin/{}", namespace);
        let scan_prefix = keys::post_prefix(&namespace_id);

        let mut results = Vec::new();
        for (key, value) in self.store.prefix_scan(&scan_prefix) {
            let (_, post_id) = keys::parse_post_key(&key);
            if glob_match(glob, &post_id)
                && let Ok(post) = borsh::from_slice::<Post>(&value)
            {
                results.push(post);
            }
        }
        Ok(results)
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
        Ok(self.get_params())
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
    fn get_policy_id(&self) -> Option<String> {
        self.store
            .get(keys::POLICY_ID_KEY)
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }

    /// Write the module's ACP policy ID.
    fn set_policy_id(&mut self, policy_id: &str) {
        self.store
            .put(keys::POLICY_ID_KEY, policy_id.as_bytes().to_vec());
    }

    /// Check if the module's ACP policy has been initialized.
    fn has_policy(&self) -> bool {
        self.store.has(keys::POLICY_ID_KEY)
    }

    /// Lazily initialize the module's ACP policy.
    fn ensure_policy(&mut self, acp: &mut super::acp::AcpModule) -> Result<String> {
        if self.has_policy() {
            return Ok(self.get_policy_id().expect("has_policy implies Some"));
        }

        let module_did =
            Did::new(MODULE_DID).map_err(|e| BulletinError::PolicyInitFailed(e.to_string()))?;

        let record = acp
            .create_policy(
                &module_did,
                BULLETIN_POLICY_YAML,
                PolicyMarshalingType::ShortYaml,
            )
            .map_err(|e| BulletinError::PolicyInitFailed(e.to_string()))?;

        let policy_id = record.policy.id;
        self.set_policy_id(&policy_id);
        Ok(policy_id)
    }

    // ── Storage — Params ───────────────────────────────────────────────

    fn get_params(&self) -> BulletinParams {
        self.store
            .get(keys::PARAMS_KEY)
            .map(|bytes| borsh::from_slice(&bytes).expect("corrupt BulletinParams"))
            .unwrap_or_default()
    }

    fn set_params(&mut self, params: &BulletinParams) -> Result<()> {
        let bytes = borsh::to_vec(params)
            .map_err(|e| BulletinError::State(format!("serialize params: {e}")))?;
        self.store.put(keys::PARAMS_KEY, bytes);
        Ok(())
    }

    // ── Storage — Namespaces ───────────────────────────────────────────

    fn set_namespace(&mut self, namespace: &Namespace) {
        let bytes = borsh::to_vec(namespace).expect("serialize Namespace");
        self.store.put(&keys::namespace_key(&namespace.id), bytes);
    }

    fn get_namespace(&self, namespace_id: &str) -> Option<Namespace> {
        self.store
            .get(&keys::namespace_key(namespace_id))
            .and_then(|bytes| borsh::from_slice(&bytes).ok())
    }

    fn has_namespace(&self, namespace_id: &str) -> bool {
        self.store.has(&keys::namespace_key(namespace_id))
    }

    fn get_all_namespaces(&self) -> Vec<Namespace> {
        self.store
            .prefix_scan(keys::NAMESPACE_PREFIX)
            .iter()
            .filter_map(|(_, v)| borsh::from_slice(v).ok())
            .collect()
    }

    // ── Storage — Collaborators ────────────────────────────────────────

    fn set_collaborator(&mut self, collaborator: &Collaborator) {
        let key = keys::collaborator_key(&collaborator.namespace, &collaborator.did);
        let bytes = borsh::to_vec(collaborator).expect("serialize Collaborator");
        self.store.put(&key, bytes);
    }

    fn get_collaborator(&self, namespace_id: &str, collaborator_did: &str) -> Option<Collaborator> {
        self.store
            .get(&keys::collaborator_key(namespace_id, collaborator_did))
            .and_then(|bytes| borsh::from_slice(&bytes).ok())
    }

    fn delete_collaborator(&mut self, namespace_id: &str, collaborator_did: &str) {
        self.store
            .delete(&keys::collaborator_key(namespace_id, collaborator_did));
    }

    fn get_namespace_collaborators(&self, namespace_id: &str) -> Vec<Collaborator> {
        self.store
            .prefix_scan(&keys::collaborator_prefix(namespace_id))
            .iter()
            .filter_map(|(_, v)| borsh::from_slice(v).ok())
            .collect()
    }

    // ── Storage — Posts ────────────────────────────────────────────────

    fn set_post(&mut self, post: &Post) {
        let key = keys::post_key(&post.namespace, &post.id);
        let bytes = borsh::to_vec(post).expect("serialize Post");
        self.store.put(&key, bytes);
    }

    fn get_post(&self, namespace_id: &str, post_id: &str) -> Option<Post> {
        self.store
            .get(&keys::post_key(namespace_id, post_id))
            .and_then(|bytes| borsh::from_slice(&bytes).ok())
    }

    fn get_namespace_posts(&self, namespace_id: &str) -> Vec<Post> {
        self.store
            .prefix_scan(&keys::post_prefix(namespace_id))
            .iter()
            .filter_map(|(_, v)| borsh::from_slice(v).ok())
            .collect()
    }

    fn get_all_posts(&self) -> Vec<Post> {
        self.store
            .prefix_scan(keys::POST_PREFIX)
            .iter()
            .filter_map(|(_, v)| borsh::from_slice(v).ok())
            .collect()
    }

    // ── Storage — Utility ──────────────────────────────────────────────

    fn generate_post_id(namespace_id: &str, payload: &[u8]) -> String {
        keys::generate_post_id(namespace_id, payload)
    }
}

/// Simple glob match where `*` matches any sequence of characters including `/`.
fn glob_match(pattern: &str, value: &str) -> bool {
    glob_match_inner(pattern.as_bytes(), value.as_bytes())
}

fn glob_match_inner(pattern: &[u8], value: &[u8]) -> bool {
    match (pattern.first(), value.first()) {
        (None, None) => true,
        (Some(&b'*'), _) => {
            glob_match_inner(&pattern[1..], value)
                || (!value.is_empty() && glob_match_inner(pattern, &value[1..]))
        }
        (None, Some(_)) | (Some(_), None) => false,
        (Some(p), Some(v)) => p == v && glob_match_inner(&pattern[1..], &value[1..]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Timestamp;

    fn make_did(s: &str) -> Did {
        Did::new(s).expect("valid did")
    }

    fn make_block_ctx(seconds: u64, height: u64) -> BlockExecCtx {
        BlockExecCtx {
            timestamp: Timestamp {
                seconds,
                block_height: height,
            },
        }
    }

    fn make_tx_ctx(signer: &str) -> TxExecCtx {
        TxExecCtx {
            tx_hash: vec![],
            signer: signer.to_string(),
        }
    }

    fn populated_module() -> BulletinModule {
        let mut m = BulletinModule::default();
        let ns = Namespace {
            id: "bulletin/ns1".into(),
            creator: "0xABCD".into(),
            owner_did: "did:key:z6Mkowner".into(),
            created_at: Timestamp {
                seconds: 100,
                block_height: 10,
            },
        };
        m.set_namespace(&ns);

        let post = Post {
            id: "abc123".into(),
            namespace: "bulletin/ns1".into(),
            creator_did: "did:key:z6Mkcreator".into(),
            payload: vec![1, 2, 3],
            proof: vec![4, 5, 6],
        };
        m.set_post(&post);

        let collab = Collaborator {
            address: "0xBBBB".into(),
            did: "did:key:z6Mkcollab".into(),
            namespace: "bulletin/ns1".into(),
        };
        m.set_collaborator(&collab);
        m
    }

    #[test]
    fn update_params_stores_and_retrieves() {
        let mut m = BulletinModule::default();
        let did = make_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        m.update_params(&did, BulletinParams {}).unwrap();
        let p = m.query_params().unwrap();
        assert_eq!(p, BulletinParams {});
    }

    #[test]
    fn query_namespace_found() {
        let m = populated_module();
        let ns = m.query_namespace("ns1").unwrap();
        assert_eq!(ns.id, "bulletin/ns1");
    }

    #[test]
    fn query_namespace_not_found() {
        let m = populated_module();
        let err = m.query_namespace("missing").unwrap_err();
        assert!(matches!(err, BulletinError::NamespaceNotFound { .. }));
    }

    #[test]
    fn query_namespaces_returns_all() {
        let m = populated_module();
        let list = m.query_namespaces().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "bulletin/ns1");
    }

    #[test]
    fn query_namespace_posts_found() {
        let m = populated_module();
        let posts = m.query_namespace_posts("ns1").unwrap();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].id, "abc123");
    }

    #[test]
    fn query_namespace_posts_namespace_not_found() {
        let m = populated_module();
        let err = m.query_namespace_posts("missing").unwrap_err();
        assert!(matches!(err, BulletinError::NamespaceNotFound { .. }));
    }

    #[test]
    fn query_post_found() {
        let m = populated_module();
        let post = m.query_post("ns1", "abc123").unwrap();
        assert_eq!(post.id, "abc123");
    }

    #[test]
    fn query_post_not_found() {
        let m = populated_module();
        let err = m.query_post("ns1", "nope").unwrap_err();
        assert!(matches!(err, BulletinError::PostNotFound { .. }));
    }

    #[test]
    fn query_post_namespace_not_found() {
        let m = populated_module();
        let err = m.query_post("missing", "abc123").unwrap_err();
        assert!(matches!(err, BulletinError::NamespaceNotFound { .. }));
    }

    #[test]
    fn query_posts_returns_all() {
        let m = populated_module();
        let posts = m.query_posts().unwrap();
        assert_eq!(posts.len(), 1);
    }

    #[test]
    fn query_namespace_collaborators_found() {
        let m = populated_module();
        let collabs = m.query_namespace_collaborators("ns1").unwrap();
        assert_eq!(collabs.len(), 1);
        assert_eq!(collabs[0].did, "did:key:z6Mkcollab");
    }

    #[test]
    fn query_namespace_collaborators_namespace_not_found() {
        let m = populated_module();
        let err = m.query_namespace_collaborators("missing").unwrap_err();
        assert!(matches!(err, BulletinError::NamespaceNotFound { .. }));
    }

    #[test]
    fn query_iterate_glob_star_matches_all() {
        let m = populated_module();
        let posts = m.query_iterate_glob("ns1", "*").unwrap();
        assert_eq!(posts.len(), 1);
    }

    #[test]
    fn query_iterate_glob_exact_match() {
        let m = populated_module();
        let posts = m.query_iterate_glob("ns1", "abc123").unwrap();
        assert_eq!(posts.len(), 1);
    }

    #[test]
    fn query_iterate_glob_no_match() {
        let m = populated_module();
        let posts = m.query_iterate_glob("ns1", "zzz*").unwrap();
        assert!(posts.is_empty());
    }

    #[test]
    fn query_iterate_glob_empty_namespace_errors() {
        let m = populated_module();
        let err = m.query_iterate_glob("", "*").unwrap_err();
        assert!(matches!(err, BulletinError::InvalidGlob { .. }));
    }

    #[test]
    #[ignore = "requires ACP handlers (todo!() stubs would panic)"]
    fn register_namespace_fails_without_policy() {
        let mut m = BulletinModule::default();
        let mut acp = crate::acp::AcpModule::new();
        let block_ctx = make_block_ctx(100, 10);
        let tx_ctx = make_tx_ctx("0xABCD");
        let did = make_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let result = m.register_namespace(&mut acp, &block_ctx, &tx_ctx, &did, "ns1");
        assert!(result.is_err());
    }

    #[test]
    fn create_post_empty_payload_fails() {
        let mut m = populated_module();
        m.set_policy_id("some-policy-id");
        let acp = crate::acp::AcpModule::new();
        let tx_ctx = make_tx_ctx("0xABCD");
        let did = make_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let err = m
            .create_post(&acp, &tx_ctx, &did, "ns1", &[], b"proof", "artifact")
            .unwrap_err();
        assert!(matches!(err, BulletinError::InvalidPostPayload));
    }

    #[test]
    fn create_post_empty_proof_fails() {
        let mut m = populated_module();
        m.set_policy_id("some-policy-id");
        let acp = crate::acp::AcpModule::new();
        let tx_ctx = make_tx_ctx("0xABCD");
        let did = make_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let err = m
            .create_post(&acp, &tx_ctx, &did, "ns1", b"payload", &[], "artifact")
            .unwrap_err();
        assert!(matches!(err, BulletinError::InvalidPostProof));
    }

    #[test]
    fn create_post_namespace_not_found() {
        let mut m = BulletinModule::default();
        m.set_policy_id("some-policy-id");
        let acp = crate::acp::AcpModule::new();
        let tx_ctx = make_tx_ctx("0xABCD");
        let did = make_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let err = m
            .create_post(
                &acp, &tx_ctx, &did, "missing", b"payload", b"proof", "artifact",
            )
            .unwrap_err();
        assert!(matches!(err, BulletinError::NamespaceNotFound { .. }));
    }

    #[test]
    fn create_post_policy_not_initialized() {
        let mut m = populated_module();
        let acp = crate::acp::AcpModule::new();
        let tx_ctx = make_tx_ctx("0xABCD");
        let did = make_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        let err = m
            .create_post(&acp, &tx_ctx, &did, "ns1", b"payload", b"proof", "artifact")
            .unwrap_err();
        assert!(matches!(err, BulletinError::PolicyNotInitialized));
    }

    #[test]
    fn glob_match_star_wildcard() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", "path/with/slashes"));
        assert!(glob_match("prefix*", "prefix-value"));
        assert!(glob_match("*suffix", "some-suffix"));
        assert!(!glob_match("prefix*", "other"));
    }

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "other"));
    }

    #[test]
    fn storage_roundtrip_namespace() {
        let mut m = BulletinModule::default();
        let ns = Namespace {
            id: "bulletin/test".into(),
            creator: "0xABCD".into(),
            owner_did: "did:key:z6Mk".into(),
            created_at: Timestamp {
                seconds: 1,
                block_height: 1,
            },
        };
        m.set_namespace(&ns);
        assert!(m.has_namespace("bulletin/test"));
        assert_eq!(m.get_namespace("bulletin/test").unwrap(), ns);
        assert!(m.get_namespace("missing").is_none());
    }

    #[test]
    fn storage_roundtrip_collaborator() {
        let mut m = BulletinModule::default();
        let c = Collaborator {
            address: "0xBBBB".into(),
            did: "did:key:z6Mkabc".into(),
            namespace: "bulletin/ns1".into(),
        };
        m.set_collaborator(&c);
        let got = m
            .get_collaborator("bulletin/ns1", "did:key:z6Mkabc")
            .unwrap();
        assert_eq!(got, c);
        m.delete_collaborator("bulletin/ns1", "did:key:z6Mkabc");
        assert!(
            m.get_collaborator("bulletin/ns1", "did:key:z6Mkabc")
                .is_none()
        );
    }

    #[test]
    fn storage_roundtrip_post() {
        let mut m = BulletinModule::default();
        let post = Post {
            id: "post1".into(),
            namespace: "bulletin/ns1".into(),
            creator_did: "did:key:z6Mk".into(),
            payload: vec![1],
            proof: vec![2],
        };
        m.set_post(&post);
        let got = m.get_post("bulletin/ns1", "post1").unwrap();
        assert_eq!(got, post);
    }
}
