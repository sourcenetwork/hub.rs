# Structured cross-object subjects on the ACP write path

**Date:** 2026-06-19
**Status:** design — pending review
**Context:** zanzibar-rl#66 follow-up. The chain now *resolves* cross-object
TupleToUserset (PR #87), but the *set* path is actor-only: the ACP precompile
constructs `Subject::entity(actor_did)` and hub-client takes `target: &Did`.
This widens the write path so a cross-object / userset subject can be set and
deleted through the normal precompile + client API, with the #1059 soundness
floor enforced on store.

## Goal

Let a relationship's subject be any `zanzibar::Subject` — not just an entity —
when set/deleted through the ACP precompile and hub-client, carried as
**structured fields** (never a parsed string), and validated against the
relation's declared subject restriction before it is stored.

## Non-goals

- No string/grammar parsing of subjects. Object IDs are path-like and quoted
  (`file:"/team/payroll.csv"`); a string grammar would force fragile
  quote-handling on a security boundary.
- No widening of the read/query path (`hasRelationship`, `filterRelationships`)
  to filter by a cross-object subject. `filterRelationships` with an empty
  actor already returns every subject (incl. EntitySet); querying by a specific
  cross-object subject is a separate future change.
- `TypedWildcard` is not exposed (not in the near-term gold tuples, which use
  `*`, usersets, objects, and entities). Reserve `subjectKind = 4` for it;
  decoding rejects it for now. Adding it later is additive and back-compatible.

## Wire contract (defradb's hub_rs provider emits exactly these fields)

Two **additive** precompile methods. The existing `setRelationship` /
`deleteRelationship` (entity-only `actor: string`) are unchanged for
back-compat.

```solidity
function setRelationshipSubject(
    bytes32 policyId,
    string  resource,        // object the relation is on
    string  objectId,
    string  relation,
    uint8   subjectKind,     // 0=Entity  1=Wildcard  2=Object  3=Userset
    string  subjectResource, // Object, Userset        (else "")
    string  subjectObjectId, // Entity=DID; Object, Userset (else "")
    string  subjectRelation  // Userset                (else "")
) external returns (bool recordExisted, bytes record);

function deleteRelationshipSubject(
    bytes32 policyId,
    string  resource,
    string  objectId,
    string  relation,
    uint8   subjectKind,
    string  subjectResource,
    string  subjectObjectId,
    string  subjectRelation
) external returns (bool recordFound);
```

### `subjectKind` → `zanzibar::Subject`

| kind | fields used | → `Subject` |
|------|-------------|-------------|
| 0 `Entity`   | `subjectObjectId` = DID        | `Entity(Did)` |
| 1 `Wildcard` | —                              | `Wildcard` |
| 2 `Object`   | `subjectResource`, `subjectObjectId` | `EntitySet { resource, object_id, relation: "" }` |
| 3 `Userset`  | `subjectResource`, `subjectObjectId`, `subjectRelation` | `EntitySet { resource, object_id, relation }` |

- An **object-edge** (kind 2) is `EntitySet` with an empty `relation`, matching
  zanzibar's own model (`Relationship::validate`: empty relation ⇒ the
  referenced *resource* must be declared; non-empty ⇒ the `resource#relation`
  must be declared).
- The Entity DID rides in `subjectObjectId` (the subject's identifier slot) to
  stay within the three named subject fields. Unused fields are `""`.
- Decoding rejects malformed kinds: unknown `subjectKind`, empty DID for
  `Entity`, empty `subjectResource`/`subjectObjectId` for `Object`/`Userset`,
  or non-empty cross-object fields for `Entity`/`Wildcard` → revert.

### Events — new types, existing ones untouched

The existing `RelationshipSet` / `RelationshipDeleted` events are **not** widened
— ABI events are position-decoded, so appending fields breaks existing indexers.
Instead the new methods emit **new** event types:

```solidity
event RelationshipSubjectSet(
    bytes32 indexed policyId, string resource, string objectId, string relation,
    uint8 subjectKind, string subjectResource, string subjectObjectId, string subjectRelation
);
event RelationshipSubjectDeleted( /* identical fields */ );
```

The entity-only `setRelationship`/`deleteRelationship` methods keep emitting the
existing `RelationshipSet`/`RelationshipDeleted` events, so existing indexers are
untouched and the provider keeps using the entity-only method+event for actor
grants.

## Floor enforcement (#1059) — gated to declared relations (#1060 Go-compat)

`AcpModule::cmd_set_relationship` currently **hard-rejects** a relationship whose
relation is not declared in the policy (`mod.rs:935`). defradb (#1060, Go-compat)
**accepts** undeclared relation names and enforces the floor only on declared
ones. Keeping hub's hard reject would make hub reject grants defradb accepts and
diverge single-node vs cross-node. So:

Replace the hard reject with a **gated floor** on set:

```rust
// Go-compat (defradb #1060): accept relationships on undeclared relation
// names; enforce the floor (#1059) only on declared relations, so hub and
// defradb make the same accept/reject decision.
if policy.get_relation(&rel.resource, &rel.relation).is_some() {
    rel.validate(&policy)
        .map_err(|e| AcpError::InvalidAccessRequest { reason: e.to_string() })?;
}
```

`Relationship::validate(&policy)` (only reached when the relation is declared, so
its internal `RelationNotFound` branch never fires) validates:
1. an `EntitySet` subject's referenced resource / `resource#relation` is declared,
2. the subject satisfies the relation's `subject_restriction` (the floor).

This runs on **set** for **every** subject, including entities, closing the
soundness gap on the existing path too. A violation maps to an `AcpError` → the
tx reverts. Undeclared relations are accepted without floor validation, matching
defradb.

The floor is **not** applied on **delete**: revocation must always succeed so a
grant can be removed even after the policy's restrictions change. The delete
path decodes the subject only to compute the relationship's storage key.

**Behavior change:** hub now accepts relationships on undeclared relations (it
previously rejected them). Existing tests asserting the old rejection are updated
to the Go-compat behavior.

## Components

1. **`crates/hub-modules/src/acp/abi.rs`** — add the two `*Subject` methods and
   the two new `RelationshipSubject{Set,Deleted}` event types. Existing methods
   and events untouched.
2. **`crates/hub-executor/src/precompiles/acp.rs`** — `decode_subject(kind,
   resource, object_id, relation) -> Result<acp::Subject, PrecompileError>`
   shared by both new handlers; handlers mirror the existing set/delete
   (auth via `did_from_signer`, dispatch via `direct_policy_cmd`) but emit the
   new `RelationshipSubject{Set,Deleted}` events.
3. **`crates/hub-modules/src/acp/mod.rs`** — `cmd_set_relationship` calls
   `rel.validate(&policy)` (the floor) and maps the error to `AcpError`. The
   delete counterpart is unchanged beyond accepting the decoded subject.
4. **`crates/hub-client`** — `enum RelationshipSubject { Entity(String),
   Wildcard, Object { resource, object_id }, Userset { resource, object_id,
   relation } }` with an encoder to the ABI fields; `set_relationship_subject` /
   `delete_relationship_subject` (EVM) + `native_*` variants.
5. **`crates/hub-e2e/tests/cross_object_acp.rs`** — seed the parent edge via the
   new tx method (replacing the bearer-cmd JSON workaround), keep the resolution
   assertion, then **delete** the child grant via `deleteRelationshipSubject`
   and assert access is revoked on every node.

## Data flow

```
defradb provider / wallet
  → setRelationshipSubject(policyId, resource, objectId, relation,
                           subjectKind, subjectResource, subjectObjectId, subjectRelation)
  → precompile decode_subject(...) → acp::Subject
  → PolicyCmd::SetRelationship(Relationship::new(resource, objectId, relation, subject))
  → AcpModule::cmd_set_relationship: auth check → rel.validate(&policy) [floor] → store
  → QmdbZanzibarStore relationship/{policy}/{storage_key}  (replicated)
  → later: check_permission → PermissionEngine::check_blocking resolves TTU
```

## Testing

- **Unit (hub-modules):** `decode_subject` for each kind incl. rejects; floor
  rejects a subject that violates a relation's `subject_restriction`; floor
  rejects an EntitySet referencing an undeclared resource/relation; entity path
  still passes the floor when unrestricted.
- **Unit (hub-client):** `RelationshipSubject` → ABI field round-trip per kind.
- **e2e:** set object-edge + userset via tx → resolve (read-only access check
  inherits across the edge) → delete child grant → access revoked, on every
  node of a 4-node cluster.

## Resolved decisions (approved)

- **Struct fields + `subjectKind` (0–3)** — locked. This is the emit contract for
  defradb's provider.
- **Entity DID in `subjectObjectId`** — approved.
- **Floor on store, not delete** — approved.
- **Floor gated to declared relations (Go-compat, #1060)** — required change;
  hub now accepts undeclared relations like defradb.
- **New event types** (`RelationshipSubject{Set,Deleted}`), existing events
  untouched — position-decoded events break on appended fields; provider keeps
  the entity-only method+event for actor grants.
- **`TypedWildcard` (kind 4)** — not needed near-term; reserved, decoding rejects.

## Notes

- Determinism unchanged: the new path only constructs a different `Subject`;
  storage, replication, and `check_blocking` resolution are unchanged.
- The Go-compat gating affects both the existing entity path and the new
  structured path (both flow through `cmd_set_relationship`), so accept/reject
  parity with defradb holds uniformly.
