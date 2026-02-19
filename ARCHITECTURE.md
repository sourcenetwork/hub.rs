# hub.rs Architecture

Rust rewrite of [sourcenetwork/sourcehub](https://github.com/sourcenetwork/sourcehub) on [Commonware](https://github.com/commonwarexyz/monorepo) consensus with EVM execution.

## Why Rewrite

SourceHub is a Cosmos SDK (Go) chain providing ACP, Bulletin, and Hub modules for the Source Network stack. The rewrite addresses three structural problems:

1. **BLS identity gap.** Orbis rings produce BLS12-381 threshold keys. Cosmos SDK transactions require secp256k1 signatures. There is no native path for a BLS DID to sign a SourceHub transaction. The current workaround is a pre-funded test account creating policies on behalf of BLS identities.

2. **Language boundary.** Orbis (Rust) talks to SourceHub (Go) over gRPC. The crypto primitives (BLS12-381, threshold DKG) exist in both languages with different implementations. A single Rust stack eliminates FFI, aligns crypto libraries, and enables shared types.

3. **Performance.** Commonware Simplex achieves 2-hop block times with BLS12-381 threshold signatures. CometBFT (Tendermint) requires multiple rounds. For a trust layer that sits in the critical path of every document write, latency matters.

## Stack

```
Commonware Simplex consensus (BLS12-381 threshold)
    |
    v
hub.rs Application (implements commonware Application trait)
    |
    +-- Native tx executor (BLS-signed SourceHub operations)
    |       |
    |       +-- ACP module
    |       +-- Bulletin module
    |       +-- Hub module
    |
    +-- EVM tx executor (secp256k1-signed, via REVM)
            |
            +-- Standard EVM execution
            +-- Precompiles (read/write into module state)
            +-- ERC20/ERC721 tokens, bridges, DeFi
```

## Dual Transaction Model

Blocks contain two kinds of transactions:

```rust
struct HubBlock {
    native_txs: Vec<NativeTx>,   // BLS-signed, processed first
    evm_txs: Vec<Bytes>,         // secp256k1-signed, standard Ethereum
    native_state_root: H256,
    evm_state_root: H256,
}
```

**Native transactions** are BLS-signed operations targeting SourceHub modules directly. No relayer, no wrapper, no meta-transaction. The BLS signature is verified natively in Rust. This is how Orbis ring identities interact with the chain.

**EVM transactions** are standard Ethereum transactions (RLP-encoded, secp256k1-signed). They execute in REVM against EVM state. Smart contracts, token transfers, bridge operations, and DeFi composability live here.

Both transaction types execute against shared state within the same block. Native txs execute first (deterministic ordering), then EVM txs.

### RPC Surfaces

| Endpoint | Transport | Signing | Use |
|----------|-----------|---------|-----|
| `eth_sendRawTransaction` | JSON-RPC | secp256k1 | MetaMask, wallets, standard tooling |
| `hub_sendNativeTx` | gRPC / JSON-RPC | BLS12-381 | Orbis, cli-tool, BLS identities |

## Module-to-Precompile Mapping

Each SourceHub module maps to a precompile contract with its own address and state. The module implementation is shared between native tx execution and EVM precompile execution.

### Architecture

```
Native BLS tx --> deserialize --> module.method(args)
                                        ^
                                   same Rust code
                                        v
EVM CALL 0x08xx --> ABI decode --> module.method(args)
```

The precompile is a thin ABI-decoding shim. The native tx path is a thin BLS-verify + deserialize shim. All business logic lives once in the module implementation.

### ACP Module (0x0810)

Access Control Policies. The core authorization primitive.

**Write methods (Cosmos Msg -> Solidity function):**

| Cosmos SDK Message | Precompile Method | Native Tx Op |
|---|---|---|
| `MsgCreatePolicy` | `createPolicy(bytes yaml) -> bytes32 policyId` | `CreatePolicy { yaml }` |
| `MsgEditPolicy` | `editPolicy(bytes32 policyId, bytes yaml)` | `EditPolicy { policy_id, yaml }` |
| `MsgDirectPolicyCmd` | `setRelationship(bytes32 policyId, string resource, string objectId, string relation, string actor)` | `SetRelationship { ... }` |
| `MsgDirectPolicyCmd` | `deleteRelationship(...)` | `DeleteRelationship { ... }` |
| `MsgDirectPolicyCmd` | `registerObject(bytes32 policyId, string objectId, string resource)` | `RegisterObject { ... }` |

**Read methods (Cosmos Query -> Solidity view function):**

| Cosmos SDK Query | Precompile View | Returns |
|---|---|---|
| `QueryCheckAccess` | `checkAccess(bytes32 policyId, string resource, string objectId, string permission, string actor) -> bool` | Whether actor has permission |
| `QueryPolicy` | `getPolicy(bytes32 policyId) -> bytes` | Policy definition |
| `QueryFilterRelationships` | `hasRelationship(bytes32 policyId, string resource, string objectId, string relation, string actor) -> bool` | Direct relationship check |

**Solidity interface:**

```solidity
interface IACP {
    function createPolicy(bytes calldata yaml) external returns (bytes32 policyId);
    function setRelationship(
        bytes32 policyId, string resource, string objectId,
        string relation, string actor
    ) external;
    function deleteRelationship(
        bytes32 policyId, string resource, string objectId,
        string relation, string actor
    ) external;
    function registerObject(
        bytes32 policyId, string objectId, string resource
    ) external;
    function checkAccess(
        bytes32 policyId, string resource, string objectId,
        string permission, string actor
    ) external view returns (bool);
    function hasRelationship(
        bytes32 policyId, string resource, string objectId,
        string relation, string actor
    ) external view returns (bool);
}
```

### Bulletin Module (0x0811)

Coordination layer for DKG messages, ring payloads, and inter-node communication.

| Cosmos SDK Message | Precompile Method |
|---|---|
| `MsgRegisterNamespace` | `registerNamespace(string namespace)` |
| `MsgAddCollaborator` | `addCollaborator(string namespace, address collaborator)` |
| `MsgRemoveCollaborator` | `removeCollaborator(string namespace, address collaborator)` |
| `MsgCreatePost` | `createPost(string namespace, bytes payload, bytes proof) -> bytes32 postId` |
| `QueryPost` | `getPost(string namespace, bytes32 postId) -> bytes` (view) |

### Hub Module (0x0812)

Identity and JWS token lifecycle management.

| Cosmos SDK Message | Precompile Method |
|---|---|
| `MsgInvalidateJWS` | `invalidateJWS(bytes32 tokenId)` |
| `QueryJWSToken` | `getJWSToken(bytes32 tokenId) -> (bool valid, uint64 issuedAt, uint64 expiresAt)` (view) |

### Standard Precompiles

| Address | Precompile | Source |
|---------|-----------|--------|
| `0x01-0x0a` | Ethereum L1 precompiles | REVM built-in |
| `0x0b-0x13` | BLS12-381 curve ops (EIP-2537) | REVM (if available) or custom |
| `0x0800` | IBC | bankd pattern (if IBC needed) |
| `0x0810` | ACP | hub.rs |
| `0x0811` | Bulletin | hub.rs |
| `0x0812` | Hub | hub.rs |

## Module Implementation Pattern

Each module follows the same structure:

```rust
/// ACP module — shared implementation for native tx and EVM precompile paths.
pub struct AcpModule {
    state: AcpStateTree,  // Merkle-ized state
}

impl AcpModule {
    /// Create a new ACP policy. Called by both native tx executor and precompile.
    pub fn create_policy(&mut self, yaml: &[u8]) -> Result<PolicyId> { ... }

    /// Check access. Pure read — no state mutation.
    pub fn check_access(&self, req: &AccessCheckRequest) -> Result<bool> { ... }

    /// Set a relationship (grant).
    pub fn set_relationship(&mut self, req: &SetRelationshipRequest) -> Result<()> { ... }

    /// Delete a relationship (revoke).
    pub fn delete_relationship(&mut self, req: &DeleteRelationshipRequest) -> Result<()> { ... }

    /// Register an object under a policy.
    pub fn register_object(&mut self, req: &RegisterObjectRequest) -> Result<()> { ... }
}
```

The precompile shim:

```rust
/// ACP precompile at 0x0810.
pub fn execute_acp(state: &mut AcpModule, input: &[u8], gas_limit: u64) -> PrecompileResult {
    let selector = &input[..4];
    match selector {
        CREATE_POLICY_SELECTOR => {
            let yaml = abi_decode_bytes(&input[4..])?;
            let policy_id = state.create_policy(&yaml)?;
            Ok(abi_encode_bytes32(policy_id))
        }
        CHECK_ACCESS_SELECTOR => {
            let req = abi_decode_check_access(&input[4..])?;
            let allowed = state.check_access(&req)?;
            Ok(abi_encode_bool(allowed))
        }
        // ...
    }
}
```

The native tx shim:

```rust
/// Execute a BLS-signed native transaction.
pub fn execute_native_tx(modules: &mut Modules, tx: &NativeTx) -> Result<()> {
    // 1. Verify BLS signature
    verify_bls_signature(&tx.bls_pubkey, &tx.payload, &tx.signature)?;

    // 2. Dispatch to module
    match tx.op {
        NativeOp::Acp(AcpOp::CreatePolicy { ref yaml }) => {
            modules.acp.create_policy(yaml)?;
        }
        NativeOp::Acp(AcpOp::SetRelationship(ref req)) => {
            modules.acp.set_relationship(req)?;
        }
        NativeOp::Bulletin(BulletinOp::CreatePost { .. }) => { ... }
        // ...
    }
    Ok(())
}
```

## Commonware Integration

### Application Trait

hub.rs implements Commonware's `Application` trait:

```rust
impl Application<E> for HubApp {
    type SigningScheme = bls12381_threshold::vrf::Scheme<ed25519::PublicKey, MinSig>;
    type Context = HubConsensusContext;
    type Block = HubBlock;

    async fn genesis(&mut self) -> Self::Block {
        // Initialize module state trees
        // Deploy system contracts (ERC20 for uopen/ucredit)
        // Return genesis block
    }

    async fn propose(&mut self, ctx: (E, Self::Context), ancestry: AncestorStream) -> Option<Self::Block> {
        // 1. Drain native tx mempool
        let native_txs = self.native_mempool.drain();
        for tx in &native_txs {
            execute_native_tx(&mut self.modules, tx)?;
        }

        // 2. Drain EVM tx mempool
        let evm_txs = self.evm_mempool.drain();
        let evm_result = self.revm_executor.execute(&evm_txs)?;

        // 3. Compute state roots
        Some(HubBlock { native_txs, evm_txs, .. })
    }
}

impl VerifyingApplication<E> for HubApp {
    async fn verify(&mut self, ctx: (E, Self::Context), ancestry: AncestorStream) -> bool {
        // Re-execute all txs, verify state roots match
    }
}
```

### Consensus Configuration

- **Consensus:** Commonware Simplex (BLS12-381 threshold, 2-hop finality)
- **Validator identity:** ed25519 (same as bankd)
- **Block signing:** BLS12-381 MinSig threshold
- **VRF:** Built into Simplex for leader election
- **Epoch management:** Configurable (start with static validator set)

## Token Model

SourceHub has two tokens (`uopen`, `ucredit`). In hub.rs these are ERC20 contracts deployed at genesis:

| Token | Address | Purpose |
|-------|---------|---------|
| `OPEN` | `0x...` (genesis) | Base fee token, staking |
| `CREDIT` | `0x...` (genesis) | Premium operations |

Native txs pay fees in OPEN (deducted from BLS-identity-linked balance). EVM txs pay fees via standard `gasPrice * gasUsed`.

Fee grant functionality (SourceHub's `x/feegrant`) is implemented as a system contract or precompile that allows one account to sponsor another's gas.

## State Model

Each module maintains a Merkle-ized state tree. State roots are committed per-block.

```
Block state commitment:
    evm_state_root:    QMDB/MPT root (EVM account + storage state)
    native_state_root: Combined root of module state trees
        acp_root:      ACP policies, relationships, objects
        bulletin_root: Namespaces, collaborators, posts
        hub_root:      JWS tokens, invalidation records
```

## Implementation Plan

### Phase 1: Fork bankd, strip to skeleton

Copy the bankd-commonware codebase into hub.rs. Remove bankd-specific logic (IBC host, CBDC mint, EEM, bankd-specific JSON-RPC) while preserving:

- Commonware Simplex consensus integration
- REVM executor and precompile framework
- Block production / verification pipeline
- e2e test framework structure
- P2P networking, storage, ledger

Result: a running chain that produces empty blocks with EVM execution, precompile plumbing in place, and a working test harness. No SourceHub modules yet.

### Phase 2: Exhaustive module audit + stub generation

For each SourceHub module (ACP, Bulletin, Hub, Epochs, Tier, FeeGrant), perform a dedicated session:

1. **Enumerate every Msg and Query** from the Go protobuf definitions and keeper implementations
2. **Create Rust stubs** for every message handler and query handler — the full usable surface area of the module as it exists on the Cosmos chain
3. **Identify all state** the module holds — what KV pairs, what indexes, what relationships between stored objects
4. **Build data models** on the hub.rs side for the module's state

Each module gets a Rust file with stub methods that compile but panic with `todo!()`. The stubs define the complete API surface.

```rust
// Example: ACP module stubs after Phase 2
impl AcpModule {
    pub fn create_policy(&mut self, yaml: &[u8]) -> Result<PolicyId> { todo!() }
    pub fn edit_policy(&mut self, policy_id: &PolicyId, yaml: &[u8]) -> Result<()> { todo!() }
    pub fn set_relationship(&mut self, req: &SetRelationshipRequest) -> Result<()> { todo!() }
    pub fn delete_relationship(&mut self, req: &DeleteRelationshipRequest) -> Result<()> { todo!() }
    pub fn register_object(&mut self, req: &RegisterObjectRequest) -> Result<()> { todo!() }
    pub fn unregister_object(&mut self, req: &UnregisterObjectRequest) -> Result<()> { todo!() }
    pub fn check_access(&self, req: &AccessCheckRequest) -> Result<bool> { todo!() }
    pub fn get_policy(&self, policy_id: &PolicyId) -> Result<Policy> { todo!() }
    pub fn filter_relationships(&self, req: &FilterRequest) -> Result<Vec<Relationship>> { todo!() }
    // ... every Msg and Query from x/acp
}
```

### Phase 3: Annotate stubs with specifications

Go method by method through every stub and write plain English (or pseudocode) descriptions:

- What the method does
- What state it reads
- What state it modifies
- What validation it performs
- What events it emits
- Edge cases and error conditions

```rust
impl AcpModule {
    /// Create a new ACP policy from YAML definition.
    ///
    /// State read: none (policy ID is hash of content)
    /// State write: policies[policy_id] = parsed policy
    /// Validation:
    ///   - YAML must parse as valid policy (name, resources, relations, permissions)
    ///   - Resource names must be unique within policy
    ///   - Relation types must reference valid actor types
    ///   - Permission expressions must reference defined relations
    /// Returns: policy_id (SHA256 of canonical policy bytes)
    /// Events: PolicyCreated { policy_id, name }
    pub fn create_policy(&mut self, yaml: &[u8]) -> Result<PolicyId> { todo!() }
}
```

### Phase 4: Wire precompiles + native tx path

With stubs and data models in place:

1. Wire each module's stubs into precompile shims (ABI decode -> stub call)
2. Wire each module's stubs into native BLS tx dispatch
3. Deploy precompile contracts at genesis
4. Add `hub_sendNativeTx` RPC endpoint

Result: chain runs, accepts both EVM and native txs, dispatches to stubs. Everything returns `todo!()` panics but the full pipeline is exercised.

### Phase 5: Integration test framework

Build e2e tests that exercise the full pipeline:

- Start chain (single validator devnet)
- Submit native BLS tx (create policy) -> verify stub is reached
- Submit EVM tx calling precompile (check access) -> verify stub is reached
- Orbis connects and submits ACP operations via native txs

Tests pass once stubs are wired. Tests fail with `todo!()` panics, which is correct — each panic becomes a concrete implementation task.

### Phase 6: Implement stubs

With the full surface area visible, annotated, and testable:

- Implement one method at a time
- Each implementation replaces a `todo!()` with real logic
- Integration tests go from panicking to passing
- Port acp_core evaluation engine for policy checking
- Priority: ACP module first (critical path for Orbis), then Bulletin, then Hub

### Phase 7: Production hardening

- Orbis e2e test passes without "test account creates policies" workaround
- Token economics (OPEN/CREDIT as ERC20s at genesis — EVM layer provides this)
- Validator set management / staking (may need tokens from EVM layer)

### Out of scope (for now)

- IBC precompile / bridge infrastructure — way off, revisit when there's a concrete cross-chain need

## Reference Implementations

| Component | Reference | Location |
|-----------|-----------|----------|
| Commonware Application | bankd-commonware | `mizufinance/bankd-commonware/crates/bankd-runner/src/app.rs` |
| REVM executor | bankd-commonware | `mizufinance/bankd-commonware/crates/bankd-executor/` |
| Precompile pattern | bankd IBC precompile | `mizufinance/bankd-commonware/crates/bankd-executor/src/precompiles/` |
| BLS12-381 threshold | Commonware monorepo | `commonwarexyz/monorepo/cryptography/src/bls12381/` |
| Simplex consensus | Commonware monorepo | `commonwarexyz/monorepo/consensus/src/simplex/` |
| ACP evaluation | sourcehub (Go) | `sourcenetwork/sourcehub/x/acp/` |
| Bulletin board | sourcehub (Go) | `sourcenetwork/sourcehub/x/bulletin/` |

## Crate Structure (Planned)

```
hub.rs/
    bin/hubd/                  # CLI binary (devnet, testnet, validator)
    crates/
        hub-app/               # Application trait impl, block executor
        hub-modules/           # ACP, Bulletin, Hub module implementations
        hub-precompiles/       # EVM precompile shims (ABI decode -> module calls)
        hub-native/            # Native BLS tx format, verification, dispatch
        hub-domain/            # Block, tx, state root types
        hub-consensus/         # Simplex integration, scheme config
        hub-state/             # State tree management (per-module Merkle trees)
        hub-jsonrpc/           # eth_* + hub_* JSON-RPC methods
        hub-e2e/               # Integration test framework
```
