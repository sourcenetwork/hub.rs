//! Native module deltas through Commonware's pending, durable and recovery lifecycle.

#![recursion_limit = "256"]

use commonware_glue::stateful::db::DatabaseSet;
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_utils::{NZU16, NZUsize};
use hub_backend::{
    BackendError,
    native::{self, NativeDb, NativeStateSet},
};
use hub_modules::{
    ModuleState,
    acp::{
        keys,
        types::{AccessRequest, Actor, Object, Operation, PolicyCmd, PolicyMarshalingType},
    },
    hub::types::ChainConfig,
    kv_store::{InMemoryKvStore, ModuleKvStore},
    module_state::{ModuleChanges, combine_module_roots},
    types::{BlockExecCtx, TxExecCtx},
};
use zanzibar::{Relationship, Subject};

const OWNER: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
const READER: &str = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
const POLICY: &str = "\
name: documents
resources:
  - name: document
    relations:
      - name: reader
        types: [actor]
      - name: blocked
    permissions:
      - name: read
        expr: reader - blocked
";

async fn open(context: &tokio::Context) -> NativeStateSet {
    let cache = CacheRef::from_pooler(context, NZU16!(4084), NZUsize!(64));
    NativeStateSet::init(context.child("native"), native::state_config("test", cache)).await
}

async fn root(set: &NativeStateSet) -> alloy_primitives::B256 {
    combine_module_roots(&[
        set.0.read().await.root().0,
        set.1.read().await.root().0,
        set.2.read().await.root().0,
        set.3.read().await.root().0,
    ])
}

fn can_read(modules: &ModuleState, policy: &str) -> bool {
    modules
        .acp
        .query_verify_access_request(
            policy,
            &AccessRequest {
                actor: Actor(READER.parse().unwrap()),
                operations: vec![Operation {
                    object: Object {
                        resource: "document".into(),
                        id: "report".into(),
                    },
                    permission: "read".into(),
                }],
            },
        )
        .unwrap()
}

#[test]
fn authorization_survives_forks_restart_and_rewind() {
    let directory = tempfile::tempdir().unwrap();
    let config = tokio::Config::new().with_storage_directory(directory.path());
    let (first_state, first_root, first_target, second_state, second_root, policy) =
        tokio::Runner::new(config.clone()).start(|context| async move {
            let set = open(&context).await;
            let empty = ModuleState::default();
            let mut first_state = empty.clone();
            let owner = OWNER.parse().unwrap();
            let policy = first_state
                .acp
                .create_policy(&owner, POLICY, PolicyMarshalingType::ShortYaml)
                .unwrap()
                .policy
                .id;
            let blocked = Relationship::new(
                "document",
                "report",
                "blocked",
                Subject::typed_wildcard("document"),
            );
            for relationship in [
                Relationship::with_entity("document", "report", "reader", READER.parse().unwrap()),
                blocked.clone(),
            ] {
                first_state
                    .acp
                    .direct_policy_cmd(&owner, &policy, PolicyCmd::SetRelationship(relationship))
                    .unwrap();
            }
            first_state
                .bulletin
                .register_namespace(
                    &mut first_state.acp,
                    &BlockExecCtx::default(),
                    &TxExecCtx {
                        sequence: 0,
                        tx_hash: vec![1; 32],
                        signer: OWNER.into(),
                    },
                    &owner,
                    "reports",
                )
                .unwrap();
            first_state
                .hub
                .set_chain_config(ChainConfig {
                    allow_zero_fee_txs: true,
                    ignore_bearer_auth: false,
                })
                .unwrap();
            first_state.nonces.check_and_increment(OWNER, 0).unwrap();
            // Clone resets dirty tracking; the delta must still include the policy and namespace.
            let first_state = first_state.clone();
            let first = native::prepare(set.new_batches().await, first_state.diff_from(&empty))
                .await
                .unwrap();
            let first_root = native::state_root(&first);

            let mut second_state = first_state.clone();
            second_state
                .acp
                .direct_policy_cmd(&owner, &policy, PolicyCmd::DeleteRelationship(blocked))
                .unwrap();
            second_state.nonces.check_and_increment(OWNER, 1).unwrap();
            let second = native::prepare(
                NativeStateSet::fork_batches(&first),
                second_state.diff_from(&first_state),
            )
            .await
            .unwrap();
            let second_root = native::state_root(&second);
            let mut rejected_state = first_state.clone();
            rejected_state
                .nonces
                .check_and_increment(READER, 0)
                .unwrap();
            let rejected = native::prepare(
                NativeStateSet::fork_batches(&first),
                rejected_state.diff_from(&first_state),
            )
            .await
            .unwrap();
            assert_ne!(native::state_root(&rejected), second_root);
            assert_eq!(
                native::load_modules(&set).await.unwrap().serialize_stores(),
                empty.serialize_stores()
            );

            set.apply(first).await;
            assert!(set.finalize().await.durable().await);
            let first_target = set.committed_targets().await;
            let loaded = native::load_modules(&set).await.unwrap();
            assert_eq!(loaded.serialize_stores(), first_state.serialize_stores());
            assert!(!can_read(&loaded, &policy));
            assert_eq!(root(&set).await, first_root);

            set.apply(second).await;
            assert!(set.finalize().await.durable().await);
            drop(rejected);
            let loaded = native::load_modules(&set).await.unwrap();
            assert_eq!(loaded.serialize_stores(), second_state.serialize_stores());
            assert!(can_read(&loaded, &policy));
            assert_eq!(loaded.nonces.get_nonce(READER), 0);
            assert_eq!(root(&set).await, second_root);

            let target = set.committed_targets().await;
            let db = set.0.read().await;
            let key = keys::policy_key(&policy);
            let value = db.get(&key).await.unwrap().unwrap();
            let proof = db.key_value_proof(key.clone()).await.unwrap();
            assert!(NativeDb::verify_key_value_proof(
                key.clone(),
                value.clone(),
                &proof,
                &db.root()
            ));
            assert!(!NativeDb::verify_key_value_proof(
                key,
                value,
                &proof,
                &target.0.root
            ));
            (
                first_state,
                first_root,
                first_target,
                second_state,
                second_root,
                policy,
            )
        });

    tokio::Runner::new(config.clone()).start(|context| async move {
        let set = open(&context).await;
        let loaded = native::load_modules(&set).await.unwrap();
        assert_eq!(loaded.serialize_stores(), second_state.serialize_stores());
        assert!(can_read(&loaded, &policy));
        assert_eq!(root(&set).await, second_root);
        set.rewind_to_targets(first_target).await;
        let loaded = native::load_modules(&set).await.unwrap();
        assert_eq!(loaded.serialize_stores(), first_state.serialize_stores());
        assert!(!can_read(&loaded, &policy));
        assert_eq!(root(&set).await, first_root);
    });
    tokio::Runner::new(config).start(|context| async move {
        assert_eq!(root(&open(&context).await).await, first_root);
    });
}

#[test]
fn record_limits_and_colliding_prefixes_survive_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let config = tokio::Config::new().with_storage_directory(directory.path());
    let expected = tokio::Runner::new(config.clone()).start(|context| async move {
        let set = open(&context).await;
        let before = set.committed_targets().await;
        for module in 0..4 {
            for invalid in [
                vec![(vec![1; native::MAX_KEY_BYTES + 1], None)],
                vec![(b"key".to_vec(), Some(vec![1; native::MAX_VALUE_BYTES + 1]))],
                vec![(b"b".to_vec(), None), (b"a".to_vec(), None)],
                vec![(b"a".to_vec(), None), (b"a".to_vec(), None)],
            ] {
                let mut changes: ModuleChanges =
                    std::array::from_fn(|_| vec![(b"valid".to_vec(), Some(vec![1]))]);
                changes[module] = invalid;
                assert!(matches!(
                    native::prepare(set.new_batches().await, changes).await,
                    Err(BackendError::InvalidModuleChange(_))
                ));
                assert_eq!(set.committed_targets().await, before);
            }
        }
        let modules = ModuleState::from_stores(std::array::from_fn(|module| {
            let mut store = InMemoryKvStore::default();
            for key in [
                vec![],
                vec![0],
                vec![1; 64],
                vec![1; 65],
                vec![1; native::MAX_KEY_BYTES],
            ] {
                store.put(&key, vec![u8::try_from(module).unwrap(); 8]);
            }
            store.put(b"large-value", vec![2; native::MAX_VALUE_BYTES]);
            store
        }));
        let sealed = native::prepare(
            set.new_batches().await,
            modules.diff_from(&ModuleState::default()),
        )
        .await
        .unwrap();
        set.apply(sealed).await;
        assert!(set.finalize().await.durable().await);
        assert_eq!(
            native::load_modules(&set).await.unwrap().serialize_stores(),
            modules.serialize_stores()
        );
        modules.serialize_stores()
    });
    tokio::Runner::new(config).start(|context| async move {
        let set = open(&context).await;
        assert_eq!(
            native::load_modules(&set).await.unwrap().serialize_stores(),
            expected
        );
    });
}
