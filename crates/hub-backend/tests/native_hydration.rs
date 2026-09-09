//! Raw-record hydration across activity changes and physical log pruning.

use commonware_glue::stateful::db::DatabaseSet as _;
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_storage::{
    merkle::Location,
    qmdb::sync::{Request, Source as _},
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use hub_backend::native::{self, NativeStateSet};
use hub_modules::{ModuleState, kv_store::InMemoryKvStore, module_state::ModuleChanges};
use std::collections::BTreeMap;

fn expected(records: &[BTreeMap<Vec<u8>, Vec<u8>>; 4]) -> [Vec<u8>; 4] {
    ModuleState::from_stores(std::array::from_fn(|i| {
        InMemoryKvStore::from_pairs(
            records[i]
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        )
    }))
    .serialize_stores()
}

#[test]
fn hydration_ignores_inactive_records_after_prune_delete_and_rewind() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::Config::new().with_storage_directory(directory.path());
    let (records, target) = tokio::Runner::new(runtime.clone()).start(|context| async move {
        let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
        let set = NativeStateSet::init(
            context.child("native"),
            native::state_config("hydrate", cache),
        )
        .await;
        let mut records: [BTreeMap<Vec<u8>, Vec<u8>>; 4] = std::array::from_fn(|_| BTreeMap::new());
        assert_eq!(
            native::load_modules(&set).await.unwrap().serialize_stores(),
            expected(&records)
        );
        for revision in 0..8 {
            let changes: ModuleChanges = std::array::from_fn(|module| {
                (0u16..256)
                    .map(|index| {
                        let mut key = vec![b'x'; native::INDEX_PREFIX_BYTES];
                        key.extend_from_slice(&index.to_be_bytes());
                        let value = if revision > 0 && index % 4 == 0 {
                            records[module].remove(&key);
                            None
                        } else {
                            let value = vec![revision ^ u8::try_from(module).unwrap(); 64];
                            records[module].insert(key.clone(), value.clone());
                            Some(value)
                        };
                        (key, value)
                    })
                    .collect()
            });
            let batch = native::prepare(set.new_batches().await, changes)
                .await
                .unwrap();
            set.apply(batch).await;
            assert!(set.finalize().await.durable().await);
        }
        let target = set.committed_targets().await;
        set.prune(&target).await;
        for (db, target) in [
            (&set.0, &target.0),
            (&set.1, &target.1),
            (&set.2, &target.2),
            (&set.3, &target.3),
        ] {
            assert!(*target.range.start() > 0);
            assert!(
                db.serve(Request::Operations {
                    size: target.range.end(),
                    start: Location::new(0),
                    max_ops: NZU64!(1)
                })
                .await
                .is_err()
            );
        }
        assert_eq!(
            native::load_modules(&set).await.unwrap().serialize_stores(),
            expected(&records)
        );

        let deletions =
            std::array::from_fn(|i| records[i].keys().cloned().map(|key| (key, None)).collect());
        let batch = native::prepare(set.new_batches().await, deletions)
            .await
            .unwrap();
        set.apply(batch).await;
        assert!(set.finalize().await.durable().await);
        assert_eq!(
            native::load_modules(&set).await.unwrap().serialize_stores(),
            ModuleState::default().serialize_stores()
        );
        set.rewind_to_targets(target.clone()).await;
        assert_eq!(
            native::load_modules(&set).await.unwrap().serialize_stores(),
            expected(&records)
        );
        (records, target)
    });
    tokio::Runner::new(runtime).start(|context| async move {
        let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
        let set = NativeStateSet::init(
            context.child("native"),
            native::state_config("hydrate", cache),
        )
        .await;
        assert_eq!(set.committed_targets().await, target);
        assert_eq!(
            native::load_modules(&set).await.unwrap().serialize_stores(),
            expected(&records)
        );
    });
}

#[test]
fn hydration_rejects_orphaned_token_indexes() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = tokio::Config::new().with_storage_directory(directory.path());
    tokio::Runner::new(runtime).start(|context| async move {
        let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
        let set = NativeStateSet::init(
            context.child("native"),
            native::state_config("token-index", cache),
        )
        .await;
        let key = hub_modules::hub::keys::jws_token_by_did_key("did:key:issuer", "missing");
        let mut changes: ModuleChanges = std::array::from_fn(|_| Vec::new());
        changes[2].push((key, Some(vec![1])));
        let batch = native::prepare(set.new_batches().await, changes).await.unwrap();
        set.apply(batch).await;
        assert!(set.finalize().await.durable().await);
        assert!(matches!(
            native::load_modules(&set).await,
            Err(hub_backend::BackendError::Storage(message)) if message.contains("token index has no record")
        ));
    });
}
