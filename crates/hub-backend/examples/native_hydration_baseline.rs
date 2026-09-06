//! Compare buffered and streamed query-map loading in separate processes.
//! Usage: native_hydration_baseline <init|buffered|streamed> <directory> <records> <value-bytes>
//! Run `init` once in an empty directory, then measure each loading mode externally.

use commonware_cryptography::{Hasher as _, Sha256};
use commonware_glue::stateful::db::{DatabaseSet as _, Shared};
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_utils::{NZU16, NZUsize};
use futures::{StreamExt as _, pin_mut};
use hub_backend::native::{self, NativeDb, NativeStateSet};
use hub_modules::{ModuleState, kv_store::InMemoryKvStore};
use std::{hint::black_box, path::PathBuf, time::Instant};

fn main() {
    let [_, mode, directory, records, value_bytes]: [String; 5] = std::env::args()
        .collect::<Vec<_>>()
        .try_into()
        .expect("expected mode, directory, records per namespace and value bytes");
    assert!(matches!(mode.as_str(), "init" | "buffered" | "streamed"));
    let records: usize = records.parse().expect("invalid record count");
    let value_bytes: usize = value_bytes.parse().expect("invalid value size");
    assert!(records > 0 && value_bytes > 0 && value_bytes <= native::MAX_VALUE_BYTES);
    let directory = PathBuf::from(directory);
    if mode == "init" {
        std::fs::create_dir_all(&directory).unwrap();
        assert!(
            std::fs::read_dir(&directory).unwrap().next().is_none(),
            "init requires an empty directory"
        );
    } else {
        assert!(directory.is_dir(), "initialize the fixture first");
    }
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory)).start(|context| async move {
        let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
        let set = NativeStateSet::init(context.child("native"), native::state_config("hydration", cache)).await;
        if mode == "init" {
            for start in (0..records).step_by(1024) {
                let changes = std::array::from_fn(|module| {
                    (start..records.min(start + 1024)).map(|i| {
                        (format!("record/{i:012}").into_bytes(), Some(vec![u8::try_from(module).unwrap(); value_bytes]))
                    }).collect()
                });
                let batch = native::prepare(set.new_batches().await, changes).await.unwrap();
                set.apply(batch).await;
                assert!(set.finalize().await.durable().await);
            }
            return;
        }
        let start = Instant::now();
        let modules = if mode == "streamed" {
            native::load_modules(&set).await.unwrap()
        } else {
            let (acp, bulletin, hub, nonces) = futures::join!(
                buffered(&set.0), buffered(&set.1), buffered(&set.2), buffered(&set.3),
            );
            ModuleState::from_stores([acp, bulletin, hub, nonces])
        };
        let load_ms = start.elapsed().as_secs_f64() * 1000.0;
        let mut hash = Sha256::default();
        let mut total_records = 0;
        let mut total_value_bytes = 0;
        for (module, store) in [modules.acp.store(), modules.bulletin.store(), modules.hub.store(), modules.nonces.store()].into_iter().enumerate() {
            assert!(store.dirty_entries().is_empty());
            hash.update(&[u8::try_from(module).unwrap()]);
            for (key, value) in store.prefix_iter(b"") {
                hash.update(&(key.len() as u64).to_le_bytes());
                hash.update(key);
                hash.update(&(value.len() as u64).to_le_bytes());
                hash.update(value);
                total_records += 1;
                total_value_bytes += value.len();
            }
        }
        assert_eq!(total_records, records * 4);
        assert_eq!(total_value_bytes, records * value_bytes * 4);
        println!("mode,records_per_namespace,value_bytes,load_ms,total_records,total_value_bytes,digest");
        println!("{mode},{records},{value_bytes},{load_ms:.6},{total_records},{total_value_bytes},{}", hash.finalize().1);
        black_box(&modules);
    });
}

async fn buffered(db: &Shared<NativeDb>) -> InMemoryKvStore {
    let db = db.read().await;
    let records = db.stream_range(Vec::new()).await.unwrap();
    pin_mut!(records);
    let mut values = Vec::new();
    while let Some(record) = records.next().await {
        let (key, value) = record.unwrap();
        values.push((key, value.to_vec()));
    }
    InMemoryKvStore::from_pairs(values)
}
