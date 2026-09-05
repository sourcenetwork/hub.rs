//! Ordered Commonware proof and recovery qualification with local component timings.
//! Timings exclude consensus and transport.

#[cfg(test)]
#[path = "ordered_prefix/lifecycle.rs"]
mod lifecycle;
#[path = "ordered_prefix/proof.rs"]
mod proof;
#[cfg(test)]
#[path = "ordered_prefix/tests.rs"]
mod tests;

use bytes::Bytes;
use commonware_codec::RangeCfg;
use commonware_cryptography::{Hasher as _, Sha256};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, buffer::paged::CacheRef, tokio};
use commonware_storage::{
    journal::contiguous::variable, merkle::full, qmdb::current::VariableConfig,
    translator::EightCap,
};
use commonware_utils::{NZU16, NZU64, NZUsize};
use proof::Store;
use std::{hint::black_box, time::Instant};

type LogCodec = ((RangeCfg<usize>, ()), RangeCfg<usize>);

fn config(context: &tokio::Context) -> VariableConfig<EightCap, LogCodec, Sequential> {
    let cache = CacheRef::from_pooler(context, NZU16!(4096), NZUsize!(1024));
    VariableConfig {
        merkle_config: full::Config {
            journal_partition: "prefix-mmr".into(),
            metadata_partition: "prefix-mmr-meta".into(),
            items_per_blob: NZU64!(1024),
            write_buffer: NZUsize!(1 << 20),
            replay_buffer: NZUsize!(1 << 20),
            strategy: Sequential,
            page_cache: cache.clone(),
        },
        journal_config: variable::Config {
            partition: "prefix-log".into(),
            items_per_section: NZU64!(1024),
            compression: None,
            codec_config: ((RangeCfg::new(0..=1024), ()), RangeCfg::new(0..=65536)),
            page_cache: cache,
            write_buffer: NZUsize!(1 << 20),
            replay_buffer: NZUsize!(1 << 20),
        },
        grafted_metadata_partition: "prefix-graft".into(),
        translator: EightCap,
        init_cache_size: Some(NZUsize!(1024)),
        init_buffer: NZUsize!(1 << 21),
        init_concurrency: (),
    }
}

fn run<F, Fut>(f: F) -> Fut::Output
where
    F: FnOnce(tokio::Context) -> Fut,
    Fut: std::future::Future,
{
    let dir = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(dir.path())).start(f)
}

fn prefix(object: usize, grouped: bool) -> Vec<u8> {
    let text = format!("relationship/policy/rel/document/{object:08}/blocked/");
    if grouped {
        Sha256::hash(&[text.as_bytes()]).to_vec()
    } else {
        text.into_bytes()
    }
}

fn key(object: usize, subject: usize, grouped: bool) -> Vec<u8> {
    let mut key = prefix(object, grouped);
    key.extend_from_slice(format!("{subject:08}").as_bytes());
    key
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert!(
        args.len() <= 3,
        "usage: ordered_prefix_baseline [other_objects] [samples] [text|grouped]"
    );
    let parse = |i: usize, default| args.get(i).map_or(default, |v| v.parse::<usize>().unwrap());
    let objects = parse(0, 1000);
    let samples = parse(1, 100);
    let layout = args.get(2).map_or("grouped", String::as_str);
    assert!(matches!(layout, "text" | "grouped"));
    let grouped = layout == "grouped";
    assert!((1..=100_000).contains(&objects) && (1..=10_000).contains(&samples));
    run(|context| async move {
        let cfg = config(&context);
        let mut db = Store::init(context, cfg).await.unwrap();
        let value = Bytes::from(vec![7; 256]);
        for start in (1..=objects).step_by(128) {
            let mut batch = db.new_batch();
            for object in start..=(start + 127).min(objects) {
                batch = batch.write(key(object, 0, grouped), Some(value.clone()));
            }
            let batch = batch.merkleize(&db, None).await.unwrap();
            (db, _) = db.apply_batch(batch).await.unwrap();
            db = db.commit().await.unwrap();
        }
        let prefix = prefix(0, grouped);
        println!(
            "layout,other_objects,samples,subjects,proof_component_bytes,generate_p50_ns,generate_p95_ns,verify_p50_ns,verify_p95_ns"
        );
        let mut previous = 0;
        for subjects in [0, 1, 8, 64, 256] {
            if subjects > previous {
                let mut batch = db.new_batch();
                for subject in previous..subjects {
                    batch = batch.write(key(0, subject, grouped), Some(value.clone()));
                }
                let batch = batch.merkleize(&db, None).await.unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.commit().await.unwrap();
            }
            previous = subjects;
            let mut generate = Vec::with_capacity(samples);
            let mut verify = Vec::with_capacity(samples);
            let mut proof_bytes = 0;
            for _ in 0..samples {
                let start = Instant::now();
                let witness = proof::prove(&db, &prefix).await.unwrap();
                generate.push(start.elapsed().as_nanos());
                assert_eq!(witness.entries.len(), subjects);
                proof_bytes = witness.component_bytes();
                let start = Instant::now();
                assert!(black_box(&witness).verify(black_box(&prefix), black_box(&db.root())));
                verify.push(start.elapsed().as_nanos());
            }
            generate.sort_unstable();
            verify.sort_unstable();
            let p50 = (samples * 50).div_ceil(100) - 1;
            let p95 = (samples * 95).div_ceil(100) - 1;
            println!(
                "{layout},{objects},{samples},{subjects},{proof_bytes},{},{},{},{}",
                generate[p50], generate[p95], verify[p50], verify[p95]
            );
        }
    });
}
