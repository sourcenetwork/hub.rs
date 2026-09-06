use super::*;
use crate::native::{MAX_KEY_BYTES, MAX_VALUE_BYTES, state_config};
use bytes::Bytes;
use commonware_codec::{Decode as _, DecodeExt as _, Encode as _};
use commonware_cryptography::{Signer as _, ed25519::PrivateKey};
use commonware_glue::stateful::db::{
    DatabaseSet as _, StateSyncDb as _, SyncEngineConfig, Unmerkleized as _,
};
use commonware_p2p::{Address, AddressableManager as _, Blocker as _, authenticated::lookup};
use commonware_runtime::{Quota, Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_storage::{
    merkle::{Location, MAX_PROOF_DIGESTS_PER_ELEMENT, Proof},
    qmdb::any::ordered::variable::Update,
};
use commonware_utils::{NZU16, NZU32, NZUsize, channel::mpsc, ordered::Map};
use std::time::Duration;

fn update(key: usize, value: usize, next_key: usize) -> Operation {
    Operation::Update(Update {
        key: vec![1; key],
        value: Bytes::from(vec![2; value]),
        next_key: vec![3; next_key],
    })
}

#[test]
fn wire_codec_bounds_every_variable_field_and_response() {
    let largest = update(MAX_KEY_BYTES, MAX_VALUE_BYTES, MAX_KEY_BYTES);
    let operations = vec![WireOperation(largest.clone()); 2];
    let response = Response::<mmr::Family, _, Digest>::Operations {
        proof: Proof {
            leaves: Location::new(2),
            inactive_peaks: 0,
            digests: vec![Digest::from([0; 32]); 2 * MAX_PROOF_DIGESTS_PER_ELEMENT],
        },
        operations,
    };
    let bytes = response.encode();
    assert!(bytes.len() < 4 * 1024 * 1024 - 1024);
    let decoded =
        Response::<mmr::Family, WireOperation, Digest>::decode_cfg(bytes.clone(), &(2, ()))
            .unwrap();
    assert_eq!(decoded.encode(), bytes);
    assert!(Response::<mmr::Family, WireOperation, Digest>::decode_cfg(bytes, &(1, ())).is_err());
    let excessive_count = Response::<mmr::Family, _, Digest>::Operations {
        proof: Proof {
            leaves: Location::new(3),
            inactive_peaks: 0,
            digests: Vec::new(),
        },
        operations: vec![WireOperation(Operation::Delete(Vec::new())); 3],
    };
    assert!(
        Response::<mmr::Family, WireOperation, Digest>::decode_cfg(
            excessive_count.encode(),
            &(2, ()),
        )
        .is_err()
    );

    for operation in [
        largest,
        Operation::Delete(vec![1; MAX_KEY_BYTES]),
        Operation::CommitFloor(
            Some(Bytes::from(vec![1; MAX_VALUE_BYTES])),
            Location::new(0),
        ),
        Operation::CommitFloor(None, Location::new(0)),
    ] {
        let bytes = operation.encode();
        assert_eq!(WireOperation::decode(bytes.clone()).unwrap().0, operation);
        assert_eq!(WireOperation(operation).encode(), bytes);
        assert!(WireOperation::decode(bytes.slice(..bytes.len() - 1)).is_err());
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(WireOperation::decode(trailing.as_slice()).is_err());
    }
    for operation in [
        update(MAX_KEY_BYTES + 1, 0, 0),
        update(0, MAX_VALUE_BYTES + 1, 0),
        update(0, 0, MAX_KEY_BYTES + 1),
        Operation::Delete(vec![1; MAX_KEY_BYTES + 1]),
        Operation::CommitFloor(
            Some(Bytes::from(vec![1; MAX_VALUE_BYTES + 1])),
            Location::new(0),
        ),
    ] {
        assert!(WireOperation::decode(operation.encode()).is_err());
    }
}

#[test]
fn peer_sync_preserves_roots_and_reports_rejected_responses() {
    let directory = tempfile::tempdir().unwrap();
    let config = tokio::Config::new().with_storage_directory(directory.path());
    tokio::Runner::new(config).start(|context| async move {
        ::tokio::time::timeout(Duration::from_secs(20), async {
            let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
            let source = Shared::<NativeDb>::init(
                context.child("source"),
                state_config("source", cache.clone()).0,
            )
            .await;
            let batch = source
                .new_batches()
                .await
                .write(
                    vec![1; MAX_KEY_BYTES],
                    Some(Bytes::from(vec![4; MAX_VALUE_BYTES])),
                )
                .write(
                    vec![2; MAX_KEY_BYTES],
                    Some(Bytes::from(vec![5; MAX_VALUE_BYTES])),
                )
                .write(b"removed".to_vec(), Some(Bytes::from_static(b"old")));
            source.apply(batch.merkleize().await.unwrap()).await;
            assert!(source.finalize().await.durable().await);
            let batch = source.new_batches().await.write(b"removed".to_vec(), None);
            source.apply(batch.merkleize().await.unwrap()).await;
            assert!(source.finalize().await.durable().await);
            let target = source.committed_targets().await;
            let root = source.read().await.root();

            let keys = [PrivateKey::from_seed(1), PrivateKey::from_seed(2)];
            let listeners = keys
                .each_ref()
                .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap());
            let addresses = listeners
                .each_ref()
                .map(|listener| listener.local_addr().unwrap());
            let peers = keys.each_ref().map(|key| key.public_key());
            let membership: Map<_, Address> = peers
                .iter()
                .cloned()
                .zip(addresses.map(Into::into))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let mut resolvers = Vec::new();
            let mut actors = Vec::new();
            let mut networks = Vec::new();
            let mut blocked = Vec::new();
            for (i, (key, listener)) in keys.into_iter().zip(listeners).enumerate() {
                let mut cfg = lookup::Config::local(
                    key,
                    b"vera-native-sync-test",
                    addresses[i],
                    NZUsize!(2),
                    4 * 1024 * 1024,
                );
                cfg.dial_frequency = Duration::from_millis(10);
                cfg.peer_connection_cooldown = Duration::from_millis(10);
                let (mut network, mut oracle) = lookup::Network::new(
                    context.child(["network_source", "network_replica"][i]),
                    cfg,
                );
                oracle.track(0, membership.clone());
                blocked.push(oracle.blocked());
                let (actor, mailbox) = p2p::Actor::new(
                    context.child(["resolver_source", "resolver_replica"][i]),
                    p2p::Config {
                        peer_provider: oracle.clone(),
                        blocker: oracle,
                        database: None::<Shared<WireDatabase>>,
                        mailbox_size: NZUsize!(4),
                        me: Some(peers[i].clone()),
                        timeout: Duration::from_secs(2),
                        fetch_retry_timeout: Duration::from_millis(10),
                        max_serve_ops: MAX_FETCH_OPS,
                        priority_requests: false,
                        priority_responses: false,
                    },
                );
                let net = network.register(0, Quota::per_second(NZU32!(100)));
                drop(listener);
                networks.push(network.start());
                actors.push(actor.start(net));
                resolvers.push(Resolver::new(mailbox));
            }
            resolvers[0].attach_database(source.clone()).await;
            let (_updates, updates_rx) = mpsc::channel(1);
            let replica = NativeDb::sync_db(
                context.child("replica"),
                state_config("replica", cache).0,
                resolvers[1].clone(),
                target.clone(),
                updates_rx,
                None,
                None,
                SyncEngineConfig {
                    fetch_batch_size: NZU64!(64),
                    apply_batch_size: NZU64!(64),
                    max_outstanding_requests: 2,
                    update_channel_size: NZUsize!(1),
                    max_retained_roots: 1,
                },
            )
            .await
            .unwrap();
            assert_eq!(replica.root(), root);
            assert_eq!(replica.ops_root(), target.root);
            assert_eq!(
                replica.get(&vec![1; MAX_KEY_BYTES]).await.unwrap(),
                Some(Bytes::from(vec![4; MAX_VALUE_BYTES]))
            );
            assert!(replica.get(&b"removed".to_vec()).await.unwrap().is_none());

            let (response, feedback) = resolvers[1]
                .serve(Request::Boundary {
                    size: target.range.end(),
                    start: target.range.start(),
                })
                .await
                .unwrap();
            assert!(matches!(response, Response::Boundary { .. }));
            feedback.unwrap().send(false).unwrap();
            loop {
                if blocked[1]
                    .recv()
                    .await
                    .unwrap()
                    .iter()
                    .any(|peer| peer == &peers[0])
                {
                    break;
                }
            }
            for actor in actors {
                actor.abort();
            }
            for network in networks {
                network.abort();
            }
        })
        .await
        .expect("peer synchronization timed out");
    });
}
