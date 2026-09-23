use super::*;
use crate::{CodeKey, state_set_config};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_glue::stateful::db::{DatabaseSet as _, Unmerkleized as _};
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_storage::{merkle::Location, qmdb::any::unordered::Update};
use commonware_utils::{NZU16, NZUsize};

type Operation = <CodeDb as Source>::Op;

#[test]
fn code_codec_bounds_values_and_commit_metadata() {
    for size in [0, MAX_CODE_BYTES, MAX_CODE_BYTES + 1] {
        for operation in [
            Operation::Update(Update(CodeKey::new([1; 32]), vec![2; size])),
            Operation::CommitFloor(Some(vec![3; size]), Location::new(0)),
        ] {
            let bytes = operation.encode();
            let decoded = WireOperation::<CodeDb>::decode(bytes.clone());
            assert_eq!(decoded.is_ok(), size <= MAX_CODE_BYTES);
            assert_eq!(CodeDb::accepts(&operation), decoded.is_ok());
            if let Ok(decoded) = decoded {
                assert_eq!(decoded.encode(), bytes);
                assert!(WireOperation::<CodeDb>::decode(bytes.slice(..bytes.len() - 1)).is_err());
                let mut trailing = bytes.to_vec();
                trailing.push(0);
                assert!(WireOperation::<CodeDb>::decode(trailing.as_slice()).is_err());
            }
        }
    }
    for operation in [
        Operation::Delete(CodeKey::new([1; 32])),
        Operation::CommitFloor(None, Location::new(0)),
    ] {
        assert!(CodeDb::accepts(&operation));
        assert_eq!(
            WireOperation::<CodeDb>::decode(operation.encode())
                .unwrap()
                .encode(),
            operation.encode()
        );
    }
}

#[test]
fn serving_rejects_code_records_outside_peer_limits() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
            let db =
                Shared::<CodeDb>::init(context.child("code"), state_set_config("code", cache).2)
                    .await;
            let key = CodeKey::new([1; 32]);
            for size in [MAX_CODE_BYTES, MAX_CODE_BYTES + 1] {
                let batch = db
                    .new_batches()
                    .await
                    .write(key.clone(), Some(vec![2; size]))
                    .merkleize()
                    .await
                    .unwrap();
                db.apply(batch).await;
                assert!(db.finalize().await.durable().await);
                let target = db.committed_targets().await;
                let result = WireDatabase::<CodeDb>::new(db.clone())
                    .serve(Request::Operations {
                        size: target.range.end(),
                        start: target.range.start(),
                        max_ops: MAX_FETCH_OPS,
                    })
                    .await;
                if size == MAX_CODE_BYTES {
                    let (response, _) = result.unwrap();
                    assert!(response.encode_size() <= MAX_RESPONSE_BYTES);
                    use commonware_codec::Decode as _;
                    assert!(
                        Response::<mmr::Family, WireOperation<CodeDb>, Digest>::decode_cfg(
                            response.encode(),
                            &(MAX_FETCH_OPS.get() as usize, ()),
                        )
                        .is_ok()
                    );
                } else {
                    assert!(result.is_err());
                    assert_eq!(
                        db.read().await.get(&key).await.unwrap().unwrap().len(),
                        size
                    );
                }
            }
        },
    );
}
