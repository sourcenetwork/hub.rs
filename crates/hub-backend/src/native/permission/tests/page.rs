use super::*;
use hub_permission::{PAGE_PROOF_BYTES, PrefixPageRequest};

#[test]
fn pages_bind_selection_successors_and_complete_prefix_semantics() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let set = init(&context).await;
            let root = apply(
                &set,
                std::array::from_fn(|_| {
                    [b"p/".as_slice(), b"p/a", b"p/b", b"p/c", b"q/z"]
                        .into_iter()
                        .map(|key| (key.to_vec(), Some(vec![1])))
                        .collect()
                }),
            )
            .await;
            let (a, b, h, n) =
                futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
            for module in [
                hub_permission::ModuleId::Acp,
                hub_permission::ModuleId::Bulletin,
                hub_permission::ModuleId::Hub,
                hub_permission::ModuleId::NativeNonce,
            ] {
                let mut request = PrefixPageRequest {
                    module,
                    prefix: b"p/".to_vec().into(),
                    start: b"p/".to_vec().into(),
                    limit: 2,
                };
                let proof = crate::native::prefix_page_at([&a, &b, &h, &n], root, &request)
                    .await
                    .unwrap();
                let page = proof.verify(root, &request, PAGE_PROOF_BYTES).unwrap();
                assert_eq!(
                    page.entries
                        .iter()
                        .map(|e| e.key.as_slice())
                        .collect::<Vec<_>>(),
                    [b"p/".as_slice(), b"p/a"]
                );
                assert_eq!(
                    page.continuation.as_ref().map(|value| value.as_ref()),
                    Some(b"p/b".as_slice())
                );
                let evidence = PrefixEvidence::decode_cfg(proof.proof.as_ref(), &2).unwrap();
                assert!(
                    evidence
                        .verify(
                            b"p/",
                            &commonware_cryptography::sha256::Digest::from(
                                proof.roots[module.index()].0
                            )
                        )
                        .is_err()
                );
                let mut omitted = evidence.clone();
                omitted.entries.remove(0);
                let mut altered = proof.clone();
                altered.proof = omitted.encode().into();
                assert!(altered.verify(root, &request, PAGE_PROOF_BYTES).is_err());
                omitted.entries.clear();
                altered.proof = omitted.encode().into();
                assert!(altered.verify(root, &request, PAGE_PROOF_BYTES).is_err());
                altered = proof.clone();
                altered.request.limit = 1;
                assert!(altered.verify(root, &request, PAGE_PROOF_BYTES).is_err());
                assert!(
                    altered
                        .verify(root, &altered.request, PAGE_PROOF_BYTES)
                        .is_err()
                );
                assert!(
                    proof
                        .verify(B256::ZERO, &request, PAGE_PROOF_BYTES)
                        .is_err()
                );
                request.start = page.continuation.unwrap();
                let final_page = crate::native::prefix_page_at([&a, &b, &h, &n], root, &request)
                    .await
                    .unwrap()
                    .verify(root, &request, PAGE_PROOF_BYTES)
                    .unwrap();
                assert_eq!(final_page.entries.len(), 2);
                assert!(final_page.continuation.is_none());
                request.start = b"q/".to_vec().into();
                assert!(request.validate().is_err());
            }
        },
    );
}

#[test]
fn page_cursor_handles_deletion_and_empty_ranges_at_a_new_root() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let set = init(&context).await;
            apply(
                &set,
                [
                    vec![
                        (b"p/a".to_vec(), Some(vec![1])),
                        (b"p/b".to_vec(), Some(vec![2])),
                    ],
                    vec![],
                    vec![],
                    vec![],
                ],
            )
            .await;
            let root = apply(
                &set,
                [
                    vec![(b"p/b".to_vec(), None), (b"p/c".to_vec(), Some(vec![3]))],
                    vec![],
                    vec![],
                    vec![],
                ],
            )
            .await;
            let (a, b, h, n) =
                futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
            let mut request = PrefixPageRequest {
                module: hub_permission::ModuleId::Acp,
                prefix: b"p/".to_vec().into(),
                start: b"p/b".to_vec().into(),
                limit: 2,
            };
            let page = crate::native::prefix_page_at([&a, &b, &h, &n], root, &request)
                .await
                .unwrap()
                .verify(root, &request, PAGE_PROOF_BYTES)
                .unwrap();
            assert_eq!(page.entries[0].key, b"p/c");
            assert!(page.continuation.is_none());
            request.start = b"p/z".to_vec().into();
            let empty = crate::native::prefix_page_at([&a, &b, &h, &n], root, &request)
                .await
                .unwrap()
                .verify(root, &request, PAGE_PROOF_BYTES)
                .unwrap();
            assert!(empty.entries.is_empty());
            assert!(empty.continuation.is_none());
        },
    );
}

#[test]
fn page_budget_stops_before_another_large_record() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| async move {
            let set = init(&context).await;
            let root = apply(
                &set,
                [
                    vec![
                        (b"o/".to_vec(), Some(vec![0; MAX_VALUE_BYTES])),
                        (b"p/a".to_vec(), Some(vec![1; MAX_VALUE_BYTES])),
                        (b"p/b".to_vec(), Some(vec![2; MAX_VALUE_BYTES])),
                    ],
                    vec![],
                    vec![],
                    vec![],
                ],
            )
            .await;
            let (a, b, h, n) =
                futures::join!(set.0.read(), set.1.read(), set.2.read(), set.3.read());
            let request = PrefixPageRequest {
                module: hub_permission::ModuleId::Acp,
                prefix: b"p/".to_vec().into(),
                start: b"p/".to_vec().into(),
                limit: 128,
            };
            let proof = crate::native::prefix_page_at([&a, &b, &h, &n], root, &request)
                .await
                .unwrap();
            let page = proof.verify(root, &request, PAGE_PROOF_BYTES).unwrap();
            assert_eq!(page.entries.len(), 1);
            assert_eq!(
                page.continuation.as_ref().map(|value| value.as_ref()),
                Some(b"p/b".as_slice())
            );
        },
    );
}
