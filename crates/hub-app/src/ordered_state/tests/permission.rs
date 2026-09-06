use super::*;
use std::{collections::BTreeMap, sync::RwLock};

use hub_client::{AccessRequest, Actor, HubClient, Object, Operation, PERMISSION_LIMITS};
use hub_jsonrpc::{JsonRpcServer, NodeState};

const POLICY: &str = "\
name: documents
resources:
  - name: document
    relations:
      - name: reader
        types: [actor]
      - name: blocked
        types: [actor]
    permissions:
      - name: read
        expr: reader - blocked
";

fn signed(signer: &BlsSigner, call: impl SolCall) -> Tx {
    Tx::new(
        signer
            .sign_native_tx(ACP_ADDRESS, call.abi_encode().into())
            .unwrap()
            .into(),
    )
}

async fn apply(set: &OrderedState, height: u64, tx: Tx) {
    let (sealed, outcome) = set
        .execute(set.new_batches().await, &block(height), &[tx])
        .await
        .unwrap();
    assert!(outcome.receipts[0].success());
    set.apply(sealed).await;
    assert!(set.finalize().await.durable().await);
}

#[test]
fn synchronized_permission_rpc_verifies_native_evidence_and_subsequent_denial() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| {
            Box::pin(async move {
                ::tokio::time::timeout(Duration::from_secs(30), async {
                    let source = OrderedState::init(
                        context.child("source"),
                        config(&context, "source", HubExecutor::new(DEPLOYMENT)),
                    )
                    .await;
                    let owner = BlsSigner::new(1u64.into(), DEPLOYMENT).unwrap();
                    let actor = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
                    apply(
                        &source,
                        1,
                        signed(
                            &owner,
                            IAcp::createPolicyCall {
                                policy: POLICY.as_bytes().to_vec().into(),
                                marshalType: 1,
                            },
                        ),
                    )
                    .await;
                    let policy = source
                        .executor
                        .modules()
                        .read()
                        .unwrap()
                        .acp
                        .query_policy_ids()
                        .unwrap()
                        .remove(0);
                    apply(
                        &source,
                        2,
                        signed(
                            &owner,
                            IAcp::batchCallsCall {
                                calls: vec![
                                    IAcp::registerObjectCall {
                                        policyId: policy.parse().unwrap(),
                                        resource: "document".into(),
                                        objectId: "report".into(),
                                    }
                                    .abi_encode()
                                    .into(),
                                    IAcp::setRelationshipCall {
                                        policyId: policy.parse().unwrap(),
                                        resource: "document".into(),
                                        objectId: "report".into(),
                                        relation: "reader".into(),
                                        actor: actor.into(),
                                    }
                                    .abi_encode()
                                    .into(),
                                ],
                            },
                        ),
                    )
                    .await;
                    let block = checkpoint::block(&source, 2).await;
                    let db = &source.databases;
                    let proof = native::SyncProof::capture(
                        &(db.3.clone(), db.4.clone(), db.5.clone(), db.6.clone()),
                        block.module_state_root,
                    )
                    .await
                    .unwrap();
                    let (light, trusted) = checkpoint::certify(&block, 42);
                    let checkpoint = OrderedCheckpoint::verify(&light, &trusted, &proof).unwrap();
                    let (replica, reached) = OrderedState::sync_checkpoint(
                        context.child("replica"),
                        config(&context, "replica", HubExecutor::new(DEPLOYMENT)),
                        source.databases.clone(),
                        checkpoint.clone(),
                        SyncEngineConfig {
                            fetch_batch_size: NZU64!(64),
                            apply_batch_size: NZU64!(64),
                            max_outstanding_requests: 2,
                            update_channel_size: NZUsize!(2),
                            max_retained_roots: 2,
                        },
                    )
                    .await
                    .unwrap();
                    assert_eq!(reached, *checkpoint.anchor());

                    let history = Arc::new(RwLock::new(BTreeMap::from([(2, light.clone())])));
                    let lookup = history.clone();
                    let db = &replica.databases;
                    let (server, address) =
                        JsonRpcServer::new("127.0.0.1:0".parse().unwrap(), DEPLOYMENT)
                            .with_node_state(Arc::new(NodeState::new(DEPLOYMENT, 0, 4)))
                            .with_hub_native_modules(
                                (db.3.clone(), db.4.clone(), db.5.clone(), db.6.clone()),
                                replica.executor.modules().clone(),
                            )
                            .with_hub_light_block_lookup(Arc::new(move |height| {
                                lookup
                                    .read()
                                    .unwrap()
                                    .get(&height)
                                    .cloned()
                                    .ok_or_else(|| "revision unavailable".into())
                            }))
                            .start()
                            .await
                            .unwrap();
                    let client = HubClient::new(format!("http://{address}"));
                    let request = AccessRequest {
                        actor: Actor(actor.parse().unwrap()),
                        operations: vec![Operation {
                            object: Object {
                                resource: "document".into(),
                                id: "report".into(),
                            },
                            permission: "read".into(),
                        }],
                    };
                    assert!(
                        client
                            .verify_access_at(
                                &policy,
                                &request,
                                &light,
                                &trusted,
                                PERMISSION_LIMITS
                            )
                            .await
                            .unwrap()
                    );
                    let mut other = request.clone();
                    other.operations[0].object.id = "ungranted".into();
                    assert!(
                        !client
                            .verify_access_at(&policy, &other, &light, &trusted, PERMISSION_LIMITS)
                            .await
                            .unwrap()
                    );
                    assert!(
                        !client
                            .verify_access_at(
                                "missing",
                                &request,
                                &light,
                                &trusted,
                                PERMISSION_LIMITS
                            )
                            .await
                            .unwrap()
                    );

                    apply(
                        &replica,
                        3,
                        signed(
                            &owner,
                            IAcp::setRelationshipCall {
                                policyId: policy.parse().unwrap(),
                                resource: "document".into(),
                                objectId: "report".into(),
                                relation: "blocked".into(),
                                actor: actor.into(),
                            },
                        ),
                    )
                    .await;
                    let (next, _) = checkpoint::certify(&checkpoint::block(&replica, 3).await, 42);
                    history.write().unwrap().insert(3, next.clone());
                    assert!(
                        client
                            .verify_access_at(
                                &policy,
                                &request,
                                &light,
                                &trusted,
                                PERMISSION_LIMITS
                            )
                            .await
                            .is_err()
                    );
                    assert!(
                        !client
                            .verify_access_at(&policy, &request, &next, &trusted, PERMISSION_LIMITS)
                            .await
                            .unwrap()
                    );
                    let mut owner_request = request;
                    owner_request.actor = Actor(owner.did().parse().unwrap());
                    assert!(
                        client
                            .verify_access_at(
                                &policy,
                                &owner_request,
                                &next,
                                &trusted,
                                PERMISSION_LIMITS
                            )
                            .await
                            .unwrap()
                    );
                    server.stop().unwrap();
                    server.stopped().await;
                })
                .await
                .expect("permission synchronization and RPC deadline");
            })
        },
    );
}
