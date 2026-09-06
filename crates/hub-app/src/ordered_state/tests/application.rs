use super::*;
use crate::{NoopSink, ReshareInput, StatefulHubApp};
use commonware_consensus::marshal::ancestry;
use commonware_glue::stateful::{Application, Input};
use hub_consensus::{Mempool as _, components::InMemoryMempool};

#[test]
fn native_proposals_bind_every_target_and_isolate_competing_execution() {
    let directory = tempfile::tempdir().unwrap();
    tokio::Runner::new(tokio::Config::new().with_storage_directory(directory.path())).start(
        |context| {
            Box::pin(async move {
                let executor = HubExecutor::new(DEPLOYMENT);
                let initialization = OrderedState::init(
                    context.child("state"),
                    config(&context, "state", executor.clone()),
                );
                // The actor moves these futures through its startup state machine.
                // Large inline journal futures previously overflowed the node's stack.
                assert!(std::mem::size_of_val(&initialization) <= 64 * 1024);
                let set = initialization.await;
                let genesis = checkpoint::block(&set, 0).await;
                type App = StatefulHubApp<NoopSink, OrderedState>;
                let genesis_targets = App::sync_targets(&genesis);
                let recovery = set.rewind_to_targets(genesis_targets.clone());
                assert!(std::mem::size_of_val(&recovery) <= 64 * 1024);
                recovery.await;
                let mempool = InMemoryMempool::new();
                let first = policy(&BlsSigner::new(1u64.into(), DEPLOYMENT).unwrap(), "first");
                assert!(mempool.insert(first.clone()));
                let mut app = App::new(
                    executor.clone(),
                    genesis.clone(),
                    mempool.clone(),
                    NoopSink,
                    64,
                    30_000_000,
                );
                let proposal = app
                    .propose(
                        (
                            context.child("propose"),
                            hub_domain::Block::genesis_context(),
                        ),
                        ancestry::from_iter([Arc::new(genesis.clone())]),
                        set.new_batches().await,
                        Input {
                            upstream: ReshareInput {
                                upstream: (),
                                payload: None,
                            },
                            provider: mempool.clone(),
                        },
                    )
                    .await
                    .unwrap();
                assert!(proposal.block.native_targets.is_some());
                assert!(OrderedState::matches_sync_targets(
                    &proposal.merkleized,
                    &App::sync_targets(&proposal.block)
                ));
                assert_eq!(set.committed_targets().await, genesis_targets);
                assert!(
                    executor
                        .modules()
                        .read()
                        .unwrap()
                        .acp
                        .query_policy_ids()
                        .unwrap()
                        .is_empty()
                );
                for mutation in 0..5 {
                    let mut changed = proposal.block.clone();
                    match mutation {
                        0 => changed.native_targets.as_mut().unwrap()[0].root.0[0] ^= 1,
                        1 => changed.native_targets.as_mut().unwrap()[1].floor += 1,
                        2 => changed.native_targets.as_mut().unwrap()[2].tip += 1,
                        3 => changed.module_state_root.0[0] ^= 1,
                        4 => changed.native_targets = None,
                        _ => unreachable!(),
                    }
                    assert!(
                        app.verify(
                            (context.child("reject"), changed.context.clone()),
                            ancestry::from_iter([Arc::new(changed), Arc::new(genesis.clone())]),
                            set.new_batches().await,
                        )
                        .await
                        .is_none()
                    );
                }
                mempool.prune(&[first.id()]);
                assert!(mempool.insert(policy(
                    &BlsSigner::new(1u64.into(), DEPLOYMENT).unwrap(),
                    "other"
                )));
                let competing = app
                    .propose(
                        (
                            context.child("competing"),
                            hub_domain::Block::genesis_context(),
                        ),
                        ancestry::from_iter([Arc::new(genesis.clone())]),
                        set.new_batches().await,
                        Input {
                            upstream: ReshareInput {
                                upstream: (),
                                payload: None,
                            },
                            provider: mempool,
                        },
                    )
                    .await
                    .unwrap();
                assert_ne!(
                    proposal.block.module_state_root,
                    competing.block.module_state_root
                );
                let verified = app
                    .verify(
                        (context.child("verify"), proposal.block.context.clone()),
                        ancestry::from_iter([Arc::new(proposal.block.clone()), Arc::new(genesis)]),
                        set.new_batches().await,
                    )
                    .await
                    .unwrap();
                let receipts = app
                    .capture(
                        (context.child("capture"), proposal.block.context.clone()),
                        &proposal.block,
                        &verified,
                        set.readers(),
                    )
                    .await;
                assert_eq!(receipts.len(), 1);
                assert!(receipts[0].success());
                set.apply(verified).await;
                assert!(set.finalize().await.durable().await);
                assert_eq!(
                    set.committed_targets().await,
                    App::sync_targets(&proposal.block)
                );
                assert_eq!(
                    executor
                        .modules()
                        .read()
                        .unwrap()
                        .acp
                        .query_policy_ids()
                        .unwrap()
                        .len(),
                    1
                );
                set.rewind_to_targets(genesis_targets).await;
                assert!(
                    executor
                        .modules()
                        .read()
                        .unwrap()
                        .acp
                        .query_policy_ids()
                        .unwrap()
                        .is_empty()
                );
            })
        },
    );
}
