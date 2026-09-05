//! Verify competing proposals and capture the winning branch's receipts.

#![recursion_limit = "256"]

use std::sync::Arc;

use alloy_primitives::{Address, U256, keccak256};
use commonware_consensus::marshal::ancestry;
use commonware_glue::stateful::{Application, Input, db::DatabaseSet as _};
use commonware_runtime::{Runner as _, Supervisor as _, buffer::paged::CacheRef, tokio};
use commonware_utils::{NZU16, NZUsize};
use hub_app::{NoopSink, ReshareInput, StatefulHubApp, apply_genesis, genesis_block};
use hub_backend::{HubStateSet, state_set_config};
use hub_consensus::{Mempool as _, components::InMemoryMempool};
use hub_domain::{Block, evm::Evm};
use hub_executor::HubExecutor;
use hub_genesis::GenesisState;
use hub_modules::ModuleState;
use k256::ecdsa::SigningKey;

const CHAIN_ID: u64 = 9001;

fn signer() -> (SigningKey, Address) {
    let key = SigningKey::from_bytes(&[7u8; 32].into()).expect("key");
    let address = Evm::address_from_key(&key);
    (key, address)
}

#[test]
fn competing_proposals_preserve_receipts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let config = tokio::Config::default().with_storage_directory(dir.path().to_path_buf());
    tokio::Runner::new(config).start(|context| async move {
        let page_cache = CacheRef::from_pooler(&context, NZU16!(4084), NZUsize!(64));
        let set =
            HubStateSet::init(context.child("set"), state_set_config("app", page_cache)).await;

        let (key, from) = signer();
        let genesis_state = GenesisState {
            genesis_alloc: vec![(from, U256::from(1_000_000_000_000_000_000u128))],
            ..Default::default()
        };
        let (root, targets) = apply_genesis(&set, &genesis_state).await.expect("genesis");
        let genesis = genesis_block(root, targets, ModuleState::default().state_root());

        let mempool = InMemoryMempool::new();
        let to = Address::repeat_byte(0x42);
        let tx = Evm::sign_eip1559_transfer(&key, CHAIN_ID, to, U256::from(1000u64), 0, 21_000);
        assert!(mempool.insert(tx));

        let mut app = StatefulHubApp::new(
            HubExecutor::new(CHAIN_ID),
            genesis.clone(),
            mempool.clone(),
            NoopSink,
            100,
            30_000_000,
        );

        let consensus_context = Block::genesis_context();
        let proposed = app
            .propose(
                (context.child("propose"), consensus_context.clone()),
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
            .expect("proposal");
        let block = proposed.block;
        assert_eq!(block.height, 1);
        assert_eq!(block.txs.len(), 1);
        assert_ne!(block.state_root, genesis.state_root);
        assert_ne!(block.db_targets, genesis.db_targets);

        let verified = app
            .verify(
                (context.child("verify"), consensus_context),
                ancestry::from_iter([Arc::new(block.clone()), Arc::new(genesis.clone())]),
                set.new_batches().await,
            )
            .await
            .expect("verification");
        assert_eq!(hub_backend::combined_root(&verified), block.state_root.0);

        mempool.prune(&[block.txs[0].id()]);
        let competing_tx = Evm::sign_eip1559_transfer(
            &key,
            CHAIN_ID,
            Address::repeat_byte(0x43),
            U256::from(2000u64),
            0,
            21_000,
        );
        assert!(mempool.insert(competing_tx));
        let mut verifier = app.clone();
        let competing = verifier
            .propose(
                (context.child("competing"), Block::genesis_context()),
                ancestry::from_iter([Arc::new(genesis)]),
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
            .expect("competing proposal");
        assert_eq!(competing.block.height, block.height);
        assert_ne!(competing.block.id(), block.id());

        for (candidate, batches) in [
            (&block, &verified),
            (&competing.block, &competing.merkleized),
        ] {
            let (_, receipts) = app
                .capture(
                    (context.child("capture"), candidate.context.clone()),
                    candidate,
                    batches,
                    set.readers(),
                )
                .await;
            assert_eq!(receipts.len(), 1);
            assert_eq!(receipts[0].tx_hash, keccak256(&candidate.txs[0].bytes));
            assert!(receipts[0].success());
            assert_eq!(receipts[0].gas_used, 21_000);
        }

        set.apply(verified).await;
        assert!(set.finalize().await.durable().await);
        let committed = set.committed_targets().await;
        assert_eq!(hub_app::db_targets_from_sync(&committed), block.db_targets);
    });
}
