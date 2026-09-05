use super::*;
use hub_modules::hub::administration::OperatorPolicy;

fn configured_genesis() -> hub_genesis::HubGenesis {
    let mut genesis = hub_genesis::HubGenesis::devnet();
    genesis.operators = Some(OperatorPolicy {
        threshold: 1,
        keys: vec!["0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into()],
    });
    genesis
}

#[test]
fn initial_authority_recovers_after_interrupted_genesis_creation() {
    let dir = tempfile::tempdir().unwrap();
    let genesis = configured_genesis();
    let (trees, mut state) = open_module_trees(dir.path()).unwrap();
    let root = initialize_genesis_modules(dir.path(), &genesis, &trees, &mut state).unwrap();
    let policy = state.hub.administration().unwrap().unwrap().policy;
    assert_eq!(Some(policy), genesis.operators);
    let version = trees[2].lock().unwrap().version();
    drop(trees);

    let (trees, mut state) = open_module_trees(dir.path()).unwrap();
    assert_eq!(
        initialize_genesis_modules(dir.path(), &genesis, &trees, &mut state).unwrap(),
        root
    );
    assert_eq!(trees[2].lock().unwrap().version(), version);
    let executor = HubExecutor::new(genesis.chain_id).with_module_trees(trees.clone());
    let anchor = genesis_block(
        hub_domain::StateRoot(alloy_primitives::B256::ZERO),
        Default::default(),
        root,
    );
    recover_modules(&executor, &trees, &anchor).unwrap();
    assert_eq!(executor.modules().read().unwrap().state_root(), root);

    let mut different = configured_genesis();
    different.operators = None;
    assert!(initialize_genesis_modules(dir.path(), &different, &trees, &mut state).is_err());
}

#[test]
fn existing_history_cannot_be_reinitialized_without_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let (trees, mut state) = open_module_trees(dir.path()).unwrap();
    {
        let mut tree = trees[0].lock().unwrap();
        let snapshot = tree.snapshot().unwrap();
        tree.commit_prepared(1, &snapshot).unwrap();
    }
    assert!(
        initialize_genesis_modules(dir.path(), &configured_genesis(), &trees, &mut state).is_err()
    );
    assert!(state.hub.administration().unwrap().is_none());
}
