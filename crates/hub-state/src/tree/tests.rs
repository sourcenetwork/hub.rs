use super::*;

fn entry(key: &[u8], value: &[u8]) -> Entries {
    vec![(key.to_vec(), Some(value.to_vec()))]
}

#[test]
fn rewind_restores_raw_values_and_removes_abandoned_versions() {
    let dir = TempDir::new().unwrap();
    let root;
    {
        let mut tree = open_tree(&dir);
        let first = tree
            .prepare(&tree.snapshot().unwrap(), entry(b"shared", b"original"))
            .unwrap();
        tree.commit_prepared(1, &first).unwrap();
        root = first.root();
        let second = tree
            .prepare(
                &first,
                vec![
                    (b"shared".to_vec(), Some(b"abandoned".to_vec())),
                    (b"abandoned".to_vec(), Some(b"value".to_vec())),
                ],
            )
            .unwrap();
        tree.commit_prepared(2, &second).unwrap();
        let third = tree
            .prepare(&second, vec![(b"shared".to_vec(), None)])
            .unwrap();
        tree.commit_prepared(3, &third).unwrap();
        assert!(
            tree.rewind_to_height(1).is_err(),
            "live snapshots must prevent rollback"
        );
    }
    {
        let mut tree = open_tree(&dir);
        tree.rewind_to_height(1).unwrap();
        tree.rewind_to_height(1).unwrap();
        assert_eq!(tree.version(), 1);
        assert_eq!(tree.root().unwrap(), root);
        assert_eq!(
            tree.load_all().unwrap(),
            vec![(b"shared".to_vec(), b"original".to_vec())]
        );
        assert!(tree.root_at_height(2).is_err());
        let replacement = tree
            .prepare(&tree.snapshot().unwrap(), entry(b"replacement", b"value"))
            .unwrap();
        tree.commit_prepared(2, &replacement).unwrap();
        assert_eq!(tree.get(b"shared").unwrap(), Some(b"original".to_vec()));
        assert!(tree.get(b"abandoned").unwrap().is_none());
        let (value, proof) = tree.prove(b"shared").unwrap();
        proof
            .verify(
                tree.root().unwrap(),
                KeyHash::with::<Sha256>(b"shared"),
                value,
            )
            .unwrap();
    }
    let tree = open_tree(&dir);
    assert_eq!(tree.canonical_height(), 2);
    assert_eq!(tree.get(b"shared").unwrap(), Some(b"original".to_vec()));
    assert_eq!(tree.get(b"replacement").unwrap(), Some(b"value".to_vec()));
    assert!(tree.get(b"abandoned").unwrap().is_none());
}

#[test]
fn rewind_to_genesis_and_across_unchanged_heights() {
    let dir = TempDir::new().unwrap();
    {
        let mut tree = open_tree(&dir);
        let changed = tree
            .prepare(&tree.snapshot().unwrap(), entry(b"key", b"value"))
            .unwrap();
        tree.commit_prepared(1, &changed).unwrap();
        tree.commit_prepared(2, &changed).unwrap();
    }
    {
        let mut tree = open_tree(&dir);
        assert!(tree.rewind_to_height(3).is_err());
        tree.rewind_to_height(1).unwrap();
    }
    let mut tree = open_tree(&dir);
    tree.rewind_to_height(0).unwrap();
    assert_eq!(tree.version(), 0);
    assert_eq!(tree.root().unwrap().0, empty_root());
    assert!(tree.load_all().unwrap().is_empty());
    assert!(tree.get(b"key").unwrap().is_none());
}

#[test]
fn competing_branches_remain_isolated_after_commit() {
    let dir = TempDir::new().unwrap();
    let mut tree = open_tree(&dir);
    tree.put(b"shared", Some(b"base".to_vec())).unwrap();
    let base = tree.snapshot().unwrap();
    let a = tree.prepare(&base, entry(b"shared", b"alice")).unwrap();
    let b = tree.prepare(&base, entry(b"shared", b"bob")).unwrap();
    let child_a = tree.prepare(&a, entry(b"only-a", b"child")).unwrap();
    let child_b = tree.prepare(&b, vec![(b"shared".to_vec(), None)]).unwrap();
    assert_eq!(tree.get(b"shared").unwrap(), Some(b"base".to_vec()));
    assert_eq!(tree.version(), 1);
    assert_eq!(
        tree.load_all().unwrap(),
        vec![(b"shared".to_vec(), b"base".to_vec())]
    );
    assert!(tree.root_at_height(1).is_err());

    tree.commit_prepared(1, &a).unwrap();
    tree.commit_prepared(1, &a).unwrap();
    assert!(tree.commit_prepared(1, &b).is_err());
    assert!(tree.commit_prepared(2, &child_b).is_err());
    tree.commit_prepared(2, &child_a).unwrap();
    assert_eq!(base.get(b"shared").unwrap(), Some(b"base".to_vec()));
    assert_eq!(b.get(b"shared").unwrap(), Some(b"bob".to_vec()));
    assert!(child_b.get(b"shared").unwrap().is_none());
    assert!(child_b.get(b"only-a").unwrap().is_none());
    assert_eq!(tree.get(b"shared").unwrap(), Some(b"alice".to_vec()));
    assert_eq!(tree.get(b"only-a").unwrap(), Some(b"child".to_vec()));
    let next = tree.prepare(&child_a, entry(b"next", b"value")).unwrap();
    assert_eq!(
        next.pending.len(),
        1,
        "committed ancestors must leave the pending view"
    );

    let (value, proof, root) = tree.prove_at_height(b"only-a", 1).unwrap();
    assert!(value.is_none());
    proof
        .verify(root, KeyHash::with::<Sha256>(b"only-a"), value)
        .unwrap();
    let (value, proof, root) = tree.prove_at_height(b"only-a", 2).unwrap();
    proof
        .verify(root, KeyHash::with::<Sha256>(b"only-a"), value)
        .unwrap();
}

#[test]
fn pending_updates_do_not_survive_reopen() {
    let dir = TempDir::new().unwrap();
    {
        let tree = open_tree(&dir);
        let pending = tree
            .prepare(&tree.snapshot().unwrap(), entry(b"pending", b"value"))
            .unwrap();
        assert_eq!(pending.get(b"pending").unwrap(), Some(b"value".to_vec()));
    }
    let tree = open_tree(&dir);
    assert_eq!(tree.version(), 0);
    assert_eq!(tree.canonical_height(), 0);
    assert!(tree.load_all().unwrap().is_empty());
    assert!(tree.get(b"pending").unwrap().is_none());
}

#[test]
fn history_and_deletions_survive_reopen() {
    let dir = TempDir::new().unwrap();
    let roots;
    {
        let mut tree = open_tree(&dir);
        let a = tree
            .prepare(&tree.snapshot().unwrap(), entry(b"key", b"value"))
            .unwrap();
        tree.commit_prepared(1, &a).unwrap();
        let b = tree.prepare(&a, vec![(b"key".to_vec(), None)]).unwrap();
        tree.commit_prepared(2, &b).unwrap();
        let unchanged = tree.prepare(&b, Vec::new()).unwrap();
        tree.commit_prepared(3, &unchanged).unwrap();
        roots = [a.root(), b.root(), unchanged.root()];
    }
    let tree = open_tree(&dir);
    assert_eq!(tree.canonical_height(), 3);
    assert!(tree.load_all().unwrap().is_empty());
    assert!(tree.get(b"key").unwrap().is_none());
    for height in 1..=3 {
        let (value, proof, root) = tree.prove_at_height(b"key", height).unwrap();
        assert_eq!(root, roots[height as usize - 1]);
        assert_eq!(value.is_some(), height == 1);
        proof
            .verify(root, KeyHash::with::<Sha256>(b"key"), value)
            .unwrap();
        assert_eq!(tree.root_at_height(height).unwrap(), root);
    }
    assert!(tree.prove_at_height(b"key", 4).is_err());
}

#[test]
fn retained_heights_are_bounded_across_reopen() {
    let dir = TempDir::new().unwrap();
    {
        let mut tree = open_tree(&dir);
        for height in 1u64..=70 {
            let next = tree
                .prepare(
                    &tree.snapshot().unwrap(),
                    entry(b"key", &height.to_be_bytes()),
                )
                .unwrap();
            tree.commit_prepared(height, &next).unwrap();
        }
    }
    let tree = open_tree(&dir);
    assert!(tree.root_at_height(5).is_err());
    assert!(tree.root_at_height(6).is_ok());
    assert!(tree.root_at_height(70).is_ok());
    assert_eq!(tree.height_versions.len(), 65);
}
use tempfile::TempDir;

fn open_tree(dir: &TempDir) -> ModuleStateTree {
    ModuleStateTree::open(dir.path().join("db")).unwrap()
}

#[test]
fn put_get_roundtrip() {
    let dir = TempDir::new().unwrap();
    let mut tree = open_tree(&dir);
    tree.put(b"key/a", Some(b"val-a".to_vec())).unwrap();
    let val = tree.get(b"key/a").unwrap();
    assert_eq!(val, Some(b"val-a".to_vec()));
}

#[test]
fn prove_existence() {
    let dir = TempDir::new().unwrap();
    let mut tree = open_tree(&dir);
    tree.put(b"key/a", Some(b"val-a".to_vec())).unwrap();
    let (val, proof) = tree.prove(b"key/a").unwrap();
    assert_eq!(val, Some(b"val-a".to_vec()));

    let root = tree.root().unwrap();
    assert!(
        proof
            .verify(root, KeyHash::with::<Sha256>(b"key/a"), val)
            .is_ok()
    );
}

#[test]
fn prove_nonexistence() {
    let dir = TempDir::new().unwrap();
    let mut tree = open_tree(&dir);
    tree.put(b"key-a", Some(b"val".to_vec())).unwrap();
    let (val, _proof) = tree.prove(b"key-missing").unwrap();
    assert!(val.is_none());
}

#[test]
fn delete_via_put_none() {
    let dir = TempDir::new().unwrap();
    let mut tree = open_tree(&dir);
    tree.put(b"key", Some(b"val".to_vec())).unwrap();
    assert!(tree.get(b"key").unwrap().is_some());
    tree.put(b"key", None).unwrap();
    assert!(tree.get(b"key").unwrap().is_none());
}

#[test]
fn versioned_reads() {
    let dir = TempDir::new().unwrap();
    let mut tree = open_tree(&dir);
    tree.put(b"key", Some(b"v1".to_vec())).unwrap();
    assert_eq!(tree.version(), 1);
    tree.put(b"key", Some(b"v2".to_vec())).unwrap();
    assert_eq!(tree.version(), 2);
    let val = tree.get(b"key").unwrap();
    assert_eq!(val, Some(b"v2".to_vec()));
}

#[test]
fn root_changes_on_put() {
    let dir = TempDir::new().unwrap();
    let mut tree = open_tree(&dir);
    let r1 = tree.put(b"k1", Some(b"v1".to_vec())).unwrap();
    let r2 = tree.put(b"k2", Some(b"v2".to_vec())).unwrap();
    assert_ne!(r1.0, r2.0);
}

#[test]
fn empty_tree_root_is_stable() {
    let d1 = TempDir::new().unwrap();
    let d2 = TempDir::new().unwrap();
    let t1 = open_tree(&d1);
    let t2 = open_tree(&d2);
    assert_eq!(t1.root().unwrap().0, t2.root().unwrap().0);
}

#[test]
fn multiple_keys_single_commit() {
    let dir = TempDir::new().unwrap();
    let mut tree = open_tree(&dir);
    let root = tree
        .commit(vec![
            (b"a".to_vec(), Some(b"1".to_vec())),
            (b"b".to_vec(), Some(b"2".to_vec())),
            (b"c".to_vec(), Some(b"3".to_vec())),
        ])
        .unwrap();
    assert_eq!(tree.version(), 1);
    assert_eq!(tree.get(b"a").unwrap(), Some(b"1".to_vec()));
    assert_eq!(tree.get(b"b").unwrap(), Some(b"2".to_vec()));
    assert_eq!(tree.get(b"c").unwrap(), Some(b"3".to_vec()));
    assert_ne!(root.0, empty_root());
}

#[test]
fn raw_kv_populated_by_direct_put() {
    let dir = TempDir::new().unwrap();
    let mut tree = open_tree(&dir);
    tree.put(b"key-1", Some(b"val-1".to_vec())).unwrap();
    tree.put(b"key-2", Some(b"val-2".to_vec())).unwrap();

    let all = tree.load_all().unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0], (b"key-1".to_vec(), b"val-1".to_vec()));
    assert_eq!(all[1], (b"key-2".to_vec(), b"val-2".to_vec()));
}

#[test]
fn raw_kv_populated_by_commit() {
    let dir = TempDir::new().unwrap();
    let mut tree = open_tree(&dir);
    tree.commit(vec![
        (b"x".to_vec(), Some(b"10".to_vec())),
        (b"y".to_vec(), Some(b"20".to_vec())),
    ])
    .unwrap();

    let all = tree.load_all().unwrap();
    assert_eq!(all.len(), 2);
}

#[test]
fn raw_kv_delete_removes_entry() {
    let dir = TempDir::new().unwrap();
    let mut tree = open_tree(&dir);
    tree.put(b"keep", Some(b"val".to_vec())).unwrap();
    tree.put(b"remove", Some(b"val".to_vec())).unwrap();
    tree.put(b"remove", None).unwrap();

    let all = tree.load_all().unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].0, b"keep".to_vec());
}

#[test]
fn load_all_on_reopen() {
    let dir = TempDir::new().unwrap();
    {
        let mut tree = open_tree(&dir);
        tree.put(b"persist-a", Some(b"val-a".to_vec())).unwrap();
        tree.put(b"persist-b", Some(b"val-b".to_vec())).unwrap();
    }

    let tree = ModuleStateTree::open(dir.path().join("db")).unwrap();
    assert_eq!(tree.version(), 2);
    let all = tree.load_all().unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0], (b"persist-a".to_vec(), b"val-a".to_vec()));
    assert_eq!(all[1], (b"persist-b".to_vec(), b"val-b".to_vec()));
}

#[test]
fn persistence_across_reopen() {
    let dir = TempDir::new().unwrap();
    let root_at_close;
    {
        let mut tree = open_tree(&dir);
        tree.put(b"key-a", Some(b"val-a".to_vec())).unwrap();
        tree.put(b"key-b", Some(b"val-b".to_vec())).unwrap();
        root_at_close = tree.root().unwrap();
    }
    let tree = ModuleStateTree::open(dir.path().join("db")).unwrap();
    assert_eq!(tree.version(), 2);
    assert_eq!(tree.get(b"key-a").unwrap(), Some(b"val-a".to_vec()));
    assert_eq!(tree.get(b"key-b").unwrap(), Some(b"val-b".to_vec()));
    assert_eq!(tree.root().unwrap().0, root_at_close.0);
}
