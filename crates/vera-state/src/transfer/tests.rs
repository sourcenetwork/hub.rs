use super::*;
use tempfile::TempDir;

fn source(dir: &Path) -> ModuleStateTree {
    let mut tree = ModuleStateTree::open(dir).unwrap();
    let mut records: Vec<_> = (0..300)
        .map(|i| {
            (
                format!("record/{i:04}").into_bytes(),
                Some(vec![i as u8; 80]),
            )
        })
        .collect();
    records.push((
        b"\0relation/count".to_vec(),
        Some(300u64.to_be_bytes().to_vec()),
    ));
    let next = tree.prepare(&tree.snapshot().unwrap(), records).unwrap();
    tree.commit_prepared(42, &next).unwrap();
    tree
}

fn chunks(view: &TreeSnapshot) -> Vec<SnapshotChunk> {
    let mut after = None;
    let mut result = Vec::new();
    while let Some(chunk) = view.export_chunk(after).unwrap() {
        after = Some(KeyHash::with::<Sha256>(&chunk.records.last().unwrap().0));
        result.push(chunk);
    }
    result
}

#[test]
fn transfer_restores_pinned_records_metadata_proofs_and_following_revision() {
    let dir = TempDir::new().unwrap();
    let mut tree = source(&dir.path().join("source"));
    let view = tree.snapshot().unwrap();
    let expected = tree.load_all().unwrap();
    let changed = tree
        .prepare(&view, vec![(b"record/0000".to_vec(), None)])
        .unwrap();
    tree.commit_prepared(43, &changed).unwrap();
    assert!(changed.export_chunk(None).is_err());
    let data = chunks(&view);
    assert_eq!(data.len(), 3);
    let path = dir.path().join("restore");
    let mut restore = ModuleRestore::create(&path, 42, view.root()).unwrap();
    for chunk in data {
        restore.add_chunk(chunk).unwrap();
    }
    let mut restored = restore.finish().unwrap();
    assert_eq!(restored.canonical_height(), 42);
    assert_eq!(restored.root().unwrap(), view.root());
    assert_eq!(restored.load_all().unwrap(), expected);
    let count = b"\0relation/count";
    assert_eq!(
        restored.get(count).unwrap(),
        Some(300u64.to_be_bytes().to_vec())
    );
    let (value, proof, root) = restored.prove_at_height(count, 42).unwrap();
    proof
        .verify(root, KeyHash::with::<Sha256>(count), value)
        .unwrap();
    let next = restored
        .prepare(
            &restored.snapshot().unwrap(),
            vec![(b"record/0000".to_vec(), None)],
        )
        .unwrap();
    restored.commit_prepared(43, &next).unwrap();
    assert_eq!(restored.root().unwrap(), tree.root().unwrap());
    drop(next);
    restored.rewind_to_height(42).unwrap();
    assert_eq!(restored.root().unwrap(), view.root());
    drop(restored);
    let restored = ModuleStateTree::open(path).unwrap();
    assert_eq!(restored.canonical_height(), 42);
    assert_eq!(restored.load_all().unwrap(), expected);
}

#[test]
fn transfer_rejects_tampering_omission_reordering_and_reuse_after_error() {
    let dir = TempDir::new().unwrap();
    let tree = source(&dir.path().join("source"));
    let view = tree.snapshot().unwrap();
    let first = view.export_chunk(None).unwrap().unwrap();
    let mut invalid = Vec::new();
    let mut chunk = first.clone();
    chunk.records[0].1[0] ^= 1;
    invalid.push(chunk);
    let mut chunk = first.clone();
    chunk.records.remove(0);
    invalid.push(chunk);
    let mut chunk = first.clone();
    chunk.records.swap(0, 1);
    invalid.push(chunk);
    let mut chunk = first.clone();
    chunk.records[1] = chunk.records[0].clone();
    invalid.push(chunk);
    let mut chunk = first.clone();
    chunk.proof.truncate(3);
    invalid.push(chunk);
    for (i, chunk) in invalid.into_iter().enumerate() {
        let path = dir.path().join(format!("restore-{i}"));
        let mut restore = ModuleRestore::create(&path, 42, view.root()).unwrap();
        assert!(restore.add_chunk(chunk).is_err());
        assert!(restore.add_chunk(first.clone()).is_err());
        assert!(restore.finish().is_err());
        assert!(ModuleStateTree::open(path).is_err());
    }
    let path = dir.path().join("foreign-root");
    let mut restore = ModuleRestore::create(&path, 42, RootHash([7; 32])).unwrap();
    assert!(restore.add_chunk(first).is_err());
}

#[test]
fn transfer_never_opens_partial_or_interrupted_state() {
    let dir = TempDir::new().unwrap();
    let tree = source(&dir.path().join("source"));
    let view = tree.snapshot().unwrap();
    for (name, finish) in [("truncated", true), ("interrupted", false)] {
        let path = dir.path().join(name);
        let mut restore = ModuleRestore::create(&path, 42, view.root()).unwrap();
        restore
            .add_chunk(view.export_chunk(None).unwrap().unwrap())
            .unwrap();
        if finish {
            assert!(restore.finish().is_err());
        } else {
            drop(restore);
        }
        assert!(
            ModuleStateTree::open(&path)
                .unwrap_err()
                .to_string()
                .contains("incomplete")
        );
        assert!(ModuleRestore::create(&path, 42, view.root()).is_err());
    }
    assert!(ModuleRestore::create(dir.path().join("source"), 42, view.root()).is_err());
    assert_eq!(tree.root().unwrap(), view.root());
}

#[test]
fn transfer_handles_both_empty_roots_and_single_leaf() {
    let dir = TempDir::new().unwrap();
    let mut tree = ModuleStateTree::open(dir.path().join("source")).unwrap();
    for i in 0..3 {
        let view = tree.snapshot().unwrap();
        let path = dir.path().join(format!("restore-{i}"));
        let mut restore = ModuleRestore::create(&path, 42, view.root()).unwrap();
        for chunk in chunks(&view) {
            restore.add_chunk(chunk).unwrap();
        }
        let restored = restore.finish().unwrap();
        assert_eq!(restored.root().unwrap(), view.root());
        assert_eq!(restored.load_all().unwrap(), tree.load_all().unwrap());
        drop(restored);
        assert_eq!(ModuleStateTree::open(path).unwrap().canonical_height(), 42);
        tree.put(b"one", if i == 0 { Some(vec![1]) } else { None })
            .unwrap();
    }
}

#[test]
fn transfer_enforces_chunk_and_proof_limits() {
    let dir = TempDir::new().unwrap();
    let tree = source(&dir.path().join("source"));
    let first = tree
        .snapshot()
        .unwrap()
        .export_chunk(None)
        .unwrap()
        .unwrap();
    for i in 0..4 {
        let mut chunk = first.clone();
        match i {
            0 => chunk.records.push(chunk.records[0].clone()),
            1 => chunk.records[0].1 = vec![0; MAX_RECORD_BYTES],
            2 => chunk.proof = vec![0; MAX_PROOF_BYTES + 1],
            _ => chunk.proof[..4].copy_from_slice(&u32::MAX.to_le_bytes()),
        }
        let mut restore = ModuleRestore::create(
            dir.path().join(format!("restore-{i}")),
            42,
            tree.root().unwrap(),
        )
        .unwrap();
        assert!(restore.add_chunk(chunk).is_err());
    }
    let mut large = ModuleStateTree::open(dir.path().join("large")).unwrap();
    large
        .put(b"large", Some(vec![0; MAX_RECORD_BYTES]))
        .unwrap();
    assert!(large.snapshot().unwrap().export_chunk(None).is_err());
}

#[test]
fn transfer_paginates_at_byte_limit_without_losing_records() {
    let dir = TempDir::new().unwrap();
    let mut tree = ModuleStateTree::open(dir.path().join("source")).unwrap();
    tree.commit(
        (0..3)
            .map(|i| (vec![i], Some(vec![i; MAX_RECORD_BYTES / 2])))
            .collect(),
    )
    .unwrap();
    let view = tree.snapshot().unwrap();
    let data = chunks(&view);
    assert_eq!(data.len(), 3);
    let mut restore = ModuleRestore::create(dir.path().join("restore"), 42, view.root()).unwrap();
    for chunk in data {
        assert_eq!(chunk.records.len(), 1);
        restore.add_chunk(chunk).unwrap();
    }
    assert_eq!(
        restore.finish().unwrap().load_all().unwrap(),
        tree.load_all().unwrap()
    );
}

#[test]
fn transfer_rejects_authenticated_records_that_overwrite_local_metadata() {
    let dir = TempDir::new().unwrap();
    let mut tree = ModuleStateTree::open(dir.path().join("source")).unwrap();
    tree.put(b"\0__canonical_version__", Some(vec![0; 8]))
        .unwrap();
    let view = tree.snapshot().unwrap();
    let path = dir.path().join("restore");
    let mut restore = ModuleRestore::create(&path, 42, view.root()).unwrap();
    assert!(
        restore
            .add_chunk(view.export_chunk(None).unwrap().unwrap())
            .is_err()
    );
    drop(restore);
    assert!(ModuleStateTree::open(path).is_err());
}
