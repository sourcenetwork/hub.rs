use super::*;
use crate::TreeSnapshot;

fn source(path: &Path, height: u64) -> [ModuleStateTree; 4] {
    let mut trees = open_module_trees(path).unwrap();
    for (i, tree) in trees.iter_mut().enumerate() {
        let next = tree
            .prepare(
                &tree.snapshot().unwrap(),
                vec![(b"key".to_vec(), Some(vec![i as u8, height as u8]))],
            )
            .unwrap();
        tree.commit_prepared(height, &next).unwrap();
    }
    trees
}

fn roots(trees: &[ModuleStateTree; 4]) -> [[u8; 32]; 4] {
    std::array::from_fn(|i| trees[i].root().unwrap().0)
}

fn feed(restore: &mut ModuleCheckpoint, module: usize, view: &TreeSnapshot) {
    let mut after = None;
    while let Some(chunk) = view.export_chunk(after).unwrap() {
        after = Some(jmt::KeyHash::with::<Sha256>(
            &chunk.records.last().unwrap().0,
        ));
        restore.add_chunk(module, chunk).unwrap();
    }
}

fn prepare(state: &Path, trees: &[ModuleStateTree; 4]) -> PreparedCheckpoint {
    let mut restore =
        ModuleCheckpoint::create(state, trees[0].canonical_height(), roots(trees)).unwrap();
    for (i, tree) in trees.iter().enumerate() {
        feed(&mut restore, i, &tree.snapshot().unwrap());
    }
    restore.finish().unwrap()
}

#[test]
fn checkpoint_publishes_all_modules_and_reopens_after_later_commits() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let legacy = source(&state, 1);
    let next = source(&dir.path().join("source"), 42);
    let prepared = prepare(&state, &next);
    assert!(!state.join("CURRENT").exists());
    assert_eq!(legacy[0].get(b"key").unwrap(), Some(vec![0, 1]));
    let mut installed = prepared.install().unwrap();
    assert_eq!(roots(&installed), roots(&next));
    assert_eq!(legacy[0].get(b"key").unwrap(), Some(vec![0, 1]));
    for tree in &mut installed {
        let next = tree
            .prepare(
                &tree.snapshot().unwrap(),
                vec![(b"later".to_vec(), Some(vec![7]))],
            )
            .unwrap();
        tree.commit_prepared(43, &next).unwrap();
    }
    let advanced = roots(&installed);
    drop(installed);
    let reopened = open_module_trees(&state).unwrap();
    assert_eq!(roots(&reopened), advanced);
    assert!(reopened.iter().all(|tree| tree.canonical_height() == 43));
    drop(reopened);
    let newer = source(&dir.path().join("newer"), 60);
    drop(prepare(&state, &newer).install().unwrap());
    assert_eq!(roots(&open_module_trees(&state).unwrap()), roots(&newer));
}

#[test]
fn checkpoint_interruption_and_failed_roots_preserve_the_active_generation() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let first = source(&dir.path().join("first"), 1);
    drop(prepare(&state, &first).install().unwrap());
    let selected = fs::read(state.join("CURRENT")).unwrap();
    let next = source(&dir.path().join("next"), 42);
    let mut interrupted = ModuleCheckpoint::create(&state, 42, roots(&next)).unwrap();
    assert!(ModuleCheckpoint::create(&state, 42, roots(&next)).is_err());
    feed(&mut interrupted, 0, &next[0].snapshot().unwrap());
    drop(interrupted);
    let unfinished = ModuleCheckpoint::create(&state, 42, roots(&next)).unwrap();
    assert!(unfinished.finish().is_err());
    drop(prepare(&state, &next));
    assert_eq!(fs::read(state.join("CURRENT")).unwrap(), selected);
    assert_eq!(roots(&open_module_trees(&state).unwrap()), roots(&first));
    drop(prepare(&state, &next).install().unwrap());
    assert_eq!(roots(&open_module_trees(state).unwrap()), roots(&next));
}

#[test]
fn checkpoint_rejects_corrupt_selection_and_missing_modules_without_creating_them() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let first = source(&dir.path().join("first"), 42);
    drop(prepare(&state, &first).install().unwrap());
    let selection = fs::read(state.join("CURRENT")).unwrap();
    for bytes in [vec![], vec![0; 31], vec![0; 33], vec![0; 32]] {
        fs::write(state.join("CURRENT"), bytes).unwrap();
        assert!(open_module_trees(&state).is_err());
    }
    fs::write(state.join("CURRENT"), &selection).unwrap();
    let generation = generation_path(&state, &selection.try_into().unwrap());
    let missing = generation.join("bulletin");
    fs::rename(&missing, generation.join("removed-bulletin")).unwrap();
    assert!(open_module_trees(&state).is_err());
    assert!(!missing.exists());
    fs::rename(generation.join("removed-bulletin"), &missing).unwrap();
    let mut manifest = fs::read(generation.join("MANIFEST")).unwrap();
    manifest[12] ^= 1;
    fs::write(generation.join("MANIFEST"), manifest).unwrap();
    assert!(open_module_trees(&state).is_err());
    #[cfg(unix)]
    {
        fs::remove_file(state.join("CURRENT")).unwrap();
        std::os::unix::fs::symlink("absent-selection", state.join("CURRENT")).unwrap();
        assert!(open_module_trees(&state).is_err());
        assert!(
            !state.join("acp").exists(),
            "invalid selection must not create a fallback store"
        );
    }
}

#[test]
fn checkpoint_empty_stores_preserve_height() {
    let dir = tempfile::tempdir().unwrap();
    let mut empty = open_module_trees(dir.path().join("empty")).unwrap();
    for tree in &mut empty {
        tree.commit_prepared(42, &tree.snapshot().unwrap()).unwrap();
    }
    let state = dir.path().join("state");
    drop(prepare(&state, &empty).install().unwrap());
    let restored = open_module_trees(state).unwrap();
    assert!(restored.iter().all(|tree| tree.canonical_height() == 42));
    assert_eq!(roots(&restored), roots(&empty));
}

#[test]
fn checkpoint_export_pins_a_retained_height_through_retention_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let mut tree = ModuleStateTree::open(dir.path().join("source")).unwrap();
    for height in 1..=2 {
        let next = tree
            .prepare(
                &tree.snapshot().unwrap(),
                vec![(b"key".to_vec(), Some(vec![height]))],
            )
            .unwrap();
        tree.commit_prepared(u64::from(height), &next).unwrap();
    }
    let pinned = tree.snapshot_at_height(1).unwrap();
    for height in 3..=70 {
        tree.commit_prepared(height, &tree.snapshot().unwrap())
            .unwrap();
    }
    assert!(tree.snapshot_at_height(1).is_err());
    let mut restored = ModuleRestore::create(dir.path().join("restore"), 1, pinned.root()).unwrap();
    restored
        .add_chunk(pinned.export_chunk(None).unwrap().unwrap())
        .unwrap();
    assert_eq!(
        restored.finish().unwrap().get(b"key").unwrap(),
        Some(vec![1])
    );
}
