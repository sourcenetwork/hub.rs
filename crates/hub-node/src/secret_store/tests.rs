use super::*;
use std::io::Read as _;

#[test]
fn updates_replace_complete_files_and_publish_only_after_success() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secrets.json");
    let store = FileSecretStore::load(&path).unwrap();
    store
        .update(|data| {
            data.seeds.insert(1, "first".into());
        })
        .unwrap();
    let original = fs::read(&path).unwrap();
    let mut previous = fs::File::open(&path).unwrap();
    store
        .update(|data| {
            data.seeds.insert(2, "second".into());
        })
        .unwrap();
    let mut retained = Vec::new();
    previous.read_to_end(&mut retained).unwrap();
    assert_eq!(
        retained, original,
        "an update must not truncate the existing inode"
    );
    assert_eq!(
        FileSecretStore::load(&path)
            .unwrap()
            .inner
            .lock()
            .seeds
            .len(),
        2
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let backup = directory.path().join("retained.json");
    fs::rename(&path, &backup).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(
        store
            .update(|data| {
                data.seeds.insert(3, "uncommitted".into());
            })
            .is_err()
    );
    assert_eq!(store.inner.lock().seeds.len(), 2);
    fs::remove_dir(&path).unwrap();
    fs::rename(backup, &path).unwrap();
    assert_eq!(
        FileSecretStore::load(&path)
            .unwrap()
            .inner
            .lock()
            .seeds
            .len(),
        2
    );
    assert!(!format!("{store:?}").contains("first"));
    fs::write(&path, []).unwrap();
    assert!(FileSecretStore::load(&path).is_err());
    assert!(fs::read(&path).unwrap().is_empty());
}

#[test]
fn cloned_writers_serialize_updates_without_losing_private_material() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secrets.json");
    let store = FileSecretStore::load(&path).unwrap();
    std::thread::scope(|scope| {
        for writer in 0..4 {
            let store = store.clone();
            scope.spawn(move || {
                for index in 0..8 {
                    store
                        .update(|data| {
                            data.seeds.insert(writer * 8 + index, "seed".into());
                        })
                        .unwrap();
                }
            });
        }
    });
    assert_eq!(store.inner.lock().seeds.len(), 32);
    assert_eq!(
        FileSecretStore::load(path)
            .unwrap()
            .inner
            .lock()
            .seeds
            .len(),
        32
    );
}
