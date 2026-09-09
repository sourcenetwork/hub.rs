use super::*;
use std::io::Read as _;

#[test]
fn updates_replace_complete_files_and_publish_only_after_success() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secrets.json");
    let store = FileSecretStore::load(&path).unwrap();
    store
        .update(|data| {
            data.seeds.insert(1, hex::encode([1; 32]));
        })
        .unwrap();
    let original = fs::read(&path).unwrap();
    let mut previous = fs::File::open(&path).unwrap();
    store
        .update(|data| {
            data.seeds.insert(2, hex::encode([2; 32]));
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
                data.seeds.insert(3, hex::encode([3; 32]));
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
    assert!(!format!("{store:?}").contains(&hex::encode([1; 32])));
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
                            data.seeds
                                .insert(writer * 8 + index, hex::encode([writer as u8; 32]));
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

#[test]
fn corrupt_private_material_fails_loading_without_changing_the_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secrets.json");
    for section in ["shares", "seeds", "dealings"] {
        for value in [
            "not-hex".to_owned(),
            "".to_owned(),
            hex::encode([0; 31]),
            hex::encode([0; 128]),
        ] {
            let mut document = serde_json::json!({"shares": {}, "seeds": {}, "dealings": {}});
            let key = if section == "dealings" { "1:abcd" } else { "1" };
            document[section][key] = value.clone().into();
            let original = serde_json::to_vec(&document).unwrap();
            fs::write(&path, &original).unwrap();
            let error = FileSecretStore::load(&path).unwrap_err();
            assert_eq!(fs::read(&path).unwrap(), original);
            if !value.is_empty() {
                assert!(!error.to_string().contains(&value));
            }
        }
    }
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(FileSecretStore::load(&path).is_err());
}

#[tokio::test]
async fn valid_material_reopens_and_invalid_dealing_keys_fail() {
    use commonware_cryptography::bls12381::primitives::group::{Private, Scalar};
    use commonware_glue::dkg::SecretStore as _;
    use commonware_utils::Participant;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secrets.json");
    let mut store = FileSecretStore::load(&path).unwrap();
    let share = Share::new(Participant::new(1), Private::new(Scalar::from(1u64)));
    let expected = share.encode();
    store.put_share(Epoch::new(1), share).await;
    let seed = Summary::decode(&[7u8; 32][..]).unwrap();
    store.put_seed(Epoch::new(1), seed).await;
    let dealing = hex::encode(DealerPrivMsg::new(Scalar::from(1u64)).encode());
    store
        .update(|data| {
            data.dealings.insert("1:abcd".into(), dealing.clone());
        })
        .unwrap();
    let mut reopened = FileSecretStore::load(&path).unwrap();
    assert_eq!(
        reopened.get_share(Epoch::new(1)).await.unwrap().encode(),
        expected
    );
    assert_eq!(reopened.get_seed(Epoch::new(1)).await.unwrap(), seed);
    assert!(reopened.get_share(Epoch::new(2)).await.is_none());
    for key in ["bad", "01:abcd", "1:", "1:xyz", "1:ABCD"] {
        let document = serde_json::json!({"shares": {}, "seeds": {}, "dealings": {key: dealing}});
        let original = serde_json::to_vec(&document).unwrap();
        fs::write(&path, &original).unwrap();
        assert!(FileSecretStore::load(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}

#[cfg(unix)]
#[test]
fn missing_secret_link_target_is_not_an_empty_store() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secrets.json");
    std::os::unix::fs::symlink("missing-target", &path).unwrap();
    assert!(FileSecretStore::load(&path).is_err());
    assert_eq!(
        fs::read_link(&path).unwrap(),
        std::path::PathBuf::from("missing-target")
    );
    fs::remove_file(&path).unwrap();
    assert!(FileSecretStore::load(&path).is_ok());
}
