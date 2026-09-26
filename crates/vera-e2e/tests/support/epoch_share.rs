use std::{fs, path::Path, time::Duration};

use commonware_codec::DecodeExt as _;
use commonware_cryptography::bls12381::primitives::group::Share;
use serde_json::Value;

fn ready_epoch(document: &Value, minimum: u64) -> Option<u64> {
    // Seeds advance even when derivation fails. An older share does not make
    // the replica ready to sign in its latest entered epoch.
    let epoch = document
        .get("seeds")?
        .as_object()?
        .keys()
        .filter_map(|key| key.parse::<u64>().ok())
        .max()?;
    if epoch < minimum {
        return None;
    }
    let encoded = document.get("shares")?.get(epoch.to_string())?.as_str()?;
    let bytes = hex::decode(encoded).ok()?;
    Share::decode(commonware_codec::Copying(bytes.as_slice())).ok()?;
    Some(epoch)
}

pub(super) async fn wait_for_epoch_share(path: &Path, minimum: u64, deadline: Duration) {
    tokio::time::timeout(deadline, async {
        loop {
            // The secret store replaces this file atomically after syncing it.
            // Read only readiness; never include private material in failures.
            let bytes = fs::read(path).expect("read replica secret store");
            let document: Value =
                serde_json::from_slice(&bytes).expect("decode replica secret store");
            if ready_epoch(&document, minimum).is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("replica must persist a share for its latest entered epoch");
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Encode as _;
    use serde_json::json;
    use vera_e2e::cluster::KeySet;

    #[test]
    fn readiness_requires_a_valid_share_for_the_latest_entered_epoch() {
        let keys = KeySet::builder().seed(9041).build().unwrap();
        let share = hex::encode(keys.share(3).unwrap().encode());
        let mut document = json!({"shares": {"9": share}, "seeds": {"9": "", "10": ""}});
        assert_eq!(ready_epoch(&document, 9), None);
        document["shares"]["10"] = document["shares"]["9"].clone();
        assert_eq!(ready_epoch(&document, 9), Some(10));
        assert_eq!(ready_epoch(&document, 11), None);
        document["shares"]["10"] = json!("00");
        assert_eq!(ready_epoch(&document, 9), None);
        assert_eq!(ready_epoch(&json!({"shares": {}, "seeds": {}}), 0), None);
    }
}
