//! File-backed secret store for DKG/reshare private material.

use std::{collections::BTreeMap, fs, path::PathBuf, sync::Arc};

use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    PublicKey,
    bls12381::{dkg::feldman_desmedt::DealerPrivMsg, primitives::group::Share},
    transcript::Summary,
};
use commonware_glue::dkg;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// JSON-file-backed [`dkg::SecretStore`] holding shares, dealer seeds, and dealings.
///
/// Material is stored as plaintext JSON, which is suitable for this example only.
#[derive(Clone, Debug)]
pub struct FileSecretStore {
    path: PathBuf,
    inner: Arc<Mutex<SecretData>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SecretData {
    shares: BTreeMap<u64, String>,
    seeds: BTreeMap<u64, String>,
    dealings: BTreeMap<String, String>,
}

impl FileSecretStore {
    /// Open the store at `path`, starting empty if the file does not exist.
    pub fn load(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let inner = if path.exists() {
            let contents = fs::read_to_string(&path)?;
            serde_json::from_str(&contents)?
        } else {
            SecretData::default()
        };
        Ok(Self {
            path,
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Seed the store with a trusted-setup share for `epoch`.
    pub fn put_initial_share(&self, epoch: Epoch, share: Share) -> anyhow::Result<()> {
        self.inner
            .lock()
            .shares
            .insert(epoch.get(), hex::encode(share.encode()));
        self.flush()
    }

    fn flush(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let contents = serde_json::to_string_pretty(&*self.inner.lock())?;
        fs::write(&self.path, contents)?;
        Ok(())
    }

    fn dealing_key<P: PublicKey>(epoch: Epoch, dealer: &P) -> String {
        format!("{}:{}", epoch.get(), hex::encode(dealer.encode()))
    }
}

impl dkg::SecretStore for FileSecretStore {
    async fn put_share(&mut self, epoch: Epoch, share: Share) {
        self.inner
            .lock()
            .shares
            .insert(epoch.get(), hex::encode(share.encode()));
        self.flush().expect("failed to flush share");
    }

    async fn get_share(&mut self, epoch: Epoch) -> Option<Share> {
        let raw = self.inner.lock().shares.get(&epoch.get()).cloned()?;
        let bytes = hex::decode(&raw).ok()?;
        Share::decode(bytes.as_slice()).ok()
    }

    async fn put_seed(&mut self, epoch: Epoch, seed: Summary) {
        self.inner
            .lock()
            .seeds
            .insert(epoch.get(), hex::encode(seed.encode()));
        self.flush().expect("failed to flush seed");
    }

    async fn get_seed(&mut self, epoch: Epoch) -> Option<Summary> {
        let raw = self.inner.lock().seeds.get(&epoch.get()).cloned()?;
        let bytes = hex::decode(&raw).ok()?;
        Summary::decode(bytes.as_slice()).ok()
    }

    async fn put_dealing<P: PublicKey>(&mut self, epoch: Epoch, dealer: P, private: DealerPrivMsg) {
        let key = Self::dealing_key(epoch, &dealer);
        self.inner
            .lock()
            .dealings
            .insert(key, hex::encode(private.encode()));
        self.flush().expect("failed to flush dealing");
    }

    async fn get_dealing<P: PublicKey>(
        &mut self,
        epoch: Epoch,
        dealer: &P,
    ) -> Option<DealerPrivMsg> {
        let key = Self::dealing_key(epoch, dealer);
        let raw = self.inner.lock().dealings.get(&key).cloned()?;
        let bytes = hex::decode(&raw).ok()?;
        DealerPrivMsg::decode(bytes.as_slice()).ok()
    }

    async fn prune(&mut self, min: Epoch) {
        let mut inner = self.inner.lock();
        inner.shares.retain(|epoch, _| *epoch >= min.get());
        inner.seeds.retain(|epoch, _| *epoch >= min.get());
        inner.dealings.retain(|key, _| {
            key.split_once(':')
                .and_then(|(epoch, _)| epoch.parse::<u64>().ok())
                .is_some_and(|epoch| epoch >= min.get())
        });
        drop(inner);
        self.flush().expect("failed to flush prune");
    }
}
