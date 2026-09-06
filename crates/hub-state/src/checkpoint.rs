use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use jmt::RootHash;
use sha2::{Digest, Sha256};

use crate::{ModuleRestore, ModuleStateTree, SnapshotChunk};

const MODULES: [&str; 4] = ["acp", "bulletin", "hub", "nonces"];
const HEADER_BYTES: usize = 140;
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Open the selected native generation, or the original layout on a fresh installation.
/// Selected generations must contain every database and a complete checkpoint manifest.
pub fn open_module_trees(state_dir: impl AsRef<Path>) -> Result<[ModuleStateTree; 4]> {
    let state_dir = state_dir.as_ref();
    let current = state_dir.join("CURRENT");
    let selected = match File::open(&current) {
        Ok(file) => Some(read_fixed::<32>(file)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ensure!(
                fs::symlink_metadata(&current).is_err(),
                "unreadable module checkpoint selection"
            );
            None
        }
        Err(e) => return Err(e.into()),
    };
    let directory = selected.map_or_else(
        || state_dir.to_path_buf(),
        |id| generation_path(state_dir, &id),
    );
    let header = if selected.is_some() {
        let header = read_fixed::<HEADER_BYTES>(File::open(directory.join("MANIFEST"))?)?;
        ensure!(
            &header[..4] == b"VMS1",
            "unsupported module checkpoint format"
        );
        for name in MODULES {
            ensure!(
                directory.join(name).join("CURRENT").is_file(),
                "missing checkpoint module {name}"
            );
        }
        Some(header)
    } else {
        None
    };
    let mut trees = Vec::with_capacity(4);
    for (index, name) in MODULES.into_iter().enumerate() {
        let tree = ModuleStateTree::open(directory.join(name))?;
        if let Some(header) = &header {
            let height = u64::from_le_bytes(header[4..12].try_into()?);
            ensure!(
                tree.canonical_height() >= height,
                "module is behind its checkpoint"
            );
            let root = tree.root()?;
            if tree.canonical_height() == height {
                ensure!(
                    root.0 == header[12 + index * 32..44 + index * 32],
                    "checkpoint module root mismatch"
                );
            }
        }
        trees.push(tree);
    }
    Ok(trees.try_into().expect("four module trees"))
}

/// Restore all four native stores into an unpublished generation.
/// The caller must authenticate the supplied roots against the selected revision.
#[derive(Debug)]
pub struct ModuleCheckpoint {
    state_dir: PathBuf,
    id: [u8; 32],
    header: [u8; HEADER_BYTES],
    lock: File,
    restores: [ModuleRestore; 4],
}

impl ModuleCheckpoint {
    /// Start a single installer without modifying the active generation.
    /// The parent of `state_dir` must already exist.
    pub fn create(state_dir: impl AsRef<Path>, height: u64, roots: [[u8; 32]; 4]) -> Result<Self> {
        let state_dir = state_dir.as_ref().to_path_buf();
        match fs::create_dir(&state_dir) {
            Ok(()) => {
                let parent = state_dir
                    .parent()
                    .filter(|path| !path.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                sync_directory(parent)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && state_dir.is_dir() => {}
            Err(e) => return Err(e.into()),
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state_dir.join("INSTALL.lock"))?;
        lock.try_lock()
            .context("another module checkpoint installer is active")?;
        let mut header = [0; HEADER_BYTES];
        header[..4].copy_from_slice(b"VMS1");
        header[4..12].copy_from_slice(&height.to_le_bytes());
        for (i, root) in roots.iter().enumerate() {
            header[12 + i * 32..44 + i * 32].copy_from_slice(root);
        }
        let mut hash = Sha256::new();
        hash.update(header);
        hash.update(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_nanos()
                .to_le_bytes(),
        );
        hash.update(std::process::id().to_le_bytes());
        hash.update(
            NEXT_GENERATION
                .fetch_add(1, Ordering::Relaxed)
                .to_le_bytes(),
        );
        let id = hash.finalize().into();
        let directory = generation_path(&state_dir, &id);
        fs::create_dir_all(state_dir.join("snapshots"))?;
        fs::create_dir(&directory)?;
        let restores = MODULES
            .into_iter()
            .zip(roots)
            .map(|(name, root)| ModuleRestore::create(directory.join(name), height, RootHash(root)))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            state_dir,
            id,
            header,
            lock,
            restores: restores.try_into().expect("four module restores"),
        })
    }

    /// Verify the next chunk for ACP, bulletin, identity or native sequences (indices 0–3).
    pub fn add_chunk(&mut self, module: usize, chunk: SnapshotChunk) -> Result<()> {
        self.restores
            .get_mut(module)
            .context("invalid snapshot module index")?
            .add_chunk(chunk)
    }

    /// Verify every complete root and persist an unpublished checkpoint manifest.
    pub fn finish(self) -> Result<PreparedCheckpoint> {
        let trees = self
            .restores
            .into_iter()
            .map(ModuleRestore::finish)
            .collect::<Result<Vec<_>>>()?;
        let directory = generation_path(&self.state_dir, &self.id);
        for name in MODULES {
            sync_directory(&directory.join(name))?;
        }
        let mut manifest = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("MANIFEST"))?;
        manifest.write_all(&self.header)?;
        manifest.sync_all()?;
        sync_directory(&directory)?;
        sync_directory(&self.state_dir.join("snapshots"))?;
        sync_directory(&self.state_dir)?;
        Ok(PreparedCheckpoint {
            state_dir: self.state_dir,
            id: self.id,
            _lock: self.lock,
            trees: trees.try_into().expect("four restored module trees"),
        })
    }
}

/// A verified generation ready for publication while execution is stopped for synchronization.
/// Publication selects native stores only; the caller must coordinate execution and history.
#[derive(Debug)]
pub struct PreparedCheckpoint {
    state_dir: PathBuf,
    id: [u8; 32],
    _lock: File,
    trees: [ModuleStateTree; 4],
}

impl PreparedCheckpoint {
    /// Atomically select the complete generation, then persist the selection directory.
    /// If this returns an I/O error, restart before using either generation: rename may have succeeded.
    pub fn install(self) -> Result<[ModuleStateTree; 4]> {
        let pending = self
            .state_dir
            .join(format!("CURRENT.{}.pending", hex_id(&self.id)));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)?;
        file.write_all(&self.id)?;
        file.sync_all()?;
        fs::rename(pending, self.state_dir.join("CURRENT"))?;
        sync_directory(&self.state_dir)?;
        Ok(self.trees)
    }
}

fn generation_path(state_dir: &Path, id: &[u8; 32]) -> PathBuf {
    state_dir.join("snapshots").join(hex_id(id))
}

fn hex_id(id: &[u8; 32]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_fixed<const N: usize>(mut file: File) -> Result<[u8; N]> {
    let mut bytes = [0; N];
    file.read_exact(&mut bytes)?;
    ensure!(file.read(&mut [0])? == 0, "trailing module checkpoint data");
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all().map_err(Into::into)
}

#[cfg(test)]
mod tests;
