//! Owner-only file writes for key material.

use std::io::Write;
use std::path::Path;

/// Write `bytes` to `path`, creating the file readable only by its owner.
///
/// Permissions are set at creation, not corrected afterwards, so the key
/// material is never briefly world-readable. The file is synced before
/// returning so a node started against it reads durable material.
pub fn write_private(path: impl AsRef<Path>, bytes: &[u8]) -> std::io::Result<()> {
    #[allow(unused_mut)]
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn created_files_are_owner_only() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("validator.key");
        write_private(&path, &[7; 32]).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = path.metadata().unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), vec![7; 32]);
    }
}
