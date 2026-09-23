//! Process crash points available only in fault-injection builds.

use std::{io::Write as _, path::Path};

pub(crate) fn after_module_commit(marker: &Path, height: u64, index: usize) {
    let configured = match std::fs::read_to_string(marker) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => panic!("read crash marker: {error}"),
    };
    let requested: usize = configured
        .trim()
        .parse()
        .expect("module index in crash marker");
    assert!(requested < 4, "invalid module crash index");
    if requested != index {
        return;
    }
    std::fs::remove_file(marker).expect("consume crash marker");
    let temporary = marker.with_extension("tmp");
    let mut witness = std::fs::File::create(&temporary).expect("create crash witness");
    writeln!(witness, "{height} {index}").expect("write crash witness");
    witness.sync_all().expect("sync crash witness");
    std::fs::rename(temporary, marker.with_extension("hit")).expect("publish crash witness");
    std::process::abort();
}
