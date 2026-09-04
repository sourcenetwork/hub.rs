//! Per-database sync targets carried by every block.
//!
//! The stateful actor checks a block's merkleized batches against these
//! targets, and state sync uses them to know which operation range and root
//! each EVM partition must reach.

use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};

use commonware_cryptography::sha256::Digest;

use crate::ConsensusDigest;

/// Root and operation range of one QMDB partition after a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DbTarget {
    /// Root of the partition's authenticated log.
    pub root: ConsensusDigest,
    /// First live operation (inactivity floor).
    pub floor: u64,
    /// Size of the log after the block.
    pub tip: u64,
}

impl Default for DbTarget {
    fn default() -> Self {
        Self {
            root: Digest([0u8; 32]),
            floor: 0,
            tip: 0,
        }
    }
}

impl Write for DbTarget {
    fn write(&self, buf: &mut impl BufMut) {
        self.root.write(buf);
        self.floor.write(buf);
        self.tip.write(buf);
    }
}

impl FixedSize for DbTarget {
    const SIZE: usize = ConsensusDigest::SIZE + u64::SIZE + u64::SIZE;
}

impl Read for DbTarget {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            root: ConsensusDigest::read(buf)?,
            floor: u64::read(buf)?,
            tip: u64::read(buf)?,
        })
    }
}

/// Sync targets for the accounts, storage, and code partitions.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DbTargets {
    /// Accounts partition target.
    pub accounts: DbTarget,
    /// Storage partition target.
    pub storage: DbTarget,
    /// Code partition target.
    pub code: DbTarget,
}

impl Write for DbTargets {
    fn write(&self, buf: &mut impl BufMut) {
        self.accounts.write(buf);
        self.storage.write(buf);
        self.code.write(buf);
    }
}

impl FixedSize for DbTargets {
    const SIZE: usize = DbTarget::SIZE * 3;
}

impl Read for DbTargets {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self {
            accounts: DbTarget::read(buf)?,
            storage: DbTarget::read(buf)?,
            code: DbTarget::read(buf)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use commonware_codec::{DecodeExt, Encode};

    use super::*;

    #[test]
    fn roundtrip() {
        let targets = DbTargets {
            accounts: DbTarget {
                root: Digest([1u8; 32]),
                floor: 3,
                tip: 9,
            },
            storage: DbTarget::default(),
            code: DbTarget {
                root: Digest([7u8; 32]),
                floor: 0,
                tip: 1,
            },
        };
        let encoded = targets.encode();
        assert_eq!(encoded.len(), DbTargets::SIZE);
        assert_eq!(DbTargets::decode(encoded).unwrap(), targets);
    }
}
