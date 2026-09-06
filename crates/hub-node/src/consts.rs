//! Tunables shared by every actor in the node.

use std::num::{NonZeroU16, NonZeroU32, NonZeroUsize};

use commonware_cryptography::bls12381::{
    dkg::feldman_desmedt::Reveal,
    primitives::sharing::{Mode, ModeVersion},
};
use commonware_runtime::Quota;
use commonware_utils::{NZU16, NZU32, NZUsize};

/// Namespace for every consensus signature; light clients verify against it.
pub const NAMESPACE: &[u8] = b"_COMMONWARE_HUB_SIMPLEX";
/// Namespace suffix for the authenticated transport handshake.
pub const P2P_SUFFIX: &[u8] = b"_P2P";
/// Maximum entries accepted in each DKG participant set.
pub const MAX_PARTICIPANTS: NonZeroU32 = NZU32!(64);
/// Share derivation mode used by DKG and reshare ceremonies.
pub const SHARING_MODE: Mode = Mode::NonZeroCounter;
/// Revealed-share calculation used by DKG and reshare ceremonies.
pub const REVEAL: Reveal = Reveal::V1;
/// Newest sharing mode version this binary accepts.
pub const MAX_SUPPORTED_MODE: ModeVersion = ModeVersion::v0();
/// Logical page size that keeps physical pages 4096-byte aligned.
pub const PAGE_SIZE: NonZeroU16 = NZU16!(4084);
/// Pages held by the shared page cache.
pub const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(4096);
/// Buffer size for journal replay and writes.
pub const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024 * 1024);
/// Mailbox capacity for every actor.
pub const MAILBOX_SIZE: NonZeroUsize = NZUsize!(1024);
/// Per-peer message quota for every P2P channel.
pub const MESSAGE_RATE: Quota = Quota::per_second(NZU32!(1000));
/// Maximum P2P message size in bytes.
pub const MAX_MESSAGE_SIZE: u32 = 4 * 1024 * 1024;
/// Maximum transactions per block.
pub const MAX_BLOCK_TXS: usize = 64;
/// Maximum encoded transaction size.
pub const MAX_TX_BYTES: usize = 65_536;

/// P2P channel carrying simplex votes.
pub const VOTE_CHANNEL: u64 = 0;
/// P2P channel carrying simplex certificates.
pub const CERTIFICATE_CHANNEL: u64 = 1;
/// P2P channel for orchestrator resolver traffic.
pub const RESOLVER_CHANNEL: u64 = 2;
/// P2P channel for marshal block backfill.
pub const BACKFILL_CHANNEL: u64 = 3;
/// P2P channel for proposed block broadcast.
pub const BROADCAST_CHANNEL: u64 = 4;
/// State-transfer channels in accounts, storage, code, ACP, bulletin, hub and sequence order.
pub const QMDB_CHANNELS: [u64; 7] = [9, 10, 11, 12, 13, 14, 15];
/// P2P channel for retained execution-history chunks.
pub const HISTORY_CHANNEL: u64 = 16;
/// P2P channel for private reshare dealings and acks.
pub const DKG_CHANNEL: u64 = 6;
/// P2P channel for the DKG probe.
pub const DKG_PROBE_CHANNEL: u64 = 7;
/// P2P channel for transaction gossip.
pub const MEMPOOL_CHANNEL: u64 = 8;
