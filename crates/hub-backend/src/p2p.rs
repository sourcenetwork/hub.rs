use bytes::{Buf, BufMut};
use commonware_codec::{Codec, EncodeSize, Error, RangeCfg, Read, Write};
use commonware_cryptography::sha256::Digest;
use commonware_glue::stateful::db::{AttachableResolver, Shared, p2p};
use commonware_storage::{
    merkle::mmr,
    qmdb::{
        self,
        sync::{FeedbackTx, Request, Response, ServeError, Source},
    },
};
use commonware_utils::NZU64;
use std::num::NonZeroU64;

use crate::{AccountsDb, CodeDb, StorageDb, native::NativeDb};

/// A persisted partition with a bounded operation codec for peer messages.
pub trait Partition:
    Source<
        Family = mmr::Family,
        Digest = Digest,
        Error = qmdb::Error<mmr::Family>,
        Op: Codec + Clone + std::fmt::Debug + Send + Sync,
    > + Sized
    + 'static
{
    /// Decode limits for one operation, including commit metadata.
    fn operation_config() -> <Self::Op as Read>::Cfg;

    /// Reject local records that cannot be decoded by a peer.
    fn accepts(operation: &Self::Op) -> bool;
}

impl Partition for NativeDb {
    fn operation_config() -> <Self::Op as Read>::Cfg {
        crate::native::operation_config()
    }
    fn accepts(operation: &Self::Op) -> bool {
        use crate::native::{MAX_KEY_BYTES, MAX_VALUE_BYTES};
        use commonware_storage::qmdb::any::operation::Operation;
        match operation {
            Operation::Update(record) => {
                record.key.len() <= MAX_KEY_BYTES
                    && record.next_key.len() <= MAX_KEY_BYTES
                    && record.value.len() <= MAX_VALUE_BYTES
            }
            Operation::Delete(key) => key.len() <= MAX_KEY_BYTES,
            Operation::CommitFloor(metadata, _) => {
                metadata.as_ref().is_none_or(|v| v.len() <= MAX_VALUE_BYTES)
            }
        }
    }
}

impl Partition for AccountsDb {
    fn operation_config() -> <Self::Op as Read>::Cfg {
        ((), ())
    }
    fn accepts(_: &Self::Op) -> bool {
        true
    }
}

impl Partition for StorageDb {
    fn operation_config() -> <Self::Op as Read>::Cfg {
        ((), ())
    }
    fn accepts(_: &Self::Op) -> bool {
        true
    }
}

/// Maximum bytecode or code-partition commit metadata accepted over peer transport.
/// Existing local journals retain their original decoding configuration.
pub const MAX_CODE_BYTES: usize = 1 << 20;

impl Partition for CodeDb {
    fn operation_config() -> <Self::Op as Read>::Cfg {
        ((), (RangeCfg::new(0..=MAX_CODE_BYTES), ()))
    }
    fn accepts(operation: &Self::Op) -> bool {
        use commonware_storage::qmdb::any::operation::Operation;
        match operation {
            Operation::Update(record) => record.1.len() <= MAX_CODE_BYTES,
            Operation::CommitFloor(metadata, _) => {
                metadata.as_ref().is_none_or(|v| v.len() <= MAX_CODE_BYTES)
            }
            Operation::Delete(_) => true,
        }
    }
}

mod serve;

/// Maximum operation count requested or served by a partition resolver.
pub const MAX_FETCH_OPS: NonZeroU64 = NZU64!(64);
/// Required network message limit, including the resolver's framing.
pub const MAX_MESSAGE_BYTES: u32 = 4 * 1024 * 1024;
/// Response payload budget, leaving room for the resolver's framing.
pub const MAX_RESPONSE_BYTES: usize = MAX_MESSAGE_BYTES as usize - 1024;

/// Persisted operation bytes decoded with the partition's peer limits.
pub struct WireOperation<DB: Partition>(pub(crate) DB::Op);

impl<DB: Partition> Clone for WireOperation<DB> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<DB: Partition> std::fmt::Debug for WireOperation<DB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<DB: Partition> Write for WireOperation<DB> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl<DB: Partition> EncodeSize for WireOperation<DB> {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl<DB: Partition> Read for WireOperation<DB> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, (): &()) -> Result<Self, Error> {
        DB::Op::read_cfg(buf, &DB::operation_config()).map(Self)
    }
}

/// Serving handle for Commonware's peer resolver actor.
pub struct WireDatabase<DB: Partition>(Shared<DB>);

impl<DB: Partition> std::fmt::Debug for WireDatabase<DB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireDatabase").finish_non_exhaustive()
    }
}

impl<DB: Partition> WireDatabase<DB> {
    /// Wrap an existing database; serving retains its read lock through proof generation.
    pub fn new(db: Shared<DB>) -> Shared<Self> {
        Shared::new("partition_resolver", Self(db))
    }
}

impl<DB: Partition> Source for WireDatabase<DB> {
    type Family = mmr::Family;
    type Digest = Digest;
    type Op = WireOperation<DB>;
    type Error = ServeError<mmr::Family>;

    async fn serve(
        &self,
        request: Request<Self::Family>,
    ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, FeedbackTx), Self::Error> {
        let db = self.0.read().await;
        let response = serve::response(&*db, bounded(request)).await?;
        Ok((map(response, WireOperation), None))
    }
}

/// Commonware mailbox whose operation codec applies partition record limits.
pub type WireMailbox<DB> = p2p::Mailbox<WireDatabase<DB>, mmr::Family, WireOperation<DB>, Digest>;

/// Partition sync source retaining Commonware's retries, cancellation and validation feedback.
pub struct Resolver<DB: Partition>(WireMailbox<DB>);

impl<DB: Partition> Clone for Resolver<DB> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<DB: Partition> std::fmt::Debug for Resolver<DB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver").finish_non_exhaustive()
    }
}

impl<DB: Partition> Resolver<DB> {
    /// Use an actor configured to serve at least [`MAX_FETCH_OPS`] operations per response.
    /// Its network must enforce [`MAX_MESSAGE_BYTES`] and a bounded receive backlog.
    pub const fn new(mailbox: WireMailbox<DB>) -> Self {
        Self(mailbox)
    }
}

impl<DB: Partition> Source for Resolver<DB> {
    type Family = mmr::Family;
    type Digest = Digest;
    type Op = DB::Op;
    type Error = p2p::ResponseDropped;

    async fn serve(
        &self,
        request: Request<Self::Family>,
    ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, FeedbackTx), Self::Error> {
        let (response, feedback) = self.0.serve(bounded(request)).await?;
        Ok((map(response, |op| op.0), feedback))
    }
}

impl<DB: Partition> AttachableResolver<DB> for Resolver<DB> {
    async fn attach_database(&self, db: Shared<DB>) {
        self.0.attach_database(WireDatabase::new(db));
    }
}

fn bounded(mut request: Request<mmr::Family>) -> Request<mmr::Family> {
    if let Request::Operations { max_ops, .. } = &mut request {
        *max_ops = (*max_ops).min(MAX_FETCH_OPS);
    }
    request
}

fn map<A, B>(
    response: Response<mmr::Family, A, Digest>,
    convert: impl Fn(A) -> B,
) -> Response<mmr::Family, B, Digest> {
    match response {
        Response::Operations { proof, operations } => Response::Operations {
            proof,
            operations: operations.into_iter().map(convert).collect(),
        },
        Response::Boundary {
            proof,
            op,
            pinned_nodes,
        } => Response::Boundary {
            proof,
            op: convert(op),
            pinned_nodes,
        },
    }
}

#[cfg(test)]
mod tests;
