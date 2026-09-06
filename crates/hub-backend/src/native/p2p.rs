use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, Write};
use commonware_cryptography::sha256::Digest;
use commonware_glue::stateful::db::{AttachableResolver, Shared, p2p};
use commonware_storage::{
    merkle::mmr,
    qmdb::sync::{FeedbackTx, Request, Response, ServeError, Source},
};
use commonware_utils::NZU64;
use std::num::NonZeroU64;

use super::{NativeDb, Operation, operation_config};

/// Two maximum-size records, their successor keys and proofs fit below 4 MiB.
pub const MAX_FETCH_OPS: NonZeroU64 = NZU64!(2);

/// Native operation bytes with the same decoding limits as the storage journal.
#[derive(Clone, Debug)]
pub struct WireOperation(Operation);

impl Write for WireOperation {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl EncodeSize for WireOperation {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl Read for WireOperation {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, (): &()) -> Result<Self, Error> {
        Operation::read_cfg(buf, &operation_config()).map(Self)
    }
}

/// Serving handle for Commonware's peer resolver actor.
pub struct WireDatabase(Shared<NativeDb>);

impl std::fmt::Debug for WireDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireDatabase").finish_non_exhaustive()
    }
}

impl WireDatabase {
    /// Wrap an existing database; serving retains its read lock through proof generation.
    pub fn new(db: Shared<NativeDb>) -> Shared<Self> {
        Shared::new("native_resolver", Self(db))
    }
}

impl Source for WireDatabase {
    type Family = mmr::Family;
    type Digest = Digest;
    type Op = WireOperation;
    type Error = ServeError<mmr::Family>;

    async fn serve(
        &self,
        request: Request<Self::Family>,
    ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, FeedbackTx), Self::Error> {
        let (response, feedback) = self.0.serve(bounded(request)).await?;
        Ok((map(response, WireOperation), feedback))
    }
}

/// Commonware mailbox whose operation codec applies native record limits.
pub type WireMailbox = p2p::Mailbox<WireDatabase, mmr::Family, WireOperation, Digest>;

/// Native sync source retaining Commonware's retries, cancellation and validation feedback.
#[derive(Clone)]
pub struct Resolver(WireMailbox);

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver").finish_non_exhaustive()
    }
}

impl Resolver {
    /// Use an actor configured to serve at least [`MAX_FETCH_OPS`] operations per response.
    /// Its network must admit 4 MiB messages and enforce a bounded receive backlog.
    pub const fn new(mailbox: WireMailbox) -> Self {
        Self(mailbox)
    }
}

impl Source for Resolver {
    type Family = mmr::Family;
    type Digest = Digest;
    type Op = Operation;
    type Error = p2p::ResponseDropped;

    async fn serve(
        &self,
        request: Request<Self::Family>,
    ) -> Result<(Response<Self::Family, Self::Op, Self::Digest>, FeedbackTx), Self::Error> {
        let (response, feedback) = self.0.serve(bounded(request)).await?;
        Ok((map(response, |op| op.0), feedback))
    }
}

impl AttachableResolver<NativeDb> for Resolver {
    async fn attach_database(&self, db: Shared<NativeDb>) {
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
