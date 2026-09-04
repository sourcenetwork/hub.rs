//! State-sync source that never answers.
//!
//! commonware-glue's p2p QMDB resolver only serves databases whose operations
//! decode with a unit codec config, which excludes the variable-length EVM
//! partitions. Nodes therefore rebuild state by re-executing finalized blocks
//! fetched through marshal backfill instead of syncing QMDB operations.

use std::{convert::Infallible, future::Future, marker::PhantomData};

use commonware_glue::stateful::db::{AttachableResolver, Shared};
use commonware_storage::qmdb::sync::{Database, FeedbackTx, Request, Response, Source};

/// Sync source for `DB` that pends forever.
pub struct NoSync<DB>(PhantomData<fn() -> DB>);

impl<DB> NoSync<DB> {
    /// A source for one database.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<DB> Default for NoSync<DB> {
    fn default() -> Self {
        Self::new()
    }
}

impl<DB> Clone for NoSync<DB> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}

impl<DB> std::fmt::Debug for NoSync<DB> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoSync")
    }
}

impl<DB: Database + Sync + 'static> Source for NoSync<DB>
where
    DB::Op: Send + Sync,
{
    type Family = DB::Family;
    type Digest = DB::Digest;
    type Op = DB::Op;
    type Error = Infallible;

    fn serve<'a>(
        &'a self,
        _request: Request<Self::Family>,
    ) -> impl Future<
        Output = Result<(Response<Self::Family, Self::Op, Self::Digest>, FeedbackTx), Self::Error>,
    > + Send
    + 'a {
        std::future::pending()
    }
}

impl<DB: Send + Sync + 'static> AttachableResolver<DB> for NoSync<DB> {
    async fn attach_database(&self, _db: Shared<DB>) {}
}
