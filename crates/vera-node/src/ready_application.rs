//! Keep speculative DKG work behind recovered execution state.

use commonware_consensus::{Application, marshal::ancestry::Ancestry};
use commonware_runtime::tokio::Context;
use tokio::sync::watch;

#[derive(Clone)]
pub(crate) struct ReadyApplication<A> {
    inner: A,
    ready: watch::Receiver<bool>,
}

impl<A> ReadyApplication<A> {
    pub(crate) fn new(inner: A) -> (Self, watch::Sender<bool>) {
        let (sender, ready) = watch::channel(false);
        (Self { inner, ready }, sender)
    }
}

impl<A> Application<Context> for ReadyApplication<A>
where
    A: Application<Context>,
    A::Context: Send,
{
    type SigningScheme = A::SigningScheme;
    type Context = A::Context;
    type Block = A::Block;
    type Input = A::Input;

    async fn propose(
        &mut self,
        context: (Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
        input: Self::Input,
    ) -> Option<Self::Block> {
        if !*self.ready.borrow() {
            return None;
        }
        self.inner.propose(context, ancestry, input).await
    }

    async fn verify(
        &mut self,
        context: (Context, Self::Context),
        ancestry: impl Ancestry<Self::Block>,
    ) -> bool {
        if self.ready.wait_for(|ready| *ready).await.is_err() {
            // Startup failure cannot establish that a peer's proposal is invalid.
            return std::future::pending().await;
        }
        self.inner.verify(context, ancestry).await
    }
}
