use std::{num::NonZeroU32, time::Duration};
use tokio::sync::{Semaphore, SemaphorePermit};

use super::{ClientError, VeraClient};

#[derive(Debug)]
pub(super) struct RequestQueue {
    slots: Semaphore,
    timeout: Duration,
}

impl VeraClient {
    /// Enable bounded FIFO waiting for occupied HTTP request slots.
    ///
    /// At most `maximum` callers wait, for at most `timeout` each. A full queue
    /// or expired wait returns `ClientCapacityExhausted` before sending bytes.
    /// Cancellation releases queue capacity. The wait is separate from the
    /// ten-second HTTP deadline; callers should also bound the whole workflow.
    /// Waiting is disabled by default and does not increase active HTTP capacity.
    #[must_use]
    pub fn with_request_queue(mut self, maximum: NonZeroU32, timeout: Duration) -> Self {
        self.request_queue = Some(RequestQueue {
            slots: Semaphore::new(maximum.get() as usize),
            timeout,
        });
        self
    }

    pub(super) async fn request_permit(&self) -> Result<SemaphorePermit<'_>, ClientError> {
        if let Ok(permit) = self.requests.try_acquire() {
            return Ok(permit);
        }
        let queue = self
            .request_queue
            .as_ref()
            .ok_or(ClientError::ClientCapacityExhausted)?;
        let _waiting = queue
            .slots
            .try_acquire()
            .map_err(|_| ClientError::ClientCapacityExhausted)?;
        tokio::time::timeout(queue.timeout, self.requests.acquire())
            .await
            .map_err(|_| ClientError::ClientCapacityExhausted)?
            .map_err(|_| ClientError::ClientCapacityExhausted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };

    #[tokio::test]
    async fn bounded_queue_preserves_order_and_releases_cancelled_waiters() {
        let client = VeraClient::new("http://unused")
            .with_max_concurrent_requests(NonZeroU32::new(1).unwrap())
            .with_request_queue(NonZeroU32::new(2).unwrap(), Duration::from_secs(5));
        let active = client.request_permit().await.unwrap();
        let mut context = Context::from_waker(Waker::noop());
        let mut cancelled = Box::pin(client.request_permit());
        let mut first = Box::pin(client.request_permit());
        assert!(cancelled.as_mut().poll(&mut context).is_pending());
        assert!(first.as_mut().poll(&mut context).is_pending());
        assert!(matches!(
            client.request_permit().await,
            Err(ClientError::ClientCapacityExhausted)
        ));
        drop(cancelled);
        let mut second = Box::pin(client.request_permit());
        assert!(second.as_mut().poll(&mut context).is_pending());
        drop(active);
        assert!(matches!(
            client.request_permit().await,
            Err(ClientError::ClientCapacityExhausted)
        ));
        assert!(second.as_mut().poll(&mut context).is_pending());
        let Poll::Ready(Ok(first)) = first.as_mut().poll(&mut context) else {
            panic!("oldest waiter did not receive the released slot");
        };
        let mut newest = Box::pin(client.request_permit());
        assert!(newest.as_mut().poll(&mut context).is_pending());
        drop(first);
        assert!(newest.as_mut().poll(&mut context).is_pending());
        let Poll::Ready(Ok(second)) = second.as_mut().poll(&mut context) else {
            panic!("second waiter did not receive the released slot");
        };
        drop(second);
        assert!(matches!(
            newest.as_mut().poll(&mut context),
            Poll::Ready(Ok(_))
        ));
        assert!(client.request_permit().await.is_ok());
    }

    #[tokio::test]
    async fn expired_wait_releases_queue_capacity() {
        let client = VeraClient::new("http://unused")
            .with_max_concurrent_requests(NonZeroU32::new(1).unwrap())
            .with_request_queue(NonZeroU32::new(1).unwrap(), Duration::from_millis(10));
        let active = client.request_permit().await.unwrap();
        assert!(matches!(
            client.request_permit().await,
            Err(ClientError::ClientCapacityExhausted)
        ));
        let mut next = Box::pin(client.request_permit());
        let mut context = Context::from_waker(Waker::noop());
        assert!(next.as_mut().poll(&mut context).is_pending());
        drop(active);
        assert!(matches!(
            next.as_mut().poll(&mut context),
            Poll::Ready(Ok(_))
        ));
    }
}
