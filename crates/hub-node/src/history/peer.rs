use std::{sync::Arc, time::Duration};

use anyhow::{Context as _, Result, ensure};
use bytes::Bytes;
use commonware_p2p::{Blocker, Provider, Receiver, Sender};
use commonware_resolver::{Consumer, Delivery, Outcome, Resolver as _, TargetedResolver as _, p2p};
use commonware_runtime::{Handle, tokio::Context};
use commonware_utils::{NZUsize, channel::oneshot, non_empty_vec, sequence::FixedBytes};
use hub_domain::PublicKey;
use parking_lot::Mutex;

use super::{FinalizedHistory, HISTORY_CHUNK_BYTES, HistoryChunk, HistoryLimits};

type Key = FixedBytes<16>;
type Mailbox = p2p::Mailbox<Key, PublicKey>;

struct Waiting {
    key: Key,
    maximum: usize,
    answer: oneshot::Sender<Result<HistoryChunk>>,
}

#[derive(Clone, Default)]
struct DeliverySlot(Arc<Mutex<Option<Waiting>>>);

impl Consumer for DeliverySlot {
    type Key = Key;
    type Value = Bytes;
    type Subscriber = ();
    type Outcome = Outcome;

    fn deliver(&mut self, delivery: Delivery<Key, ()>, value: Bytes) -> oneshot::Receiver<Outcome> {
        let (verdict, receiver) = oneshot::channel();
        let mut slot = self.0.lock();
        let Some(waiting) = slot.as_ref().filter(|w| w.key == delivery.key) else {
            let _ = verdict.send(Outcome::Ignored);
            return receiver;
        };
        let offset = u64::from_be_bytes(delivery.key[8..].try_into().expect("fixed key"));
        let Ok(chunk) = decode_chunk(&value, offset) else {
            let _ = verdict.send(Outcome::Invalid);
            return receiver;
        };
        let result = if chunk.total > waiting.maximum as u64 {
            Err(anyhow::anyhow!("history record exceeds assembly limit"))
        } else {
            Ok(chunk)
        };
        let waiting = slot.take().expect("matching delivery slot");
        let _ = waiting.answer.send(result);
        // A chunk alone cannot authenticate the record; do not score it as valid peer data.
        let _ = verdict.send(Outcome::Ignored);
        receiver
    }
}

#[derive(Clone)]
struct HistoryProducer(Arc<FinalizedHistory>);

impl p2p::Producer for HistoryProducer {
    type Key = Key;

    fn produce(&mut self, key: Key) -> oneshot::Receiver<Bytes> {
        let (answer, receiver) = oneshot::channel();
        let height = u64::from_be_bytes(key[..8].try_into().expect("fixed key"));
        let offset = u64::from_be_bytes(key[8..].try_into().expect("fixed key"));
        if let Ok(chunk) = self.0.record_chunk(height, offset, HISTORY_CHUNK_BYTES) {
            let mut response = Vec::with_capacity(16 + chunk.bytes.len());
            response.extend_from_slice(&chunk.total.to_be_bytes());
            response.extend_from_slice(&chunk.offset.to_be_bytes());
            response.extend_from_slice(&chunk.bytes);
            let _ = answer.send(response.into());
        }
        receiver
    }
}

/// One sequential history importer backed by Commonware's authenticated peer resolver.
/// A record is only accepted by the destination after ancestry and receipt verification.
pub struct HistoryPeer {
    mailbox: Mailbox,
    delivery: DeliverySlot,
}

impl std::fmt::Debug for HistoryPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryPeer").finish_non_exhaustive()
    }
}

struct Pending {
    mailbox: Mailbox,
    delivery: DeliverySlot,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.delivery.0.lock().take();
        self.mailbox.retain(|_, _| false);
    }
}

impl HistoryPeer {
    /// Fetch and durably stage the next required record from one current group member.
    /// The deadline covers all chunks and resolver retries. Cancellation retires the fetch;
    /// the durable import cursor advances only after complete record verification.
    pub async fn import_next_from(
        &mut self,
        peer: PublicKey,
        destination: &FinalizedHistory,
        limits: HistoryLimits,
        deadline: Duration,
    ) -> Result<Option<u64>> {
        let Some((height, _)) = destination.import_next()? else {
            return Ok(None);
        };
        tokio::time::timeout(deadline, async {
            let mut record = Vec::new();
            let mut total = None;
            loop {
                let mut key = [0; 16];
                key[..8].copy_from_slice(&height.to_be_bytes());
                key[8..].copy_from_slice(&(record.len() as u64).to_be_bytes());
                let key = Key::new(key);
                let (answer, receiver) = oneshot::channel();
                *self.delivery.0.lock() = Some(Waiting {
                    key: key.clone(),
                    maximum: limits.record_bytes,
                    answer,
                });
                let pending = Pending {
                    mailbox: self.mailbox.clone(),
                    delivery: self.delivery.clone(),
                };
                ensure!(
                    self.mailbox
                        .fetch_targeted(key, non_empty_vec![peer.clone()])
                        .accepted(),
                    "history resolver unavailable"
                );
                let chunk = receiver.await.context("history response dropped")??;
                drop(pending);
                ensure!(
                    total.is_none_or(|length| length == chunk.total),
                    "history record length changed during transfer"
                );
                let length = usize::try_from(chunk.total)?;
                if total.is_none() {
                    record
                        .try_reserve_exact(length)
                        .context("allocate bounded history record")?;
                    total = Some(chunk.total);
                }
                record.extend_from_slice(&chunk.bytes);
                if record.len() == length {
                    break;
                }
            }
            destination.import_record(&record, limits)?;
            Ok(Some(height))
        })
        .await
        .context("history transfer deadline exceeded")?
    }
}

/// Start serving retained history and return a sequential import client.
/// The supplied channel must use authenticated transport and a bounded receive backlog.
pub fn start_history_peer<D, B, S, R>(
    context: Context,
    history: Arc<FinalizedHistory>,
    peer_provider: D,
    blocker: B,
    me: PublicKey,
    network: (S, R),
) -> (HistoryPeer, Handle<()>)
where
    D: Provider<PublicKey = PublicKey>,
    B: Blocker<PublicKey = PublicKey>,
    S: Sender<PublicKey = PublicKey>,
    R: Receiver<PublicKey = PublicKey>,
{
    let delivery = DeliverySlot::default();
    let (engine, mailbox) = p2p::Engine::new(
        context,
        p2p::Config {
            peer_provider,
            blocker,
            me: Some(me),
            consumer: delivery.clone(),
            producer: HistoryProducer(history),
            mailbox_size: NZUsize!(16),
            timeout: Duration::from_secs(2),
            fetch_retry_timeout: Duration::from_millis(100),
            priority_requests: false,
            priority_responses: false,
        },
    );
    (HistoryPeer { mailbox, delivery }, engine.start(network))
}

fn decode_chunk(value: &[u8], expected_offset: u64) -> Result<HistoryChunk> {
    ensure!(
        (17..=16 + HISTORY_CHUNK_BYTES).contains(&value.len()),
        "invalid history chunk size"
    );
    let total = u64::from_be_bytes(value[..8].try_into()?);
    let offset = u64::from_be_bytes(value[8..16].try_into()?);
    let bytes = &value[16..];
    ensure!(offset == expected_offset, "history chunk offset mismatch");
    let end = offset
        .checked_add(bytes.len() as u64)
        .context("history chunk range overflow")?;
    ensure!(
        end <= total && (end == total || bytes.len() == HISTORY_CHUNK_BYTES),
        "invalid history chunk range"
    );
    Ok(HistoryChunk {
        total,
        offset,
        bytes: bytes.to_vec(),
    })
}

#[cfg(test)]
mod tests;
