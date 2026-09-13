use super::*;
use crate::kv_store::InMemoryKvStore;

pub(super) struct Replacement {
    pub(super) key: Vec<u8>,
    pub(super) value: Vec<u8>,
    pub(super) node: String,
}

pub(super) struct Retention {
    prefix: Vec<u8>,
    count: u32,
    expired: Vec<(Vec<u8>, Vec<u8>)>,
}
impl Retention {
    pub(super) fn apply(self, store: &mut InMemoryKvStore, session: &str, id: &str, expires: u64) {
        for (index, entry) in self.expired {
            store.delete(&index);
            store.delete(&entry);
        }
        let mut entry = self.prefix.clone();
        entry.extend_from_slice(b"session/");
        entry.extend_from_slice(session.as_bytes());
        let mut value = expires.to_be_bytes().to_vec();
        value.extend_from_slice(id.as_bytes());
        store.put(&entry, value);
        let mut index = self.prefix.clone();
        index.extend_from_slice(b"expiry/");
        index.extend_from_slice(&expires.to_be_bytes());
        index.extend_from_slice(session.as_bytes());
        store.put(&index, vec![]);
        let mut count_key = self.prefix;
        count_key.extend_from_slice(b"count");
        store.put(&count_key, self.count.to_be_bytes().to_vec());
    }
}
impl HubModule {
    pub(super) fn report_retention(
        &self,
        ring: &str,
        session: &str,
        now: u64,
    ) -> Result<Retention> {
        let prefix = format!("orbis/reports/v1/{ring}/").into_bytes();
        let mut count_key = prefix.clone();
        count_key.extend_from_slice(b"count");
        let mut count = self
            .store
            .get_ref(&count_key)
            .map(|b| b.try_into().map(u32::from_be_bytes).map_err(invalid))
            .transpose()?
            .unwrap_or(0);
        let mut entry = prefix.clone();
        entry.extend_from_slice(b"session/");
        entry.extend_from_slice(session.as_bytes());
        let mut expired = Vec::new();
        let mut index_prefix = prefix.clone();
        index_prefix.extend_from_slice(b"expiry/");
        if let Some(value) = self.store.get_ref(&entry) {
            if value.len() != 72 {
                return Err(invalid("invalid report retention record"));
            }
            let timestamp = u64::from_be_bytes(value[..8].try_into().map_err(invalid)?);
            if timestamp >= now {
                return Err(invalid("report session already accepted"));
            }
            let mut index = index_prefix.clone();
            index.extend_from_slice(&timestamp.to_be_bytes());
            index.extend_from_slice(session.as_bytes());
            if self.store.get_ref(&index) != Some(&[][..]) {
                return Err(invalid("missing report expiry index"));
            }
            expired.push((index, entry));
            count = count
                .checked_sub(1)
                .ok_or_else(|| invalid("report retention counter underflow"))?;
        }
        for (key, value) in self.store.prefix_iter(&index_prefix).take(PRUNE_LIMIT) {
            if expired.iter().any(|(index, _)| index == key) {
                continue;
            }
            if key.len() != index_prefix.len() + 72 || !value.is_empty() {
                return Err(invalid("invalid report expiry index"));
            }
            let timestamp = u64::from_be_bytes(
                key[index_prefix.len()..index_prefix.len() + 8]
                    .try_into()
                    .map_err(invalid)?,
            );
            if timestamp >= now {
                break;
            }
            let session = &key[index_prefix.len() + 8..];
            let mut entry = prefix.clone();
            entry.extend_from_slice(b"session/");
            entry.extend_from_slice(session);
            let value = self
                .store
                .get_ref(&entry)
                .ok_or_else(|| invalid("orphan report expiry index"))?;
            if value.len() != 72 || value[..8] != timestamp.to_be_bytes() {
                return Err(invalid("report expiry index mismatch"));
            }
            expired.push((key.to_vec(), entry));
            count = count
                .checked_sub(1)
                .ok_or_else(|| invalid("report retention counter underflow"))?;
        }
        if count >= MAX_RETAINED_REPORTS {
            return Err(invalid("report retention capacity reached"));
        }
        Ok(Retention {
            prefix,
            count: count + 1,
            expired,
        })
    }

    pub(super) fn report_replacement(
        &self,
        mut record: RingRecord,
        accused: &str,
        points: u64,
        revision: &Timestamp,
    ) -> Result<Option<Replacement>> {
        let mut settings = record.current_settings();
        if points < settings.reporting.kick_threshold
            || settings.pending_reshare.is_some()
            || settings
                .peer_node_keys
                .binary_search_by(|key| key.as_str().cmp(accused))
                .is_err()
        {
            return Ok(None);
        }
        let mut replacement = None;
        for (index, key) in settings.reporting.backup_node_keys.iter().enumerate() {
            if settings.peer_node_keys.binary_search(key).is_ok() {
                continue;
            }
            if self
                .threshold_node(key)?
                .is_some_and(|node| node.info.allows_ring(&record.config.policy_id, &record.id))
            {
                replacement = Some(index);
                break;
            }
        }
        let Some(index) = replacement else {
            return Ok(None);
        };
        let replacement = settings.reporting.backup_node_keys.remove(index);
        let mut peers = settings.peer_node_keys.clone();
        peers.retain(|key| key != accused);
        peers.push(replacement.clone());
        peers.sort();
        settings.pending_reshare = Some(ReshareTarget {
            peer_node_keys: peers,
            threshold: settings.threshold,
        });
        record.settings = Some(settings);
        record.sequence = record
            .sequence
            .checked_add(1)
            .ok_or_else(|| invalid("ring sequence exhausted"))?;
        record.revision = revision.clone();
        Ok(Some(Replacement {
            key: ring_key(&record.id)?,
            value: super::super::record_bytes(&record)?,
            node: replacement,
        }))
    }
}
