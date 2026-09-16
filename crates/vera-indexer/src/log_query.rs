//! Aggregate log query limits.

use crate::{IndexedLog, IndexerError, LogFilter};
use alloy_primitives::B256;

/// Whole-query scan and result accounting, shared by memory and archive reads.
#[derive(Debug)]
pub struct LogQuery {
    /// First requested revision, inclusive.
    pub from: u64,
    /// Last requested revision, inclusive.
    pub to: u64,
    filter: LogFilter,
    result: Vec<IndexedLog>,
    inspected: usize,
    remaining_bytes: usize,
}

impl LogQuery {
    /// Validate selectors before any archive work begins.
    pub fn new(filter: LogFilter, head: u64) -> Result<Self, IndexerError> {
        let from_block = filter.from_block.unwrap_or(0);
        let to_block = filter.to_block.unwrap_or(head);

        if from_block > to_block {
            return Err(IndexerError::InvalidBlockRange {
                from: from_block,
                to: to_block,
            });
        }
        if to_block - from_block >= 10_000
            || filter
                .address
                .as_ref()
                .is_some_and(|values| values.len() > 64)
            || filter
                .topics
                .iter()
                .flatten()
                .any(|values| values.len() > 64)
        {
            return Err(IndexerError::LogQueryLimit);
        }
        Ok(Self {
            from: from_block,
            to: to_block,
            filter,
            result: Vec::new(),
            inspected: 0,
            remaining_bytes: 1 << 20,
        })
    }

    pub(crate) fn push(&mut self, log: &IndexedLog) -> Result<(), IndexerError> {
        self.inspected += 1;
        if self.inspected > 10_000 {
            return Err(IndexerError::LogQueryLimit);
        }
        if !crate::store::matches_filter(log, &self.filter) {
            return Ok(());
        }
        let bytes = size_of::<IndexedLog>()
            .saturating_add(log.topics.len().saturating_mul(size_of::<B256>()))
            .saturating_add(log.data.len());
        self.remaining_bytes = self
            .remaining_bytes
            .checked_sub(bytes)
            .ok_or(IndexerError::LogQueryLimit)?;
        if self.result.len() == 1_000 {
            return Err(IndexerError::LogQueryLimit);
        }
        self.result.push(log.clone());
        Ok(())
    }

    /// Return results only after every requested revision was processed.
    pub fn finish(self) -> Vec<IndexedLog> {
        self.result
    }
}
