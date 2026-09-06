use super::*;

impl OrderedState {
    pub(super) async fn apply_with_faults(&self, batches: Sealed, height: u64, changed: bool) {
        self.execution_databases()
            .apply((batches.0, batches.1, batches.2))
            .await;
        let native = self.native_databases();
        for (index, (database, batch)) in [native.0, native.1, native.2, native.3]
            .into_iter()
            .zip([batches.3, batches.4, batches.5, batches.6])
            .enumerate()
        {
            database.apply(batch).await;
            assert!(database.finalize().await.durable().await);
            if changed {
                self.executor.after_module_commit(height, index);
            }
        }
        self.databases.7.apply(batches.7).await;
    }
}
