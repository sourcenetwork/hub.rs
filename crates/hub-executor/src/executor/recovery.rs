use super::*;
use hub_modules::kv_store::InMemoryKvStore;

impl HubExecutor {
    /// Return the common persisted module height, rejecting partial commits.
    pub fn module_height(&self) -> Result<u64, ExecutionError> {
        let _guard = self.commit_lock.lock().unwrap();
        let Some(trees) = &self.module_trees else {
            return Ok(0);
        };
        let height = trees[0].lock().unwrap().canonical_height();
        for tree in trees.iter().skip(1) {
            if tree.lock().unwrap().canonical_height() != height {
                return Err(ExecutionError::ModuleTree("module heights disagree".into()));
            }
        }
        Ok(height)
    }

    /// Recover before execution views are issued, checking the authenticated anchor.
    pub fn recover_modules(&self, height: u64, expected_root: B256) -> Result<(), ExecutionError> {
        let _guard = self.commit_lock.lock().unwrap();
        let trees = self.module_trees.as_ref().ok_or_else(|| {
            ExecutionError::ModuleTree("module recovery requires persistent trees".into())
        })?;
        let mut stores: [InMemoryKvStore; 4] = Default::default();
        let mut roots = [[0; 32]; 4];
        for (i, tree) in trees.iter().enumerate() {
            let mut tree = tree.lock().unwrap();
            tree.rewind_to_height(height)
                .map_err(|e| ExecutionError::ModuleTree(e.to_string()))?;
            roots[i] = tree
                .root()
                .map_err(|e| ExecutionError::ModuleTree(e.to_string()))?
                .0;
            stores[i] = InMemoryKvStore::from_pairs(
                tree.load_all()
                    .map_err(|e| ExecutionError::ModuleTree(e.to_string()))?,
            );
        }
        let modules = ModuleState::from_stores(stores);
        let root = if height == 0 {
            modules.state_root()
        } else {
            state_root_from_jmt(&roots)
        };
        if root != expected_root {
            return Err(ExecutionError::ModuleTree(
                "recovered module root does not match the durable anchor".into(),
            ));
        }
        self.set_base_modules(modules);
        Ok(())
    }
}
