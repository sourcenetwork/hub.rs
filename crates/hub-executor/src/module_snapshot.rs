//! Module maps and authenticated tree views for one execution branch.

use alloy_primitives::B256;
use hub_modules::ModuleState;
use hub_modules::module_state::state_root_from_jmt;
use hub_state::TreeSnapshot;

/// Module values and their matching authenticated tree snapshots.
#[derive(Clone, Debug)]
pub struct ModuleSnapshot {
    /// Values read and changed by module execution.
    pub(crate) modules: ModuleState,
    pub(crate) trees: Option<[TreeSnapshot; 4]>,
}

impl ModuleSnapshot {
    /// Logical changes from the supplied execution parent, excluding storage-specific indexes.
    pub fn changes_from(&self, parent: &Self) -> hub_modules::module_state::ModuleChanges {
        self.modules.diff_from(&parent.modules)
    }

    /// Root for this revision, preserving the genesis store commitment format.
    pub fn state_root(&self, height: u64) -> B256 {
        match &self.trees {
            Some(trees) if height > 0 => {
                state_root_from_jmt(&std::array::from_fn(|i| trees[i].root().0))
            }
            _ => self.modules.state_root(),
        }
    }
}
