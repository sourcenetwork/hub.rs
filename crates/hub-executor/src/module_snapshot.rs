//! Module maps and authenticated tree views for one execution branch.

use hub_modules::ModuleState;
use hub_state::TreeSnapshot;

/// Module values and their matching authenticated tree snapshots.
#[derive(Clone, Debug)]
pub struct ModuleSnapshot {
    /// Values read and changed by module execution.
    pub(crate) modules: ModuleState,
    pub(crate) trees: Option<[TreeSnapshot; 4]>,
}
