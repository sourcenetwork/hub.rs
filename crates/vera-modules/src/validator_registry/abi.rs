//! Solidity ABI interface for the ValidatorRegistry precompile at `0x0813`.

use alloy_sol_types::sol;

sol! {
    /// Solidity interface for the ValidatorRegistry precompile at `0x0813`.
    interface IValidatorRegistry {
        // ── Events ──────────────────────────────────────────────────────

        event ValidatorAdded(address indexed evmAddr, bytes32 consensusPubkey);
        event ValidatorRemoved(address indexed evmAddr);
        event ValidatorStatusChanged(address indexed evmAddr, bool active);
        event ValidatorUpdated(address indexed evmAddr);

        // ── Write methods (ACP-gated) ───────────────────────────────────

        function addValidator(
            address evmAddr,
            bytes32 consensusPubkey,
            string calldata p2pAddr
        ) external;

        function removeValidator(address evmAddr) external;

        function setValidatorStatus(address evmAddr, bool active) external;

        function setValidatorStatusByIndex(uint256 index, bool active) external;

        // ── Bootstrap (one-time, only when no policy is set) ─────────────

        function setPolicy(bytes32 policyId) external;

        // ── Self-update (caller must be the validator) ──────────────────

        function updateP2PAddress(string calldata p2pAddr) external;

        // ── Query methods ───────────────────────────────────────────────

        function getValidators() external view returns (bytes);

        function getValidator(address evmAddr) external view returns (bytes);

        function getActiveValidatorCount() external view returns (uint256);
    }
}
