use alloy_sol_types::sol;

sol! {
    /// Solidity interface for the ACP precompile at `0x0810`.
    interface IAcp {
        // ── Write methods (map to Cosmos Msgs) ──────────────────────────

        function createPolicy(bytes calldata yaml) external returns (bytes32 policyId);
        function editPolicy(bytes32 policyId, bytes calldata yaml) external;

        function setRelationship(
            bytes32 policyId,
            string resource,
            string objectId,
            string relation,
            string actor
        ) external;

        function deleteRelationship(
            bytes32 policyId,
            string resource,
            string objectId,
            string relation,
            string actor
        ) external;

        function registerObject(
            bytes32 policyId,
            string objectId,
            string resource
        ) external;

        function archiveObject(
            bytes32 policyId,
            string objectId,
            string resource
        ) external;

        function unarchiveObject(
            bytes32 policyId,
            string objectId,
            string resource
        ) external;

        function commitRegistrations(
            bytes32 policyId,
            bytes commitment
        ) external returns (uint64 commitmentId);

        function revealRegistration(
            uint64 commitmentId,
            bytes proof
        ) external;

        function flagHijackAttempt(uint64 eventId) external;

        // ── Read methods (map to Cosmos Queries) ────────────────────────

        function checkAccess(
            bytes32 policyId,
            string resource,
            string objectId,
            string permission,
            string actor
        ) external view returns (bool);

        function verifyAccessRequest(
            bytes32 policyId,
            string resource,
            string objectId,
            string permission,
            string actor
        ) external view returns (bool);

        function hasRelationship(
            bytes32 policyId,
            string resource,
            string objectId,
            string relation,
            string actor
        ) external view returns (bool);

        function getPolicy(bytes32 policyId) external view returns (bytes);

        function getObjectOwner(
            bytes32 policyId,
            string resource,
            string objectId
        ) external view returns (string);
    }
}
