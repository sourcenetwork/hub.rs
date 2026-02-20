//! Solidity ABI interface for the Bulletin precompile at `0x0811`.

use alloy_sol_types::sol;

sol! {
    /// Solidity interface for the Bulletin precompile at `0x0811`.
    interface IBulletin {
        // ── Write methods ───────────────────────────────────────────────

        function registerNamespace(string namespace) external returns (bytes);

        function createPost(
            string namespace,
            bytes payload,
            bytes proof,
            string artifact
        ) external returns (bytes32 postId);

        function addCollaborator(
            string namespace,
            address collaborator
        ) external returns (string collaboratorDid);

        function removeCollaborator(
            string namespace,
            address collaborator
        ) external returns (string collaboratorDid);

        function updateParams(bytes params) external;

        // ── Read methods ────────────────────────────────────────────────

        function getPost(
            string namespace,
            bytes32 postId
        ) external view returns (bytes);

        function getNamespace(
            string namespace
        ) external view returns (bytes);

        function getNamespaces() external view returns (bytes);

        function getNamespaceCollaborators(
            string namespace
        ) external view returns (bytes);

        function getNamespacePosts(
            string namespace
        ) external view returns (bytes);

        function getPosts() external view returns (bytes);

        function iterateGlob(
            string namespace,
            string glob
        ) external view returns (bytes);

        function getParams() external view returns (bytes);
    }
}
