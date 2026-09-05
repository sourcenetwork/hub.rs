//! Solidity ABI interface for the Hub precompile at `0x0812`.

use alloy_sol_types::sol;

sol! {
    /// Solidity interface for the Hub precompile at `0x0812`.
    interface IHub {
        // ── Events ──────────────────────────────────────────────────────

        event JWSTokenCreated(string indexed tokenHash, string issuerDid);
        event JWSTokenInvalidated(string indexed tokenHash, string issuerDid);

        // ── Write methods ───────────────────────────────────────────────

        function invalidateJWS(string tokenHash) external;

        function revokeDelegation(string token) external;

        function updateParams(bytes params) external;

        function applyAdministration(bytes request) external;

        function getAdministration() external view returns (bytes);

        // ── Read methods ────────────────────────────────────────────────

        function getJWSToken(
            string tokenHash
        ) external view returns (bool found, bytes record);

        function getJWSTokensByDid(
            string did
        ) external view returns (bytes);

        function getJWSTokensByAccount(
            address account
        ) external view returns (bytes);

        function getDelegationsBySubmitter(
            string submitter
        ) external view returns (bytes);

        function getChainConfig() external view returns (bytes);

        function getParams() external view returns (bytes);
    }
}
