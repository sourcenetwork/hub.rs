//! Solidity ABI interface for the Hub precompile at `0x0812`.

use alloy_sol_types::sol;

sol! {
    /// Solidity interface for the Hub precompile at `0x0812`.
    interface IHub {
        // ── Write methods ───────────────────────────────────────────────

        function invalidateJWS(bytes32 tokenHash) external;

        // ── Read methods ────────────────────────────────────────────────

        function getJWSToken(
            bytes32 tokenHash
        ) external view returns (bool valid, uint64 issuedAt, uint64 expiresAt);
    }
}
