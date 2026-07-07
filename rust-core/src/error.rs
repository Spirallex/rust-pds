//! Core error type.
//!
//! Core APIs are HTTP-agnostic, so they cannot depend on the server's
//! `XrpcError`. `CoreError` carries just enough structure for the server to map
//! each variant onto the right HTTP status (see the `From<CoreError>` impl in
//! the server's `xrpc::error`):
//!   - `ExpiredToken` / `InvalidToken` → 401 (auth failures)
//!   - `Internal`                      → 500 (unexpected; detail not leaked)

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    /// A JWT presented to a verify path had a valid signature but was expired.
    #[error("expired token")]
    ExpiredToken,

    /// A JWT was malformed, had a bad signature, or the wrong scope.
    #[error("invalid token")]
    InvalidToken,

    /// An unexpected internal failure (crypto, encoding, etc.). The inner detail
    /// is for server-side diagnostics and must never be surfaced to clients.
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}
