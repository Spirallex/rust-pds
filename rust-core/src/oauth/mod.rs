//! AT Protocol OAuth 2.0 authorization server — portable protocol layer.
//!
//! This module holds everything about the OAuth profile that does not depend on
//! an HTTP framework: JWK handling, DPoP proof verification, PKCE, token
//! minting and verification, client-metadata validation, scope rules, and the
//! authorization-request state machine. The axum routes, HTML login/consent
//! pages, and outbound client-metadata fetching live in `stelyph`'s
//! `xrpc::oauth`.
//!
//! The split exists so the on-device embedded server (`crate::server`) can serve
//! OAuth without pulling in axum, and so this logic stays testable without
//! standing up a server.
//!
//! # Profile constraints
//!
//! The AT Protocol OAuth profile is considerably narrower than base OAuth 2.1,
//! and the narrowing is load-bearing — each of these is enforced rather than
//! merely defaulted:
//!
//! - **PAR is mandatory.** Authorization parameters are never accepted directly
//!   on the authorization endpoint, only via a `request_uri` from a pushed
//!   request. This keeps parameters off the front channel entirely.
//! - **PKCE is mandatory**, `S256` only. `plain` is rejected.
//! - **DPoP is mandatory** on the token endpoint and on every resource request,
//!   with server-issued nonces.
//! - **`client_id` is a URL** that resolves to a client-metadata document, not
//!   an opaque registered identifier. There is no dynamic registration.
//! - **Asymmetric crypto only** — ES256 / ES256K. No RSA, no HMAC.
//! - **Refresh tokens rotate** on every use, and are DPoP-bound.

pub mod client;
pub mod device;
pub mod dpop;
pub mod jwk;
pub mod jws;
pub mod metadata;
pub mod pkce;
pub mod request;
pub mod scope;
pub mod store;
pub mod token;

pub use client::{ClientId, ClientMetadata};
pub use device::{approval_challenge, verify_approval, SigninStatus};
pub use dpop::{DpopProof, DpopVerifier};
pub use jwk::{Alg, JwkSet, PublicJwk, SigningKey};
pub use metadata::{AuthorizationServerMetadata, ProtectedResourceMetadata};
pub use pkce::CodeChallenge;
pub use request::{AuthorizationRequest, PushedRequest};
pub use scope::Scope;
pub use store::{AuthCode, OAuthStore, RefreshTokenRecord};
pub use token::{AccessTokenClaims, TokenIssuer};

/// Everything that can go wrong in the OAuth layer.
///
/// Variants map onto the RFC 6749 §5.2 / RFC 9449 error codes via
/// [`OAuthError::error_code`], so the HTTP layer never has to invent a mapping
/// and cannot leak an internal message into a protocol response.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("invalid_request: {0}")]
    InvalidRequest(String),

    #[error("invalid_client: {0}")]
    InvalidClient(String),

    #[error("invalid_grant: {0}")]
    InvalidGrant(String),

    #[error("invalid_scope: {0}")]
    InvalidScope(String),

    #[error("unauthorized_client: {0}")]
    UnauthorizedClient(String),

    #[error("unsupported_grant_type: {0}")]
    UnsupportedGrantType(String),

    #[error("access_denied: {0}")]
    AccessDenied(String),

    /// The DPoP proof was missing, malformed, or did not verify.
    #[error("invalid_dpop_proof: {0}")]
    InvalidDpopProof(String),

    /// The client must retry with a server-supplied nonce. The HTTP layer turns
    /// this into a `DPoP-Nonce` header plus `use_dpop_nonce`, which is a normal
    /// part of the handshake rather than a failure.
    #[error("use_dpop_nonce: {0}")]
    UseDpopNonce(String),

    #[error("invalid_token: {0}")]
    InvalidToken(String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("server_error: {0}")]
    Internal(String),
}

impl OAuthError {
    /// The RFC error code that belongs in the `error` member of a response body.
    pub fn error_code(&self) -> &'static str {
        match self {
            OAuthError::InvalidRequest(_) => "invalid_request",
            OAuthError::InvalidClient(_) => "invalid_client",
            OAuthError::InvalidGrant(_) => "invalid_grant",
            OAuthError::InvalidScope(_) => "invalid_scope",
            OAuthError::UnauthorizedClient(_) => "unauthorized_client",
            OAuthError::UnsupportedGrantType(_) => "unsupported_grant_type",
            OAuthError::AccessDenied(_) => "access_denied",
            OAuthError::InvalidDpopProof(_) => "invalid_dpop_proof",
            OAuthError::UseDpopNonce(_) => "use_dpop_nonce",
            OAuthError::InvalidToken(_) => "invalid_token",
            OAuthError::UnsupportedAlgorithm(_) => "invalid_request",
            // Storage and internal failures are ours, not the client's. They
            // must never be reported as a client error, or a client will retry
            // forever against a broken server.
            OAuthError::Storage(_) | OAuthError::Internal(_) => "server_error",
        }
    }

    /// The `error_description` to return to the client.
    ///
    /// Internal and storage failures deliberately return a fixed string: their
    /// `Display` output can carry database paths and driver detail that must not
    /// cross the network. The full error is still available to the caller for
    /// server-side logging.
    pub fn public_description(&self) -> String {
        match self {
            OAuthError::Storage(_) | OAuthError::Internal(_) => "internal server error".to_string(),
            other => other.to_string(),
        }
    }
}

/// Current Unix time in seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs()
}

/// Generate `n` bytes of cryptographically random data, base64url-encoded.
///
/// Used for authorization codes, refresh tokens, `request_uri` handles, and DPoP
/// nonces — every one of which is a bearer secret, so `OsRng` is required.
pub fn random_token(n: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    data_encoding::BASE64URL_NOPAD.encode(&buf)
}

/// Compare two secrets in constant time.
///
/// Authorization codes and refresh tokens are looked up by value; a
/// short-circuiting `==` on the stored secret would leak its prefix through
/// timing. Length is compared first and non-secretly, which is fine — the length
/// of these tokens is fixed and public.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_errors_do_not_leak_detail() {
        let e = OAuthError::Internal("connection to /var/db/secret.sqlite failed".into());
        assert_eq!(e.error_code(), "server_error");
        assert_eq!(e.public_description(), "internal server error");
        assert!(
            !e.public_description().contains("secret.sqlite"),
            "internal detail must not reach the client"
        );
    }

    #[test]
    fn client_errors_keep_their_description() {
        let e = OAuthError::InvalidGrant("authorization code expired".into());
        assert_eq!(e.error_code(), "invalid_grant");
        assert!(e.public_description().contains("expired"));
    }

    #[test]
    fn random_tokens_are_unique_and_long_enough() {
        let a = random_token(32);
        let b = random_token(32);
        assert_ne!(a, b);
        // 32 bytes base64url-unpadded is 43 chars.
        assert_eq!(a.len(), 43);
    }

    #[test]
    fn constant_time_eq_matches_equality() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }
}
