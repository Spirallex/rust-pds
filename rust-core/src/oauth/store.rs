//! Persistence for OAuth server state.
//!
//! Four short-lived record types, all of which must expire: pushed
//! authorization requests, authorization codes, refresh tokens, and the DPoP
//! `jti` replay cache.
//!
//! # Secrets are stored hashed
//!
//! Authorization codes and refresh tokens are bearer secrets. They are keyed and
//! stored by SHA-256 rather than in the clear, so a database leak does not hand
//! an attacker live sessions. SHA-256 without a salt is deliberate and correct
//! here — unlike a password these are 256-bit random values, so there is nothing
//! to brute-force and a slow KDF would only add latency to every token request.
//!
//! # Single-use is enforced by the backend, not the caller
//!
//! [`OAuthStore::consume_auth_code`] and [`OAuthStore::consume_refresh_token`]
//! are atomic test-and-set operations, not a get followed by a delete. Two
//! concurrent redemptions of one code must not both succeed, and a
//! check-then-act split at the call site cannot guarantee that no matter how
//! carefully it is written.

use async_trait::async_trait;
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};

use crate::storage::StorageError;

/// Hash a bearer secret for storage and lookup.
///
/// Lowercase hex rather than base64 so the value is safe as a database key
/// under any collation.
pub fn hash_secret(secret: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(secret.as_bytes()))
}

/// A pushed authorization request awaiting the user's decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPushedRequest {
    /// Opaque handle the client passes back as `request_uri`. Stored hashed.
    pub request_uri_hash: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub code_challenge: String,
    /// `jkt` of the client key, when the client bound the request to one at PAR
    /// time. Carried through to the issued token.
    pub dpop_jkt: Option<String>,
    /// Handle or DID the client suggests pre-filling on the login screen.
    pub login_hint: Option<String>,
    pub expires_at: u64,
}

/// An issued authorization code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthCode {
    /// SHA-256 of the code. The code itself is never stored.
    pub code_hash: String,
    pub did: String,
    pub client_id: String,
    /// Must match the `redirect_uri` presented at the token endpoint.
    pub redirect_uri: String,
    pub scope: String,
    pub code_challenge: String,
    pub dpop_jkt: Option<String>,
    pub expires_at: u64,
}

/// A refresh token in a rotation chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshTokenRecord {
    /// SHA-256 of the token. The token itself is never stored.
    pub token_hash: String,
    /// Groups every token in one rotation chain. Reuse of a spent token revokes
    /// the whole chain by this id.
    pub session_id: String,
    pub did: String,
    pub client_id: String,
    pub scope: String,
    /// The DPoP key this token is bound to. A refresh presented with a proof
    /// from a different key must be rejected.
    pub dpop_jkt: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Outcome of redeeming a refresh token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeResult {
    /// Redeemed successfully; the record is now spent.
    Consumed(Box<RefreshTokenRecord>),
    /// A token that was already spent was presented again.
    ///
    /// This means either the client retried, or a token was stolen and one of
    /// the two parties has used it. The two are indistinguishable, so the safe
    /// response is to revoke the entire chain named by this `session_id` — the
    /// behaviour OAuth 2.1 §6.1 requires of rotating refresh tokens.
    Reused { session_id: String },
    /// No such token, or it expired.
    NotFound,
}

/// OAuth server state.
#[async_trait]
pub trait OAuthStore: Send + Sync {
    // --- pushed authorization requests ---

    /// Store a pushed request. Overwrites any entry with the same hash.
    async fn put_pushed_request(&self, req: StoredPushedRequest) -> Result<(), StorageError>;

    /// Fetch an unexpired pushed request.
    ///
    /// Deliberately a read, not a consume: the authorization endpoint may be
    /// loaded more than once (the user reloads the login page, or fails a
    /// password attempt) before a decision is reached. The request is consumed
    /// when the code is issued.
    async fn get_pushed_request(
        &self,
        request_uri_hash: &str,
        now: u64,
    ) -> Result<Option<StoredPushedRequest>, StorageError>;

    /// Delete a pushed request, once it has produced a code or been rejected.
    async fn delete_pushed_request(&self, request_uri_hash: &str) -> Result<(), StorageError>;

    // --- authorization codes ---

    async fn put_auth_code(&self, code: AuthCode) -> Result<(), StorageError>;

    /// Atomically redeem an authorization code.
    ///
    /// Returns the record and removes it, or `None` if it is unknown, expired,
    /// or already redeemed. Must be a single atomic operation — a code that two
    /// requests can redeem concurrently is a token-duplication bug.
    async fn consume_auth_code(
        &self,
        code_hash: &str,
        now: u64,
    ) -> Result<Option<AuthCode>, StorageError>;

    // --- refresh tokens ---

    async fn put_refresh_token(&self, token: RefreshTokenRecord) -> Result<(), StorageError>;

    /// Atomically redeem a refresh token, distinguishing reuse from absence.
    ///
    /// A spent token that is presented again must report
    /// [`ConsumeResult::Reused`] rather than `NotFound`, so the caller can
    /// revoke the chain. That requires keeping spent tokens until they expire
    /// instead of deleting them on use.
    async fn consume_refresh_token(
        &self,
        token_hash: &str,
        now: u64,
    ) -> Result<ConsumeResult, StorageError>;

    /// Revoke every token in a rotation chain. Returns how many were removed.
    async fn revoke_session(&self, session_id: &str) -> Result<u64, StorageError>;

    /// Revoke one refresh token and the chain it belongs to, for the revocation
    /// endpoint. Returns `true` if the token was known.
    async fn revoke_refresh_token(&self, token_hash: &str) -> Result<bool, StorageError>;

    /// Every active session for `did`, for an account-management view.
    async fn list_sessions_for_did(
        &self,
        did: &str,
        now: u64,
    ) -> Result<Vec<RefreshTokenRecord>, StorageError>;

    // --- DPoP replay cache ---

    /// Record a DPoP `jti`, returning `true` if it had not been seen.
    ///
    /// `false` means replay. Must be atomic: a check-then-insert split lets two
    /// concurrent requests both observe "unseen" and both proceed, which is
    /// exactly the replay this cache exists to stop.
    async fn record_dpop_jti(&self, jti: &str, expires_at: u64) -> Result<bool, StorageError>;

    // --- maintenance ---

    /// Delete every expired record across all four kinds. Returns the count.
    ///
    /// Nothing here is correctness-critical — every read already filters on
    /// expiry — but without it the tables grow without bound.
    async fn purge_expired(&self, now: u64) -> Result<u64, StorageError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_secret_is_stable_and_distinct() {
        assert_eq!(hash_secret("abc"), hash_secret("abc"));
        assert_ne!(hash_secret("abc"), hash_secret("abd"));
        // Known SHA-256("abc").
        assert_eq!(
            hash_secret("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hash_secret_does_not_contain_the_secret() {
        let secret = "super-secret-refresh-token";
        assert!(!hash_secret(secret).contains(secret));
    }
}
