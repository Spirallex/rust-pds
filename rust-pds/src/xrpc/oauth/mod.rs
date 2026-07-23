//! OAuth 2.0 authorization server — HTTP layer.
//!
//! The protocol logic lives in `stelyph_core::oauth`; this module is the axum
//! binding: routes, request/response shapes, the login and consent pages, and
//! outbound client-metadata fetching.
//!
//! # Endpoints
//!
//! | Method | Path                                        | Purpose |
//! |--------|---------------------------------------------|---------|
//! | GET    | `/.well-known/oauth-authorization-server`    | AS metadata (RFC 8414) |
//! | GET    | `/.well-known/oauth-protected-resource`      | RS metadata (RFC 9728) |
//! | GET    | `/oauth/jwks`                                | AS public keys |
//! | POST   | `/oauth/par`                                 | pushed authorization request |
//! | GET    | `/oauth/authorize`                           | login + consent page |
//! | POST   | `/oauth/authorize`                           | credentials + decision |
//! | POST   | `/oauth/token`                               | code and refresh grants |
//! | POST   | `/oauth/revoke`                              | revocation (RFC 7009) |

pub mod authorize;
pub mod client_resolver;
pub mod error;
pub mod html;
pub mod jwks;
pub mod metadata;
pub mod par;
pub mod revoke;
pub mod token;

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use stelyph_core::oauth::{DpopVerifier, TokenIssuer};

pub use client_resolver::{ClientResolver, HttpClientResolver, StaticClientResolver};
pub use error::OAuthHttpError;

/// Everything the OAuth endpoints need beyond the shared `AppState`.
pub struct OAuthState {
    /// Mints and verifies access tokens; owns the AS signing key.
    pub issuer: TokenIssuer,
    /// Verifies DPoP proofs and issues nonces.
    pub dpop: DpopVerifier,
    /// Resolves a `client_id` to its metadata document. Injectable so tests do
    /// not need a live HTTP server for the client.
    pub client_resolver: Arc<dyn ClientResolver>,
    /// Issuer origin, e.g. `https://pds.example.com`. No trailing slash.
    pub issuer_url: String,
}

/// Key id under which the authorization server's ES256 signing key is stored.
///
/// Namespaced with `oauth#` so it cannot collide with a `{did}#signing` account
/// key in the same table.
const AS_SIGNING_KEY_ID: &str = "oauth#as-signing";

impl OAuthState {
    /// The absolute URL of `path` on this server, for DPoP `htu` comparison.
    ///
    /// Built from the configured issuer rather than from request headers: `Host`
    /// and `X-Forwarded-*` are attacker-controlled, and letting them determine
    /// the `htu` a proof is checked against would let a proof minted for one
    /// origin be replayed at another.
    pub fn endpoint_url(&self, path: &str) -> String {
        format!("{}{}", self.issuer_url, path)
    }

    /// Build the OAuth state, loading or creating the AS signing key.
    ///
    /// `issuer_url` is the PDS origin and `service_did` its `did:web`; together
    /// they are the `iss` and `aud` of every access token. `jwt_secret` is reused
    /// only as entropy for the DPoP nonce secret (see below) — it never signs an
    /// OAuth token.
    pub async fn bootstrap(
        store: &dyn stelyph_core::storage::StorageBackend,
        key_passphrase: &[u8],
        jwt_secret: &[u8],
        issuer_url: String,
        service_did: String,
        client_resolver: Arc<dyn ClientResolver>,
    ) -> Result<Self, stelyph_core::oauth::OAuthError> {
        let key = load_or_create_signing_key(store, key_passphrase).await?;
        let issuer_url = issuer_url.trim_end_matches('/').to_string();

        Ok(Self {
            issuer: TokenIssuer::new(key, issuer_url.clone(), service_did),
            dpop: DpopVerifier::new(derive_nonce_secret(jwt_secret)),
            client_resolver,
            issuer_url,
        })
    }
}

/// Derive the DPoP nonce secret from the server's JWT secret.
///
/// The nonce secret has to be stable across restarts — a fresh one would
/// invalidate every in-flight proof — and secret. Deriving it from the existing
/// persisted JWT secret gets both without adding a config knob the operator
/// could forget to set. The domain-separation prefix keeps it unrelated to the
/// JWT signing use: recovering one does not yield the other.
fn derive_nonce_secret(jwt_secret: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"stelyph-oauth-dpop-nonce-v1");
    h.update(jwt_secret);
    h.finalize().to_vec()
}

/// Load the AS signing key, generating and persisting one on first start.
///
/// Stored through the ordinary encrypted [`stelyph_core::storage::KeyStore`]
/// path, so it is at rest under the same argon2id + AES-GCM envelope as account
/// signing keys.
async fn load_or_create_signing_key(
    store: &dyn stelyph_core::storage::StorageBackend,
    passphrase: &[u8],
) -> Result<stelyph_core::oauth::SigningKey, stelyph_core::oauth::OAuthError> {
    use stelyph_core::oauth::{OAuthError, SigningKey};
    use stelyph_core::storage::crypto;

    match crypto::load_key(store, AS_SIGNING_KEY_ID, passphrase).await {
        Ok(scalar) => SigningKey::import(&scalar),
        Err(_) => {
            // No key yet (or it cannot be decrypted). Generate one and persist it.
            //
            // Note this also fires if the passphrase changed, in which case a new
            // key is minted and previously-issued access tokens stop verifying.
            // That is the safe direction: clients re-authenticate, and no token
            // is accepted under a key the operator can no longer produce.
            let key = SigningKey::generate();
            crypto::store_key(store, AS_SIGNING_KEY_ID, &key.export(), passphrase)
                .await
                .map_err(|e| {
                    OAuthError::Internal(format!("could not persist the OAuth signing key: {e}"))
                })?;
            Ok(key)
        }
    }
}

/// Build an `OAuthState` with an ephemeral signing key, for tests.
///
/// Public because the integration tests in `tests/` are a separate crate and
/// cannot see `#[cfg(test)]` items. It is not part of the server's real startup
/// path — [`OAuthState::bootstrap`] is — and the key it mints is thrown away
/// when the process ends, so nothing it produces survives a restart.
pub fn test_oauth_state() -> Arc<OAuthState> {
    use stelyph_core::oauth::SigningKey;

    Arc::new(OAuthState {
        issuer: TokenIssuer::new(
            SigningKey::generate(),
            "https://pds.test".into(),
            "did:web:pds.test".into(),
        ),
        dpop: DpopVerifier::new(b"test-dpop-nonce-secret".to_vec()),
        client_resolver: client_resolver::StaticClientResolver::new(vec![]),
        issuer_url: "https://pds.test".into(),
    })
}

/// OAuth routes, merged into the main router.
pub fn routes() -> Router<crate::xrpc::AppState> {
    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata::authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(metadata::protected_resource_metadata),
        )
        .route("/oauth/jwks", get(jwks::jwks))
        .route("/oauth/par", post(par::pushed_authorization_request))
        .route(
            "/oauth/authorize",
            get(authorize::authorize_page).post(authorize::authorize_submit),
        )
        .route("/oauth/token", post(token::token))
        .route("/oauth/revoke", post(revoke::revoke))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stelyph_core::storage::MemoryStore;

    #[tokio::test]
    async fn signing_key_is_generated_once_and_reused() {
        let store = MemoryStore::new();
        let pass = b"test-key-passphrase";

        let first = load_or_create_signing_key(&store, pass).await.unwrap();
        let second = load_or_create_signing_key(&store, pass).await.unwrap();
        assert_eq!(
            first.kid(),
            second.kid(),
            "a restart must reuse the persisted key, not mint a new one"
        );
    }

    #[tokio::test]
    async fn the_stored_signing_key_is_encrypted_at_rest() {
        use stelyph_core::storage::KeyStore;

        let store = MemoryStore::new();
        let pass = b"test-key-passphrase";
        let key = load_or_create_signing_key(&store, pass).await.unwrap();

        let raw = store
            .get_key_blob(AS_SIGNING_KEY_ID)
            .await
            .unwrap()
            .unwrap();
        let scalar = key.export();
        assert!(
            !raw.windows(scalar.len()).any(|w| w == scalar.as_slice()),
            "the private scalar must not appear in the stored blob"
        );
    }

    #[tokio::test]
    async fn a_changed_passphrase_mints_a_fresh_key_rather_than_failing() {
        let store = MemoryStore::new();
        let first = load_or_create_signing_key(&store, b"old-pass")
            .await
            .unwrap();
        let second = load_or_create_signing_key(&store, b"new-pass")
            .await
            .unwrap();
        assert_ne!(
            first.kid(),
            second.kid(),
            "an undecryptable key must be replaced, not silently reused"
        );
    }

    #[test]
    fn nonce_secret_is_derived_deterministically_and_domain_separated() {
        let a = derive_nonce_secret(b"jwt-secret");
        assert_eq!(a, derive_nonce_secret(b"jwt-secret"), "must be stable");
        assert_ne!(a, derive_nonce_secret(b"another-secret"));
        assert_ne!(
            a,
            b"jwt-secret".to_vec(),
            "the nonce secret must not be the JWT secret itself"
        );
        assert_eq!(a.len(), 32);
    }

    #[tokio::test]
    async fn endpoint_urls_come_from_config_not_headers() {
        let store = MemoryStore::new();
        let state = OAuthState::bootstrap(
            &store,
            b"pass",
            b"jwt",
            "https://pds.example.com/".into(),
            "did:web:pds.example.com".into(),
            client_resolver::StaticClientResolver::new(vec![]),
        )
        .await
        .unwrap();

        assert_eq!(state.issuer_url, "https://pds.example.com");
        assert_eq!(
            state.endpoint_url("/oauth/token"),
            "https://pds.example.com/oauth/token"
        );
    }
}
