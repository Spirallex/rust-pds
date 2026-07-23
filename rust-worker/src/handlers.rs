//! HTTP surface served by the Durable Object.
//!
//! Handlers are written against `stelyph-core` directly rather than reusing the
//! axum handlers in the `stelyph` server crate: that crate cannot compile to
//! wasm32 (tokio-full, reqwest + rustls, axum-server, rustls-acme, keyring), so
//! sharing them would mean extracting them into a fourth crate first. The
//! protocol logic — which is the part worth sharing — already lives in
//! `stelyph-core` and is used as-is here.

use worker::*;

use stelyph_core::oauth::{AuthorizationServerMetadata, JwkSet, ProtectedResourceMetadata};

use crate::store::DoStore;

/// Key id for this PDS's OAuth authorization-server signing key.
const AS_SIGNING_KEY_ID: &str = "oauth#as-signing";

/// Everything a handler needs to know about which PDS it is serving.
///
/// A single Worker and Durable Object class serve every hostname, so identity is
/// per-request, not per-deployment.
pub struct Ctx {
    /// e.g. `https://joey.spirallex.net` — the OAuth issuer. No trailing slash,
    /// because clients compare `iss` byte-for-byte.
    pub issuer: String,
    /// e.g. `did:web:joey.spirallex.net`.
    pub did: String,
}

impl Ctx {
    pub fn from_host(hostname: &str) -> Self {
        Self {
            issuer: format!("https://{hostname}"),
            did: format!("did:web:{hostname}"),
        }
    }
}

/// `GET /.well-known/oauth-authorization-server` (RFC 8414).
pub fn oauth_as_metadata(ctx: &Ctx) -> Result<Response> {
    Response::from_json(&AuthorizationServerMetadata::new(&ctx.issuer))
}

/// `GET /.well-known/oauth-protected-resource` (RFC 9728).
pub fn oauth_protected_resource(ctx: &Ctx) -> Result<Response> {
    Response::from_json(&ProtectedResourceMetadata::new(&ctx.issuer))
}

/// `GET /xrpc/com.atproto.server.describeServer`.
///
/// The first call most atproto clients make. `availableUserDomains` is the
/// zone suffix rather than this hostname: it advertises where *new* handles can
/// be created, and every account on this deployment is a label under the zone.
pub fn describe_server(ctx: &Ctx, zone_suffix: &str) -> Result<Response> {
    Response::from_json(&serde_json::json!({
        "did": ctx.did,
        "availableUserDomains": [format!(".{zone_suffix}")],
        // No open registration: an account needs a `pulumi`-free but
        // operator-driven creation step, so advertise the invite requirement
        // rather than letting clients attempt a signup that will fail.
        "inviteCodeRequired": true,
        "links": {},
    }))
}

/// `GET /oauth/jwks` — the authorization server's public keys.
///
/// The private half never leaves the Durable Object: `public_jwk()` cannot
/// produce private material, so there is no path by which the scalar could be
/// serialized here.
pub async fn jwks(store: &DoStore, passphrase: &[u8]) -> Result<Response> {
    let key = load_or_create_signing_key(store, passphrase).await?;
    Response::from_json(&JwkSet {
        keys: vec![key.public_jwk()],
    })
}

/// Load this PDS's AS signing key, generating and persisting one on first use.
///
/// Stored through the ordinary encrypted `KeyStore` path, so it sits at rest
/// under the same argon2id + AES-GCM envelope as account signing keys. Note the
/// KDF runs inline on wasm32 (no thread pool), which is why the crate builds
/// with `lean-auth`.
pub async fn load_or_create_signing_key(
    store: &DoStore,
    passphrase: &[u8],
) -> Result<stelyph_core::oauth::SigningKey> {
    use stelyph_core::oauth::SigningKey;
    use stelyph_core::storage::crypto;

    if let Ok(scalar) = crypto::load_key(store, AS_SIGNING_KEY_ID, passphrase).await {
        if let Ok(key) = SigningKey::import(&scalar) {
            return Ok(key);
        }
    }

    let key = SigningKey::generate();
    crypto::store_key(store, AS_SIGNING_KEY_ID, &key.export(), passphrase)
        .await
        .map_err(|e| Error::RustError(format!("persist OAuth signing key: {e}")))?;
    Ok(key)
}

/// `GET /.well-known/did.json` — the did:web document for this PDS.
///
/// Advertises the PDS service endpoint so a resolver pointed at the handle can
/// find where the repo lives. The verification method is deliberately absent
/// until account signing keys are wired in; a did:web document without one is
/// still valid and still resolves the service endpoint.
pub fn did_web_document(ctx: &Ctx) -> Result<Response> {
    Response::from_json(&serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ],
        "id": ctx.did,
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": ctx.issuer,
        }],
    }))
}
