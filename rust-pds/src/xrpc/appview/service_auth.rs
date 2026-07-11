//! ES256K service-auth minting — thin wrappers over the shared
//! implementation in `stelyph_core::auth::service_auth`, so the production
//! and embedded servers sign identical tokens.

use crate::xrpc::XrpcError;
use atrium_crypto::keypair::Secp256k1Keypair;

/// Mint a short-lived (60s) ES256K service-auth JWT signed by the account key.
/// iss = account DID, aud = AppView service DID, lxm = full method NSID.
pub fn mint_service_auth_jwt(
    signing_key: &Secp256k1Keypair,
    iss: &str,
    aud: &str,
    lxm: &str,
) -> Result<String, XrpcError> {
    stelyph_core::auth::service_auth::mint_service_auth_jwt(signing_key, iss, aud, lxm)
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!(e)))
}

/// Mint an ES256K service-auth JWT with an explicit expiry and optional `lxm`.
///
/// Backs both the internal AppView proxy (pinned `lxm`, 60s expiry) and the
/// public `com.atproto.server.getServiceAuth` endpoint (optional `lxm`,
/// caller-requested `exp`).
pub fn mint_service_auth_jwt_with(
    signing_key: &Secp256k1Keypair,
    iss: &str,
    aud: &str,
    lxm: Option<&str>,
    exp_unix: u64,
) -> Result<String, XrpcError> {
    stelyph_core::auth::service_auth::mint_service_auth_jwt_with(
        signing_key,
        iss,
        aud,
        lxm,
        exp_unix,
    )
    .map_err(|e| XrpcError::Internal(anyhow::anyhow!(e)))
}
