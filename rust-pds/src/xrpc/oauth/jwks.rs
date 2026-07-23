//! `GET /oauth/jwks` — the authorization server's public signing keys.

use axum::extract::State;
use axum::Json;

use stelyph_core::oauth::JwkSet;

use crate::xrpc::AppState;

/// Publishes the AS signing key so a relying party can verify access tokens.
///
/// Only ever the *public* half: [`stelyph_core::oauth::SigningKey::public_jwk`]
/// cannot produce private material, so there is no path by which the private
/// scalar could be serialized here.
pub async fn jwks(State(state): State<AppState>) -> Json<JwkSet> {
    Json(JwkSet {
        keys: vec![state.oauth.issuer.signing_key().public_jwk()],
    })
}
