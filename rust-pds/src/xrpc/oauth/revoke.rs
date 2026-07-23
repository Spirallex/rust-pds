//! `POST /oauth/revoke` — token revocation (RFC 7009).
//!
//! Revoking any token in a rotation chain ends the whole session. Access tokens
//! already issued remain valid until they expire (they are self-contained JWTs),
//! but no new ones can be minted, so a session dies within one access-token
//! lifetime.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Form;
use serde::Deserialize;

use stelyph_core::oauth::store::hash_secret;

use crate::xrpc::AppState;

#[derive(Debug, Deserialize)]
pub struct RevokeForm {
    pub token: String,
    /// `refresh_token` or `access_token`. A hint only, per RFC 7009 §2.1.
    pub token_type_hint: Option<String>,
}

/// Always responds 200, whether or not the token existed.
///
/// RFC 7009 §2.2 requires this: reporting "unknown token" would turn the
/// endpoint into an oracle for testing whether a stolen token is still live.
/// The endpoint is deliberately unauthenticated for the same reason it is
/// idempotent — a client that has lost its DPoP key must still be able to
/// invalidate a token it holds.
pub async fn revoke(State(state): State<AppState>, Form(form): Form<RevokeForm>) -> Response {
    // Only refresh tokens are revocable server-side. An access token is a signed
    // JWT with no stored state, so there is nothing to delete — attempting it is
    // a no-op rather than an error, which is exactly what RFC 7009 prescribes
    // for an unsupported token type when the response must stay uniform.
    match state
        .store
        .revoke_refresh_token(&hash_secret(&form.token))
        .await
    {
        Ok(_) => {}
        Err(e) => {
            // Log, but still return 200: a storage failure must not be
            // distinguishable from "no such token" by an unauthenticated caller.
            eprintln!("oauth: revocation storage error: {e}");
        }
    }
    StatusCode::OK.into_response()
}
