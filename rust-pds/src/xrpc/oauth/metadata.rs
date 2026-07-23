//! Discovery endpoints.

use axum::extract::State;
use axum::Json;

use stelyph_core::oauth::{AuthorizationServerMetadata, ProtectedResourceMetadata};

use crate::xrpc::AppState;

/// `GET /.well-known/oauth-authorization-server`
pub async fn authorization_server_metadata(
    State(state): State<AppState>,
) -> Json<AuthorizationServerMetadata> {
    Json(AuthorizationServerMetadata::new(&state.oauth.issuer_url))
}

/// `GET /.well-known/oauth-protected-resource`
pub async fn protected_resource_metadata(
    State(state): State<AppState>,
) -> Json<ProtectedResourceMetadata> {
    Json(ProtectedResourceMetadata::new(&state.oauth.issuer_url))
}
