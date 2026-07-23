//! `POST /oauth/par` — Pushed Authorization Request (RFC 9126).
//!
//! Mandatory in the atproto profile. The client submits every authorization
//! parameter here, over a back channel it authenticates on, and receives an
//! opaque `request_uri` to hand to the browser. Nothing sensitive ever travels
//! through the front channel.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::{Deserialize, Serialize};

use stelyph_core::oauth::{ClientId, OAuthError, PushedRequest};

use crate::xrpc::oauth::error::OAuthHttpError;
use crate::xrpc::AppState;

/// Form body of a pushed authorization request.
#[derive(Debug, Deserialize)]
pub struct ParForm {
    pub client_id: String,
    pub response_type: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub login_hint: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ParResponse {
    pub request_uri: String,
    pub expires_in: u64,
}

pub async fn pushed_authorization_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<ParForm>,
) -> Response {
    let nonce = state.oauth.dpop.current_nonce();
    match handle(&state, &headers, form).await {
        Ok(body) => {
            // Supply a nonce even on success: the client's very next call is the
            // token endpoint, which requires one, and this saves it a round trip.
            let mut resp = (axum::http::StatusCode::CREATED, Json(body)).into_response();
            if let Ok(v) = axum::http::HeaderValue::from_str(&nonce) {
                resp.headers_mut().insert("DPoP-Nonce", v);
                resp.headers_mut().insert(
                    axum::http::header::ACCESS_CONTROL_EXPOSE_HEADERS,
                    axum::http::HeaderValue::from_static("DPoP-Nonce"),
                );
            }
            resp
        }
        Err(e) => OAuthHttpError::with_nonce(e, nonce).into_response(),
    }
}

async fn handle(
    state: &AppState,
    headers: &HeaderMap,
    form: ParForm,
) -> Result<ParResponse, OAuthError> {
    // The client_id must be structurally valid before anything dereferences it.
    let client_id = ClientId::parse(&form.client_id)?;

    // The form's client_id and the one we validated must agree — `ClientId`
    // normalizes, so compare the canonical forms.
    let resolved = state.oauth.client_resolver.resolve(&client_id).await?;

    // A DPoP proof on the PAR request is optional, but if present it binds the
    // eventual token to this key. Nonce is not required here: this may be the
    // client's first contact, so it has no nonce yet, and PAR carries no
    // authority on its own.
    let dpop_jkt = match headers.get("DPoP").and_then(|v| v.to_str().ok()) {
        Some(proof) => {
            let url = state.oauth.endpoint_url("/oauth/par");
            let verified = state
                .oauth
                .dpop
                .verify(state.store.as_ref(), proof, "POST", &url, None, false)
                .await?;
            Some(verified.jkt)
        }
        None => None,
    };

    let request = PushedRequest {
        client_id: form.client_id,
        response_type: form.response_type,
        redirect_uri: form.redirect_uri,
        scope: form.scope,
        state: form.state,
        code_challenge: form.code_challenge,
        code_challenge_method: form.code_challenge_method,
        login_hint: form.login_hint,
    };

    let validated = request.validate(&client_id, resolved, dpop_jkt)?;
    let expires_in = validated
        .stored
        .expires_at
        .saturating_sub(stelyph_core::oauth::now_unix());

    state
        .store
        .put_pushed_request(validated.stored)
        .await
        .map_err(OAuthError::Storage)?;

    Ok(ParResponse {
        request_uri: validated.request_uri,
        expires_in,
    })
}
