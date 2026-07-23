//! `POST /oauth/token` — the `authorization_code` and `refresh_token` grants.
//!
//! Both grants require a valid DPoP proof with a server nonce. Both issue a new
//! access token and a **new** refresh token: refresh tokens rotate on every use,
//! so a stolen one is usable at most once before its reuse is detected and the
//! whole chain is revoked.

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::{Deserialize, Serialize};

use stelyph_core::oauth::store::{hash_secret, ConsumeResult, RefreshTokenRecord};
use stelyph_core::oauth::{
    now_unix, random_token, token as token_consts, CodeChallenge, DpopProof, OAuthError, Scope,
};

use crate::xrpc::oauth::error::OAuthHttpError;
use crate::xrpc::AppState;

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    pub grant_type: String,
    pub client_id: String,
    // authorization_code grant
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    // refresh_token grant
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    /// Always `DPoP` — this server never issues a plain bearer token.
    pub token_type: &'static str,
    pub expires_in: u64,
    pub refresh_token: String,
    pub scope: String,
    /// The authenticated account's DID, which atproto clients need immediately.
    pub sub: String,
}

pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    let nonce = state.oauth.dpop.current_nonce();
    match handle(&state, &headers, form).await {
        Ok(body) => {
            let mut resp = Json(body).into_response();
            let h = resp.headers_mut();
            if let Ok(v) = HeaderValue::from_str(&nonce) {
                h.insert("DPoP-Nonce", v);
                h.insert(
                    header::ACCESS_CONTROL_EXPOSE_HEADERS,
                    HeaderValue::from_static("DPoP-Nonce"),
                );
            }
            // Tokens must never be cached by an intermediary.
            h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
            resp
        }
        Err(e) => OAuthHttpError::with_nonce(e, nonce).into_response(),
    }
}

async fn handle(
    state: &AppState,
    headers: &HeaderMap,
    form: TokenForm,
) -> Result<TokenResponse, OAuthError> {
    // DPoP is mandatory here, nonce included. Doing this first means an
    // unauthenticated caller cannot probe grant handling at all.
    let proof = verify_dpop(state, headers).await?;

    match form.grant_type.as_str() {
        "authorization_code" => authorization_code_grant(state, form, &proof).await,
        "refresh_token" => refresh_token_grant(state, form, &proof).await,
        other => Err(OAuthError::UnsupportedGrantType(other.to_string())),
    }
}

async fn verify_dpop(state: &AppState, headers: &HeaderMap) -> Result<DpopProof, OAuthError> {
    // RFC 9449 §4.3: exactly one DPoP header. Several values is ambiguous and
    // must be rejected rather than resolved by picking one.
    let mut values = headers.get_all("DPoP").iter();
    let proof = values
        .next()
        .ok_or_else(|| OAuthError::InvalidDpopProof("a DPoP proof is required".into()))?;
    if values.next().is_some() {
        return Err(OAuthError::InvalidDpopProof(
            "exactly one DPoP header is permitted".into(),
        ));
    }
    let proof = proof
        .to_str()
        .map_err(|_| OAuthError::InvalidDpopProof("DPoP header is not valid ASCII".into()))?;

    let url = state.oauth.endpoint_url("/oauth/token");
    state
        .oauth
        .dpop
        .verify(state.store.as_ref(), proof, "POST", &url, None, true)
        .await
}

async fn authorization_code_grant(
    state: &AppState,
    form: TokenForm,
    proof: &DpopProof,
) -> Result<TokenResponse, OAuthError> {
    let code = form
        .code
        .ok_or_else(|| OAuthError::InvalidRequest("code is required".into()))?;

    // Redeem atomically. From here the code is spent regardless of what follows,
    // so a failed exchange cannot be retried with the same code.
    let record = state
        .store
        .consume_auth_code(&hash_secret(&code), now_unix())
        .await?
        .ok_or_else(|| {
            OAuthError::InvalidGrant(
                "authorization code is invalid, expired, or already used".into(),
            )
        })?;

    // The client redeeming must be the one the code was issued to.
    if record.client_id != form.client_id {
        return Err(OAuthError::InvalidGrant(
            "authorization code was issued to a different client".into(),
        ));
    }

    // RFC 6749 §4.1.3: the redirect_uri must match the one from the
    // authorization request, which stops a code obtained via one registered URI
    // from being redeemed as though it came from another.
    let redirect_uri = form
        .redirect_uri
        .ok_or_else(|| OAuthError::InvalidRequest("redirect_uri is required".into()))?;
    if redirect_uri != record.redirect_uri {
        return Err(OAuthError::InvalidGrant(
            "redirect_uri does not match".into(),
        ));
    }

    // PKCE.
    let verifier = form
        .code_verifier
        .ok_or_else(|| OAuthError::InvalidRequest("code_verifier is required".into()))?;
    CodeChallenge {
        challenge: record.code_challenge.clone(),
    }
    .verify(&verifier)?;

    // If the client bound the pushed request to a key, the same key must finish
    // the flow. Without this, an intercepted code could be redeemed by anyone
    // presenting any valid proof of their own.
    if let Some(expected) = &record.dpop_jkt {
        if expected != &proof.jkt {
            return Err(OAuthError::InvalidGrant(
                "DPoP key does not match the key bound at authorization time".into(),
            ));
        }
    }

    let scope = Scope::parse(&record.scope)?;
    issue(
        state,
        &record.did,
        &record.client_id,
        &scope,
        &proof.jkt,
        None,
    )
    .await
}

async fn refresh_token_grant(
    state: &AppState,
    form: TokenForm,
    proof: &DpopProof,
) -> Result<TokenResponse, OAuthError> {
    let presented = form
        .refresh_token
        .ok_or_else(|| OAuthError::InvalidRequest("refresh_token is required".into()))?;

    let record = match state
        .store
        .consume_refresh_token(&hash_secret(&presented), now_unix())
        .await?
    {
        ConsumeResult::Consumed(rec) => *rec,
        // OAuth 2.1 §6.1: a replayed refresh token means either the client or an
        // attacker holds a copy, and there is no way to tell which. Revoking the
        // whole chain is the only safe response — it costs a legitimate client
        // one re-login and shuts an attacker out entirely.
        ConsumeResult::Reused { session_id } => {
            let revoked = state.store.revoke_session(&session_id).await?;
            eprintln!(
                "oauth: refresh token reuse detected for session {session_id}; \
                 revoked {revoked} token(s)"
            );
            return Err(OAuthError::InvalidGrant(
                "refresh token has already been used; the session has been revoked".into(),
            ));
        }
        ConsumeResult::NotFound => {
            return Err(OAuthError::InvalidGrant(
                "refresh token is invalid or expired".into(),
            ))
        }
    };

    if record.client_id != form.client_id {
        return Err(OAuthError::InvalidGrant(
            "refresh token was issued to a different client".into(),
        ));
    }

    // The refresh token is bound to a DPoP key; a proof from any other key must
    // not be able to spend it.
    if record.dpop_jkt != proof.jkt {
        return Err(OAuthError::InvalidGrant(
            "DPoP key does not match the key this refresh token is bound to".into(),
        ));
    }

    // A client may narrow its scope on refresh but never widen it.
    let granted = Scope::parse(&record.scope)?;
    let scope = match form.scope.as_deref() {
        None => granted,
        Some(requested) => {
            let requested = Scope::parse(requested)?;
            if !requested.is_subset_of(&granted) {
                return Err(OAuthError::InvalidScope(
                    "requested scope exceeds the originally granted scope".into(),
                ));
            }
            requested
        }
    };

    // Stay in the same rotation chain so reuse detection keeps working across
    // the whole session rather than resetting on every refresh.
    issue(
        state,
        &record.did,
        &record.client_id,
        &scope,
        &proof.jkt,
        Some(record.session_id),
    )
    .await
}

/// Mint an access token and the next refresh token in a chain.
async fn issue(
    state: &AppState,
    did: &str,
    client_id: &str,
    scope: &Scope,
    jkt: &str,
    session_id: Option<String>,
) -> Result<TokenResponse, OAuthError> {
    let (access_token, expires_in) = state
        .oauth
        .issuer
        .issue_access_token(did, client_id, scope, jkt)?;

    let refresh_token = random_token(32);
    let now = now_unix();
    state
        .store
        .put_refresh_token(RefreshTokenRecord {
            token_hash: hash_secret(&refresh_token),
            session_id: session_id.unwrap_or_else(|| random_token(16)),
            did: did.to_string(),
            client_id: client_id.to_string(),
            scope: scope.to_string(),
            dpop_jkt: jkt.to_string(),
            issued_at: now,
            expires_at: now + token_consts::REFRESH_TOKEN_TTL_SECS,
        })
        .await?;

    Ok(TokenResponse {
        access_token,
        token_type: "DPoP",
        expires_in,
        refresh_token,
        scope: scope.to_string(),
        sub: did.to_string(),
    })
}
