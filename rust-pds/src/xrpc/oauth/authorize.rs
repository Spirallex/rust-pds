//! `GET`/`POST /oauth/authorize` — the front-channel endpoint.
//!
//! `GET` renders the combined login + consent page for a pushed request.
//! `POST` takes credentials and a decision, and on success issues an
//! authorization code and redirects back to the client.
//!
//! # Error routing
//!
//! Once a `redirect_uri` has been validated (which PAR already did), errors go
//! back to the client as `error`/`error_description`/`state` query parameters,
//! per RFC 6749 §4.1.2.1. Only when there is no trustworthy redirect target —
//! an unknown or expired `request_uri` — is an HTML error page rendered.
//! Rendering an unvalidated redirect target would make this an open redirector.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;

use stelyph_core::oauth::store::{hash_secret, AuthCode, StoredPushedRequest};
use stelyph_core::oauth::{
    now_unix, random_token, request::validate_request_uri, token, ClientId, OAuthError, Scope,
};

use crate::xrpc::oauth::html;
use crate::xrpc::AppState;

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub request_uri: String,
    /// Sent by clients for symmetry with the non-PAR flow. Checked against the
    /// stored request when present; the stored value is authoritative either way.
    pub client_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeForm {
    pub request_uri: String,
    pub username: String,
    pub password: String,
    /// `accept` or `deny`.
    pub action: String,
}

/// `GET /oauth/authorize`
pub async fn authorize_page(
    State(state): State<AppState>,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    let stored = match load_request(&state, &q.request_uri).await {
        Ok(s) => s,
        Err(page) => return page,
    };

    // If the client also passed client_id, it must agree with the pushed
    // request. A mismatch means the browser was pointed at someone else's
    // pending request.
    if let Some(client_id) = &q.client_id {
        if client_id != &stored.client_id {
            return error_html(
                StatusCode::BAD_REQUEST,
                "Invalid request",
                "The client_id does not match this authorization request.",
            );
        }
    }

    render_page(&state, &q.request_uri, &stored, None).await
}

/// `POST /oauth/authorize`
pub async fn authorize_submit(
    State(state): State<AppState>,
    Form(form): Form<AuthorizeForm>,
) -> Response {
    let stored = match load_request(&state, &form.request_uri).await {
        Ok(s) => s,
        Err(page) => return page,
    };

    // An explicit denial is a normal outcome, reported to the client as
    // `access_denied` rather than as a failure of this server.
    if form.action != "accept" {
        let _ = state
            .store
            .delete_pushed_request(&stored.request_uri_hash)
            .await;
        return redirect_error(&stored, "access_denied", "The user denied the request.");
    }

    // Authenticate. A wrong password re-renders the page rather than redirecting,
    // so the user can retry without the client having to restart the flow.
    let did = match authenticate(&state, &form.username, &form.password).await {
        Ok(did) => did,
        Err(message) => {
            return render_page(&state, &form.request_uri, &stored, Some(message)).await
        }
    };

    match issue_code(&state, &stored, &did).await {
        Ok(redirect) => redirect,
        Err(e) => redirect_error(&stored, e.error_code(), &e.public_description()),
    }
}

/// Load and validate the pushed request behind a `request_uri`.
///
/// On failure returns a rendered error page: at this point no `redirect_uri` is
/// known to be trustworthy, so there is nowhere safe to redirect.
async fn load_request(
    state: &AppState,
    request_uri: &str,
) -> Result<StoredPushedRequest, Response> {
    if validate_request_uri(request_uri).is_err() {
        return Err(error_html(
            StatusCode::BAD_REQUEST,
            "Invalid request",
            "This authorization request is not recognised.",
        ));
    }

    let hash = hash_secret(request_uri);
    match state.store.get_pushed_request(&hash, now_unix()).await {
        Ok(Some(stored)) => Ok(stored),
        Ok(None) => Err(error_html(
            StatusCode::BAD_REQUEST,
            "Request expired",
            "This authorization request has expired or has already been used. \
             Please start again from the application.",
        )),
        Err(e) => {
            eprintln!("oauth: authorize storage error: {e}");
            Err(error_html(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Server error",
                "Something went wrong. Please try again.",
            ))
        }
    }
}

/// Verify a handle/email + password against the account store.
///
/// The failure message is deliberately identical for an unknown account and a
/// wrong password, so this cannot be used to enumerate accounts.
async fn authenticate(
    state: &AppState,
    username: &str,
    password: &str,
) -> Result<String, &'static str> {
    const GENERIC: &str = "Incorrect handle or password.";

    let handle = username.trim().trim_start_matches('@').to_ascii_lowercase();
    let account = match state.store.get_account_by_handle(&handle).await {
        Ok(Some(a)) => a,
        Ok(None) => return Err(GENERIC),
        Err(e) => {
            eprintln!("oauth: account lookup failed: {e}");
            return Err("Something went wrong. Please try again.");
        }
    };
    let (did, phc) = account;

    match stelyph_core::auth::jwt::verify_password(password, &phc) {
        Ok(true) => Ok(did),
        Ok(false) => Err(GENERIC),
        Err(e) => {
            eprintln!("oauth: password verification failed: {e}");
            Err("Something went wrong. Please try again.")
        }
    }
}

/// Issue an authorization code and build the redirect back to the client.
async fn issue_code(
    state: &AppState,
    stored: &StoredPushedRequest,
    did: &str,
) -> Result<Response, OAuthError> {
    let code = random_token(32);

    state
        .store
        .put_auth_code(AuthCode {
            code_hash: hash_secret(&code),
            did: did.to_string(),
            client_id: stored.client_id.clone(),
            redirect_uri: stored.redirect_uri.clone(),
            scope: stored.scope.clone(),
            code_challenge: stored.code_challenge.clone(),
            dpop_jkt: stored.dpop_jkt.clone(),
            expires_at: now_unix() + token::AUTH_CODE_TTL_SECS,
        })
        .await
        .map_err(OAuthError::Storage)?;

    // The pushed request has served its purpose. Deleting it makes the whole
    // authorization single-use: a replayed request_uri cannot mint a second code.
    state
        .store
        .delete_pushed_request(&stored.request_uri_hash)
        .await
        .map_err(OAuthError::Storage)?;

    // `iss` on the response lets the client detect a mix-up between two
    // authorization servers, which PKCE alone does not prevent.
    let location = append_query(
        &stored.redirect_uri,
        &[
            ("code", code.as_str()),
            ("state", stored.state.as_str()),
            ("iss", state.oauth.issuer_url.as_str()),
        ],
    );
    Ok(Redirect::to(&location).into_response())
}

/// Render the login + consent page for a pending request.
///
/// `request_uri` is the raw handle as the browser supplied it. Only its hash is
/// stored, so it has to be passed in to go back into the form's hidden field;
/// the POST handler re-validates and re-hashes whatever comes back rather than
/// trusting it.
async fn render_page(
    state: &AppState,
    request_uri: &str,
    stored: &StoredPushedRequest,
    error: Option<&str>,
) -> Response {
    // Re-resolve the client so the consent screen shows its current name — and
    // so a client whose metadata has since become invalid cannot be consented to.
    let client_name = match ClientId::parse(&stored.client_id) {
        Ok(id) => match state.oauth.client_resolver.resolve(&id).await {
            Ok(md) => md.display_name().to_string(),
            Err(_) => stored.client_id.clone(),
        },
        Err(_) => stored.client_id.clone(),
    };

    let scope = Scope::parse(&stored.scope).unwrap_or_default();
    let scopes: Vec<&str> = scope.iter().collect();

    Html(html::authorize_page(
        request_uri,
        &client_name,
        &stored.client_id,
        &scopes,
        stored.login_hint.as_deref(),
        error,
    ))
    .into_response()
}

/// Build `base` with `params` appended, preserving any query already present.
fn append_query(base: &str, params: &[(&str, &str)]) -> String {
    let mut url = base.to_string();
    let mut sep = if base.contains('?') { '&' } else { '?' };
    for (k, v) in params {
        url.push(sep);
        url.push_str(&urlencode(k));
        url.push('=');
        url.push_str(&urlencode(v));
        sep = '&';
    }
    url
}

/// Percent-encode a query parameter value.
///
/// Only the RFC 3986 unreserved set passes through unescaped. Encoding
/// conservatively means a value containing `&`, `=`, or `#` cannot inject an
/// extra parameter or truncate the URL.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Redirect an OAuth error back to the client's registered redirect URI.
fn redirect_error(stored: &StoredPushedRequest, code: &str, description: &str) -> Response {
    let location = append_query(
        &stored.redirect_uri,
        &[
            ("error", code),
            ("error_description", description),
            ("state", &stored.state),
        ],
    );
    Redirect::to(&location).into_response()
}

fn error_html(status: StatusCode, title: &str, message: &str) -> Response {
    (status, Html(html::error_page(title, message))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_query_handles_existing_query_strings() {
        assert_eq!(
            append_query("https://a.test/cb", &[("code", "abc"), ("state", "s1")]),
            "https://a.test/cb?code=abc&state=s1"
        );
        assert_eq!(
            append_query("https://a.test/cb?x=1", &[("code", "abc")]),
            "https://a.test/cb?x=1&code=abc"
        );
    }

    #[test]
    fn query_values_are_percent_encoded() {
        // A state value that tries to inject another parameter.
        let url = append_query("https://a.test/cb", &[("state", "a&code=evil")]);
        assert_eq!(url, "https://a.test/cb?state=a%26code%3Devil");
        assert!(
            !url.contains("&code=evil"),
            "an injected parameter must not survive encoding"
        );

        // A fragment would otherwise truncate everything after it.
        let url = append_query("https://a.test/cb", &[("state", "a#frag")]);
        assert!(url.ends_with("a%23frag"));
    }

    #[test]
    fn urlencode_passes_the_unreserved_set_through() {
        assert_eq!(urlencode("aZ09-._~"), "aZ09-._~");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("/"), "%2F");
    }
}
