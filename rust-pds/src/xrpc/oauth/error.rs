//! HTTP rendering of [`OAuthError`].
//!
//! Every OAuth endpoint returns errors in the RFC 6749 §5.2 JSON shape. Two
//! cases need more than a status code and a body:
//!
//! - `use_dpop_nonce` must carry a `DPoP-Nonce` header, or the client has
//!   nothing to retry with. It is part of the handshake, not a failure.
//! - `invalid_client` and `invalid_token` carry a `WWW-Authenticate` header so a
//!   client can tell an auth failure from a malformed request.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use stelyph_core::oauth::OAuthError;

/// An [`OAuthError`] plus the nonce to advertise alongside it.
pub struct OAuthHttpError {
    pub error: OAuthError,
    /// Sent as `DPoP-Nonce`. Always supplied on endpoints that require DPoP, so
    /// a client that got the nonce wrong can immediately retry with a fresh one.
    pub nonce: Option<String>,
}

impl OAuthHttpError {
    pub fn new(error: OAuthError) -> Self {
        Self { error, nonce: None }
    }

    pub fn with_nonce(error: OAuthError, nonce: impl Into<String>) -> Self {
        Self {
            error,
            nonce: Some(nonce.into()),
        }
    }

    fn status(&self) -> StatusCode {
        match &self.error {
            // RFC 9449: a missing or stale nonce is reported as 400 with
            // `use_dpop_nonce` on the token endpoint (401 on a resource server,
            // which is handled separately by the resource extractor).
            OAuthError::UseDpopNonce(_) => StatusCode::BAD_REQUEST,
            OAuthError::InvalidClient(_) | OAuthError::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            OAuthError::InvalidDpopProof(_) => StatusCode::UNAUTHORIZED,
            OAuthError::AccessDenied(_) => StatusCode::FORBIDDEN,
            OAuthError::Storage(_) | OAuthError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

impl From<OAuthError> for OAuthHttpError {
    fn from(error: OAuthError) -> Self {
        Self::new(error)
    }
}

impl IntoResponse for OAuthHttpError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.error.error_code();

        // Log the full error server-side; only the sanitized description goes
        // out. `public_description` collapses storage and internal errors so a
        // database path cannot reach the client.
        if matches!(self.error, OAuthError::Storage(_) | OAuthError::Internal(_)) {
            eprintln!("oauth: internal error: {}", self.error);
        }

        let mut response = (
            status,
            Json(serde_json::json!({
                "error": code,
                "error_description": self.error.public_description(),
            })),
        )
            .into_response();

        if let Some(nonce) = self.nonce {
            if let Ok(v) = HeaderValue::from_str(&nonce) {
                response.headers_mut().insert("DPoP-Nonce", v);
                // Browsers cannot read a response header cross-origin unless it
                // is exposed; without this a web client never sees the nonce and
                // can never complete the handshake.
                response.headers_mut().insert(
                    header::ACCESS_CONTROL_EXPOSE_HEADERS,
                    HeaderValue::from_static("DPoP-Nonce"),
                );
            }
        }

        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("DPoP algs=\"ES256 ES256K\""),
            );
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_of(e: OAuthError) -> StatusCode {
        OAuthHttpError::new(e).status()
    }

    #[test]
    fn status_codes_follow_the_rfc() {
        assert_eq!(
            status_of(OAuthError::InvalidRequest("x".into())),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_of(OAuthError::InvalidClient("x".into())),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status_of(OAuthError::InvalidGrant("x".into())),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_of(OAuthError::UseDpopNonce("x".into())),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_of(OAuthError::Internal("x".into())),
            StatusCode::INTERNAL_SERVER_ERROR,
            "an internal failure must not be reported as a client error"
        );
    }

    #[tokio::test]
    async fn nonce_is_sent_and_exposed_to_browsers() {
        let resp =
            OAuthHttpError::with_nonce(OAuthError::UseDpopNonce("need one".into()), "nonce-abc")
                .into_response();
        assert_eq!(resp.headers().get("DPoP-Nonce").unwrap(), "nonce-abc");
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
                .unwrap(),
            "DPoP-Nonce",
            "a browser client cannot read DPoP-Nonce unless it is exposed"
        );
    }

    #[tokio::test]
    async fn internal_detail_does_not_reach_the_body() {
        use axum::body::to_bytes;
        let resp = OAuthHttpError::new(OAuthError::Internal(
            "postgres://user:pw@internal-host/db".into(),
        ))
        .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "server_error");
        assert!(
            !body
                .windows(b"internal-host".len())
                .any(|w| w == b"internal-host"),
            "internal connection detail must never reach the client"
        );
    }

    #[tokio::test]
    async fn unauthorized_carries_www_authenticate() {
        let resp = OAuthHttpError::new(OAuthError::InvalidToken("bad".into())).into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("DPoP"));
    }
}
