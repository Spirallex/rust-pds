use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::repo::RepoError;
use crate::storage::StorageError;

/// Typed XRPC error enum.
///
/// Every arm maps to an ATProto lexicon error name and HTTP status code.
/// The `error` field in the JSON body MUST match the lexicon name exactly
/// (case-sensitive string literal) — the official Bluesky client branches on it.
///
/// Internal errors map to HTTP 500 with a fixed message ("Internal error") and
/// name ("InternalServerError"). The inner anyhow detail is NEVER included in the
/// response body — it could leak internal paths, queries, or other implementation detail.
#[derive(Debug, thiserror::Error)]
pub enum XrpcError {
    // --- Session / Auth ---
    #[error("Token has expired")]
    ExpiredToken,
    #[error("Token could not be verified")]
    InvalidToken,
    #[error("Authentication required")]
    AuthRequired,
    #[error("Account has been taken down")]
    AccountTakedown,

    // --- Account creation ---
    #[error("Invalid handle")]
    InvalidHandle,
    #[error("Handle not available")]
    HandleNotAvailable,
    #[error("Invalid invite code")]
    InvalidInviteCode,
    #[error("Unsupported domain")]
    UnsupportedDomain,
    #[error("DID cannot be resolved")]
    UnresolvableDid,
    #[error("Incompatible DID document")]
    IncompatibleDidDoc,

    // --- Repo ---
    #[error("Swap commit mismatch")]
    InvalidSwap,

    // --- Identity ---
    #[error("Handle not found")]
    HandleNotFound,

    // --- Generic ---
    #[error("{0}")]
    InvalidRequest(String),

    // --- Upstream / proxy (maps to 502, never reveals upstream detail) ---
    #[error("Upstream service error")]
    UpstreamFailure(String),

    // --- Internal (maps to 500, never reveals details) ---
    #[error("Internal error")]
    Internal(#[from] anyhow::Error),
}

/// Map StorageError into XrpcError::Internal (wraps via anyhow).
/// Cannot use #[from] since anyhow::Error already has a #[from] on the Internal arm.
impl From<StorageError> for XrpcError {
    fn from(e: StorageError) -> Self {
        XrpcError::Internal(anyhow::anyhow!(e))
    }
}

/// Map RepoError into XrpcError::Internal (wraps via anyhow).
impl From<RepoError> for XrpcError {
    fn from(e: RepoError) -> Self {
        XrpcError::Internal(anyhow::anyhow!(e))
    }
}

/// Map the device-portable `CoreError` (returned by the JWT and PLC signing
/// helpers in `stelyph-core`) onto the HTTP-facing XrpcError. The token arms
/// preserve their 401 semantics; everything else is an opaque 500.
impl From<stelyph_core::error::CoreError> for XrpcError {
    fn from(e: stelyph_core::error::CoreError) -> Self {
        use stelyph_core::error::CoreError;
        match e {
            CoreError::ExpiredToken => XrpcError::ExpiredToken,
            CoreError::InvalidToken => XrpcError::InvalidToken,
            CoreError::Internal(inner) => XrpcError::Internal(inner),
        }
    }
}

/// Wire shape: `{"error":"<lexicon name>","message":"<human message>"}`.
#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    message: String,
}

impl IntoResponse for XrpcError {
    fn into_response(self) -> Response {
        let status = match &self {
            XrpcError::ExpiredToken => StatusCode::UNAUTHORIZED,
            XrpcError::InvalidToken => StatusCode::UNAUTHORIZED,
            XrpcError::AuthRequired => StatusCode::UNAUTHORIZED,
            XrpcError::AccountTakedown => StatusCode::UNAUTHORIZED,
            XrpcError::InvalidHandle => StatusCode::BAD_REQUEST,
            XrpcError::HandleNotAvailable => StatusCode::BAD_REQUEST,
            XrpcError::InvalidInviteCode => StatusCode::BAD_REQUEST,
            XrpcError::UnsupportedDomain => StatusCode::BAD_REQUEST,
            XrpcError::UnresolvableDid => StatusCode::BAD_REQUEST,
            XrpcError::IncompatibleDidDoc => StatusCode::BAD_REQUEST,
            XrpcError::InvalidSwap => StatusCode::BAD_REQUEST,
            XrpcError::HandleNotFound => StatusCode::NOT_FOUND,
            XrpcError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            XrpcError::UpstreamFailure(_) => StatusCode::BAD_GATEWAY,
            XrpcError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        // Explicit string literals — NO serde rename magic.
        // These MUST match the ATProto lexicon names exactly.
        let name = match &self {
            XrpcError::ExpiredToken => "ExpiredToken",
            XrpcError::InvalidToken => "InvalidToken",
            XrpcError::AuthRequired => "AuthRequired",
            XrpcError::AccountTakedown => "AccountTakedown",
            XrpcError::InvalidHandle => "InvalidHandle",
            XrpcError::HandleNotAvailable => "HandleNotAvailable",
            XrpcError::InvalidInviteCode => "InvalidInviteCode",
            XrpcError::UnsupportedDomain => "UnsupportedDomain",
            XrpcError::UnresolvableDid => "UnresolvableDid",
            XrpcError::IncompatibleDidDoc => "IncompatibleDidDoc",
            XrpcError::InvalidSwap => "InvalidSwap",
            XrpcError::HandleNotFound => "HandleNotFound",
            XrpcError::InvalidRequest(_) => "InvalidRequest",
            XrpcError::UpstreamFailure(_) => "UpstreamFailure",
            XrpcError::Internal(_) => "InternalServerError",
        };

        // For Internal and UpstreamFailure errors, NEVER serialize the inner detail
        // — use fixed messages, to avoid leaking implementation detail to the client.
        let message = match &self {
            XrpcError::Internal(_) => "Internal error".to_string(),
            XrpcError::UpstreamFailure(_) => "Upstream service error".to_string(),
            other => other.to_string(),
        };

        let body = ErrorBody {
            error: name,
            message,
        };
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::response::IntoResponse;

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn expired_token_body_and_status() {
        let resp = XrpcError::ExpiredToken.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "ExpiredToken");
    }

    #[tokio::test]
    async fn invalid_token_body() {
        let resp = XrpcError::InvalidToken.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "InvalidToken");
    }

    #[tokio::test]
    async fn internal_never_leaks() {
        let resp = XrpcError::Internal(anyhow::anyhow!("db password leak")).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "InternalServerError");
        let msg = json["message"].as_str().unwrap();
        assert_eq!(
            msg, "Internal error",
            "Internal error message must be fixed 'Internal error', not the inner detail"
        );
        assert!(
            !msg.contains("db password leak"),
            "Internal error must not leak inner error detail"
        );
    }

    #[tokio::test]
    async fn upstream_failure_maps_to_502() {
        let resp = XrpcError::UpstreamFailure("secret upstream url leak".into()).into_response();
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let json = body_json(resp).await;
        assert_eq!(json["error"], "UpstreamFailure");
        let msg = json["message"].as_str().unwrap();
        assert_eq!(
            msg, "Upstream service error",
            "UpstreamFailure message must be fixed, not the inner detail"
        );
        assert!(
            !msg.contains("secret upstream url leak"),
            "UpstreamFailure must not leak inner detail"
        );
    }
}
