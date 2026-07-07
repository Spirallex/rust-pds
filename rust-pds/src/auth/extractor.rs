//! Bearer JWT extractor functions + axum FromRequestParts extractors.
//!
//! Plain functions (authenticate_access / authenticate_refresh) are free of
//! AppState so Plan 03-01 tests pass without circular deps.
//!
//! Plan 03-02 adds the axum extractors (AccessAuth / RefreshAuth) that pull the
//! JWT secret from AppState and delegate to the plain functions.
//!
//! T-03-03 mitigation: access path rejects refresh-scoped tokens.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::HeaderMap;

use crate::auth::jwt::decode_jwt;
use crate::xrpc::XrpcError;

/// Extract the Bearer token string from the `Authorization` header.
fn bearer_token(headers: &HeaderMap) -> Result<&str, XrpcError> {
    let header = headers
        .get("Authorization")
        .ok_or(XrpcError::AuthRequired)?
        .to_str()
        .map_err(|_| XrpcError::InvalidToken)?;

    header
        .strip_prefix("Bearer ")
        .ok_or(XrpcError::InvalidToken)
}

/// Authenticate an access-scoped request.
///
/// Reads the `Authorization: Bearer <token>` header, decodes the JWT, and
/// asserts that `scope == "com.atproto.access"`. Refresh-scoped tokens are
/// rejected with `XrpcError::InvalidToken` (Pitfall 3 / T-03-03).
///
/// Returns the DID (`claims.sub`) on success.
///
/// Plan 03-02 wraps this in an axum extractor: `AccessAuth(pub String)`.
pub fn authenticate_access(headers: &HeaderMap, secret: &[u8]) -> Result<String, XrpcError> {
    let token = bearer_token(headers)?;
    let claims = decode_jwt(token, secret)?;
    if claims.scope != "com.atproto.access" {
        return Err(XrpcError::InvalidToken);
    }
    Ok(claims.sub)
}

/// Authenticate a refresh-scoped request.
///
/// Reads the `Authorization: Bearer <token>` header, decodes the JWT, and
/// asserts that `scope == "com.atproto.refresh"`. Access-scoped tokens are
/// rejected with `XrpcError::InvalidToken`.
///
/// Returns the DID (`claims.sub`) on success.
///
/// Plan 03-02 wraps this in an axum extractor: `RefreshAuth(pub String)`.
pub fn authenticate_refresh(headers: &HeaderMap, secret: &[u8]) -> Result<String, XrpcError> {
    let token = bearer_token(headers)?;
    let claims = decode_jwt(token, secret)?;
    if claims.scope != "com.atproto.refresh" {
        return Err(XrpcError::InvalidToken);
    }
    Ok(claims.sub)
}

// ---------------------------------------------------------------------------
// axum FromRequestParts extractors (Plan 03-02)
// ---------------------------------------------------------------------------

/// Axum extractor for access-scoped Bearer tokens.
///
/// Wraps `authenticate_access` and pulls the JWT secret from `AppState`.
/// Used by authenticated XRPC handlers that require a valid access JWT.
///
/// On success, yields `AccessAuth(did_string)`.
/// On failure, returns the appropriate `XrpcError` as the rejection.
pub struct AccessAuth(pub String);

impl<S> FromRequestParts<S> for AccessAuth
where
    S: Send + Sync + AsRef<crate::xrpc::AppState>,
{
    type Rejection = XrpcError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state: &crate::xrpc::AppState = state.as_ref();
        let did = authenticate_access(&parts.headers, app_state.jwt_secret.as_ref())?;
        Ok(AccessAuth(did))
    }
}

/// Axum extractor for refresh-scoped Bearer tokens.
///
/// Used exclusively by `refreshSession`. Pulls the JWT secret from `AppState`.
/// Expired refresh JWTs → `XrpcError::ExpiredToken`.
/// Access-scoped tokens on the refresh path → `XrpcError::InvalidToken`.
pub struct RefreshAuth(pub String);

impl<S> FromRequestParts<S> for RefreshAuth
where
    S: Send + Sync + AsRef<crate::xrpc::AppState>,
{
    type Rejection = XrpcError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state: &crate::xrpc::AppState = state.as_ref();
        let did = authenticate_refresh(&parts.headers, app_state.jwt_secret.as_ref())?;
        Ok(RefreshAuth(did))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::{encode_access_jwt, encode_refresh_jwt};
    use axum::http::HeaderValue;

    const SECRET: &[u8] = b"extractor-test-secret";
    const DID: &str = "did:plc:extractortest";

    fn headers_with_bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    #[test]
    fn access_extractor_accepts_access_token() {
        let token = encode_access_jwt(DID, SECRET).unwrap();
        let did = authenticate_access(&headers_with_bearer(&token), SECRET).unwrap();
        assert_eq!(did, DID);
    }

    #[test]
    fn access_extractor_rejects_refresh_token() {
        let token = encode_refresh_jwt(DID, SECRET).unwrap();
        let result = authenticate_access(&headers_with_bearer(&token), SECRET);
        match result {
            Err(XrpcError::InvalidToken) => {}
            other => panic!(
                "expected InvalidToken for refresh token on access path, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn missing_auth_header_returns_auth_required() {
        let headers = HeaderMap::new();
        let result = authenticate_access(&headers, SECRET);
        match result {
            Err(XrpcError::AuthRequired) => {}
            other => panic!("expected AuthRequired, got: {:?}", other),
        }
    }

    #[test]
    fn refresh_extractor_accepts_refresh_token() {
        let token = encode_refresh_jwt(DID, SECRET).unwrap();
        let did = authenticate_refresh(&headers_with_bearer(&token), SECRET).unwrap();
        assert_eq!(did, DID);
    }

    #[test]
    fn refresh_extractor_rejects_access_token() {
        let token = encode_access_jwt(DID, SECRET).unwrap();
        let result = authenticate_refresh(&headers_with_bearer(&token), SECRET);
        match result {
            Err(XrpcError::InvalidToken) => {}
            other => panic!(
                "expected InvalidToken for access token on refresh path, got: {:?}",
                other
            ),
        }
    }
}
