//! Bearer JWT extractor functions + axum FromRequestParts extractors.
//!
//! Plain functions (authenticate_access / authenticate_refresh) are free of
//! AppState so they can be unit-tested without circular deps.
//!
//! The axum extractors (AccessAuth / RefreshAuth) pull the JWT secret from
//! AppState and delegate to the plain functions.
//!
//! Security: the access path rejects refresh-scoped tokens.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::HeaderMap;

use crate::auth::jwt::decode_jwt;
use crate::xrpc::XrpcError;

/// The authentication scheme a request presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scheme {
    /// Legacy `createSession` / app-password JWT.
    Bearer,
    /// OAuth access token, which must additionally carry a DPoP proof.
    Dpop,
}

/// Split the `Authorization` header into its scheme and token.
///
/// Scheme matching is case-insensitive because RFC 7235 says the scheme is, and
/// clients do send `dpop` and `DPoP` interchangeably.
fn authorization(headers: &HeaderMap) -> Result<(Scheme, &str), XrpcError> {
    let header = headers
        .get("Authorization")
        .ok_or(XrpcError::AuthRequired)?
        .to_str()
        .map_err(|_| XrpcError::InvalidToken)?;

    let (scheme, token) = header.split_once(' ').ok_or(XrpcError::InvalidToken)?;
    let token = token.trim();
    if token.is_empty() {
        return Err(XrpcError::InvalidToken);
    }

    if scheme.eq_ignore_ascii_case("bearer") {
        Ok((Scheme::Bearer, token))
    } else if scheme.eq_ignore_ascii_case("dpop") {
        Ok((Scheme::Dpop, token))
    } else {
        Err(XrpcError::InvalidToken)
    }
}

/// Extract the Bearer token string from the `Authorization` header.
fn bearer_token(headers: &HeaderMap) -> Result<&str, XrpcError> {
    match authorization(headers)? {
        (Scheme::Bearer, token) => Ok(token),
        (Scheme::Dpop, _) => Err(XrpcError::InvalidToken),
    }
}

/// Authenticate an access-scoped request.
///
/// Reads the `Authorization: Bearer <token>` header, decodes the JWT, and
/// asserts that `scope == "com.atproto.access"`. Refresh-scoped tokens are
/// rejected with `XrpcError::InvalidToken`.
///
/// Returns the DID (`claims.sub`) on success.
///
/// Wrapped by the axum extractor `AccessAuth(pub String)`.
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
        match authorization(&parts.headers)? {
            // Legacy app-password session. Still supported: atproto has not
            // removed app passwords, and the user's existing clients rely on it.
            (Scheme::Bearer, _) => {
                let did = authenticate_access(&parts.headers, app_state.jwt_secret.as_ref())?;
                Ok(AccessAuth(did))
            }
            (Scheme::Dpop, token) => {
                let did = authenticate_dpop(app_state, parts, token).await?;
                Ok(AccessAuth(did))
            }
        }
    }
}

/// Authenticate an OAuth access token plus its DPoP proof.
///
/// Three things must all hold, and checking only the first two is the common
/// mistake that makes DPoP decorative:
///
/// 1. the access token verifies and has not expired;
/// 2. the DPoP proof verifies against this method and URI, is fresh, carries a
///    valid nonce, and has not been replayed;
/// 3. the proof's key thumbprint equals the token's `cnf.jkt`, and the proof's
///    `ath` covers this exact token.
///
/// Without (3) any valid proof from any key would authorize any token.
async fn authenticate_dpop(
    state: &crate::xrpc::AppState,
    parts: &Parts,
    access_token: &str,
) -> Result<String, XrpcError> {
    // Exactly one DPoP header (RFC 9449 §4.3).
    let mut values = parts.headers.get_all("DPoP").iter();
    let proof = values.next().ok_or(XrpcError::AuthRequired)?;
    if values.next().is_some() {
        return Err(XrpcError::InvalidToken);
    }
    let proof = proof.to_str().map_err(|_| XrpcError::InvalidToken)?;

    let claims = state
        .oauth
        .issuer
        .verify_access_token(access_token)
        .map_err(|_| XrpcError::InvalidToken)?;

    // Build the URI from the configured issuer plus the request path. `Host` and
    // `X-Forwarded-*` are attacker-controlled; deriving `htu` from them would let
    // a proof minted for one origin be replayed here.
    let url = state.oauth.endpoint_url(parts.uri.path());

    let verified = state
        .oauth
        .dpop
        .verify(
            state.store.as_ref(),
            proof,
            parts.method.as_str(),
            &url,
            Some(access_token),
            true,
        )
        .await
        .map_err(|_| XrpcError::InvalidToken)?;

    if verified.jkt != claims.cnf.jkt {
        return Err(XrpcError::InvalidToken);
    }

    Ok(claims.sub)
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
