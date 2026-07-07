use super::service_auth::mint_service_auth_jwt;
use crate::auth::extractor::AccessAuth;
use crate::storage::keys::load_key;
use crate::xrpc::{AppState, XrpcError};
use atrium_crypto::keypair::Secp256k1Keypair;
use axum::{
    body::Body,
    extract::{Path, RawQuery, State},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};

/// Forward an authenticated `GET /xrpc/app.bsky.<suffix>` request to the AppView.
///
/// Mints a fresh ES256K service-auth JWT (iss=account DID, aud=appview_did,
/// lxm=full NSID) and attaches it as a Bearer token. The caller's session token
/// is validated and stripped by `AccessAuth` — it is NEVER forwarded upstream.
/// Non-2xx upstream responses are passed through verbatim; transport errors
/// surface as `XrpcError::UpstreamFailure` (HTTP 502).
pub async fn proxy_handler(
    State(state): State<AppState>,
    AccessAuth(did): AccessAuth,
    Path(method_suffix): Path<String>,
    RawQuery(raw_query): RawQuery,
) -> Result<Response, XrpcError> {
    let nsid = format!("app.bsky.{method_suffix}"); // RESEARCH Pitfall 2: full NSID
    let key_id = format!("{did}#signing");
    let key_bytes = load_key(&state.store, &key_id, &state.key_passphrase)
        .await
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("failed to load signing key: {e}")))?;
    let signing = Secp256k1Keypair::import(&key_bytes)
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("failed to import signing key: {e}")))?;
    let jwt = mint_service_auth_jwt(&signing, &did, &state.appview_did, &nsid)?;
    let query = raw_query.as_deref().unwrap_or("");
    let (status, body, content_type) = state
        .appview_client
        .proxy_get(&state.appview_url, &nsid, query, &jwt)
        .await?;
    let mut builder = Response::builder().status(status);
    // The upstream-supplied Content-Type is attacker-influencable bytes from a
    // remote service. Skip it if it is not a valid HTTP header value rather than
    // letting an invalid value poison the builder and panic on body().
    if let Some(ct) = content_type {
        if let Ok(hv) = axum::http::HeaderValue::from_str(&ct) {
            builder = builder.header("content-type", hv);
        }
    }
    let resp = builder
        .body(Body::from(body))
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("build proxy response: {e}")))?;
    Ok(resp.into_response())
}

/// Wildcard read proxy. Merge AFTER explicit routes (preferences come in Plan 03).
pub fn routes() -> Router<AppState> {
    Router::new().route("/xrpc/app.bsky.{*method}", get(proxy_handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xrpc::appview::client::{AppViewClient, MockAppViewClient};
    use crate::xrpc::appview::service_auth::mint_service_auth_jwt;

    /// Guard against Pitfall 2: the lxm in the minted JWT MUST be the full NSID.
    #[test]
    fn lxm_is_full_nsid() {
        use atrium_crypto::keypair::Secp256k1Keypair;
        use data_encoding::BASE64URL_NOPAD;

        let method_suffix = "feed.getTimeline";
        let nsid = format!("app.bsky.{method_suffix}");
        assert_eq!(nsid, "app.bsky.feed.getTimeline");

        let key = Secp256k1Keypair::import(&[0x11u8; 32]).unwrap();
        let token =
            mint_service_auth_jwt(&key, "did:plc:abc", "did:web:api.bsky.app", &nsid).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let claims: serde_json::Value =
            serde_json::from_slice(&BASE64URL_NOPAD.decode(parts[1].as_bytes()).unwrap()).unwrap();
        assert_eq!(
            claims["lxm"].as_str().unwrap(),
            "app.bsky.feed.getTimeline",
            "lxm must be the full NSID"
        );
    }

    /// Mock proxy_get records the call and returns the canned response unchanged.
    #[tokio::test]
    async fn mock_proxy_passes_through() {
        let mock = MockAppViewClient::new((
            200,
            b"{\"feed\":[]}".to_vec(),
            Some("application/json".into()),
        ));
        let (status, body, ct) = mock
            .proxy_get(
                "https://api.bsky.app",
                "app.bsky.feed.getTimeline",
                "limit=1",
                "tok",
            )
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(&body[..], b"{\"feed\":[]}");
        assert_eq!(ct, Some("application/json".to_string()));
        let calls = mock.calls();
        assert_eq!(calls[0].0, "app.bsky.feed.getTimeline");
    }

    /// XrpcError::UpstreamFailure maps to HTTP 502 Bad Gateway.
    #[test]
    fn transport_error_is_502() {
        let err = XrpcError::UpstreamFailure("down".into());
        let resp = err.into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_GATEWAY);
    }
}
