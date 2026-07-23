//! Generalized XRPC service proxy — the PDS-side of `atproto-proxy` routing.
//!
//! The official Bluesky client sends EVERY non-repo request to its PDS and
//! expects the PDS to forward it to the right service: the AppView by
//! default, and whatever the `atproto-proxy: <did>#<fragment>` header names
//! otherwise (chat, moderation reports, video, feed generators, labelers,
//! push notifications). Both lexicon queries (GET) and procedures (POST) are
//! proxied.
//!
//! This is mounted as the router FALLBACK, so every explicitly-registered
//! local route (sessions, repo CRUD, preferences, firehose, …) wins first.
//!
//! Per request: validate the caller's session (the session token is NEVER
//! forwarded), resolve the target service DID to a base URL, mint a fresh
//! ES256K service-auth JWT (iss = account DID, aud = service DID, lxm = the
//! NSID), forward with body + `atproto-accept-labelers`, and relay the
//! response (status, body, content-type, `atproto-content-labelers`)
//! verbatim. Transport errors surface as 502 UpstreamFailure.

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use super::client::{ProxyMethod, UpstreamRequest};
use super::service_auth::mint_service_auth_jwt;
use crate::auth::extractor::AccessAuth;
use crate::xrpc::repo::load_signing_key_cached;
use crate::xrpc::{AppState, XrpcError};

/// Cap on a proxied POST body. Procedure payloads are small JSON; blobs and
/// video bytes do NOT go through this path (uploadBlob is local, video goes
/// direct with service auth).
const MAX_PROXY_BODY: usize = 1024 * 1024;

/// Router fallback: proxy any unmatched `/xrpc/<nsid>` GET/POST upstream.
pub async fn proxy_fallback(
    State(state): State<AppState>,
    AccessAuth(did): AccessAuth,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, XrpcError> {
    let Some(nsid) = uri.path().strip_prefix("/xrpc/").map(str::to_owned) else {
        return Err(XrpcError::MethodNotImplemented);
    };
    if nsid.is_empty() || nsid.contains('/') {
        return Err(XrpcError::MethodNotImplemented);
    }
    let proxy_method = match method {
        Method::GET => ProxyMethod::Get,
        Method::POST => ProxyMethod::Post,
        _ => return Err(XrpcError::MethodNotImplemented),
    };
    if body.len() > MAX_PROXY_BODY {
        return Err(XrpcError::InvalidRequest("request body too large".into()));
    }

    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };

    // Route: explicit atproto-proxy header wins; bare app.bsky.* defaults to
    // the configured AppView; anything else unaddressed is unimplemented.
    let (target_did, base_url) = match header("atproto-proxy") {
        Some(target) => {
            let (tdid, fragment) = target.split_once('#').ok_or_else(|| {
                XrpcError::InvalidRequest("atproto-proxy must be <did>#<service-fragment>".into())
            })?;
            let base = state.service_resolver.resolve(tdid, fragment).await?;
            (tdid.to_string(), base)
        }
        None if nsid.starts_with("app.bsky.") => {
            (state.appview_did.clone(), state.appview_url.clone())
        }
        None => return Err(XrpcError::MethodNotImplemented),
    };

    // Mint a fresh service token for the target; the caller's session Bearer
    // is validated above and never forwarded.
    let signing = load_signing_key_cached(&state, &did).await?;
    let jwt = mint_service_auth_jwt(&signing, &did, &target_did, &nsid)?;

    let upstream = state
        .appview_client
        .proxy_request(UpstreamRequest {
            method: proxy_method,
            base_url,
            nsid,
            query: uri.query().unwrap_or("").to_string(),
            body,
            content_type: header("content-type"),
            jwt,
            accept_labelers: header("atproto-accept-labelers"),
        })
        .await?;

    let mut builder = Response::builder()
        .status(StatusCode::from_u16(upstream.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    // Upstream header values are attacker-influencable bytes from a remote
    // service; skip any that would poison the builder rather than panic.
    if let Some(ct) = upstream.content_type {
        if let Ok(hv) = axum::http::HeaderValue::from_str(&ct) {
            builder = builder.header("content-type", hv);
        }
    }
    if let Some(labelers) = upstream.content_labelers {
        if let Ok(hv) = axum::http::HeaderValue::from_str(&labelers) {
            builder = builder.header("atproto-content-labelers", hv);
        }
    }
    let resp = builder
        .body(Body::from(upstream.body))
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("build proxy response: {e}")))?;
    Ok(resp.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xrpc::appview::client::AppViewClient;
    use crate::xrpc::appview::client::MockAppViewClient;
    use crate::xrpc::appview::service_auth::mint_service_auth_jwt;

    /// The lxm in the minted JWT MUST be the full NSID, not the route suffix.
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

    /// Mock proxy passes the canned response through unchanged.
    #[tokio::test]
    async fn mock_proxy_passes_through() {
        let mock = MockAppViewClient::new((
            200,
            b"{\"feed\":[]}".to_vec(),
            Some("application/json".into()),
        ));
        let resp = mock
            .proxy_request(UpstreamRequest {
                method: ProxyMethod::Get,
                base_url: "https://api.bsky.app".into(),
                nsid: "app.bsky.feed.getTimeline".into(),
                query: "limit=1".into(),
                body: Bytes::new(),
                content_type: None,
                jwt: "tok".into(),
                accept_labelers: None,
            })
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(&resp.body[..], b"{\"feed\":[]}");
        assert_eq!(resp.content_type, Some("application/json".to_string()));
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

    // ---- router-level routing tests --------------------------------------

    use std::sync::Arc;

    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::auth::jwt::encode_access_jwt;
    use crate::storage::crypto::store_key;
    use crate::storage::SqliteStore;
    use crate::xrpc::app;
    use crate::xrpc::appview::MockServiceDidResolver;

    const TEST_SECRET: &[u8] = b"proxy-router-test-secret";
    const TEST_DID: &str = "did:plc:proxyrouter";

    async fn test_state() -> (
        crate::xrpc::AppState,
        Arc<MockAppViewClient>,
        tempfile::NamedTempFile,
    ) {
        let (store, tmp) = SqliteStore::open_in_memory().await.expect("open_in_memory");
        let upstream = Arc::new(MockAppViewClient::new((
            200,
            b"{\"ok\":true}".to_vec(),
            Some("application/json".into()),
        )));
        let state = crate::xrpc::AppState {
            store: Arc::new(store),
            jwt_secret: Arc::new(TEST_SECRET.to_vec()),
            hostname: "pds.test".to_string(),
            pds_endpoint: "https://pds.test".to_string(),
            open_registration: false,
            plc_client: Arc::new(crate::identity::plc::MockPlcClient::new()),
            did_web_resolver: Arc::new(crate::identity::web_resolver::MockDidWebResolver::new_ok()),
            key_passphrase: Arc::new(b"proxy-router-passphrase".to_vec()),
            firehose_tx: tokio::sync::broadcast::channel(16).0,
            relay_client: Arc::new(crate::firehose::MockRelayClient::new()),
            relay_url: "https://relay.test".to_string(),
            appview_client: upstream.clone(),
            appview_url: "https://appview.test".to_string(),
            appview_did: "did:web:appview.test".to_string(),
            service_resolver: Arc::new(MockServiceDidResolver::new("https://plcsvc.test")),
            did_locks: Arc::new(dashmap::DashMap::new()),
            signing_key_cache: Arc::new(dashmap::DashMap::new()),
            oauth: crate::xrpc::oauth::test_oauth_state(),
        };
        // The proxy mints service auth with the account signing key.
        use atrium_crypto::keypair::{Export, Secp256k1Keypair};
        let signing = Secp256k1Keypair::create(&mut rand::rngs::OsRng);
        store_key(
            state.store.as_ref(),
            &format!("{TEST_DID}#signing"),
            &signing.export(),
            &state.key_passphrase,
        )
        .await
        .expect("store_key");
        (state, upstream, tmp)
    }

    fn bearer() -> String {
        format!(
            "Bearer {}",
            encode_access_jwt(TEST_DID, TEST_SECRET).unwrap()
        )
    }

    /// GET app.bsky.* without a proxy header goes to the configured AppView.
    #[tokio::test]
    async fn bare_app_bsky_get_defaults_to_appview() {
        let (state, upstream, _tmp) = test_state().await;
        let resp = app(state)
            .oneshot(
                Request::get("/xrpc/app.bsky.feed.getTimeline?limit=5")
                    .header("Authorization", bearer())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let reqs = upstream.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].base_url, "https://appview.test");
        assert_eq!(reqs[0].nsid, "app.bsky.feed.getTimeline");
        assert_eq!(reqs[0].method, ProxyMethod::Get);
    }

    /// atproto-proxy header routes a POST (with body) to the named service,
    /// with lxm/aud minted for that service and the body forwarded.
    #[tokio::test]
    async fn proxy_header_routes_post_with_body() {
        use data_encoding::BASE64URL_NOPAD;
        let (state, upstream, _tmp) = test_state().await;
        let resp = app(state)
            .oneshot(
                Request::post("/xrpc/chat.bsky.convo.sendMessage")
                    .header("Authorization", bearer())
                    .header("atproto-proxy", "did:web:api.bsky.chat#bsky_chat")
                    .header("content-type", "application/json")
                    .header("atproto-accept-labelers", "did:plc:lab;redact")
                    .body(axum::body::Body::from(r#"{"convoId":"c1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let reqs = upstream.requests();
        assert_eq!(reqs.len(), 1);
        let r = &reqs[0];
        assert_eq!(r.method, ProxyMethod::Post);
        assert_eq!(r.base_url, "https://api.bsky.chat");
        assert_eq!(r.nsid, "chat.bsky.convo.sendMessage");
        assert_eq!(&r.body[..], br#"{"convoId":"c1"}"#);
        assert_eq!(r.content_type.as_deref(), Some("application/json"));
        assert_eq!(r.accept_labelers.as_deref(), Some("did:plc:lab;redact"));
        // Service JWT aud must be the chat service DID, lxm the full NSID.
        let parts: Vec<&str> = r.jwt.split('.').collect();
        let claims: serde_json::Value =
            serde_json::from_slice(&BASE64URL_NOPAD.decode(parts[1].as_bytes()).unwrap()).unwrap();
        assert_eq!(claims["iss"], TEST_DID);
        assert_eq!(claims["aud"], "did:web:api.bsky.chat");
        assert_eq!(claims["lxm"], "chat.bsky.convo.sendMessage");
    }

    /// Non-app.bsky NSIDs without a proxy header stay MethodNotImplemented,
    /// and unauthenticated requests never reach the upstream.
    #[tokio::test]
    async fn unrouted_and_unauthed_requests_are_rejected() {
        let (state, upstream, _tmp) = test_state().await;

        let resp = app(state.clone())
            .oneshot(
                Request::get("/xrpc/com.example.custom.method")
                    .header("Authorization", bearer())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "MethodNotImplemented");

        let resp = app(state)
            .oneshot(
                Request::get("/xrpc/app.bsky.feed.getTimeline")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert!(upstream.requests().is_empty(), "upstream must not be hit");
    }

    /// deleteSession returns 200 so client logout never errors.
    #[tokio::test]
    async fn delete_session_is_stateless_ok() {
        let (state, _upstream, _tmp) = test_state().await;
        let resp = app(state)
            .oneshot(
                Request::post("/xrpc/com.atproto.server.deleteSession")
                    .header("Authorization", bearer())
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }
}
