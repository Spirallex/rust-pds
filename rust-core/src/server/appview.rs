//! Generalized service forwarding for the embedded server — the PDS side of
//! `atproto-proxy` routing.
//!
//! The official Bluesky client sends every non-repo request to its PDS and
//! routes by the `atproto-proxy: <did>#<fragment>` header (AppView, chat,
//! moderation reports, push notifications, video, feed generators, labelers)
//! with both GET and POST. The embedded host deliberately carries no outbound
//! HTTPS stack (Jetsam budget), so the network legs are delegated to the
//! EMBEDDER — on iOS, Swift URLSession behind [`OutboundProxy`]. This module
//! owns everything else: session validation, target resolution (did:web by
//! convention, did:plc via a PLC-directory fetch through the embedder,
//! cached), service-auth minting (shared `auth::service_auth`), and response
//! relay. The caller's session token is validated and stripped — never
//! forwarded upstream.
//!
//! It also serves `com.atproto.server.getServiceAuth`, which needs no
//! outbound call at all (pure signing).

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};

use crate::auth::service_auth::{mint_service_auth_jwt, mint_service_auth_jwt_with};
use crate::identity::service::{did_web_endpoint, service_endpoint_from_doc};

use super::repo::load_signing_key;
use super::{authed_did, json_response, query_param, xrpc_error, AppState};

/// Cap on a proxied POST body. Procedure payloads are small JSON; blobs and
/// video bytes do NOT take this path (uploadBlob is local, video goes direct
/// with service auth).
const MAX_PROXY_BODY: usize = 1024 * 1024;

/// One fully-resolved upstream request handed to the embedder.
pub struct ProxyRequest {
    /// "GET" or "POST".
    pub method: String,
    /// e.g. `https://api.bsky.app`.
    pub base_url: String,
    /// Full method NSID, e.g. `chat.bsky.convo.listConvos`.
    pub nsid: String,
    /// Raw query string ("" when none).
    pub query: String,
    /// Request body (empty for GET).
    pub body: Vec<u8>,
    /// Request Content-Type, forwarded verbatim when present.
    pub content_type: Option<String>,
    /// Service-auth JWT minted for the target service.
    pub service_jwt: String,
    /// Caller's `atproto-accept-labelers` header, forwarded verbatim.
    pub accept_labelers: Option<String>,
}

/// Upstream response relayed by an [`OutboundProxy`] implementation.
pub struct ProxyResponse {
    pub status: u16,
    /// Upstream Content-Type, if any. Treated as untrusted bytes: dropped if
    /// it isn't a valid header value.
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    /// Upstream `atproto-content-labelers` header (moderation attribution).
    pub content_labelers: Option<String>,
}

/// Embedder-provided outbound HTTP client (e.g. Swift URLSession on iOS).
///
/// `forward` performs `<method> <base_url>/xrpc/<nsid>?<query>` with
/// `Authorization: Bearer <service_jwt>` (plus body / Content-Type /
/// `atproto-accept-labelers` when present) and returns the upstream response
/// verbatim (including non-2xx). `fetch` performs a plain GET of `url` and
/// returns the body — used for PLC-directory DID-document lookups. In both,
/// `Err(msg)` means a TRANSPORT failure (DNS, TLS, timeout) and is surfaced
/// to the client as 502 UpstreamFailure.
#[async_trait::async_trait]
pub trait OutboundProxy: Send + Sync {
    async fn forward(&self, req: ProxyRequest) -> Result<ProxyResponse, String>;
    async fn fetch(&self, url: String) -> Result<Vec<u8>, String>;
}

/// Resolve an `atproto-proxy` DID to a base URL, caching did:plc lookups.
async fn resolve_target(
    state: &AppState,
    proxy: &dyn OutboundProxy,
    did: &str,
    fragment: &str,
) -> Result<String, Response<Full<Bytes>>> {
    if did.starts_with("did:web:") {
        return did_web_endpoint(did)
            .map_err(|m| xrpc_error(StatusCode::BAD_REQUEST, "InvalidRequest", &m));
    }
    if !did.starts_with("did:plc:") {
        return Err(xrpc_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            &format!("unsupported proxy DID method: {did}"),
        ));
    }
    let cache_key = format!("{did}#{fragment}");
    if let Some(hit) = state
        .proxy_target_cache
        .lock()
        .expect("proxy-target cache lock poisoned")
        .get(&cache_key)
    {
        return Ok(hit.clone());
    }
    let url = format!("{}/{did}", state.config.plc_url);
    let bytes = proxy.fetch(url).await.map_err(|_| {
        xrpc_error(
            StatusCode::BAD_GATEWAY,
            "UpstreamFailure",
            "PLC directory fetch failed",
        )
    })?;
    let doc: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
        xrpc_error(
            StatusCode::BAD_GATEWAY,
            "UpstreamFailure",
            "PLC document decode failed",
        )
    })?;
    let endpoint = service_endpoint_from_doc(&doc, did, fragment).ok_or_else(|| {
        xrpc_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            &format!("no #{fragment} service on {did}"),
        )
    })?;
    state
        .proxy_target_cache
        .lock()
        .expect("proxy-target cache lock poisoned")
        .insert(cache_key, endpoint.clone());
    Ok(endpoint)
}

/// GET/POST /xrpc/* fallback — authenticated proxy to the addressed service.
pub(super) async fn forward(
    state: &AppState,
    auth_header: Option<String>,
    req: Request<Incoming>,
    query: &str,
) -> Response<Full<Bytes>> {
    let Some(proxy) = state.proxy.clone() else {
        return xrpc_error(
            StatusCode::NOT_FOUND,
            "MethodNotImplemented",
            "no upstream forwarder is configured on this embedded server",
        );
    };
    let did = match authed_did(&auth_header, &state.config.jwt_secret, "com.atproto.access") {
        Ok(did) => did,
        Err(resp) => return resp,
    };
    let nsid = req.uri().path().trim_start_matches("/xrpc/").to_owned();
    if nsid.is_empty() || nsid.contains('/') {
        return xrpc_error(
            StatusCode::NOT_FOUND,
            "MethodNotImplemented",
            "method not implemented by the embedded server",
        );
    }
    let method = req.method().as_str().to_owned();

    let header = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let proxy_header = header("atproto-proxy");
    let content_type = header("content-type");
    let accept_labelers = header("atproto-accept-labelers");

    // Route: explicit atproto-proxy header wins; bare app.bsky.* defaults to
    // the configured AppView; anything else unaddressed is unimplemented.
    let (target_did, base_url) = match proxy_header {
        Some(target) => {
            let Some((tdid, fragment)) = target.split_once('#') else {
                return xrpc_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "atproto-proxy must be <did>#<service-fragment>",
                );
            };
            let tdid = tdid.to_owned();
            match resolve_target(state, proxy.as_ref(), &tdid, fragment).await {
                Ok(base) => (tdid, base),
                Err(resp) => return resp,
            }
        }
        None if nsid.starts_with("app.bsky.") => (
            state.config.appview_did.clone(),
            state.config.appview_url.clone(),
        ),
        None => {
            return xrpc_error(
                StatusCode::NOT_FOUND,
                "MethodNotImplemented",
                "method not implemented by the embedded server",
            )
        }
    };

    // Read the body AFTER auth/routing so rejected requests don't buffer it.
    let body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return xrpc_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "could not read body",
            )
        }
    };
    if body.len() > MAX_PROXY_BODY {
        return xrpc_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "InvalidRequest",
            "request body too large",
        );
    }

    // Mint a fresh service token; the caller's session Bearer never leaves.
    let signing = match load_signing_key(state, &did).await {
        Ok(k) => k,
        Err(resp) => return resp,
    };
    let jwt = match mint_service_auth_jwt(&signing, &did, &target_did, &nsid) {
        Ok(j) => j,
        Err(_) => {
            return xrpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "service-auth mint failed",
            )
        }
    };

    match proxy
        .forward(ProxyRequest {
            method,
            base_url,
            nsid,
            query: query.to_owned(),
            body: body.to_vec(),
            content_type,
            service_jwt: jwt,
            accept_labelers,
        })
        .await
    {
        Ok(upstream) => {
            let status =
                StatusCode::from_u16(upstream.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let mut builder = Response::builder().status(status);
            // Upstream header values are attacker-influencable; skip invalid
            // ones rather than letting them poison the builder.
            if let Some(ct) = upstream.content_type {
                if let Ok(hv) = hyper::header::HeaderValue::from_str(&ct) {
                    builder = builder.header("content-type", hv);
                }
            }
            if let Some(labelers) = upstream.content_labelers {
                if let Ok(hv) = hyper::header::HeaderValue::from_str(&labelers) {
                    builder = builder.header("atproto-content-labelers", hv);
                }
            }
            builder
                .body(Full::new(Bytes::from(upstream.body)))
                .unwrap_or_else(|_| {
                    xrpc_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        "proxy response build failed",
                    )
                })
        }
        Err(_) => xrpc_error(
            StatusCode::BAD_GATEWAY,
            "UpstreamFailure",
            "upstream request failed",
        ),
    }
}

/// Only GET and POST are proxied; used by the router guard arm.
pub(super) fn proxyable_method(m: &Method) -> bool {
    m == Method::GET || m == Method::POST
}

/// GET com.atproto.server.getServiceAuth — mint an inter-service token signed
/// with the account key. Default 60s expiry; a caller-requested `exp` is
/// honored but capped 30 minutes ahead and never in the past.
pub(super) async fn get_service_auth(
    state: &AppState,
    auth_header: Option<String>,
    query: &str,
) -> Response<Full<Bytes>> {
    let did = match authed_did(&auth_header, &state.config.jwt_secret, "com.atproto.access") {
        Ok(did) => did,
        Err(resp) => return resp,
    };
    let Some(aud) = query_param(query, "aud") else {
        return xrpc_error(StatusCode::BAD_REQUEST, "InvalidRequest", "aud is required");
    };
    let lxm = query_param(query, "lxm");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs();
    let max_exp = now + 30 * 60;
    let exp = match query_param(query, "exp").and_then(|e| e.parse::<i64>().ok()) {
        Some(e) if e as u64 > now => (e as u64).min(max_exp),
        _ => now + 60,
    };

    let signing = match load_signing_key(state, &did).await {
        Ok(k) => k,
        Err(resp) => return resp,
    };
    match mint_service_auth_jwt_with(&signing, &did, &aud, lxm.as_deref(), exp) {
        Ok(token) => json_response(
            StatusCode::OK,
            serde_json::json!({ "token": token }).to_string(),
        ),
        Err(_) => xrpc_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "service-auth mint failed",
        ),
    }
}
