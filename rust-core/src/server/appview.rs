//! AppView forwarding for the embedded server.
//!
//! The embedded host deliberately carries no outbound HTTPS stack (Jetsam
//! budget), so the actual network call is delegated to the EMBEDDER — on iOS,
//! a Swift URLSession behind the [`OutboundProxy`] trait. This module owns
//! everything else, mirroring the production AppView proxy: session
//! validation, service-auth minting (shared `auth::service_auth`), and
//! response relay. The caller's session token is validated and stripped —
//! never forwarded upstream.
//!
//! It also serves `com.atproto.server.getServiceAuth`, which needs no
//! outbound call at all (pure signing).

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};

use crate::auth::service_auth::{mint_service_auth_jwt, mint_service_auth_jwt_with};

use super::repo::load_signing_key;
use super::{authed_did, json_response, query_param, xrpc_error, AppState};

/// Upstream response relayed by an [`OutboundProxy`] implementation.
pub struct ProxyResponse {
    pub status: u16,
    /// Upstream Content-Type, if any. Treated as untrusted bytes: dropped if
    /// it isn't a valid header value.
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

/// Embedder-provided outbound HTTP client (e.g. Swift URLSession on iOS).
///
/// `forward` performs `GET <appview>/xrpc/<nsid>?<query>` with
/// `Authorization: Bearer <service_jwt>` and returns the upstream response
/// verbatim (including non-2xx). `Err(msg)` means a TRANSPORT failure (DNS,
/// TLS, timeout) and is surfaced to the client as 502 UpstreamFailure.
#[async_trait::async_trait]
pub trait OutboundProxy: Send + Sync {
    async fn forward(
        &self,
        nsid: String,
        query: String,
        service_jwt: String,
    ) -> Result<ProxyResponse, String>;
}

/// GET /xrpc/app.bsky.* fallback — authenticated read proxy to the AppView.
pub(super) async fn forward(
    state: &AppState,
    auth_header: Option<String>,
    path: &str,
    query: &str,
) -> Response<Full<Bytes>> {
    let Some(proxy) = state.proxy.clone() else {
        return xrpc_error(
            StatusCode::NOT_FOUND,
            "MethodNotImplemented",
            "no AppView forwarder is configured on this embedded server",
        );
    };
    let did = match authed_did(&auth_header, &state.config.jwt_secret, "com.atproto.access") {
        Ok(did) => did,
        Err(resp) => return resp,
    };
    // lxm must be the full NSID (path is "/xrpc/app.bsky.<rest>").
    let nsid = path.trim_start_matches("/xrpc/").to_owned();

    let signing = match load_signing_key(state, &did).await {
        Ok(k) => k,
        Err(resp) => return resp,
    };
    let jwt = match mint_service_auth_jwt(&signing, &did, &state.config.appview_did, &nsid) {
        Ok(j) => j,
        Err(_) => {
            return xrpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "service-auth mint failed",
            )
        }
    };

    match proxy.forward(nsid, query.to_owned(), jwt).await {
        Ok(upstream) => {
            let status =
                StatusCode::from_u16(upstream.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let mut builder = Response::builder().status(status);
            // Upstream Content-Type is attacker-influencable; skip if invalid
            // rather than letting it poison the builder.
            if let Some(ct) = upstream.content_type {
                if let Ok(hv) = hyper::header::HeaderValue::from_str(&ct) {
                    builder = builder.header("content-type", hv);
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
            "AppView request failed",
        ),
    }
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
