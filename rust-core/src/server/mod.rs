//! Feature-gated, in-process HTTP server for on-device hosting (`embedded-server`).
//!
//! This is **not** the production `stelyph` server. That one lives in the
//! `stelyph` crate and pulls axum + tower + ACME/TLS + the `subscribeRepos`
//! WebSocket + a relay `requestCrawl` client + reqwest — none of which fit an
//! iOS Network Extension under the Jetsam per-process memory ceiling.
//!
//! This is a deliberately minimal `hyper` 1.x server: no TLS, no WebSocket, no
//! extra runtime threads beyond what the caller's tokio provides. It binds
//! `127.0.0.1` (or whatever the caller passes) and serves a small XRPC read
//! surface straight off [`SqliteStore`]. TLS termination and inbound routing
//! are an edge concern (reverse tunnel / VPS), not this process's.
//!
//! It does add permissive CORS headers and answers `OPTIONS` preflights, since
//! browser AT Proto clients (e.g. bsky.app) are served from a different origin
//! and the browser blocks any response lacking `Access-Control-Allow-Origin`.
//!
//! The point of having it in `stelyph-core` (rather than the server crate) is so
//! it compiles for `aarch64-apple-ios` and its resident footprint can be
//! measured before the Network Extension target exists — see
//! `examples/server_footprint.rs`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::storage::SqliteStore;

/// Minimal server configuration — the device-host subset of the full PDS config.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// PDS hostname. Drives `did:web:<hostname>` and `availableUserDomains`.
    pub hostname: String,
    /// When `false`, `describeServer` reports `inviteCodeRequired: true`.
    pub open_registration: bool,
}

#[derive(Clone)]
struct AppState {
    store: Arc<SqliteStore>,
    config: Arc<ServerConfig>,
}

fn json_response(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("static response builder never fails")
}

/// XRPC error envelope: `{"error": "...", "message": "..."}`.
fn xrpc_error(status: StatusCode, error: &str, message: &str) -> Response<Full<Bytes>> {
    json_response(
        status,
        serde_json::json!({ "error": error, "message": message }).to_string(),
    )
}

/// Add permissive CORS headers to every response. `Access-Control-Allow-Origin: *`
/// (no credentials) lets the wildcard `Allow-Headers` cover AT Proto's custom
/// request headers (`atproto-proxy`, `atproto-accept-labelers`, `authorization`,
/// …) without enumerating them. The production server does this via tower-http;
/// here it's by hand to avoid the dependency.
fn apply_cors(resp: &mut Response<Full<Bytes>>) {
    let headers = resp.headers_mut();
    headers.insert(
        "access-control-allow-origin",
        HeaderValue::from_static("*"),
    );
    headers.insert(
        "access-control-allow-methods",
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        "access-control-allow-headers",
        HeaderValue::from_static("*"),
    );
    headers.insert(
        "access-control-max-age",
        HeaderValue::from_static("86400"),
    );
}

/// Empty `204 No Content` used to answer a CORS preflight; the CORS headers are
/// added uniformly by [`apply_cors`] on the way out.
fn preflight_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Full::new(Bytes::new()))
        .expect("static response builder never fails")
}

/// Pull a single query-string value, percent-decoded. Minimal on purpose: the
/// only callers here pass handles/DIDs, not arbitrary blobs.
fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| percent_decode(v))
    })
}

/// Tiny `application/x-www-form-urlencoded` value decoder (`+` → space, `%XX`
/// → byte). Avoids a urlencoding dependency for the one place we need it.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h * 16 + l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn route(state: AppState, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();

    // CORS preflight: browsers send OPTIONS before the real request. Answer any
    // path so clients can probe endpoints this server hasn't implemented yet.
    if method == Method::OPTIONS {
        return preflight_response();
    }

    match (&method, path.as_str()) {
        // Liveness probe for the host app / NE supervisor.
        (&Method::GET, "/xrpc/_health") => json_response(
            StatusCode::OK,
            serde_json::json!({ "version": env!("CARGO_PKG_VERSION") }).to_string(),
        ),

        // com.atproto.server.describeServer — mirrors the production handler.
        (&Method::GET, "/xrpc/com.atproto.server.describeServer") => json_response(
            StatusCode::OK,
            serde_json::json!({
                "did": format!("did:web:{}", state.config.hostname),
                "availableUserDomains": [format!(".{}", state.config.hostname)],
                "inviteCodeRequired": !state.config.open_registration,
            })
            .to_string(),
        ),

        // com.atproto.identity.resolveHandle — reads the real account store.
        (&Method::GET, "/xrpc/com.atproto.identity.resolveHandle") => {
            match query_param(&query, "handle") {
                None => xrpc_error(StatusCode::BAD_REQUEST, "InvalidRequest", "missing handle"),
                Some(handle) => match state.store.get_did_by_handle(&handle).await {
                    Ok(Some(did)) => json_response(
                        StatusCode::OK,
                        serde_json::json!({ "did": did }).to_string(),
                    ),
                    Ok(None) => {
                        xrpc_error(StatusCode::NOT_FOUND, "HandleNotFound", "handle not found")
                    }
                    Err(_) => xrpc_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        "store error",
                    ),
                },
            }
        }

        _ => xrpc_error(
            StatusCode::NOT_FOUND,
            "MethodNotImplemented",
            "method not implemented by the embedded server",
        ),
    }
}

/// Bind a listening socket. Pass port `0` to let the OS choose; read the chosen
/// port back via [`TcpListener::local_addr`].
pub async fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

/// Accept-loop: serve HTTP/1.1 on `listener` until the task is dropped/aborted.
/// Each connection is driven on the caller's tokio runtime; no threads are spun
/// up here, keeping the footprint the caller's to control.
pub async fn serve(
    listener: TcpListener,
    store: Arc<SqliteStore>,
    config: ServerConfig,
) -> std::io::Result<()> {
    let state = AppState {
        store,
        config: Arc::new(config),
    };
    loop {
        let (stream, _peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = state.clone();
                async move {
                    let mut resp = route(state, req).await;
                    apply_cors(&mut resp);
                    Ok::<_, Infallible>(resp)
                }
            });
            // Connection errors (client hangups) are non-fatal to the server.
            let _ = http1::Builder::new().serve_connection(io, service).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_handles_plus_and_hex() {
        assert_eq!(percent_decode("alice.pds.test"), "alice.pds.test");
        assert_eq!(percent_decode("a%2Eb"), "a.b");
        assert_eq!(percent_decode("a+b"), "a b");
        // Malformed trailing % is passed through, not panicked on.
        assert_eq!(percent_decode("a%2"), "a%2");
    }

    #[test]
    fn query_param_extracts_named_value() {
        assert_eq!(
            query_param("handle=alice.pds.test&foo=bar", "handle").as_deref(),
            Some("alice.pds.test")
        );
        assert_eq!(query_param("foo=bar", "handle"), None);
    }

    async fn boot() -> (SocketAddr, Arc<SqliteStore>) {
        let (store, tmp) = SqliteStore::open_in_memory().await.unwrap();
        // Leak the temp file so the on-disk DB outlives the test server.
        std::mem::forget(tmp);
        let store = Arc::new(store);
        let listener = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv_store = store.clone();
        tokio::spawn(async move {
            let _ = serve(
                listener,
                srv_store,
                ServerConfig {
                    hostname: "pds.test".into(),
                    open_registration: false,
                },
            )
            .await;
        });
        (addr, store)
    }

    /// Raw HTTP/1.1 request so the tests don't need hyper's `client` feature.
    /// Returns the status code and the full raw response text (headers + body).
    async fn request(addr: SocketAddr, method: &str, path: &str) -> (StatusCode, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req =
            format!("{method} {path} HTTP/1.1\r\nHost: pds.test\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        let code: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap();
        (StatusCode::from_u16(code).unwrap(), text)
    }

    /// Convenience GET returning the status and parsed JSON body.
    async fn get(addr: SocketAddr, path: &str) -> (StatusCode, serde_json::Value) {
        let (status, text) = request(addr, "GET", path).await;
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
        let json = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    #[tokio::test]
    async fn describe_server_returns_did_and_domains() {
        let (addr, _store) = boot().await;
        let (status, json) = get(addr, "/xrpc/com.atproto.server.describeServer").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["did"], "did:web:pds.test");
        assert_eq!(json["availableUserDomains"][0], ".pds.test");
        assert_eq!(json["inviteCodeRequired"], true);
    }

    #[tokio::test]
    async fn resolve_handle_hits_the_store() {
        let (addr, store) = boot().await;
        store
            .insert_account("did:plc:abc123", "alice.pds.test", None, "x")
            .await
            .unwrap();

        let (status, json) = get(
            addr,
            "/xrpc/com.atproto.identity.resolveHandle?handle=alice.pds.test",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["did"], "did:plc:abc123");

        let (status, json) = get(
            addr,
            "/xrpc/com.atproto.identity.resolveHandle?handle=nobody.pds.test",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json["error"], "HandleNotFound");
    }

    #[tokio::test]
    async fn unknown_route_is_method_not_implemented() {
        let (addr, _store) = boot().await;
        let (status, json) = get(addr, "/xrpc/com.atproto.repo.createRecord").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json["error"], "MethodNotImplemented");
    }

    #[tokio::test]
    async fn responses_carry_cors_headers() {
        let (addr, _store) = boot().await;
        // Real responses (even errors) must be readable cross-origin.
        let (_status, text) = request(addr, "GET", "/xrpc/_health").await;
        let lower = text.to_ascii_lowercase();
        assert!(
            lower.contains("access-control-allow-origin: *"),
            "missing CORS allow-origin header:\n{text}"
        );
    }

    #[tokio::test]
    async fn options_preflight_is_no_content_with_cors() {
        let (addr, _store) = boot().await;
        // A browser preflight to an unimplemented method must still succeed so
        // the client can send the real request.
        let (status, text) = request(addr, "OPTIONS", "/xrpc/com.atproto.server.createSession").await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let lower = text.to_ascii_lowercase();
        assert!(lower.contains("access-control-allow-origin: *"), "preflight lacks CORS:\n{text}");
        assert!(lower.contains("access-control-allow-methods"), "preflight lacks methods:\n{text}");
    }
}
