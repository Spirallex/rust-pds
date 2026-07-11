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
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::auth::jwt::{decode_jwt, encode_access_jwt, encode_refresh_jwt, verify_password};
use crate::error::CoreError;
use crate::storage::SqliteStore;

/// Cap on a request body we'll buffer. Session inputs are tiny JSON objects;
/// this just bounds a hostile client, not real traffic.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Minimal server configuration — the device-host subset of the full PDS config.
#[derive(Clone)]
pub struct ServerConfig {
    /// PDS hostname. Drives `did:web:<hostname>` and `availableUserDomains`.
    pub hostname: String,
    /// When `false`, `describeServer` reports `inviteCodeRequired: true`.
    pub open_registration: bool,
    /// HMAC secret for signing/verifying session JWTs. Must be stable across
    /// restarts (so issued tokens keep validating) and secret — the host app
    /// generates one per device and persists it (e.g. Keychain). An empty
    /// secret disables the session endpoints (they return 401).
    pub jwt_secret: Vec<u8>,
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

fn text_response(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
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
    headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
    headers.insert(
        "access-control-allow-methods",
        HeaderValue::from_static("GET, POST, OPTIONS"),
    );
    headers.insert(
        "access-control-allow-headers",
        HeaderValue::from_static("*"),
    );
    headers.insert("access-control-max-age", HeaderValue::from_static("86400"));
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

/// Buffer a request body up to [`MAX_BODY_BYTES`], returning the JSON value or a
/// ready-made error response.
// The Err is a fully-built HTTP response by design (the caller just returns it),
// so its size is inherent, not accidental — boxing would only add a hop.
#[allow(clippy::result_large_err)]
async fn read_json_body(
    req: Request<Incoming>,
) -> Result<serde_json::Value, Response<Full<Bytes>>> {
    let collected = req
        .into_body()
        .collect()
        .await
        .map_err(|_| {
            xrpc_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "could not read body",
            )
        })?
        .to_bytes();
    if collected.len() > MAX_BODY_BYTES {
        return Err(xrpc_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "InvalidRequest",
            "request body too large",
        ));
    }
    serde_json::from_slice(&collected).map_err(|_| {
        xrpc_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "invalid JSON body",
        )
    })
}

/// Extract and validate the `Authorization: Bearer <jwt>` DID for a required
/// token scope. Returns the subject DID or a ready-made XRPC error response.
// See read_json_body: the Err is intentionally a full response.
#[allow(clippy::result_large_err)]
fn authed_did(
    auth_header: &Option<String>,
    secret: &[u8],
    want_scope: &str,
) -> Result<String, Response<Full<Bytes>>> {
    if secret.is_empty() {
        return Err(xrpc_error(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "sessions are not enabled on this server",
        ));
    }
    let token = auth_header
        .as_deref()
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| {
            xrpc_error(
                StatusCode::UNAUTHORIZED,
                "AuthenticationRequired",
                "missing bearer token",
            )
        })?;
    let claims = decode_jwt(token, secret).map_err(|e| match e {
        CoreError::ExpiredToken => {
            xrpc_error(StatusCode::BAD_REQUEST, "ExpiredToken", "token has expired")
        }
        _ => xrpc_error(StatusCode::BAD_REQUEST, "InvalidToken", "invalid token"),
    })?;
    if claims.scope != want_scope {
        return Err(xrpc_error(
            StatusCode::BAD_REQUEST,
            "InvalidToken",
            "token has the wrong scope",
        ));
    }
    Ok(claims.sub)
}

/// POST com.atproto.server.createSession — verify handle + password, issue JWTs.
async fn create_session(state: &AppState, body: serde_json::Value) -> Response<Full<Bytes>> {
    if state.config.jwt_secret.is_empty() {
        return xrpc_error(
            StatusCode::UNAUTHORIZED,
            "AuthenticationRequired",
            "sessions are not enabled on this server",
        );
    }
    let (Some(identifier), Some(password)) =
        (body["identifier"].as_str(), body["password"].as_str())
    else {
        return xrpc_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "identifier and password are required",
        );
    };

    // Look up by handle. Missing account and wrong password return the SAME
    // error, so a caller can't probe which handles exist.
    let bad_creds = || {
        xrpc_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "invalid identifier or password",
        )
    };
    let (did, phc) = match state.store.get_account_by_handle(identifier).await {
        Ok(Some(v)) => v,
        Ok(None) => return bad_creds(),
        Err(_) => {
            return xrpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "store error",
            )
        }
    };

    // Verify off the async runtime: the argon2id KDF is CPU-heavy and must not
    // block tokio worker threads.
    let password = password.to_owned();
    let verified = tokio::task::spawn_blocking(move || verify_password(&password, &phc)).await;
    match verified {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => return bad_creds(),
        _ => {
            return xrpc_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "password verification failed",
            )
        }
    }

    session_response(state, &did, identifier)
}

/// GET com.atproto.server.getSession — validate an access token, return identity.
async fn get_session(state: &AppState, auth_header: Option<String>) -> Response<Full<Bytes>> {
    let did = match authed_did(&auth_header, &state.config.jwt_secret, "com.atproto.access") {
        Ok(did) => did,
        Err(resp) => return resp,
    };
    match state.store.get_handle_by_did(&did).await {
        Ok(Some(handle)) => json_response(
            StatusCode::OK,
            serde_json::json!({ "handle": handle, "did": did, "active": true }).to_string(),
        ),
        Ok(None) => xrpc_error(
            StatusCode::BAD_REQUEST,
            "AccountTakedown",
            "account is deactivated or taken down",
        ),
        Err(_) => xrpc_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "store error",
        ),
    }
}

/// POST com.atproto.server.refreshSession — validate a refresh token, reissue.
async fn refresh_session(state: &AppState, auth_header: Option<String>) -> Response<Full<Bytes>> {
    let did = match authed_did(
        &auth_header,
        &state.config.jwt_secret,
        "com.atproto.refresh",
    ) {
        Ok(did) => did,
        Err(resp) => return resp,
    };
    match state.store.get_handle_by_did(&did).await {
        Ok(Some(handle)) => session_response(state, &did, &handle),
        Ok(None) => xrpc_error(
            StatusCode::BAD_REQUEST,
            "AccountTakedown",
            "account is deactivated or taken down",
        ),
        Err(_) => xrpc_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "store error",
        ),
    }
}

/// Mint an access+refresh pair and build the shared session response body.
fn session_response(state: &AppState, did: &str, handle: &str) -> Response<Full<Bytes>> {
    let secret = &state.config.jwt_secret;
    let (Ok(access), Ok(refresh)) = (
        encode_access_jwt(did, secret),
        encode_refresh_jwt(did, secret),
    ) else {
        return xrpc_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "could not issue tokens",
        );
    };
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "accessJwt": access,
            "refreshJwt": refresh,
            "handle": handle,
            "did": did,
            "active": true,
        })
        .to_string(),
    )
}

async fn route(state: AppState, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

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

        // .well-known/atproto-did — HTTPS handle resolution. In the device model
        // the single account's handle IS the PDS hostname, so a client resolving
        // `https://<hostname>/.well-known/atproto-did` gets that account's DID as
        // plain text. This avoids a `_atproto` DNS TXT record: the hostname sits
        // within the wildcard TLS cert, unlike a deeper `user.<hostname>` handle.
        (&Method::GET, "/.well-known/atproto-did") => {
            match state.store.get_did_by_handle(&state.config.hostname).await {
                Ok(Some(did)) => text_response(StatusCode::OK, did),
                Ok(None) => text_response(StatusCode::NOT_FOUND, "no account for this host".into()),
                Err(_) => text_response(StatusCode::INTERNAL_SERVER_ERROR, "store error".into()),
            }
        }

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

        // com.atproto.server.createSession — handle + password → session tokens.
        (&Method::POST, "/xrpc/com.atproto.server.createSession") => {
            match read_json_body(req).await {
                Ok(body) => create_session(&state, body).await,
                Err(resp) => resp,
            }
        }

        // com.atproto.server.getSession — validate access token, return identity.
        (&Method::GET, "/xrpc/com.atproto.server.getSession") => {
            get_session(&state, auth_header).await
        }

        // com.atproto.server.refreshSession — refresh token → new token pair.
        (&Method::POST, "/xrpc/com.atproto.server.refreshSession") => {
            refresh_session(&state, auth_header).await
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
                    jwt_secret: b"test-embedded-jwt-secret".to_vec(),
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
        (status, parse_body(&text))
    }

    fn parse_body(text: &str) -> serde_json::Value {
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
        serde_json::from_str(body).unwrap_or(serde_json::Value::Null)
    }

    /// Raw request with an optional bearer token and JSON body, returning the
    /// status and parsed JSON body.
    async fn send(
        addr: SocketAddr,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        body: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut req =
            format!("{method} {path} HTTP/1.1\r\nHost: pds.test\r\nConnection: close\r\n");
        if let Some(token) = bearer {
            req.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        if let Some(b) = body {
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        req.push_str("\r\n");
        if let Some(b) = body {
            req.push_str(b);
        }
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        let code: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap();
        (StatusCode::from_u16(code).unwrap(), parse_body(&text))
    }

    /// Insert an account with a real argon2 password hash, for login tests.
    async fn seed_account(store: &SqliteStore, did: &str, handle: &str, password: &str) {
        let phc = crate::auth::jwt::hash_password(password).unwrap();
        store.insert_account(did, handle, None, &phc).await.unwrap();
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
    async fn wellknown_atproto_did_returns_hostname_account_did() {
        let (addr, store) = boot().await;
        // The single account's handle is the PDS hostname itself (boot: pds.test).
        store
            .insert_account("did:plc:selfhost", "pds.test", None, "x")
            .await
            .unwrap();

        let (status, text) = request(addr, "GET", "/.well-known/atproto-did").await;
        assert_eq!(status, StatusCode::OK);
        assert!(text
            .to_ascii_lowercase()
            .contains("content-type: text/plain"));
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
        assert_eq!(body, "did:plc:selfhost");
    }

    #[tokio::test]
    async fn wellknown_atproto_did_404_without_account() {
        let (addr, _store) = boot().await;
        let (status, _text) = request(addr, "GET", "/.well-known/atproto-did").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
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
        let (status, text) =
            request(addr, "OPTIONS", "/xrpc/com.atproto.server.createSession").await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let lower = text.to_ascii_lowercase();
        assert!(
            lower.contains("access-control-allow-origin: *"),
            "preflight lacks CORS:\n{text}"
        );
        assert!(
            lower.contains("access-control-allow-methods"),
            "preflight lacks methods:\n{text}"
        );
    }

    #[tokio::test]
    async fn create_session_valid_login_returns_tokens() {
        let (addr, store) = boot().await;
        seed_account(&store, "did:plc:alice", "alice.pds.test", "hunter2hunter2").await;

        let (status, json) = send(
            addr,
            "POST",
            "/xrpc/com.atproto.server.createSession",
            None,
            Some(r#"{"identifier":"alice.pds.test","password":"hunter2hunter2"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["did"], "did:plc:alice");
        assert_eq!(json["handle"], "alice.pds.test");
        assert!(json["accessJwt"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(json["refreshJwt"].as_str().is_some_and(|s| !s.is_empty()));
    }

    #[tokio::test]
    async fn create_session_wrong_password_is_rejected() {
        let (addr, store) = boot().await;
        seed_account(&store, "did:plc:alice", "alice.pds.test", "hunter2hunter2").await;

        let (status, json) = send(
            addr,
            "POST",
            "/xrpc/com.atproto.server.createSession",
            None,
            Some(r#"{"identifier":"alice.pds.test","password":"wrong"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"], "InvalidRequest");
    }

    #[tokio::test]
    async fn create_session_unknown_handle_matches_wrong_password() {
        let (addr, _store) = boot().await;
        let (status, json) = send(
            addr,
            "POST",
            "/xrpc/com.atproto.server.createSession",
            None,
            Some(r#"{"identifier":"nobody.pds.test","password":"whatever"}"#),
        )
        .await;
        // Same response as a wrong password, so existence can't be probed.
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"], "InvalidRequest");
    }

    #[tokio::test]
    async fn get_session_validates_access_token() {
        let (addr, store) = boot().await;
        seed_account(&store, "did:plc:alice", "alice.pds.test", "hunter2hunter2").await;
        let (_s, login) = send(
            addr,
            "POST",
            "/xrpc/com.atproto.server.createSession",
            None,
            Some(r#"{"identifier":"alice.pds.test","password":"hunter2hunter2"}"#),
        )
        .await;
        let access = login["accessJwt"].as_str().unwrap();

        let (status, json) = send(
            addr,
            "GET",
            "/xrpc/com.atproto.server.getSession",
            Some(access),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["did"], "did:plc:alice");
        assert_eq!(json["handle"], "alice.pds.test");
    }

    #[tokio::test]
    async fn get_session_without_token_is_unauthorized() {
        let (addr, _store) = boot().await;
        let (status, json) = send(
            addr,
            "GET",
            "/xrpc/com.atproto.server.getSession",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json["error"], "AuthenticationRequired");
    }

    #[tokio::test]
    async fn refresh_session_rejects_access_scope_and_reissues() {
        let (addr, store) = boot().await;
        seed_account(&store, "did:plc:alice", "alice.pds.test", "hunter2hunter2").await;
        let (_s, login) = send(
            addr,
            "POST",
            "/xrpc/com.atproto.server.createSession",
            None,
            Some(r#"{"identifier":"alice.pds.test","password":"hunter2hunter2"}"#),
        )
        .await;
        let access = login["accessJwt"].as_str().unwrap();
        let refresh = login["refreshJwt"].as_str().unwrap();

        // An access token must not be accepted where a refresh token is required.
        let (status, json) = send(
            addr,
            "POST",
            "/xrpc/com.atproto.server.refreshSession",
            Some(access),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"], "InvalidToken");

        // The refresh token issues a fresh pair.
        let (status, json) = send(
            addr,
            "POST",
            "/xrpc/com.atproto.server.refreshSession",
            Some(refresh),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["did"], "did:plc:alice");
        assert!(json["accessJwt"].as_str().is_some_and(|s| !s.is_empty()));
    }
}
