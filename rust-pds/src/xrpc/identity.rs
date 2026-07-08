/// XRPC identity handlers: resolveHandle, /.well-known/atproto-did, /.well-known/did.json.
///
/// Route table:
/// | Method | Path                                            | Handler             |
/// |--------|-------------------------------------------------|---------------------|
/// | GET    | /xrpc/com.atproto.identity.resolveHandle        | resolve_handle      |
/// | GET    | /.well-known/atproto-did                        | well_known_atproto_did |
/// | GET    | /.well-known/did.json                           | well_known_did_json |
///
/// ## Account scoping for /.well-known/atproto-did
///
/// In multi-tenant PDS deployments, the correct account to serve depends on the
/// Host header (the request domain). For this demo single-tenant PDS we resolve
/// the *server's own* account by looking up the account whose handle == `state.hostname`.
/// This is the account that "claims" the server apex domain. If no such account exists
/// yet (freshly bootstrapped PDS), the route returns 404.
///
/// ## /.well-known/did.json behaviour for did:plc accounts
///
/// The spec requires `/.well-known/did.json` only for `did:web` accounts. This server
/// defaults to provisioning accounts with `did:plc`. The did.json route
/// therefore looks up the signing key stored under `did:web:<hostname>#signing`. If no
/// such key exists, it returns 404. For did:web accounts (seeded in tests, or created via
/// the init wizard's did:web option), the route serves the full did:web DID document.
use std::collections::HashMap;

use atrium_crypto::keypair::Secp256k1Keypair;
use axum::{
    extract::{Query, State},
    http::header,
    response::IntoResponse,
    routing::get,
    Json,
};
use serde::Serialize;

use crate::identity::web::{did_web, did_web_document};
use crate::storage::keys::load_key;
use crate::xrpc::{AppState, XrpcError};

// ---------------------------------------------------------------------------
// resolveHandle
// ---------------------------------------------------------------------------

/// GET /xrpc/com.atproto.identity.resolveHandle?handle=<h>
///
/// Returns `{"did": "<did>"}` for a known handle or HandleNotFound (404) for
/// unknown handles. Query param `handle` is required.
pub async fn resolve_handle(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, XrpcError> {
    let handle = params
        .get("handle")
        .ok_or_else(|| XrpcError::InvalidRequest("missing required query param: handle".into()))?;

    let did = state
        .store
        .get_did_by_handle(handle)
        .await?
        .ok_or(XrpcError::HandleNotFound)?;

    #[derive(Serialize)]
    struct ResolveHandleResponse {
        did: String,
    }

    Ok(Json(ResolveHandleResponse { did }))
}

// ---------------------------------------------------------------------------
// /.well-known/atproto-did
// ---------------------------------------------------------------------------

/// GET /.well-known/atproto-did
///
/// Returns the server's own account DID as `text/plain` (no JSON wrapper).
/// Per the AT Protocol handle resolution spec, this is how HTTPS handle resolution
/// works — the client GETs `https://<handle>/.well-known/atproto-did` and expects
/// a bare DID string with `Content-Type: text/plain`.
///
/// This route looks up the account whose handle == `state.hostname` (the server's
/// apex domain handle). If no such account exists, returns 404 HandleNotFound.
///
/// Scoping note: single-tenant demo. See module-level doc for multi-tenant extension.
pub async fn well_known_atproto_did(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, XrpcError> {
    let did = state
        .store
        .get_did_by_handle(&state.hostname)
        .await?
        .ok_or(XrpcError::HandleNotFound)?;

    Ok((
        axum::http::StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain")],
        did,
    ))
}

// ---------------------------------------------------------------------------
// /.well-known/did.json
// ---------------------------------------------------------------------------

/// GET /.well-known/did.json
///
/// Returns the did:web DID document for the server's own identity.
///
/// The signing key is loaded from the `keys` table under the id
/// `did:web:<hostname>#signing`. If this key does not exist (because no did:web
/// account has been provisioned), the route returns 404.
///
/// The document is built by `identity::web::did_web_document` from the hostname,
/// signing key, and pds_endpoint — no caller-supplied content is reflected.
pub async fn well_known_did_json(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, XrpcError> {
    let did = did_web(&state.hostname);
    let key_id = format!("{did}#signing");

    // Load and decrypt the signing key for the did:web identity.
    let key_bytes = load_key(&state.store, &key_id, &state.key_passphrase)
        .await
        .map_err(|_| XrpcError::HandleNotFound)?;

    let signing = Secp256k1Keypair::import(&key_bytes)
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("bad signing key: {e}")))?;

    let doc = did_web_document(&state.hostname, &signing, &state.pds_endpoint);

    Ok(Json(doc))
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

/// Register the three identity routes on a `Router<AppState>`.
pub fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route(
            "/xrpc/com.atproto.identity.resolveHandle",
            get(resolve_handle),
        )
        .route("/.well-known/atproto-did", get(well_known_atproto_did))
        .route("/.well-known/did.json", get(well_known_did_json))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use atrium_crypto::keypair::{Export, Secp256k1Keypair};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use rand::rngs::OsRng;
    use tower::ServiceExt;

    use crate::auth::jwt::hash_password;
    use crate::identity::plc::MockPlcClient;
    use crate::storage::keys::store_key;
    use crate::storage::SqliteStore;
    use crate::xrpc::{app, AppState};

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// Build a test AppState backed by an in-memory SQLite database.
    async fn test_state() -> (AppState, tempfile::NamedTempFile) {
        let (store, tmp) = SqliteStore::open_in_memory().await.expect("open_in_memory");
        let state = AppState {
            store: Arc::new(store),
            jwt_secret: Arc::new(b"test-jwt-secret-03-03".to_vec()),
            hostname: "pds.test".to_string(),
            pds_endpoint: "https://pds.test".to_string(),
            open_registration: false,
            plc_client: Arc::new(MockPlcClient::new()),
            did_web_resolver: Arc::new(crate::identity::web_resolver::MockDidWebResolver::new_ok()),
            key_passphrase: Arc::new(b"test-key-passphrase-03-03".to_vec()),
            firehose_tx: tokio::sync::broadcast::channel(16).0,
            relay_client: std::sync::Arc::new(crate::firehose::MockRelayClient::new()),
            relay_url: "https://relay.test".to_string(),
            appview_client: std::sync::Arc::new(
                crate::xrpc::appview::client::MockAppViewClient::new((200, Vec::new(), None)),
            ),
            appview_url: "https://appview.test".to_string(),
            appview_did: "did:web:appview.test".to_string(),
            did_locks: Arc::new(dashmap::DashMap::new()),
            signing_key_cache: Arc::new(dashmap::DashMap::new()),
        };
        (state, tmp)
    }

    async fn response_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn response_text(resp: axum::response::Response) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    // -----------------------------------------------------------------------
    // resolveHandle: known handle
    // -----------------------------------------------------------------------

    /// GET resolveHandle?handle=alice.pds.test → 200 + {"did":"..."}
    #[tokio::test]
    async fn resolve_known_handle() {
        let (state, _tmp) = test_state().await;

        // Seed an account with a known DID.
        let phc = hash_password("pw").unwrap();
        state
            .store
            .insert_account("did:plc:alicetestdid1234", "alice.pds.test", None, &phc)
            .await
            .unwrap();

        let resp = app(state)
            .oneshot(
                Request::get("/xrpc/com.atproto.identity.resolveHandle?handle=alice.pds.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let json = response_json(resp).await;
        assert_eq!(
            json["did"].as_str().unwrap(),
            "did:plc:alicetestdid1234",
            "resolveHandle must return the seeded DID"
        );
    }

    // -----------------------------------------------------------------------
    // resolveHandle: unknown handle
    // -----------------------------------------------------------------------

    /// GET resolveHandle?handle=nobody.pds.test → 404 + {"error":"HandleNotFound"}
    #[tokio::test]
    async fn resolve_unknown_handle() {
        let (state, _tmp) = test_state().await;

        let resp = app(state)
            .oneshot(
                Request::get("/xrpc/com.atproto.identity.resolveHandle?handle=nobody.pds.test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let json = response_json(resp).await;
        assert_eq!(
            json["error"].as_str().unwrap(),
            "HandleNotFound",
            "unknown handle must return HandleNotFound"
        );
    }

    // -----------------------------------------------------------------------
    // /.well-known/atproto-did
    // -----------------------------------------------------------------------

    /// GET /.well-known/atproto-did → 200, text/plain, bare DID string.
    #[tokio::test]
    async fn well_known_atproto_did() {
        let (state, _tmp) = test_state().await;

        // Seed the server account: handle == hostname ("pds.test").
        let phc = hash_password("server-pw").unwrap();
        state
            .store
            .insert_account("did:plc:serverdid0000001", "pds.test", None, &phc)
            .await
            .unwrap();

        let resp = app(state)
            .oneshot(
                Request::get("/.well-known/atproto-did")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        // Content-Type must start with "text/plain".
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.starts_with("text/plain"),
            "content-type must be text/plain, got {ct:?}"
        );

        let body = response_text(resp).await;
        assert_eq!(
            body, "did:plc:serverdid0000001",
            "/.well-known/atproto-did must return the bare DID string"
        );
    }

    // -----------------------------------------------------------------------
    // /.well-known/did.json
    // -----------------------------------------------------------------------

    /// GET /.well-known/did.json → 200 + valid did:web DID document.
    ///
    /// Seeds a did:web account by storing the signing key under
    /// `did:web:pds.test#signing`. The handler builds the DID document from that
    /// key — no live plc.directory call required.
    #[tokio::test]
    async fn well_known_did_json() {
        let (state, _tmp) = test_state().await;

        // Generate a secp256k1 keypair for the server's did:web identity.
        let signing = Secp256k1Keypair::create(&mut OsRng);
        let key_bytes = signing.export();

        // Store the signing key under "did:web:pds.test#signing".
        store_key(
            &state.store,
            "did:web:pds.test#signing",
            &key_bytes,
            &state.key_passphrase,
        )
        .await
        .unwrap();

        let resp = app(state)
            .oneshot(
                Request::get("/.well-known/did.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);

        let json = response_json(resp).await;

        // id must be "did:web:<hostname>"
        assert_eq!(
            json["id"].as_str().unwrap(),
            "did:web:pds.test",
            "did.json id must be did:web:<hostname>"
        );

        // verificationMethod must contain a Multikey entry
        let vms = json["verificationMethod"].as_array().unwrap();
        assert!(!vms.is_empty(), "verificationMethod must be non-empty");
        let vm = &vms[0];
        assert_eq!(
            vm["type"].as_str().unwrap(),
            "Multikey",
            "verificationMethod type must be Multikey"
        );
        assert!(
            vm["publicKeyMultibase"]
                .as_str()
                .unwrap_or("")
                .starts_with('z'),
            "publicKeyMultibase must start with 'z' (base58btc multibase)"
        );

        // service must contain AtprotoPersonalDataServer
        let services = json["service"].as_array().unwrap();
        assert!(!services.is_empty(), "service must be non-empty");
        assert_eq!(
            services[0]["type"].as_str().unwrap(),
            "AtprotoPersonalDataServer"
        );
    }
}
