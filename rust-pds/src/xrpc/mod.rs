pub mod appview;
pub mod error;
pub mod identity;
pub mod preferences;
pub mod repo;
pub mod server;

pub use error::XrpcError;
pub use server::{create_account_inner, CreateAccountInput, CreateAccountResponse};

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::CorsLayer;

use crate::identity::plc::PlcClient;
use crate::identity::web_resolver::DidWebResolver;
use crate::storage::SqliteStore;
use crate::xrpc::appview::client::AppViewClient;

/// Shared application state injected into every XRPC handler.
///
/// `Clone` is cheap — every field is already behind `Arc` or is `Copy`/`String`.
#[derive(Clone)]
pub struct AppState {
    /// The underlying SQLite store (accounts, keys, blocks, invites, …).
    pub store: Arc<SqliteStore>,
    /// HMAC secret for JWT signing/verification (HS256).
    pub jwt_secret: Arc<Vec<u8>>,
    /// Server hostname, e.g. `"pds.example.com"`.
    /// Used for `availableUserDomains`, did:web derivation, and UnsupportedDomain checks.
    pub hostname: String,
    /// Full PDS endpoint URL, e.g. `"https://pds.example.com"`.
    /// Used as the `serviceEndpoint` in did:plc genesis ops and did:web documents.
    pub pds_endpoint: String,
    /// When `true`, account registration does NOT require an invite code.
    pub open_registration: bool,
    /// Injectable PLC client. Tests supply `MockPlcClient`; production supplies
    /// `ReqwestPlcClient` which POSTs to https://plc.directory/{did}.
    pub plc_client: Arc<dyn PlcClient>,
    /// Injectable did:web resolver. Tests supply a mock; production supplies
    /// `ReqwestDidWebResolver`, which GETs a backend-served /.well-known/did.json
    /// (IDEN-04). Used by `createAccount` when the caller supplies a did:web DID.
    pub did_web_resolver: Arc<dyn DidWebResolver>,
    /// Passphrase used to encrypt/decrypt per-account signing and rotation keys
    /// at rest (AES-256-GCM + argon2id KDF).
    pub key_passphrase: Arc<Vec<u8>>,
    /// Broadcast sender for live firehose events. The commit path publishes a
    /// fully-encoded #commit frame after each successful commit; subscribers receive it.
    pub firehose_tx: tokio::sync::broadcast::Sender<crate::firehose::FirehoseEvent>,
    /// Injectable relay client for requestCrawl. Tests supply MockRelayClient.
    pub relay_client: Arc<dyn crate::firehose::RelayClient>,
    /// Relay base URL, e.g. "https://bsky.network". Used by requestCrawl.
    pub relay_url: String,
    /// Injectable AppView client (proxy_get). Tests supply MockAppViewClient.
    pub appview_client: std::sync::Arc<dyn AppViewClient>,
    /// AppView base URL, default "https://api.bsky.app".
    pub appview_url: String,
    /// AppView service DID, default "did:web:api.bsky.app" (the JWT aud).
    pub appview_did: String,
}

/// Implement `AsRef<AppState>` so the axum extractor impls in `auth::extractor`
/// can extract the state with a generic bound `S: AsRef<AppState>`.
impl AsRef<AppState> for AppState {
    fn as_ref(&self) -> &AppState {
        self
    }
}

/// Assemble the complete axum `Router` for the PDS.
///
/// Route table:
/// | Method | Path                                         | Handler             |
/// |--------|----------------------------------------------|---------------------|
/// | GET    | /xrpc/com.atproto.server.describeServer      | describeServer      |
/// | POST   | /xrpc/com.atproto.server.createSession       | createSession       |
/// | POST   | /xrpc/com.atproto.server.refreshSession      | refreshSession      |
/// | POST   | /xrpc/com.atproto.server.createAccount       | createAccount       |
///
/// Identity routes (resolveHandle, /.well-known/*) are filled by Plan 03-03 via
/// `identity::routes()`. Repo routes (createRecord, getRepo, listRecords) are
/// filled by Plan 03-04 via `repo::routes()`.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route(
            "/xrpc/com.atproto.server.describeServer",
            get(server::describe_server),
        )
        .route(
            "/xrpc/com.atproto.server.createSession",
            post(server::create_session),
        )
        .route(
            "/xrpc/com.atproto.server.refreshSession",
            post(server::refresh_session),
        )
        .route(
            "/xrpc/com.atproto.server.getSession",
            get(server::get_session),
        )
        .route(
            "/xrpc/com.atproto.server.getServiceAuth",
            get(server::get_service_auth),
        )
        .route(
            "/xrpc/com.atproto.server.createAccount",
            post(server::create_account),
        )
        .merge(identity::routes())
        .merge(repo::routes())
        .merge(crate::firehose::subscribe::routes())
        .merge(preferences::routes())
        .merge(appview::routes())
        .with_state(state)
        // Browser clients (e.g. the Bluesky web app) issue a CORS preflight
        // OPTIONS request before each XRPC call. Without this layer those
        // preflights hit a method-less route and return 405, blocking the real
        // request. atproto auth is Bearer-token based (no cookies), so a
        // permissive policy (any origin, any method, any header) is correct.
        .layer(CorsLayer::permissive())
}
