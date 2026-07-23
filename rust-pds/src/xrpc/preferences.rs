use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};

use crate::auth::extractor::AccessAuth;
use crate::xrpc::{AppState, XrpcError};

// ---------------------------------------------------------------------------
// Lexicon types
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
pub struct GetPreferencesOutput {
    preferences: Vec<serde_json::Value>,
}

#[derive(serde::Deserialize)]
pub struct PutPreferencesInput {
    preferences: Vec<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /xrpc/app.bsky.actor.getPreferences
///
/// Returns the stored preferences array for the authenticated DID, or
/// `{"preferences":[]}` if none have been stored yet.
pub async fn get_preferences(
    State(state): State<AppState>,
    AccessAuth(did): AccessAuth,
) -> Result<Json<GetPreferencesOutput>, XrpcError> {
    let prefs = match state.store.get_preferences(&did).await? {
        None => vec![],
        Some(json_str) => serde_json::from_str(&json_str)
            .map_err(|e| XrpcError::Internal(anyhow::anyhow!("prefs decode: {e}")))?,
    };
    Ok(Json(GetPreferencesOutput { preferences: prefs }))
}

/// POST /xrpc/app.bsky.actor.putPreferences
///
/// Persists the preferences array for the authenticated DID. Returns 200 OK
/// with an empty body on success.
pub async fn put_preferences(
    State(state): State<AppState>,
    AccessAuth(did): AccessAuth,
    Json(input): Json<PutPreferencesInput>,
) -> Result<StatusCode, XrpcError> {
    let json_str = serde_json::to_string(&input.preferences)
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("prefs encode: {e}")))?;
    state.store.upsert_preferences(&did, &json_str).await?;
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/xrpc/app.bsky.actor.getPreferences", get(get_preferences))
        .route("/xrpc/app.bsky.actor.putPreferences", post(put_preferences))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::auth::jwt::encode_access_jwt;
    use crate::identity::plc::MockPlcClient;
    use crate::storage::SqliteStore;
    use crate::xrpc::app;
    use crate::xrpc::appview::client::MockAppViewClient;

    const TEST_SECRET: &[u8] = b"prefs-test-jwt-secret";
    const TEST_DID: &str = "did:plc:preftest";

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    async fn test_state() -> (crate::xrpc::AppState, tempfile::NamedTempFile) {
        let (store, tmp) = SqliteStore::open_in_memory().await.expect("open_in_memory");
        let state = crate::xrpc::AppState {
            store: Arc::new(store),
            jwt_secret: Arc::new(TEST_SECRET.to_vec()),
            hostname: "pds.test".to_string(),
            pds_endpoint: "https://pds.test".to_string(),
            open_registration: false,
            plc_client: Arc::new(MockPlcClient::new()),
            did_web_resolver: Arc::new(crate::identity::web_resolver::MockDidWebResolver::new_ok()),
            key_passphrase: Arc::new(b"test-key-passphrase-prefs".to_vec()),
            firehose_tx: tokio::sync::broadcast::channel(16).0,
            relay_client: std::sync::Arc::new(crate::firehose::MockRelayClient::new()),
            relay_url: "https://relay.test".to_string(),
            appview_client: std::sync::Arc::new(MockAppViewClient::new((200, Vec::new(), None))),
            appview_url: "https://appview.test".to_string(),
            appview_did: "did:web:appview.test".to_string(),
            service_resolver: std::sync::Arc::new(
                crate::xrpc::appview::MockServiceDidResolver::new("https://svc.test"),
            ),
            did_locks: Arc::new(dashmap::DashMap::new()),
            signing_key_cache: Arc::new(dashmap::DashMap::new()),
            oauth: crate::xrpc::oauth::test_oauth_state(),
        };
        (state, tmp)
    }

    fn bearer_header(token: &str) -> String {
        format!("Bearer {token}")
    }

    async fn response_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /// getPreferences for a brand-new DID with no stored row returns {"preferences":[]}.
    #[tokio::test]
    async fn get_preferences_empty_returns_empty_array() {
        let (state, _tmp) = test_state().await;
        let token = encode_access_jwt(TEST_DID, TEST_SECRET).unwrap();

        let resp = app(state)
            .oneshot(
                Request::get("/xrpc/app.bsky.actor.getPreferences")
                    .header("Authorization", bearer_header(&token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let json = response_json(resp).await;
        assert_eq!(
            json["preferences"],
            serde_json::Value::Array(vec![]),
            "expected empty preferences array, got: {json}"
        );
    }

    /// putPreferences then getPreferences round-trips the array verbatim.
    #[tokio::test]
    async fn preferences_round_trip() {
        let (state, _tmp) = test_state().await;
        let token = encode_access_jwt(TEST_DID, TEST_SECRET).unwrap();

        let prefs_payload = serde_json::json!({
            "preferences": [
                {"$type": "app.bsky.actor.defs#savedFeedsPref", "saved": ["x"]}
            ]
        });

        // POST putPreferences
        let put_resp = app(state.clone())
            .oneshot(
                Request::post("/xrpc/app.bsky.actor.putPreferences")
                    .header("Authorization", bearer_header(&token))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&prefs_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            put_resp.status(),
            StatusCode::OK,
            "putPreferences should return 200"
        );

        // GET getPreferences — must return the same array
        let get_resp = app(state)
            .oneshot(
                Request::get("/xrpc/app.bsky.actor.getPreferences")
                    .header("Authorization", bearer_header(&token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(get_resp.status(), StatusCode::OK);
        let json = response_json(get_resp).await;
        assert_eq!(
            json["preferences"], prefs_payload["preferences"],
            "round-trip mismatch: {json}"
        );
    }

    /// getPreferences and putPreferences both require a valid session — no
    /// Authorization header returns 401.
    #[tokio::test]
    async fn preferences_require_session() {
        let (state, _tmp) = test_state().await;

        // GET without auth
        let get_resp = app(state.clone())
            .oneshot(
                Request::get("/xrpc/app.bsky.actor.getPreferences")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            get_resp.status(),
            StatusCode::UNAUTHORIZED,
            "getPreferences without auth should be 401"
        );

        // POST without auth
        let put_resp = app(state)
            .oneshot(
                Request::post("/xrpc/app.bsky.actor.putPreferences")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&serde_json::json!({"preferences": []})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            put_resp.status(),
            StatusCode::UNAUTHORIZED,
            "putPreferences without auth should be 401"
        );
    }
}
