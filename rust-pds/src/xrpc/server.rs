/// XRPC server handlers: describeServer, createSession, refreshSession, createAccount.
///
/// Plan 03-02: Full implementation — AppState is wired, all four handlers are live.
///
/// createAccount gate (ACCT-01/02):
///   - First account (count_accounts == 0) claims the server with no invite.
///   - Subsequent accounts require a valid unused invite code UNLESS
///     `AppState::open_registration` is true.
///
/// DID method selection rule:
///   - Default (and only mode in this plan): did:plc via the injected `PlcClient`.
///   - did:web can be derived from `state.hostname` but is NOT automatically
///     selected here; a future plan may add a `did_method` config field.
///     For now, createAccount ALWAYS uses did:plc so tests work with MockPlcClient.
///
/// Empty-repo-init decision:
///   - LAZY. createAccount persists only the account row + two encrypted keys.
///   - The first empty repo commit is written lazily by `RepoWriter::create_record`
///     on the first `createRecord` call. This avoids an extra round of block writes
///     at account-creation time for accounts that may never post.
///   - The plan's success criterion ("account created + can post") is satisfied by
///     the createRecord round-trip in Plan 03-04.
use atrium_crypto::keypair::Secp256k1Keypair;
use axum::extract::{Query, State};
use axum::Json;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::auth::extractor::{AccessAuth, RefreshAuth};
use crate::auth::jwt::{encode_access_jwt, encode_refresh_jwt, hash_password, verify_password};
use crate::identity::plc::register_did_plc;
use crate::storage::keys::{load_key, store_key};
use crate::xrpc::appview::service_auth::mint_service_auth_jwt_with;
use crate::xrpc::{AppState, XrpcError};

// ---------------------------------------------------------------------------
// describeServer
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeServerResponse {
    pub did: String,
    pub available_user_domains: Vec<String>,
    pub invite_code_required: bool,
}

/// GET /xrpc/com.atproto.server.describeServer
///
/// Returns server metadata: the server DID, available user domains, and whether
/// an invite code is required for registration.
pub async fn describe_server(
    State(state): State<AppState>,
) -> Result<Json<DescribeServerResponse>, XrpcError> {
    let did = format!("did:web:{}", state.hostname);
    Ok(Json(DescribeServerResponse {
        did,
        available_user_domains: vec![format!(".{}", state.hostname)],
        invite_code_required: !state.open_registration,
    }))
}

// ---------------------------------------------------------------------------
// createSession
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateSessionInput {
    pub identifier: String,
    pub password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionResponse {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: String,
    pub did: String,
    pub active: bool,
}

/// POST /xrpc/com.atproto.server.createSession
///
/// Verify identifier (handle) + password → issue access + refresh JWTs.
pub async fn create_session(
    State(state): State<AppState>,
    Json(input): Json<CreateSessionInput>,
) -> Result<Json<SessionResponse>, XrpcError> {
    // Look up account. Missing or taken-down → 401 (no detail).
    let (did, phc) = state
        .store
        .get_account_by_handle(&input.identifier)
        .await?
        .ok_or_else(|| XrpcError::InvalidRequest("invalid identifier or password".into()))?;

    // Verify password. Wrong password → same 401 (no detail leakage).
    if !verify_password(&input.password, &phc)? {
        return Err(XrpcError::InvalidRequest(
            "invalid identifier or password".into(),
        ));
    }

    let access = encode_access_jwt(&did, &state.jwt_secret)?;
    let refresh = encode_refresh_jwt(&did, &state.jwt_secret)?;

    Ok(Json(SessionResponse {
        access_jwt: access,
        refresh_jwt: refresh,
        handle: input.identifier,
        did,
        active: true,
    }))
}

// ---------------------------------------------------------------------------
// refreshSession
// ---------------------------------------------------------------------------

/// POST /xrpc/com.atproto.server.refreshSession
///
/// Validate refresh JWT (scope must be com.atproto.refresh; expired → ExpiredToken,
/// wrong scope → InvalidToken) and issue a fresh access + refresh pair.
pub async fn refresh_session(
    State(state): State<AppState>,
    RefreshAuth(did): RefreshAuth,
) -> Result<Json<SessionResponse>, XrpcError> {
    // Confirm account still exists and is not taken down.
    // get_handle_by_did filters deactivated_at IS NULL AND takedown_ref IS NULL,
    // so None means the account is absent or taken down — reject with AccountTakedown.
    let handle = state
        .store
        .get_handle_by_did(&did)
        .await?
        .ok_or(XrpcError::AccountTakedown)?;

    let access = encode_access_jwt(&did, &state.jwt_secret)?;
    let refresh = encode_refresh_jwt(&did, &state.jwt_secret)?;

    Ok(Json(SessionResponse {
        access_jwt: access,
        refresh_jwt: refresh,
        handle,
        did,
        active: true,
    }))
}

// ---------------------------------------------------------------------------
// getSession
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSessionResponse {
    pub handle: String,
    pub did: String,
    pub active: bool,
}

/// GET /xrpc/com.atproto.server.getSession
///
/// Return the authenticated account's identity. The Bluesky client calls this
/// right after login to validate the access token and fetch handle/did.
pub async fn get_session(
    State(state): State<AppState>,
    AccessAuth(did): AccessAuth,
) -> Result<Json<GetSessionResponse>, XrpcError> {
    let handle = state
        .store
        .get_handle_by_did(&did)
        .await?
        .ok_or(XrpcError::AccountTakedown)?;

    Ok(Json(GetSessionResponse {
        handle,
        did,
        active: true,
    }))
}

// ---------------------------------------------------------------------------
// getServiceAuth
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct GetServiceAuthParams {
    /// The DID of the service the token is for (e.g. did:web:api.bsky.app).
    pub aud: String,
    /// Optional lexicon method NSID this token is scoped to.
    pub lxm: Option<String>,
    /// Optional absolute expiry (unix seconds). Capped to 30 minutes ahead.
    pub exp: Option<i64>,
}

#[derive(Serialize)]
pub struct GetServiceAuthOutput {
    pub token: String,
}

/// GET /xrpc/com.atproto.server.getServiceAuth
///
/// Mint an ES256K inter-service auth token signed with the account's signing
/// key (iss = account DID). The Bluesky client uses this to call the AppView,
/// chat, video, and labeler services on the user's behalf.
pub async fn get_service_auth(
    State(state): State<AppState>,
    AccessAuth(did): AccessAuth,
    Query(params): Query<GetServiceAuthParams>,
) -> Result<Json<GetServiceAuthOutput>, XrpcError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let key_id = format!("{did}#signing");
    let key_bytes = load_key(&state.store, &key_id, &state.key_passphrase)
        .await
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("failed to load signing key: {e}")))?;
    let signing = Secp256k1Keypair::import(&key_bytes)
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("failed to import signing key: {e}")))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs();
    // Default 60s; honor a caller-requested exp but never beyond 30 minutes
    // ahead, and never in the past.
    let max_exp = now + 30 * 60;
    let exp = match params.exp {
        Some(e) if e as u64 > now => (e as u64).min(max_exp),
        _ => now + 60,
    };

    let token =
        mint_service_auth_jwt_with(&signing, &did, &params.aud, params.lxm.as_deref(), exp)?;
    Ok(Json(GetServiceAuthOutput { token }))
}

// ---------------------------------------------------------------------------
// createAccount
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountInput {
    pub handle: String,
    pub email: Option<String>,
    pub password: Option<String>,
    pub invite_code: Option<String>,
    pub did: Option<String>, // did:web DID: resolved + stored (IDEN-02); else did:plc is derived
    pub recovery_key: Option<String>, // ignored — rotation key is the recovery key
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountResponse {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: String,
    pub did: String,
}

/// Validate that a handle string is well-formed per the ATProto handle spec.
///
/// Rules (from atproto.com/specs/handle):
/// - ≤ 253 characters total.
/// - ASCII alphanumeric + hyphens only within segments.
/// - Segments separated by `.`; at least two segments.
/// - No segment may start or end with a hyphen.
/// - No segment may be empty.
fn validate_handle(handle: &str) -> Result<(), XrpcError> {
    if handle.is_empty() || handle.len() > 253 {
        return Err(XrpcError::InvalidHandle);
    }
    let segments: Vec<&str> = handle.split('.').collect();
    if segments.len() < 2 {
        return Err(XrpcError::InvalidHandle);
    }
    for seg in &segments {
        if seg.is_empty() {
            return Err(XrpcError::InvalidHandle);
        }
        if seg.starts_with('-') || seg.ends_with('-') {
            return Err(XrpcError::InvalidHandle);
        }
        if !seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(XrpcError::InvalidHandle);
        }
    }
    Ok(())
}

/// POST /xrpc/com.atproto.server.createAccount
///
/// Thin axum handler wrapper around `create_account_inner`.
/// The wizard (Plan 04) calls `create_account_inner` directly without HTTP.
pub async fn create_account(
    State(state): State<AppState>,
    Json(input): Json<CreateAccountInput>,
) -> Result<Json<CreateAccountResponse>, XrpcError> {
    create_account_inner(&state, input).await.map(Json)
}

/// Core createAccount logic, callable without axum extractors.
///
/// Full sequence:
/// 1. Validate handle.
/// 2. Require handle to equal `{hostname}` or end with `.{hostname}` (UnsupportedDomain).
/// 3. Check handle availability (HandleNotAvailable).
/// 4. The gate: first account → no invite; else require invite OR open_registration.
/// 5. Generate two Secp256k1 keypairs (signing + rotation).
/// 6. Register did:plc via injected PlcClient.
/// 7. Hash password, insert account row, store both encrypted keys.
/// 8. Issue access + refresh JWTs.
///
/// Called by the axum handler via `create_account`, and directly by the
/// `rust-pds init` wizard (Plan 04) to create the first account in-process.
pub async fn create_account_inner(
    state: &AppState,
    input: CreateAccountInput,
) -> Result<CreateAccountResponse, XrpcError> {
    // IN-02: normalize to lowercase before all validation and DB operations.
    // ATProto handles are case-insensitive; storing in canonical lowercase form
    // prevents duplicate registrations of e.g. "Alice.pds.test" vs "alice.pds.test".
    let handle = input.handle.to_ascii_lowercase();

    // Step 1: validate handle format.
    validate_handle(&handle)?;

    // Step 2: handle must be the server's user domain or a subdomain of it.
    // Rule: handle == hostname (single-user PDS: handle and PDS share one domain,
    // e.g. handle `me.example.com` on PDS `me.example.com`) OR handle ends with
    // ".{hostname}" (multi-user: `<username>.pds.example.com`). Arbitrary external
    // domains are rejected.
    let expected_suffix = format!(".{}", state.hostname);
    if handle != state.hostname && !handle.ends_with(&expected_suffix) {
        return Err(XrpcError::UnsupportedDomain);
    }

    // Step 3: check handle availability.
    if state.store.get_account_by_handle(&handle).await?.is_some() {
        return Err(XrpcError::HandleNotAvailable);
    }

    // Step 4: the invite gate.
    //
    // WR-02: To prevent a TOCTOU race where two concurrent first registrations
    // both see count == 0 and skip the invite check, we determine invite need
    // using a preliminary reader count, but the ACTUAL first-account detection
    // is enforced inside `count_and_insert_account` which re-checks the count
    // inside a BEGIN IMMEDIATE writer transaction. If a race is detected (the
    // atomic count shows we were not actually first despite not consuming an
    // invite), we reject with InvalidInviteCode rather than inserting a second
    // account without an invite.
    let preliminary_n = state.store.count_accounts().await?;
    let invite_consumed = if preliminary_n == 0 {
        // Likely the first account — no invite consumed yet (will be verified atomically).
        false
    } else if state.open_registration {
        // Server is open — no invite required.
        false
    } else {
        // Invite required. Consume it now (atomic in consume_invite).
        let code = input
            .invite_code
            .as_deref()
            .ok_or(XrpcError::InvalidInviteCode)?;
        // Use the handle as the used_by key (handle is unique at this point).
        let consumed = state.store.consume_invite(code, &handle).await?;
        if !consumed {
            return Err(XrpcError::InvalidInviteCode);
        }
        true
    };

    // Step 5: generate two secp256k1 keypairs.
    let signing = Secp256k1Keypair::create(&mut OsRng);
    let rotation = Secp256k1Keypair::create(&mut OsRng);

    // Step 6: register the account's DID.
    //
    // IDEN-02: if the caller supplied a did:web DID, resolve it (the backend
    // must serve a matching document — D17-B) and store THAT DID instead of
    // deriving a did:plc. Resolution failure is a typed error, NEVER a silent
    // downgrade to did:plc (T-05-03). Any other input (absent, or a non-did:web
    // did) keeps the unchanged did:plc path so Stelyph's own accounts and
    // existing tests are unaffected (T-05-04).
    let did = match input.did.as_deref() {
        Some(d) if d.starts_with("did:web:") => {
            let doc = state
                .did_web_resolver
                .resolve(d)
                .await
                .map_err(|_| XrpcError::UnresolvableDid)?;
            // Strengthening: the resolved document's `id` must match the DID
            // the caller claimed — otherwise the caller could point us at any
            // resolvable-but-mismatched document.
            if doc.get("id").and_then(|v| v.as_str()) != Some(d) {
                return Err(XrpcError::UnresolvableDid);
            }
            d.to_string()
        }
        _ => {
            // Unchanged did:plc path.
            register_did_plc(
                &handle,
                &state.pds_endpoint,
                &signing,
                &rotation,
                state.plc_client.as_ref(),
            )
            .await?
        }
    };

    // Step 7: persist account + encrypted keys.
    // WR-01: require a non-empty password of at least 8 characters. Never hash the
    // empty string or a trivially short credential.
    let password = input
        .password
        .as_deref()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| XrpcError::InvalidRequest("password is required".into()))?;
    if password.len() < 8 {
        return Err(XrpcError::InvalidRequest(
            "password must be at least 8 characters".into(),
        ));
    }
    let phc = hash_password(password)?;

    // WR-02: Use count_and_insert_account to atomically count and insert in a
    // single BEGIN IMMEDIATE writer transaction. This eliminates the TOCTOU race
    // for concurrent first-account registrations.
    let count_before = state
        .store
        .count_and_insert_account(&did, &handle, input.email.as_deref(), &phc)
        .await?;

    // WR-02: If we thought we were the first account (preliminary_n == 0) but
    // the atomic count says there was already an account (count_before > 0), and
    // we're not in open_registration mode, we lost the race. Reject to avoid
    // inserting a second "first account" without an invite.
    if count_before > 0 && !state.open_registration && !invite_consumed {
        return Err(XrpcError::InvalidInviteCode);
    }

    // Export signing key scalar bytes and encrypt at rest.
    use atrium_crypto::keypair::Export;
    let signing_scalar = signing.export();
    let rotation_scalar = rotation.export();

    store_key(
        &state.store,
        &format!("{did}#signing"),
        &signing_scalar,
        &state.key_passphrase,
    )
    .await?;

    store_key(
        &state.store,
        &format!("{did}#rotation"),
        &rotation_scalar,
        &state.key_passphrase,
    )
    .await?;

    // Step 8: issue session JWTs.
    let access = encode_access_jwt(&did, &state.jwt_secret)?;
    let refresh = encode_refresh_jwt(&did, &state.jwt_secret)?;

    Ok(CreateAccountResponse {
        access_jwt: access,
        refresh_jwt: refresh,
        handle,
        did,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::auth::jwt::encode_access_jwt;
    use crate::identity::plc::MockPlcClient;
    use crate::storage::SqliteStore;
    use crate::xrpc::app;

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Build a test AppState with in-memory SQLite, fixed secrets, and MockPlcClient.
    async fn test_state() -> (AppState, tempfile::NamedTempFile) {
        let (store, tmp) = SqliteStore::open_in_memory().await.expect("open_in_memory");
        let state = AppState {
            store: Arc::new(store),
            jwt_secret: Arc::new(b"test-jwt-secret-03-02".to_vec()),
            hostname: "pds.test".to_string(),
            pds_endpoint: "https://pds.test".to_string(),
            open_registration: false,
            plc_client: Arc::new(MockPlcClient::new()),
            did_web_resolver: Arc::new(crate::identity::web_resolver::MockDidWebResolver::new_ok()),
            key_passphrase: Arc::new(b"test-key-passphrase-03-02".to_vec()),
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

    /// Build AppState with open_registration = true.
    async fn test_state_open() -> (AppState, tempfile::NamedTempFile) {
        let (store, tmp) = SqliteStore::open_in_memory().await.expect("open_in_memory");
        let state = AppState {
            store: Arc::new(store),
            jwt_secret: Arc::new(b"test-jwt-secret-03-02".to_vec()),
            hostname: "pds.test".to_string(),
            pds_endpoint: "https://pds.test".to_string(),
            open_registration: true,
            plc_client: Arc::new(MockPlcClient::new()),
            did_web_resolver: Arc::new(crate::identity::web_resolver::MockDidWebResolver::new_ok()),
            key_passphrase: Arc::new(b"test-key-passphrase-03-02".to_vec()),
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

    /// POST a JSON body to `path` on the test app.
    async fn post_json(
        state: AppState,
        path: &str,
        body: serde_json::Value,
    ) -> axum::response::Response {
        app(state)
            .oneshot(
                Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// Shorthand to create one account via HTTP and return the response JSON.
    async fn create_first_account(
        state: AppState,
        handle: &str,
    ) -> (StatusCode, serde_json::Value) {
        let resp = post_json(
            state,
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({
                "handle": handle,
                "password": "hunter2!"  // 8 chars — meets minimum length requirement
            }),
        )
        .await;
        let status = resp.status();
        let json = response_json(resp).await;
        (status, json)
    }

    // -----------------------------------------------------------------------
    // describeServer
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn describe_server_returns_200_with_did_and_domains() {
        let (state, _tmp) = test_state().await;
        let resp = app(state)
            .oneshot(
                Request::get("/xrpc/com.atproto.server.describeServer")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = response_json(resp).await;
        assert!(json["did"].as_str().is_some(), "did must be present");
        assert!(
            json["availableUserDomains"].as_array().is_some(),
            "availableUserDomains must be present"
        );
        assert_eq!(json["inviteCodeRequired"], true);
    }

    // -----------------------------------------------------------------------
    // createSession
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn create_session_valid_credentials_returns_tokens() {
        let (state, _tmp) = test_state().await;
        // Seed an account directly via storage helpers.
        let phc = hash_password("correct-pw").unwrap();
        state
            .store
            .insert_account("did:plc:seed1234567890", "alice.pds.test", None, &phc)
            .await
            .unwrap();

        let resp = post_json(
            state,
            "/xrpc/com.atproto.server.createSession",
            serde_json::json!({
                "identifier": "alice.pds.test",
                "password": "correct-pw"
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = response_json(resp).await;
        assert!(
            !json["accessJwt"].as_str().unwrap_or("").is_empty(),
            "accessJwt must be non-empty"
        );
        assert!(
            !json["refreshJwt"].as_str().unwrap_or("").is_empty(),
            "refreshJwt must be non-empty"
        );
    }

    #[tokio::test]
    async fn create_session_wrong_password_returns_400() {
        let (state, _tmp) = test_state().await;
        let phc = hash_password("correct-pw").unwrap();
        state
            .store
            .insert_account("did:plc:seed1234567890", "alice.pds.test", None, &phc)
            .await
            .unwrap();

        let resp = post_json(
            state,
            "/xrpc/com.atproto.server.createSession",
            serde_json::json!({
                "identifier": "alice.pds.test",
                "password": "wrong-password"
            }),
        )
        .await;
        // InvalidRequest maps to 400 (per XrpcError).
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // -----------------------------------------------------------------------
    // refreshSession
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn refresh_session_expired_refresh_token_returns_expired_token() {
        let (state, _tmp) = test_state().await;
        let secret = state.jwt_secret.clone();

        // Craft an expired refresh JWT (exp in the past).
        let expired = {
            use crate::auth::jwt::AuthClaims;
            use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
            let claims = AuthClaims {
                sub: "did:plc:test".to_string(),
                scope: "com.atproto.refresh".to_string(),
                exp: 1_000_000, // far in the past
                iat: 999_999,
                jti: Some("test-jti".into()),
            };
            encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(&secret),
            )
            .unwrap()
        };

        let resp = app(state)
            .oneshot(
                Request::post("/xrpc/com.atproto.server.refreshSession")
                    .header("Authorization", format!("Bearer {expired}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "ExpiredToken");
    }

    /// CR-02: refresh_session for a taken-down account must return 401 AccountTakedown.
    #[tokio::test]
    async fn refresh_session_taken_down_account_returns_account_takedown() {
        let (state, _tmp) = test_state().await;
        let secret = state.jwt_secret.clone();

        // Seed an account.
        let phc = crate::auth::jwt::hash_password("pw").unwrap();
        state
            .store
            .insert_account("did:plc:takedowntest", "alice.pds.test", None, &phc)
            .await
            .unwrap();

        // Issue a valid refresh token for that DID.
        let refresh = {
            use crate::auth::jwt::AuthClaims;
            use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let claims = AuthClaims {
                sub: "did:plc:takedowntest".to_string(),
                scope: "com.atproto.refresh".to_string(),
                exp: now + 3600,
                iat: now,
                jti: Some("cr02-test".into()),
            };
            encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(&secret),
            )
            .unwrap()
        };

        // Mark account as taken down.
        state
            .store
            .set_takedown("did:plc:takedowntest", "")
            .await
            .unwrap();

        let resp = app(state)
            .oneshot(
                Request::post("/xrpc/com.atproto.server.refreshSession")
                    .header("Authorization", format!("Bearer {refresh}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "AccountTakedown");
    }

    /// CR-02: refresh_session for a nonexistent DID must return 401 AccountTakedown.
    #[tokio::test]
    async fn refresh_session_missing_account_returns_account_takedown() {
        let (state, _tmp) = test_state().await;
        let secret = state.jwt_secret.clone();

        // Issue a valid refresh token for a DID that was never inserted.
        let refresh = {
            use crate::auth::jwt::AuthClaims;
            use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let claims = AuthClaims {
                sub: "did:plc:ghost".to_string(),
                scope: "com.atproto.refresh".to_string(),
                exp: now + 3600,
                iat: now,
                jti: Some("cr02-ghost".into()),
            };
            encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(&secret),
            )
            .unwrap()
        };

        let resp = app(state)
            .oneshot(
                Request::post("/xrpc/com.atproto.server.refreshSession")
                    .header("Authorization", format!("Bearer {refresh}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "AccountTakedown");
    }

    #[tokio::test]
    async fn refresh_session_access_scoped_token_returns_invalid_token() {
        let (state, _tmp) = test_state().await;
        let secret = state.jwt_secret.clone();
        let access_token = encode_access_jwt("did:plc:test", &secret).unwrap();

        let resp = app(state)
            .oneshot(
                Request::post("/xrpc/com.atproto.server.refreshSession")
                    .header("Authorization", format!("Bearer {access_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "InvalidToken");
    }

    // -----------------------------------------------------------------------
    // createAccount — the gate
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn first_account_no_invite() {
        let (state, _tmp) = test_state().await;
        let (status, json) = create_first_account(state, "alice.pds.test").await;
        assert_eq!(status, StatusCode::OK, "first account must succeed: {json}");
        assert!(
            !json["accessJwt"].as_str().unwrap_or("").is_empty(),
            "accessJwt must be present"
        );
    }

    #[tokio::test]
    async fn second_account_requires_invite() {
        let (state, _tmp) = test_state().await;

        // Create first account (no invite needed).
        let resp = post_json(
            state.clone(),
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({"handle": "alice.pds.test", "password": "password1"}),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Try second account without invite — must fail.
        let resp = post_json(
            state,
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({"handle": "bob.pds.test", "password": "password2"}),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "InvalidInviteCode");
    }

    #[tokio::test]
    async fn second_account_with_valid_invite_succeeds() {
        let (state, _tmp) = test_state().await;

        // Create first account.
        let resp = post_json(
            state.clone(),
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({"handle": "alice.pds.test", "password": "password1"}),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Seed a single-use invite code.
        state
            .store
            .insert_invite("invite-abc", 1, "admin")
            .await
            .unwrap();

        // Second account WITH invite → success.
        let resp = post_json(
            state.clone(),
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({
                "handle": "bob.pds.test",
                "password": "password2",
                "inviteCode": "invite-abc"
            }),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "second account with valid invite must succeed: {}",
            response_json(resp).await
        );

        // Re-use same invite → InvalidInviteCode.
        let resp = post_json(
            state,
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({
                "handle": "carol.pds.test",
                "password": "password3",
                "inviteCode": "invite-abc"
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "InvalidInviteCode");
    }

    #[tokio::test]
    async fn open_registration_bypasses_invite() {
        let (state, _tmp) = test_state_open().await;

        // Create first account.
        let resp = post_json(
            state.clone(),
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({"handle": "alice.pds.test", "password": "password1"}),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Second account — no invite, open_registration=true → success.
        let resp = post_json(
            state,
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({"handle": "bob.pds.test", "password": "password2"}),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "open registration must allow second account without invite"
        );
    }

    #[tokio::test]
    async fn account_provisions_keys() {
        let (state, _tmp) = test_state().await;

        let resp = post_json(
            state.clone(),
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({"handle": "alice.pds.test", "password": "secretkey"}),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = response_json(resp).await;
        let did = json["did"].as_str().expect("did must be present");

        // Both keys must decrypt successfully with the key_passphrase.
        let signing = crate::storage::keys::load_key(
            &state.store,
            &format!("{did}#signing"),
            &state.key_passphrase,
        )
        .await
        .expect("signing key must exist and decrypt");
        assert_eq!(signing.len(), 32, "signing key must be 32 bytes");

        let rotation = crate::storage::keys::load_key(
            &state.store,
            &format!("{did}#rotation"),
            &state.key_passphrase,
        )
        .await
        .expect("rotation key must exist and decrypt");
        assert_eq!(rotation.len(), 32, "rotation key must be 32 bytes");
    }

    // -----------------------------------------------------------------------
    // Handle validation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn invalid_handle_too_short() {
        let (state, _tmp) = test_state().await;
        // "x" has only one segment — must be InvalidHandle.
        let resp = post_json(
            state,
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({"handle": "x", "password": "pw"}),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "InvalidHandle");
    }

    #[tokio::test]
    async fn unsupported_domain_for_external_handle() {
        let (state, _tmp) = test_state().await;
        // Valid handle format but wrong domain → UnsupportedDomain.
        let resp = post_json(
            state,
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({"handle": "alice.other.example", "password": "pw"}),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "UnsupportedDomain");
    }

    /// Single-user PDS: a handle equal to the server hostname is accepted
    /// (handle and PDS share one domain, e.g. handle `pds.test` on PDS `pds.test`).
    #[tokio::test]
    async fn handle_equal_to_hostname_is_accepted() {
        let (state, _tmp) = test_state().await; // hostname = "pds.test"
        let resp = post_json(
            state,
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({"handle": "pds.test", "password": "hunter2!"}),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "handle == hostname must be accepted: {}",
            response_json(resp).await
        );
    }

    // -----------------------------------------------------------------------
    // WR-01: password validation
    // -----------------------------------------------------------------------

    /// WR-01: createAccount with an empty password must be rejected with InvalidRequest.
    #[tokio::test]
    async fn create_account_empty_password_rejected() {
        let (state, _tmp) = test_state().await;
        let resp = post_json(
            state,
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({"handle": "alice.pds.test", "password": ""}),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "InvalidRequest");
    }

    /// WR-01: createAccount with a missing password field must be rejected with InvalidRequest.
    #[tokio::test]
    async fn create_account_missing_password_rejected() {
        let (state, _tmp) = test_state().await;
        let resp = post_json(
            state,
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({"handle": "alice.pds.test"}),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "InvalidRequest");
    }

    /// WR-01: createAccount with a password shorter than 8 chars must be rejected.
    #[tokio::test]
    async fn create_account_short_password_rejected() {
        let (state, _tmp) = test_state().await;
        let resp = post_json(
            state,
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({"handle": "alice.pds.test", "password": "short"}),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "InvalidRequest");
    }

    // -----------------------------------------------------------------------
    // did:web createAccount (IDEN-02)
    // -----------------------------------------------------------------------

    /// IDEN-02: createAccount with a caller-supplied did:web DID and a resolver
    /// that succeeds must store and return THAT did:web DID, not a derived did:plc.
    #[tokio::test]
    async fn create_account_with_did_web_resolves_and_stores_it() {
        let (state, _tmp) = test_state().await;
        let resp = post_json(
            state,
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({
                "handle": "alice.pds.test",
                "password": "password1",
                "did": "did:web:pds.test:devices:d001"
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = response_json(resp).await;
        assert_eq!(json["did"], "did:web:pds.test:devices:d001");
    }

    /// IDEN-02/T-05-03: createAccount with a did:web DID that fails to resolve
    /// must reject with UnresolvableDid — NEVER silently fall back to did:plc.
    #[tokio::test]
    async fn create_account_with_unresolvable_did_web_is_rejected() {
        let (mut state, _tmp) = test_state().await;
        state.did_web_resolver =
            std::sync::Arc::new(crate::identity::web_resolver::MockDidWebResolver::new_err());

        let resp = post_json(
            state,
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({
                "handle": "alice.pds.test",
                "password": "password1",
                "did": "did:web:pds.test:devices:d001"
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "UnresolvableDid");
    }

    /// T-05-04: createAccount with no `did` field is unaffected by the did:web
    /// branch — the existing did:plc derivation path still runs (regression guard).
    #[tokio::test]
    async fn create_account_without_did_still_derives_did_plc() {
        let (state, _tmp) = test_state().await;
        let resp = post_json(
            state,
            "/xrpc/com.atproto.server.createAccount",
            serde_json::json!({"handle": "alice.pds.test", "password": "password1"}),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = response_json(resp).await;
        let did = json["did"].as_str().unwrap();
        assert!(
            did.starts_with("did:plc:"),
            "did:plc path must be unchanged when no did:web is supplied, got {did}"
        );
    }
}
