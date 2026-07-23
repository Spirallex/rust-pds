//! End-to-end tests for the OAuth 2.0 authorization server.
//!
//! These drive the real router with a real DPoP client, all the way from a
//! pushed authorization request to an authenticated XRPC call and a refresh.
//! Unit tests cover each primitive in isolation; what these prove is that the
//! pieces agree with each other — that the `jkt` the token endpoint binds is the
//! one the resource extractor checks, that a code issued by the authorize page
//! is redeemable at the token endpoint, and that a replayed refresh token
//! actually kills the session.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use data_encoding::BASE64URL_NOPAD;
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use stelyph::auth::jwt::hash_password;
use stelyph::firehose::MockRelayClient;
use stelyph::identity::plc::MockPlcClient;
use stelyph::identity::web_resolver::MockDidWebResolver;
use stelyph::storage::MemoryStore;
use stelyph::xrpc::oauth::{OAuthState, StaticClientResolver};
use stelyph::xrpc::{app, AppState};
use stelyph_core::oauth::{ClientMetadata, DpopVerifier, SigningKey, TokenIssuer};

const ISSUER: &str = "https://pds.test";
const CLIENT_ID: &str = "https://app.test/client-metadata.json";
const REDIRECT_URI: &str = "https://app.test/callback";
const PASSWORD: &str = "correct-horse-battery-staple";
const HANDLE: &str = "alice.pds.test";
const DID: &str = "did:plc:alicetest00000000000000";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn client_metadata() -> ClientMetadata {
    ClientMetadata {
        client_id: CLIENT_ID.into(),
        client_name: Some("Test Application".into()),
        redirect_uris: vec![REDIRECT_URI.into()],
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        response_types: vec!["code".into()],
        scope: "atproto transition:generic".into(),
        token_endpoint_auth_method: "none".into(),
        dpop_bound_access_tokens: true,
        application_type: Some("web".into()),
        jwks_uri: None,
        jwks: None,
        client_uri: None,
        logo_uri: None,
        policy_uri: None,
        tos_uri: None,
    }
}

async fn harness() -> AppState {
    let store = Arc::new(MemoryStore::new());

    // Seed the account the flow will authenticate as.
    use stelyph::storage::AccountStore;
    store
        .insert_account(DID, HANDLE, None, &hash_password(PASSWORD).unwrap())
        .await
        .expect("insert_account");

    let oauth = OAuthState {
        issuer: TokenIssuer::new(
            SigningKey::generate(),
            ISSUER.into(),
            "did:web:pds.test".into(),
        ),
        dpop: DpopVerifier::new(b"oauth-flow-test-nonce-secret".to_vec()),
        client_resolver: StaticClientResolver::new(vec![(CLIENT_ID.into(), client_metadata())]),
        issuer_url: ISSUER.into(),
    };

    AppState {
        store,
        jwt_secret: Arc::new(b"oauth-flow-test-jwt-secret".to_vec()),
        hostname: "pds.test".into(),
        pds_endpoint: ISSUER.into(),
        open_registration: true,
        plc_client: Arc::new(MockPlcClient::new()),
        did_web_resolver: Arc::new(MockDidWebResolver::new_ok()),
        key_passphrase: Arc::new(b"oauth-flow-test-key-passphrase".to_vec()),
        firehose_tx: tokio::sync::broadcast::channel(16).0,
        relay_client: Arc::new(MockRelayClient::new()),
        relay_url: "https://relay.test".into(),
        appview_client: Arc::new(stelyph::xrpc::appview::client::MockAppViewClient::new((
            200,
            Vec::new(),
            None,
        ))),
        appview_url: "https://appview.test".into(),
        appview_did: "did:web:appview.test".into(),
        service_resolver: Arc::new(stelyph::xrpc::appview::MockServiceDidResolver::new(
            "https://svc.test",
        )),
        did_locks: Arc::new(dashmap::DashMap::new()),
        signing_key_cache: Arc::new(dashmap::DashMap::new()),
        oauth: Arc::new(oauth),
    }
}

/// A DPoP-capable OAuth client.
struct TestClient {
    key: SigningKey,
    /// Incremented per proof so each gets a unique `jti`.
    counter: std::cell::Cell<u64>,
}

impl TestClient {
    fn new() -> Self {
        Self {
            key: SigningKey::generate(),
            counter: std::cell::Cell::new(0),
        }
    }

    fn jkt(&self) -> String {
        self.key.public_jwk().thumbprint()
    }

    /// Mint a DPoP proof for one request.
    fn proof(&self, htm: &str, path: &str, nonce: Option<&str>, ath: Option<&str>) -> String {
        self.counter.set(self.counter.get() + 1);
        let header = serde_json::json!({
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": self.key.bare_public_jwk(),
        });
        let mut payload = serde_json::json!({
            "jti": format!("jti-{}", self.counter.get()),
            "htm": htm,
            "htu": format!("{ISSUER}{path}"),
            "iat": stelyph_core::oauth::now_unix(),
        });
        if let Some(n) = nonce {
            payload["nonce"] = serde_json::Value::String(n.into());
        }
        if let Some(a) = ath {
            payload["ath"] = serde_json::Value::String(a.into());
        }

        let h = BASE64URL_NOPAD.encode(&serde_json::to_vec(&header).unwrap());
        let p = BASE64URL_NOPAD.encode(&serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = self.key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", BASE64URL_NOPAD.encode(&sig))
    }
}

/// base64url SHA-256 of an access token, for the DPoP `ath` claim.
fn ath_for(token: &str) -> String {
    BASE64URL_NOPAD.encode(&Sha256::digest(token.as_bytes()))
}

/// PKCE pair: `(verifier, challenge)`.
fn pkce() -> (String, String) {
    let verifier = "test-code-verifier-that-is-at-least-43-chars-long".to_string();
    let challenge = BASE64URL_NOPAD.encode(&Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

async fn send(
    state: &AppState,
    req: Request<Body>,
) -> (StatusCode, Vec<u8>, axum::http::HeaderMap) {
    let resp = app(state.clone()).oneshot(req).await.expect("request");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, body, headers)
}

fn form_request(path: &str, body: String, dpop: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(proof) = dpop {
        b = b.header("DPoP", proof);
    }
    b.body(Body::from(body)).unwrap()
}

/// Run PAR → authorize → token and return `(access_token, refresh_token)`.
async fn complete_flow(state: &AppState, client: &TestClient) -> (String, String) {
    let (verifier, challenge) = pkce();

    // 1. Pushed authorization request.
    let par_body = format!(
        "client_id={}&response_type=code&redirect_uri={}&scope=atproto%20transition%3Ageneric\
         &state=client-state&code_challenge={challenge}&code_challenge_method=S256",
        urlencoding(CLIENT_ID),
        urlencoding(REDIRECT_URI),
    );
    let proof = client.proof("POST", "/oauth/par", None, None);
    let (status, body, headers) =
        send(state, form_request("/oauth/par", par_body, Some(&proof))).await;
    assert_eq!(status, StatusCode::CREATED, "PAR failed: {}", show(&body));
    let par: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let request_uri = par["request_uri"].as_str().unwrap().to_string();
    let nonce = headers
        .get("DPoP-Nonce")
        .expect("PAR must supply a nonce")
        .to_str()
        .unwrap()
        .to_string();

    // 2. Submit credentials and accept.
    let form = format!(
        "request_uri={}&username={HANDLE}&password={}&action=accept",
        urlencoding(&request_uri),
        urlencoding(PASSWORD),
    );
    let (status, _, headers) = send(state, form_request("/oauth/authorize", form, None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "authorize must redirect");
    let location = headers.get("location").unwrap().to_str().unwrap();
    let code = query_param(location, "code").expect("redirect must carry a code");

    // 3. Exchange the code.
    let token_body = format!(
        "grant_type=authorization_code&client_id={}&code={}&redirect_uri={}&code_verifier={verifier}",
        urlencoding(CLIENT_ID),
        urlencoding(&code),
        urlencoding(REDIRECT_URI),
    );
    let proof = client.proof("POST", "/oauth/token", Some(&nonce), None);
    let (status, body, _) = send(
        state,
        form_request("/oauth/token", token_body, Some(&proof)),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "token exchange failed: {}",
        show(&body)
    );
    let tokens: serde_json::Value = serde_json::from_slice(&body).unwrap();

    (
        tokens["access_token"].as_str().unwrap().to_string(),
        tokens["refresh_token"].as_str().unwrap().to_string(),
    )
}

fn urlencoding(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap(), 16)
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn show(body: &[u8]) -> String {
    String::from_utf8_lossy(body).into_owned()
}

fn current_nonce(state: &AppState) -> String {
    state.oauth.dpop.current_nonce()
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_documents_are_served() {
    let state = harness().await;

    let req = Request::builder()
        .uri("/.well-known/oauth-authorization-server")
        .body(Body::empty())
        .unwrap();
    let (status, body, _) = send(&state, req).await;
    assert_eq!(status, StatusCode::OK);
    let md: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(md["issuer"], ISSUER);
    assert_eq!(md["require_pushed_authorization_requests"], true);
    assert_eq!(md["code_challenge_methods_supported"][0], "S256");

    let req = Request::builder()
        .uri("/.well-known/oauth-protected-resource")
        .body(Body::empty())
        .unwrap();
    let (status, body, _) = send(&state, req).await;
    assert_eq!(status, StatusCode::OK);
    let md: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(md["authorization_servers"][0], ISSUER);
}

#[tokio::test]
async fn jwks_publishes_only_public_key_material() {
    let state = harness().await;
    let req = Request::builder()
        .uri("/oauth/jwks")
        .body(Body::empty())
        .unwrap();
    let (status, body, _) = send(&state, req).await;
    assert_eq!(status, StatusCode::OK);

    let jwks: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let key = &jwks["keys"][0];
    assert_eq!(key["kty"], "EC");
    assert_eq!(key["crv"], "P-256");
    assert!(key["kid"].is_string());
    assert!(
        key.get("d").is_none(),
        "the private scalar must never be published"
    );
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_authorization_code_flow_issues_a_usable_token() {
    let state = harness().await;
    let client = TestClient::new();
    let (access, refresh) = complete_flow(&state, &client).await;

    assert!(!access.is_empty());
    assert!(!refresh.is_empty());

    // The access token must be bound to this client's key.
    let claims = state
        .oauth
        .issuer
        .verify_access_token(&access)
        .expect("issued token must verify");
    assert_eq!(claims.sub, DID);
    assert_eq!(claims.cnf.jkt, client.jkt());
    assert_eq!(claims.scope, "atproto transition:generic");
}

#[tokio::test]
async fn the_authorize_page_renders_the_client_and_scopes() {
    let state = harness().await;
    let client = TestClient::new();
    let (_, challenge) = pkce();

    let par_body = format!(
        "client_id={}&response_type=code&redirect_uri={}&scope=atproto\
         &state=s&code_challenge={challenge}&code_challenge_method=S256",
        urlencoding(CLIENT_ID),
        urlencoding(REDIRECT_URI),
    );
    let proof = client.proof("POST", "/oauth/par", None, None);
    let (_, body, _) = send(&state, form_request("/oauth/par", par_body, Some(&proof))).await;
    let par: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let request_uri = par["request_uri"].as_str().unwrap();

    let req = Request::builder()
        .uri(format!(
            "/oauth/authorize?request_uri={}",
            urlencoding(request_uri)
        ))
        .body(Body::empty())
        .unwrap();
    let (status, body, _) = send(&state, req).await;
    assert_eq!(status, StatusCode::OK);

    let page = show(&body);
    assert!(
        page.contains("Test Application"),
        "client name must be shown"
    );
    assert!(
        page.contains("Know which account you are"),
        "scope must be shown"
    );
    assert!(page.contains(r#"name="password""#));
}

// ---------------------------------------------------------------------------
// Resource access
// ---------------------------------------------------------------------------

#[tokio::test]
async fn access_token_with_a_matching_dpop_proof_authenticates_an_xrpc_call() {
    let state = harness().await;
    let client = TestClient::new();
    let (access, _) = complete_flow(&state, &client).await;

    let path = "/xrpc/com.atproto.server.getSession";
    let proof = client.proof(
        "GET",
        path,
        Some(&current_nonce(&state)),
        Some(&ath_for(&access)),
    );
    let req = Request::builder()
        .uri(path)
        .header("Authorization", format!("DPoP {access}"))
        .header("DPoP", proof)
        .body(Body::empty())
        .unwrap();

    let (status, body, _) = send(&state, req).await;
    assert_eq!(status, StatusCode::OK, "getSession failed: {}", show(&body));
    let session: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(session["did"], DID);
}

#[tokio::test]
async fn an_access_token_without_a_dpop_proof_is_rejected() {
    let state = harness().await;
    let client = TestClient::new();
    let (access, _) = complete_flow(&state, &client).await;

    let req = Request::builder()
        .uri("/xrpc/com.atproto.server.getSession")
        .header("Authorization", format!("DPoP {access}"))
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(&state, req).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a DPoP-scheme token with no proof must not authenticate"
    );
}

/// The core DPoP guarantee: a stolen token is useless without the key.
#[tokio::test]
async fn a_stolen_access_token_cannot_be_used_with_another_key() {
    let state = harness().await;
    let victim = TestClient::new();
    let (access, _) = complete_flow(&state, &victim).await;

    // The attacker has the token but signs proofs with their own key.
    let attacker = TestClient::new();
    let path = "/xrpc/com.atproto.server.getSession";
    let proof = attacker.proof(
        "GET",
        path,
        Some(&current_nonce(&state)),
        Some(&ath_for(&access)),
    );

    let req = Request::builder()
        .uri(path)
        .header("Authorization", format!("DPoP {access}"))
        .header("DPoP", proof)
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(&state, req).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a token bound to one key must not be usable with another"
    );
}

/// A proof minted for one endpoint must not authorize a call to another.
#[tokio::test]
async fn a_proof_is_bound_to_its_request() {
    let state = harness().await;
    let client = TestClient::new();
    let (access, _) = complete_flow(&state, &client).await;

    // Proof says /oauth/token; the request goes to getSession.
    let proof = client.proof(
        "GET",
        "/oauth/token",
        Some(&current_nonce(&state)),
        Some(&ath_for(&access)),
    );
    let req = Request::builder()
        .uri("/xrpc/com.atproto.server.getSession")
        .header("Authorization", format!("DPoP {access}"))
        .header("DPoP", proof)
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(&state, req).await;
    assert_ne!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_dpop_proof_cannot_be_replayed() {
    let state = harness().await;
    let client = TestClient::new();
    let (access, _) = complete_flow(&state, &client).await;

    let path = "/xrpc/com.atproto.server.getSession";
    let proof = client.proof(
        "GET",
        path,
        Some(&current_nonce(&state)),
        Some(&ath_for(&access)),
    );

    let build = || {
        Request::builder()
            .uri(path)
            .header("Authorization", format!("DPoP {access}"))
            .header("DPoP", proof.clone())
            .body(Body::empty())
            .unwrap()
    };

    let (first, _, _) = send(&state, build()).await;
    assert_eq!(first, StatusCode::OK);
    let (second, _, _) = send(&state, build()).await;
    assert_ne!(
        second,
        StatusCode::OK,
        "the same proof must not be accepted twice"
    );
}

// ---------------------------------------------------------------------------
// Refresh and rotation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn refresh_rotates_the_token() {
    let state = harness().await;
    let client = TestClient::new();
    let (_, refresh) = complete_flow(&state, &client).await;

    let body = format!(
        "grant_type=refresh_token&client_id={}&refresh_token={}",
        urlencoding(CLIENT_ID),
        urlencoding(&refresh),
    );
    let proof = client.proof("POST", "/oauth/token", Some(&current_nonce(&state)), None);
    let (status, resp, _) = send(&state, form_request("/oauth/token", body, Some(&proof))).await;
    assert_eq!(status, StatusCode::OK, "refresh failed: {}", show(&resp));

    let tokens: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    let new_refresh = tokens["refresh_token"].as_str().unwrap();
    assert_ne!(new_refresh, refresh, "the refresh token must rotate");
    assert_eq!(tokens["sub"], DID);
    assert_eq!(tokens["token_type"], "DPoP");
}

/// Reuse of a spent refresh token must revoke the entire chain.
#[tokio::test]
async fn refresh_reuse_revokes_the_session() {
    let state = harness().await;
    let client = TestClient::new();
    let (_, first_refresh) = complete_flow(&state, &client).await;

    let refresh_with = |token: String, client: &TestClient| {
        let body = format!(
            "grant_type=refresh_token&client_id={}&refresh_token={}",
            urlencoding(CLIENT_ID),
            urlencoding(&token),
        );
        let proof = client.proof("POST", "/oauth/token", Some(&current_nonce(&state)), None);
        form_request("/oauth/token", body, Some(&proof))
    };

    // Legitimate rotation.
    let (status, resp, _) = send(&state, refresh_with(first_refresh.clone(), &client)).await;
    assert_eq!(status, StatusCode::OK);
    let second_refresh: String = serde_json::from_slice::<serde_json::Value>(&resp).unwrap()
        ["refresh_token"]
        .as_str()
        .unwrap()
        .into();

    // Replay of the spent first token.
    let (status, _, _) = send(&state, refresh_with(first_refresh, &client)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a replayed refresh token must be rejected"
    );

    // ...and the legitimate successor must now be dead too.
    let (status, _, _) = send(&state, refresh_with(second_refresh, &client)).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "reuse must revoke the whole rotation chain, not just the replayed token"
    );
}

#[tokio::test]
async fn a_refresh_token_is_bound_to_its_dpop_key() {
    let state = harness().await;
    let client = TestClient::new();
    let (_, refresh) = complete_flow(&state, &client).await;

    let attacker = TestClient::new();
    let body = format!(
        "grant_type=refresh_token&client_id={}&refresh_token={}",
        urlencoding(CLIENT_ID),
        urlencoding(&refresh),
    );
    let proof = attacker.proof("POST", "/oauth/token", Some(&current_nonce(&state)), None);
    let (status, _, _) = send(&state, form_request("/oauth/token", body, Some(&proof))).await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a refresh token must not be spendable with a different key"
    );
}

#[tokio::test]
async fn revocation_ends_the_session() {
    let state = harness().await;
    let client = TestClient::new();
    let (_, refresh) = complete_flow(&state, &client).await;

    let body = format!("token={}", urlencoding(&refresh));
    let (status, _, _) = send(&state, form_request("/oauth/revoke", body, None)).await;
    assert_eq!(status, StatusCode::OK);

    // The revoked token must no longer refresh.
    let body = format!(
        "grant_type=refresh_token&client_id={}&refresh_token={}",
        urlencoding(CLIENT_ID),
        urlencoding(&refresh),
    );
    let proof = client.proof("POST", "/oauth/token", Some(&current_nonce(&state)), None);
    let (status, _, _) = send(&state, form_request("/oauth/token", body, Some(&proof))).await;
    assert_ne!(status, StatusCode::OK);
}

#[tokio::test]
async fn revoking_an_unknown_token_still_returns_ok() {
    // RFC 7009 §2.2 — otherwise the endpoint is an oracle for whether a stolen
    // token is still live.
    let state = harness().await;
    let (status, _, _) = send(
        &state,
        form_request("/oauth/revoke", "token=never-issued".into(), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Rejections
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_authorization_code_cannot_be_redeemed_twice() {
    let state = harness().await;
    let client = TestClient::new();
    let (verifier, challenge) = pkce();

    let par_body = format!(
        "client_id={}&response_type=code&redirect_uri={}&scope=atproto\
         &state=s&code_challenge={challenge}&code_challenge_method=S256",
        urlencoding(CLIENT_ID),
        urlencoding(REDIRECT_URI),
    );
    let proof = client.proof("POST", "/oauth/par", None, None);
    let (_, body, headers) = send(&state, form_request("/oauth/par", par_body, Some(&proof))).await;
    let request_uri = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["request_uri"]
        .as_str()
        .unwrap()
        .to_string();
    let nonce = headers
        .get("DPoP-Nonce")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let form = format!(
        "request_uri={}&username={HANDLE}&password={}&action=accept",
        urlencoding(&request_uri),
        urlencoding(PASSWORD),
    );
    let (_, _, headers) = send(&state, form_request("/oauth/authorize", form, None)).await;
    let code = query_param(headers.get("location").unwrap().to_str().unwrap(), "code").unwrap();

    let exchange = |client: &TestClient| {
        let body = format!(
            "grant_type=authorization_code&client_id={}&code={}&redirect_uri={}&code_verifier={verifier}",
            urlencoding(CLIENT_ID),
            urlencoding(&code),
            urlencoding(REDIRECT_URI),
        );
        let proof = client.proof("POST", "/oauth/token", Some(&nonce), None);
        form_request("/oauth/token", body, Some(&proof))
    };

    let (first, _, _) = send(&state, exchange(&client)).await;
    assert_eq!(first, StatusCode::OK);
    let (second, _, _) = send(&state, exchange(&client)).await;
    assert_eq!(
        second,
        StatusCode::BAD_REQUEST,
        "an authorization code must be single-use"
    );
}

#[tokio::test]
async fn the_token_endpoint_requires_a_dpop_nonce() {
    let state = harness().await;
    let client = TestClient::new();

    // No nonce in the proof.
    let proof = client.proof("POST", "/oauth/token", None, None);
    let body = format!(
        "grant_type=refresh_token&client_id={}&refresh_token=x",
        urlencoding(CLIENT_ID)
    );
    let (status, resp, headers) =
        send(&state, form_request("/oauth/token", body, Some(&proof))).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let err: serde_json::Value = serde_json::from_slice(&resp).unwrap();
    assert_eq!(err["error"], "use_dpop_nonce");
    assert!(
        headers.get("DPoP-Nonce").is_some(),
        "the response must supply a nonce so the client can retry"
    );
}

#[tokio::test]
async fn par_rejects_an_unregistered_redirect_uri() {
    let state = harness().await;
    let client = TestClient::new();
    let (_, challenge) = pkce();

    let body = format!(
        "client_id={}&response_type=code&redirect_uri={}&scope=atproto\
         &state=s&code_challenge={challenge}&code_challenge_method=S256",
        urlencoding(CLIENT_ID),
        urlencoding("https://evil.test/steal"),
    );
    let proof = client.proof("POST", "/oauth/par", None, None);
    let (status, resp, _) = send(&state, form_request("/oauth/par", body, Some(&proof))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(show(&resp).contains("redirect_uri"));
}

#[tokio::test]
async fn par_rejects_a_plain_pkce_challenge() {
    let state = harness().await;
    let client = TestClient::new();
    let (_, challenge) = pkce();

    let body = format!(
        "client_id={}&response_type=code&redirect_uri={}&scope=atproto\
         &state=s&code_challenge={challenge}&code_challenge_method=plain",
        urlencoding(CLIENT_ID),
        urlencoding(REDIRECT_URI),
    );
    let proof = client.proof("POST", "/oauth/par", None, None);
    let (status, _, _) = send(&state, form_request("/oauth/par", body, Some(&proof))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn par_rejects_an_unknown_client() {
    let state = harness().await;
    let client = TestClient::new();
    let (_, challenge) = pkce();

    let body = format!(
        "client_id={}&response_type=code&redirect_uri={}&scope=atproto\
         &state=s&code_challenge={challenge}&code_challenge_method=S256",
        urlencoding("https://unknown.test/client-metadata.json"),
        urlencoding(REDIRECT_URI),
    );
    let proof = client.proof("POST", "/oauth/par", None, None);
    let (status, _, _) = send(&state, form_request("/oauth/par", body, Some(&proof))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_wrong_password_re_renders_the_page_rather_than_issuing_a_code() {
    let state = harness().await;
    let client = TestClient::new();
    let (_, challenge) = pkce();

    let par_body = format!(
        "client_id={}&response_type=code&redirect_uri={}&scope=atproto\
         &state=s&code_challenge={challenge}&code_challenge_method=S256",
        urlencoding(CLIENT_ID),
        urlencoding(REDIRECT_URI),
    );
    let proof = client.proof("POST", "/oauth/par", None, None);
    let (_, body, _) = send(&state, form_request("/oauth/par", par_body, Some(&proof))).await;
    let request_uri = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["request_uri"]
        .as_str()
        .unwrap()
        .to_string();

    let form = format!(
        "request_uri={}&username={HANDLE}&password=wrong-password&action=accept",
        urlencoding(&request_uri),
    );
    let (status, body, _) = send(&state, form_request("/oauth/authorize", form, None)).await;
    assert_eq!(status, StatusCode::OK, "a failed login re-renders the form");
    let page = show(&body);
    assert!(page.contains("Incorrect handle or password"));
    assert!(!page.contains("code="), "no code may be issued");
}

#[tokio::test]
async fn denying_redirects_with_access_denied() {
    let state = harness().await;
    let client = TestClient::new();
    let (_, challenge) = pkce();

    let par_body = format!(
        "client_id={}&response_type=code&redirect_uri={}&scope=atproto\
         &state=client-state&code_challenge={challenge}&code_challenge_method=S256",
        urlencoding(CLIENT_ID),
        urlencoding(REDIRECT_URI),
    );
    let proof = client.proof("POST", "/oauth/par", None, None);
    let (_, body, _) = send(&state, form_request("/oauth/par", par_body, Some(&proof))).await;
    let request_uri = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["request_uri"]
        .as_str()
        .unwrap()
        .to_string();

    let form = format!(
        "request_uri={}&username={HANDLE}&password={}&action=deny",
        urlencoding(&request_uri),
        urlencoding(PASSWORD),
    );
    let (status, _, headers) = send(&state, form_request("/oauth/authorize", form, None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    let location = headers.get("location").unwrap().to_str().unwrap();
    assert!(location.starts_with(REDIRECT_URI));
    assert_eq!(
        query_param(location, "error").as_deref(),
        Some("access_denied")
    );
    assert_eq!(
        query_param(location, "state").as_deref(),
        Some("client-state")
    );
    assert!(query_param(location, "code").is_none());
}

#[tokio::test]
async fn an_unknown_request_uri_renders_an_error_page_not_a_redirect() {
    let state = harness().await;
    let req = Request::builder()
        .uri("/oauth/authorize?request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Anope")
        .body(Body::empty())
        .unwrap();
    let (status, body, headers) = send(&state, req).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        headers.get("location").is_none(),
        "with no validated redirect target this must not redirect — that would be an open redirector"
    );
    assert!(show(&body).contains("expired"));
}

#[tokio::test]
async fn the_authorization_response_carries_iss() {
    // Lets a client detect a mix-up between two authorization servers.
    let state = harness().await;
    let client = TestClient::new();
    let (_, challenge) = pkce();

    let par_body = format!(
        "client_id={}&response_type=code&redirect_uri={}&scope=atproto\
         &state=s&code_challenge={challenge}&code_challenge_method=S256",
        urlencoding(CLIENT_ID),
        urlencoding(REDIRECT_URI),
    );
    let proof = client.proof("POST", "/oauth/par", None, None);
    let (_, body, _) = send(&state, form_request("/oauth/par", par_body, Some(&proof))).await;
    let request_uri = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["request_uri"]
        .as_str()
        .unwrap()
        .to_string();

    let form = format!(
        "request_uri={}&username={HANDLE}&password={}&action=accept",
        urlencoding(&request_uri),
        urlencoding(PASSWORD),
    );
    let (_, _, headers) = send(&state, form_request("/oauth/authorize", form, None)).await;
    let location = headers.get("location").unwrap().to_str().unwrap();
    assert_eq!(query_param(location, "iss").as_deref(), Some(ISSUER));
}
