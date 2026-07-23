//! Integration tests for the subscribeRepos WebSocket endpoint.
//!
//! These tests run against a real bound server (ephemeral port) and use
//! tokio-tungstenite as a real WebSocket client.
//!
//! Test coverage:
//! - `test_cursor_backfill`      — cursor=N replays seq>N in order with injected seq
//! - `test_future_cursor`        — cursor > max_seq sends FutureCursor error frame + close
//! - `test_live_stream`          — no cursor streams live events as they are published
//! - `test_no_cursor_live_only`  — no cursor does NOT replay pre-existing repo_seq rows
//! - `test_binary_not_text`      — all frames are Binary, never Text

use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use atrium_api::types::string::Did;
use atrium_crypto::keypair::{Did as KeypairDid, Export, Secp256k1Keypair};
use futures_util::StreamExt;
use ipld_core::ipld::Ipld;
use rand::rngs::OsRng;
use stelyph::auth::jwt::{encode_access_jwt, hash_password};
use stelyph::firehose::MockRelayClient;
use stelyph::identity::plc::MockPlcClient;
use stelyph::identity::web_resolver::MockDidWebResolver;
use stelyph::repo::RepoWriter;
use stelyph::storage::crypto::store_key;
use stelyph::storage::SqliteStore;
use stelyph::xrpc::{app, AppState};
use tokio_tungstenite::tungstenite::Message;

const JWT_SECRET: &[u8] = b"test-jwt-secret-firehose-ws";
const KEY_PASSPHRASE: &[u8] = b"test-key-passphrase-firehose-ws";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Spawn a real server on an ephemeral port and return its address + AppState.
///
/// Uses a named temp file for SQLite (`:memory:` disables WAL and causes
/// reader/writer pool isolation). Keeps `_tmp` alive in the returned struct.
async fn spawn_server() -> (SocketAddr, AppState, tempfile::NamedTempFile) {
    // Use a named temp file — deadpool and tokio-rusqlite both need an on-disk path.
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let path = tmp.path().to_str().expect("temp path utf8").to_string();
    let store = SqliteStore::open(&path).await.expect("open store");

    let (firehose_tx, _) = tokio::sync::broadcast::channel(512);
    let state = AppState {
        store: Arc::new(store),
        jwt_secret: Arc::new(JWT_SECRET.to_vec()),
        hostname: "pds.test".to_string(),
        pds_endpoint: "https://pds.test".to_string(),
        open_registration: true,
        plc_client: Arc::new(MockPlcClient::new()),
        did_web_resolver: Arc::new(MockDidWebResolver::new_ok()),
        key_passphrase: Arc::new(KEY_PASSPHRASE.to_vec()),
        firehose_tx,
        relay_client: Arc::new(MockRelayClient::new()),
        relay_url: "https://relay.test".to_string(),
        appview_client: Arc::new(stelyph::xrpc::appview::client::MockAppViewClient::new((
            200,
            Vec::new(),
            None,
        ))),
        appview_url: "https://appview.test".to_string(),
        appview_did: "did:web:appview.test".to_string(),
        service_resolver: std::sync::Arc::new(stelyph::xrpc::appview::MockServiceDidResolver::new(
            "https://svc.test",
        )),
        did_locks: Arc::new(dashmap::DashMap::new()),
        signing_key_cache: Arc::new(dashmap::DashMap::new()),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local_addr");

    let router = app(state.clone());
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });

    (addr, state, tmp)
}

/// Seed a test account: insert account row + store signing key.
/// Returns (did, signing_keypair, access_token).
async fn seed_account(state: &AppState, handle: &str) -> (String, Secp256k1Keypair, String) {
    let did = format!("did:plc:test{}", handle.replace('.', ""));
    let phc = hash_password("test-password").unwrap();
    state
        .store
        .insert_account(&did, handle, None, &phc)
        .await
        .expect("insert_account");

    let signing = Secp256k1Keypair::create(&mut OsRng);
    let key_bytes = signing.export();
    store_key(
        state.store.as_ref(),
        &format!("{did}#signing"),
        &key_bytes,
        &state.key_passphrase,
    )
    .await
    .expect("store_key");

    let access_token = encode_access_jwt(&did, JWT_SECRET).expect("encode_access_jwt");

    // Re-import: Secp256k1Keypair does not implement Clone, so we import again
    // to give the caller a fresh keypair with the same private key.
    let signing2 = Secp256k1Keypair::import(&key_bytes).expect("import key");

    (did, signing2, access_token)
}

/// Write N records to the store via RepoWriter, returning their assigned seqs.
/// `start_offset` allows callers to produce unique rkeys across multiple calls.
/// Uses the state's firehose_tx so live subscribers see the events too.
async fn write_records_offset(state: &AppState, did: &str, n: u32, start_offset: u32) -> Vec<i64> {
    let did_typed = did.parse::<Did>().expect("parse did");

    // Re-import the key from the store.
    let key_bytes = stelyph::storage::crypto::load_key(
        state.store.as_ref(),
        &format!("{did}#signing"),
        &state.key_passphrase,
    )
    .await
    .expect("load_key");
    let signing = Secp256k1Keypair::import(&key_bytes).expect("import key");

    let writer = RepoWriter::new(
        Arc::clone(&state.store),
        signing,
        did_typed,
        state.firehose_tx.clone(),
    );

    let mut seqs = Vec::new();
    for i in 0..n {
        let rkey_id = start_offset + i;
        let key = format!("app.bsky.feed.post/test{rkey_id:06}");
        let record = Ipld::Map(
            [
                (
                    "$type".to_string(),
                    Ipld::String("app.bsky.feed.post".to_string()),
                ),
                (
                    "text".to_string(),
                    Ipld::String(format!("test post {rkey_id}")),
                ),
            ]
            .into_iter()
            .collect(),
        );
        writer
            .create_record(&key, record)
            .await
            .expect("create_record");
        let seq = state.store.max_seq().await.expect("max_seq");
        seqs.push(seq);
    }
    seqs
}

/// Write N records starting at offset 0.
async fn write_records(state: &AppState, did: &str, n: u32) -> Vec<i64> {
    write_records_offset(state, did, n, 0).await
}

/// Decode the two-object CBOR frame: (header_map, body_map).
fn decode_frame(
    bytes: &[u8],
) -> (
    std::collections::BTreeMap<String, Ipld>,
    std::collections::BTreeMap<String, Ipld>,
) {
    let cursor = Cursor::new(bytes);
    let mut reader = BufReader::new(cursor);

    let header: Ipld =
        serde_ipld_dagcbor::de::from_reader_once(&mut reader).expect("decode frame header");
    let body: Ipld =
        serde_ipld_dagcbor::de::from_reader_once(&mut reader).expect("decode frame body");

    let hdr_map = if let Ipld::Map(m) = header {
        m
    } else {
        panic!("header must be an IPLD map, got: {:?}", header)
    };
    let body_map = if let Ipld::Map(m) = body {
        m
    } else {
        panic!("body must be an IPLD map, got: {:?}", body)
    };
    (hdr_map, body_map)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// cursor=1 replays seq>1 rows (seq 2 and 3) in order with injected seq fields.
#[tokio::test]
async fn test_cursor_backfill() {
    let (addr, state, _tmp) = spawn_server().await;
    let (did, _signing, _token) = seed_account(&state, "alice.test").await;

    // Write 3 records — seqs will be 1, 2, 3.
    write_records(&state, &did, 3).await;

    let url = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?cursor=1");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect");

    // Expect 2 frames: seq=2 and seq=3.
    let mut received_seqs = Vec::new();
    for _ in 0..2usize {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timeout waiting for frame")
            .expect("stream ended early")
            .expect("ws error");

        // Assert binary (not text).
        let bytes = match msg {
            Message::Binary(b) => b,
            other => panic!("expected Binary frame, got: {:?}", other),
        };

        let (hdr, body) = decode_frame(&bytes);
        // Header: op=1, t="#commit"
        assert_eq!(hdr.get("op"), Some(&Ipld::Integer(1)), "op must be 1");
        assert_eq!(
            hdr.get("t"),
            Some(&Ipld::String("#commit".to_string())),
            "t must be #commit"
        );

        // Body: seq field is injected.
        let seq = match body.get("seq") {
            Some(Ipld::Integer(s)) => *s,
            other => panic!("expected seq integer, got: {:?}", other),
        };
        received_seqs.push(seq);
    }

    assert_eq!(
        received_seqs,
        vec![2, 3],
        "should replay seq 2 and 3 in order"
    );
}

/// cursor > max_seq → first message is FutureCursor error frame, connection closes.
#[tokio::test]
async fn test_future_cursor() {
    let (addr, state, _tmp) = spawn_server().await;
    let (did, _signing, _token) = seed_account(&state, "bob.test").await;

    // Write 1 record → max_seq = 1.
    write_records(&state, &did, 1).await;

    let url = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?cursor=99999");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect");

    // First (and only) message should be the FutureCursor error frame.
    let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("timeout waiting for FutureCursor frame")
        .expect("stream ended without sending FutureCursor")
        .expect("ws error");

    let bytes = match msg {
        Message::Binary(b) => b,
        other => panic!("expected Binary frame, got: {:?}", other),
    };

    let (hdr, body) = decode_frame(&bytes);
    // Error header: op=-1, no "t" field.
    assert_eq!(
        hdr.get("op"),
        Some(&Ipld::Integer(-1)),
        "op must be -1 for error"
    );
    assert!(
        !hdr.contains_key("t"),
        "error header must not have 't' field"
    );

    // Error body: error="FutureCursor".
    assert_eq!(
        body.get("error"),
        Some(&Ipld::String("FutureCursor".to_string())),
        "error field must be FutureCursor"
    );

    // Connection should close after the error frame.
    let next = tokio::time::timeout(Duration::from_secs(3), ws.next()).await;
    // Either the stream ends (None) or we get a Close frame — both are acceptable.
    match next {
        Ok(None) => {}                        // server closed gracefully
        Ok(Some(Ok(Message::Close(_)))) => {} // explicit Close frame
        Ok(Some(Ok(other))) => panic!("expected stream close, got: {:?}", other),
        Ok(Some(Err(_))) => {} // connection reset after close
        Err(_timeout) => panic!("expected connection to close after FutureCursor"),
    }
}

/// No cursor: connecting without cursor streams live events as they arrive.
#[tokio::test]
async fn test_live_stream() {
    let (addr, state, _tmp) = spawn_server().await;
    let (did, _signing, _token) = seed_account(&state, "carol.test").await;

    // Connect WITHOUT cursor (live-only).
    let url = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect");

    // Spawn a task that creates a record AFTER the WS connection is open.
    let state_clone = state.clone();
    let did_clone = did.clone();
    tokio::spawn(async move {
        // Small delay to ensure the subscriber is registered.
        tokio::time::sleep(Duration::from_millis(50)).await;
        write_records(&state_clone, &did_clone, 1).await;
    });

    // We should receive the new #commit frame within 2 seconds.
    let msg = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("timeout: no live frame received within 2s")
        .expect("stream ended")
        .expect("ws error");

    let bytes = match msg {
        Message::Binary(b) => b,
        other => panic!("expected Binary frame, got: {:?}", other),
    };

    let (hdr, body) = decode_frame(&bytes);
    assert_eq!(hdr.get("op"), Some(&Ipld::Integer(1)));
    assert_eq!(hdr.get("t"), Some(&Ipld::String("#commit".to_string())));
    let seq = match body.get("seq") {
        Some(Ipld::Integer(s)) => *s,
        other => panic!("expected seq integer, got: {:?}", other),
    };
    assert!(seq >= 1, "seq must be at least 1");
}

/// No cursor: does NOT replay pre-existing repo_seq rows; only new events arrive.
#[tokio::test]
async fn test_no_cursor_live_only() {
    let (addr, state, _tmp) = spawn_server().await;
    let (did, _signing, _token) = seed_account(&state, "dave.test").await;

    // Write 2 records BEFORE connecting.
    write_records(&state, &did, 2).await;
    let max_before = state.store.max_seq().await.expect("max_seq");

    // Connect WITHOUT cursor — should NOT see the 2 pre-existing rows.
    let url = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect");

    // Write 1 more record AFTER connecting — use offset 100 to avoid key collision.
    let state_clone = state.clone();
    let did_clone = did.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        write_records_offset(&state_clone, &did_clone, 1, 100).await;
    });

    // Should receive exactly ONE frame (the newly published one).
    let msg = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("timeout: no live frame received within 2s")
        .expect("stream ended")
        .expect("ws error");

    let bytes = match msg {
        Message::Binary(b) => b,
        other => panic!("expected Binary frame, got: {:?}", other),
    };

    let (_, body) = decode_frame(&bytes);
    let seq = match body.get("seq") {
        Some(Ipld::Integer(s)) => *s,
        other => panic!("expected seq integer, got: {:?}", other),
    };

    // The frame's seq must be AFTER the pre-existing rows — live-only means no backfill.
    // `seq` is i128 (from Ipld::Integer); `max_before` is i64 — cast for comparison.
    assert!(
        seq > max_before as i128,
        "no-cursor subscriber must not receive pre-existing rows; got seq={seq}, max_before={max_before}"
    );

    // No second message arrives within a short window (only 1 live record was written).
    let next = tokio::time::timeout(Duration::from_millis(300), ws.next()).await;
    assert!(
        next.is_err(),
        "expected no second frame for no-cursor live-only (got {:?})",
        next
    );
}

/// FED-04: create an account + post, subscribe live, receive the #commit, and its signature verifies.
///
/// This is the load-bearing falsifiable proof for FED-04. If `verify_commit_sig` returns Err,
/// the federation spine is broken (signing key mismatch, wrong unsigned bytes, CAR encoding bug, etc.).
#[tokio::test]
async fn test_fed04_e2e_signature_verifies() {
    let (addr, state, _tmp) = spawn_server().await;
    let (did, signing, _token) = seed_account(&state, "fed04.test").await;

    // Connect LIVE (no cursor) BEFORE creating the post.
    let url = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect");

    // The verification key is the signing keypair's did:key — NOT body.repo (Pitfall 6).
    let did_key = signing.did();

    // Create the post AFTER connecting so it arrives as a live event.
    let state_clone = state.clone();
    let did_clone = did.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        write_records(&state_clone, &did_clone, 1).await;
    });

    // Receive the live #commit frame within 2s.
    let msg = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("timeout: no live frame in 2s")
        .expect("stream ended")
        .expect("ws error");
    let bytes = match msg {
        Message::Binary(b) => b,
        other => panic!("expected Binary, got: {other:?}"),
    };

    // Decode + FED-04 signature assertion.
    let body = stelyph::firehose::tail::decode_commit_frame(&bytes)
        .expect("frame should decode as #commit");
    stelyph::firehose::tail::verify_commit_sig(&body, &did_key)
        .await
        .expect("FED-04 FAILED: live commit signature did not verify");

    // Sanity checks.
    assert_eq!(body.repo, did, "repo DID must match the poster");
    assert!(!body.blocks.is_empty(), "blocks must be non-empty");
    assert_eq!(body.ops.len(), 1, "one op for one create");
    assert_eq!(body.ops[0].action, "create", "op must be a create");
}

/// All received WebSocket messages are Binary, never Text.
#[tokio::test]
async fn test_binary_not_text() {
    let (addr, state, _tmp) = spawn_server().await;
    let (did, _signing, _token) = seed_account(&state, "eve.test").await;

    // Write 2 records — we'll replay them with cursor=0.
    write_records(&state, &did, 2).await;

    let url = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos?cursor=0");
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect");

    // Read the 2 backfill frames and assert each is Binary.
    for i in 0..2usize {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .unwrap_or_else(|_| panic!("timeout on frame {i}"))
            .unwrap_or_else(|| panic!("stream ended before frame {i}"))
            .unwrap_or_else(|e| panic!("ws error on frame {i}: {e}"));

        match msg {
            Message::Binary(_) => {} // correct — binary frame
            Message::Text(_) => panic!("frame {i} was Text — must be Binary (Pitfall 1)"),
            other => panic!("unexpected frame type for frame {i}: {:?}", other),
        }
    }
}
