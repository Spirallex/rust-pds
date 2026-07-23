//! Backend conformance suite.
//!
//! Every behaviour the rest of the crate relies on is asserted here once, then
//! run against *both* backends via [`storage_conformance_tests!`]. This is what
//! makes the second implementation worth having: a rule that only the SQLite
//! backend enforces — an auth lookup that forgets to hide taken-down accounts, a
//! `put_block` that errors on a duplicate CID — fails here loudly instead of
//! surfacing as a subtle divergence the first time a new backend goes live.
//!
//! When adding a storage method, add its behavioural contract here rather than
//! in a backend-specific test module. Backend-specific tests should assert only
//! things that genuinely have no cross-backend meaning (WAL mode, SQLITE_BUSY,
//! the online-backup API).
//!
//! # Usage
//!
//! ```ignore
//! async fn setup() -> (Arc<dyn StorageBackend>, Box<dyn Any + Send>) {
//!     (Arc::new(MyStore::new()), Box::new(()))
//! }
//! storage_conformance_tests!(setup);
//! ```
//!
//! The second tuple element is an opaque guard kept alive for the duration of
//! each test — the SQLite backend uses it to hold its `NamedTempFile`.

/// Generate the full conformance suite for one backend.
///
/// `$setup` names an `async fn() -> (Arc<dyn StorageBackend>, Box<dyn Any + Send>)`.
#[macro_export]
macro_rules! storage_conformance_tests {
    ($setup:path) => {
        // The suite is generated inside a module so two invocations in one crate
        // (one per backend) cannot collide on test names.
        mod storage_conformance {
            #![allow(unused_imports)]
            use super::*;
            use atrium_repo::blockstore::DAG_CBOR;
            use $crate::oauth::store::{
                AuthCode, ConsumeResult, OAuthStore, RefreshTokenRecord, StoredPushedRequest,
            };
            use $crate::storage::{
                cid_of, crypto, AccountStore, BlobStore, BlockStore, KeyStore, RepoStore,
                Sequencer, StorageError,
            };

            // --- blocks ---------------------------------------------------

            #[tokio::test]
            async fn block_roundtrip_and_missing() {
                let (s, _g) = $setup().await;
                let bytes = b"conformance block".to_vec();
                let cid = cid_of(DAG_CBOR, &bytes);

                s.put_block(cid, bytes.clone()).await.unwrap();
                assert_eq!(s.read_block_bytes(cid).await.unwrap(), bytes);

                let missing = cid_of(DAG_CBOR, b"absent");
                assert!(
                    matches!(
                        s.read_block_bytes(missing).await,
                        Err(StorageError::BlockNotFound)
                    ),
                    "a missing CID must map to BlockNotFound, not a backend error"
                );
            }

            #[tokio::test]
            async fn put_block_is_idempotent() {
                let (s, _g) = $setup().await;
                let bytes = b"written twice".to_vec();
                let cid = cid_of(DAG_CBOR, &bytes);

                s.put_block(cid, bytes.clone()).await.unwrap();
                s.put_block(cid, bytes.clone())
                    .await
                    .expect("re-writing an existing CID must not error");
                assert_eq!(s.read_block_bytes(cid).await.unwrap(), bytes);
            }

            // --- commits, roots, sequencer --------------------------------

            #[tokio::test]
            async fn empty_repo_has_no_root() {
                let (s, _g) = $setup().await;
                assert_eq!(s.load_repo_root("did:plc:none").await.unwrap(), None);
            }

            #[tokio::test]
            async fn commit_sets_root_and_returns_increasing_seq() {
                let (s, _g) = $setup().await;
                let did = "did:plc:commit";

                let a = b"root A".to_vec();
                let cid_a = cid_of(DAG_CBOR, &a);
                let seq1 = s
                    .commit_blocks(vec![(cid_a, a)], did, cid_a, vec![0xa0])
                    .await
                    .unwrap();
                assert!(seq1 > 0, "seq must be positive");
                assert_eq!(s.load_repo_root(did).await.unwrap(), Some(cid_a));

                let b = b"root B".to_vec();
                let cid_b = cid_of(DAG_CBOR, &b);
                let seq2 = s
                    .commit_blocks(vec![(cid_b, b)], did, cid_b, vec![0xa0])
                    .await
                    .unwrap();
                assert_eq!(seq2, seq1 + 1, "seq must increment by exactly one");
                assert_eq!(s.load_repo_root(did).await.unwrap(), Some(cid_b));
            }

            #[tokio::test]
            async fn commit_persists_blocks_and_event_body() {
                let (s, _g) = $setup().await;
                let payload = b"committed block".to_vec();
                let cid = cid_of(DAG_CBOR, &payload);
                let event = vec![1u8, 2, 3, 4];

                let seq = s
                    .commit_blocks(
                        vec![(cid, payload.clone())],
                        "did:plc:body",
                        cid,
                        event.clone(),
                    )
                    .await
                    .unwrap();

                assert_eq!(s.read_block_bytes(cid).await.unwrap(), payload);
                let page = s.backfill_page(seq - 1, 10).await.unwrap();
                assert_eq!(page.first().map(|(_, e)| e.clone()), Some(event));
            }

            #[tokio::test]
            async fn max_seq_starts_at_zero_and_tracks_commits() {
                let (s, _g) = $setup().await;
                assert_eq!(s.max_seq().await.unwrap(), 0, "empty log reports 0");

                let payload = b"seq tracking".to_vec();
                let cid = cid_of(DAG_CBOR, &payload);
                let seq = s
                    .commit_blocks(vec![(cid, payload)], "did:plc:seq", cid, vec![0xa0])
                    .await
                    .unwrap();
                assert_eq!(s.max_seq().await.unwrap(), seq);
            }

            #[tokio::test]
            async fn backfill_is_ordered_and_paged() {
                let (s, _g) = $setup().await;
                let bodies: Vec<Vec<u8>> = vec![vec![1], vec![2], vec![3], vec![4]];
                let mut written = Vec::new();
                for (i, body) in bodies.iter().enumerate() {
                    let data = format!("backfill {i}").into_bytes();
                    let cid = cid_of(DAG_CBOR, &data);
                    written.push(
                        s.commit_blocks(vec![(cid, data)], "did:plc:bf", cid, body.clone())
                            .await
                            .unwrap(),
                    );
                }

                let all = s.backfill_page(0, 500).await.unwrap();
                assert_eq!(all.len(), 4);
                for (i, (seq, event)) in all.iter().enumerate() {
                    assert_eq!(*seq, written[i], "row {i} out of order");
                    assert_eq!(*event, bodies[i], "row {i} carries the wrong event");
                }

                let page1 = s.backfill_page(0, 2).await.unwrap();
                assert_eq!(page1.len(), 2, "limit must cap the page");
                let page2 = s.backfill_page(page1.last().unwrap().0, 500).await.unwrap();
                assert_eq!(page2.len(), 2, "cursor must resume after the last row");
                assert_eq!(page2[0].0, written[2]);
            }

            #[tokio::test]
            async fn update_repo_root_overwrites() {
                let (s, _g) = $setup().await;
                let did = "did:plc:setroot";
                let a = cid_of(DAG_CBOR, b"a");
                let b = cid_of(DAG_CBOR, b"b");

                s.update_repo_root(did, a).await.unwrap();
                assert_eq!(s.load_repo_root(did).await.unwrap(), Some(a));
                s.update_repo_root(did, b).await.unwrap();
                assert_eq!(s.load_repo_root(did).await.unwrap(), Some(b));
            }

            // --- accounts -------------------------------------------------

            #[tokio::test]
            async fn account_insert_and_lookups() {
                let (s, _g) = $setup().await;
                s.insert_account("did:plc:a1", "alice.test", Some("a@x.test"), "phc-a")
                    .await
                    .unwrap();

                assert_eq!(
                    s.get_account_by_handle("alice.test").await.unwrap(),
                    Some(("did:plc:a1".into(), "phc-a".into()))
                );
                assert_eq!(
                    s.get_did_by_handle("alice.test").await.unwrap(),
                    Some("did:plc:a1".into())
                );
                assert_eq!(
                    s.get_handle_by_did("did:plc:a1").await.unwrap(),
                    Some("alice.test".into())
                );
                assert_eq!(s.get_did_by_handle("nobody.test").await.unwrap(), None);
                assert_eq!(s.get_handle_by_did("did:plc:nope").await.unwrap(), None);
            }

            #[tokio::test]
            async fn duplicate_did_is_rejected() {
                let (s, _g) = $setup().await;
                s.insert_account("did:plc:dup", "first.test", None, "phc")
                    .await
                    .unwrap();
                assert!(
                    s.insert_account("did:plc:dup", "second.test", None, "phc")
                        .await
                        .is_err(),
                    "did is a primary key — a duplicate must be rejected"
                );
            }

            #[tokio::test]
            async fn duplicate_handle_is_rejected() {
                let (s, _g) = $setup().await;
                s.insert_account("did:plc:h1", "taken.test", None, "phc")
                    .await
                    .unwrap();
                assert!(
                    s.insert_account("did:plc:h2", "taken.test", None, "phc")
                        .await
                        .is_err(),
                    "handle is unique — a duplicate must be rejected"
                );
            }

            #[tokio::test]
            async fn count_and_insert_returns_prior_count() {
                let (s, _g) = $setup().await;
                assert_eq!(s.count_accounts().await.unwrap(), 0);

                let before_first = s
                    .count_and_insert_account("did:plc:c1", "c1.test", None, "phc")
                    .await
                    .unwrap();
                assert_eq!(before_first, 0, "the first account sees a prior count of 0");

                let before_second = s
                    .count_and_insert_account("did:plc:c2", "c2.test", None, "phc")
                    .await
                    .unwrap();
                assert_eq!(
                    before_second, 1,
                    "the second account sees a prior count of 1"
                );
                assert_eq!(s.count_accounts().await.unwrap(), 2);
            }

            /// A failed insert must not leave the backend unusable — this is the
            /// regression guard for a transaction left open on the shared writer.
            #[tokio::test]
            async fn failed_insert_leaves_backend_usable() {
                let (s, _g) = $setup().await;
                s.count_and_insert_account("did:plc:dup", "first.test", None, "phc-1")
                    .await
                    .unwrap();
                assert!(s
                    .count_and_insert_account("did:plc:dup", "second.test", None, "phc-2")
                    .await
                    .is_err());

                let before = s
                    .count_and_insert_account("did:plc:fresh", "fresh.test", None, "phc-3")
                    .await
                    .expect("an independent write after a failure must still succeed");
                assert_eq!(before, 1);
            }

            #[tokio::test]
            async fn takedown_hides_from_auth_lookups_and_clears() {
                let (s, _g) = $setup().await;
                s.insert_account("did:plc:t1", "target.test", None, "phc")
                    .await
                    .unwrap();
                assert!(s.get_handle_by_did("did:plc:t1").await.unwrap().is_some());

                assert_eq!(s.set_takedown("did:plc:t1", "spam-42").await.unwrap(), 1);
                assert!(
                    s.get_handle_by_did("did:plc:t1").await.unwrap().is_none(),
                    "a taken-down account must be invisible to DID lookup"
                );
                assert!(
                    s.get_did_by_handle("target.test").await.unwrap().is_none(),
                    "a taken-down account must be invisible to handle lookup"
                );
                assert!(
                    s.get_account_by_handle("target.test")
                        .await
                        .unwrap()
                        .is_none(),
                    "a taken-down account must not be able to authenticate"
                );

                assert_eq!(s.clear_takedown("did:plc:t1").await.unwrap(), 1);
                assert!(s.get_handle_by_did("did:plc:t1").await.unwrap().is_some());
            }

            #[tokio::test]
            async fn takedown_with_empty_reference_still_takes_effect() {
                let (s, _g) = $setup().await;
                s.insert_account("did:plc:t2", "empty.test", None, "phc")
                    .await
                    .unwrap();
                assert_eq!(s.set_takedown("did:plc:t2", "").await.unwrap(), 1);
                assert!(
                    s.get_handle_by_did("did:plc:t2").await.unwrap().is_none(),
                    "an empty reference must still mark the account taken down"
                );
            }

            #[tokio::test]
            async fn takedown_on_unknown_did_affects_zero_rows() {
                let (s, _g) = $setup().await;
                assert_eq!(s.set_takedown("did:plc:nope", "x").await.unwrap(), 0);
                assert_eq!(s.clear_takedown("did:plc:nope").await.unwrap(), 0);
            }

            #[tokio::test]
            async fn update_password_replaces_hash() {
                let (s, _g) = $setup().await;
                s.insert_account("did:plc:p1", "bob.test", None, "old-phc")
                    .await
                    .unwrap();

                assert_eq!(s.update_password("did:plc:p1", "new-phc").await.unwrap(), 1);
                let (_did, phc) = s.get_account_by_handle("bob.test").await.unwrap().unwrap();
                assert_eq!(phc, "new-phc");

                assert_eq!(
                    s.update_password("did:plc:none", "x").await.unwrap(),
                    0,
                    "an unknown DID affects no rows"
                );
            }

            #[tokio::test]
            async fn list_accounts_includes_taken_down_in_creation_order() {
                let (s, _g) = $setup().await;
                s.insert_account("did:plc:l1", "l1.test", None, "phc")
                    .await
                    .unwrap();
                s.insert_account("did:plc:l2", "l2.test", None, "phc")
                    .await
                    .unwrap();
                s.set_takedown("did:plc:l2", "reason").await.unwrap();

                let accounts = s.list_accounts().await.unwrap();
                assert_eq!(
                    accounts.len(),
                    2,
                    "the operator view must include taken-down accounts"
                );
                assert_eq!(
                    accounts.iter().map(|a| a.did.as_str()).collect::<Vec<_>>(),
                    vec!["did:plc:l1", "did:plc:l2"],
                    "accounts must come back oldest-first"
                );
                let l2 = accounts.iter().find(|a| a.did == "did:plc:l2").unwrap();
                assert_eq!(l2.takedown_ref.as_deref(), Some("reason"));
            }

            // --- invites --------------------------------------------------

            #[tokio::test]
            async fn invite_consumes_once_per_did() {
                let (s, _g) = $setup().await;
                s.insert_invite("code-1", 1, "admin").await.unwrap();

                assert!(
                    s.consume_invite("code-1", "did:plc:u1").await.unwrap(),
                    "first redemption succeeds"
                );
                assert!(
                    !s.consume_invite("code-1", "did:plc:u1").await.unwrap(),
                    "the same DID must not redeem twice"
                );
                assert!(
                    !s.consume_invite("code-1", "did:plc:u2").await.unwrap(),
                    "an exhausted code must not be redeemable"
                );
            }

            #[tokio::test]
            async fn invite_with_multiple_uses_serves_distinct_dids() {
                let (s, _g) = $setup().await;
                s.insert_invite("code-2", 2, "admin").await.unwrap();
                assert!(s.consume_invite("code-2", "did:plc:a").await.unwrap());
                assert!(s.consume_invite("code-2", "did:plc:b").await.unwrap());
                assert!(
                    !s.consume_invite("code-2", "did:plc:c").await.unwrap(),
                    "the third DID exceeds available_uses"
                );
            }

            #[tokio::test]
            async fn unknown_invite_is_false_not_error() {
                let (s, _g) = $setup().await;
                assert!(
                    !s.consume_invite("never-issued", "did:plc:u").await.unwrap(),
                    "an unknown code is a false, not an Err"
                );
            }

            // --- preferences ----------------------------------------------

            #[tokio::test]
            async fn preferences_round_trip_and_overwrite() {
                let (s, _g) = $setup().await;
                assert_eq!(s.get_preferences("did:plc:x").await.unwrap(), None);

                let v1 = r#"[{"$type":"a"}]"#;
                s.upsert_preferences("did:plc:x", v1).await.unwrap();
                assert_eq!(
                    s.get_preferences("did:plc:x").await.unwrap(),
                    Some(v1.to_string())
                );

                s.upsert_preferences("did:plc:x", "[]").await.unwrap();
                assert_eq!(
                    s.get_preferences("did:plc:x").await.unwrap(),
                    Some("[]".to_string())
                );
            }

            // --- keys -----------------------------------------------------

            #[tokio::test]
            async fn key_blob_round_trip() {
                let (s, _g) = $setup().await;
                assert_eq!(s.get_key_blob("absent").await.unwrap(), None);

                s.put_key_blob("signing", vec![1, 2, 3]).await.unwrap();
                assert_eq!(
                    s.get_key_blob("signing").await.unwrap(),
                    Some(vec![1, 2, 3])
                );

                // Re-keying a slot replaces it rather than erroring.
                s.put_key_blob("signing", vec![4, 5]).await.unwrap();
                assert_eq!(s.get_key_blob("signing").await.unwrap(), Some(vec![4, 5]));
            }

            #[tokio::test]
            async fn store_and_load_key_round_trip() {
                let (s, _g) = $setup().await;
                let key: Vec<u8> = (0u8..32).collect();
                let pass = b"conformance passphrase";

                crypto::store_key(s.as_ref(), "signing", &key, pass)
                    .await
                    .unwrap();
                assert_eq!(
                    crypto::load_key(s.as_ref(), "signing", pass).await.unwrap(),
                    key
                );

                // What lands in storage must be ciphertext, never the key itself.
                let raw = s.get_key_blob("signing").await.unwrap().unwrap();
                assert!(
                    !raw.windows(key.len()).any(|w| w == key.as_slice()),
                    "stored blob contains the plaintext key"
                );

                assert!(
                    crypto::load_key(s.as_ref(), "signing", b"wrong")
                        .await
                        .is_err(),
                    "the wrong passphrase must fail"
                );
                assert!(
                    crypto::load_key(s.as_ref(), "missing", pass).await.is_err(),
                    "a missing key must fail"
                );
            }

            #[tokio::test]
            async fn key_export_import_round_trip() {
                let (s, _g) = $setup().await;
                let (dst, _g2) = $setup().await;
                let key: Vec<u8> = (0u8..32).collect();
                let pass = b"export passphrase";

                crypto::store_key(s.as_ref(), "signing", &key, pass)
                    .await
                    .unwrap();
                let blob = crypto::export_keys(s.as_ref(), "signing", pass)
                    .await
                    .unwrap();

                crypto::import_keys(dst.as_ref(), "signing", &blob, pass)
                    .await
                    .unwrap();
                assert_eq!(
                    crypto::load_key(dst.as_ref(), "signing", pass)
                        .await
                        .unwrap(),
                    key
                );

                assert!(
                    crypto::import_keys(dst.as_ref(), "signing", &blob, b"wrong")
                        .await
                        .is_err(),
                    "importing with the wrong passphrase must fail"
                );
                assert!(
                    crypto::export_keys(s.as_ref(), "absent", pass)
                        .await
                        .is_err(),
                    "exporting a missing key must fail"
                );
            }

            // --- blobs ----------------------------------------------------

            #[tokio::test]
            async fn blob_round_trip_scoped_per_did() {
                let (s, _g) = $setup().await;
                assert_eq!(s.get_blob("did:plc:b", "cid1").await.unwrap(), None);

                s.put_blob("did:plc:b", "cid1", "image/png", 3, vec![1, 2, 3])
                    .await
                    .unwrap();
                assert_eq!(
                    s.get_blob("did:plc:b", "cid1").await.unwrap(),
                    Some(("image/png".to_string(), vec![1, 2, 3]))
                );

                // The same CID under a different DID is a separate entry.
                assert_eq!(
                    s.get_blob("did:plc:other", "cid1").await.unwrap(),
                    None,
                    "blobs are scoped per account"
                );

                // Re-uploading replaces rather than erroring.
                s.put_blob("did:plc:b", "cid1", "image/jpeg", 2, vec![9, 9])
                    .await
                    .unwrap();
                assert_eq!(
                    s.get_blob("did:plc:b", "cid1").await.unwrap(),
                    Some(("image/jpeg".to_string(), vec![9, 9]))
                );
            }

            // --- OAuth: pushed authorization requests ---------------------

            fn par(hash: &str, expires_at: u64) -> StoredPushedRequest {
                StoredPushedRequest {
                    request_uri_hash: hash.into(),
                    client_id: "https://app.test/client-metadata.json".into(),
                    redirect_uri: "https://app.test/cb".into(),
                    scope: "atproto".into(),
                    state: "st".into(),
                    code_challenge: "chal".into(),
                    dpop_jkt: Some("jkt".into()),
                    login_hint: None,
                    expires_at,
                }
            }

            #[tokio::test]
            async fn pushed_request_round_trip_and_expiry() {
                let (s, _g) = $setup().await;
                assert_eq!(s.get_pushed_request("nope", 100).await.unwrap(), None);

                s.put_pushed_request(par("h1", 1000)).await.unwrap();
                assert_eq!(
                    s.get_pushed_request("h1", 100).await.unwrap(),
                    Some(par("h1", 1000))
                );

                // Reads are repeatable — the login page may be loaded more than
                // once before a decision is made.
                assert!(s.get_pushed_request("h1", 100).await.unwrap().is_some());

                // Expired requests are invisible.
                assert_eq!(
                    s.get_pushed_request("h1", 1001).await.unwrap(),
                    None,
                    "an expired pushed request must not be returned"
                );

                s.delete_pushed_request("h1").await.unwrap();
                assert_eq!(s.get_pushed_request("h1", 100).await.unwrap(), None);
            }

            // --- OAuth: authorization codes -------------------------------

            fn code(hash: &str, expires_at: u64) -> AuthCode {
                AuthCode {
                    code_hash: hash.into(),
                    did: "did:plc:user".into(),
                    client_id: "https://app.test/client-metadata.json".into(),
                    redirect_uri: "https://app.test/cb".into(),
                    scope: "atproto".into(),
                    code_challenge: "chal".into(),
                    dpop_jkt: Some("jkt".into()),
                    expires_at,
                }
            }

            #[tokio::test]
            async fn auth_code_is_single_use() {
                let (s, _g) = $setup().await;
                s.put_auth_code(code("c1", 1000)).await.unwrap();

                assert_eq!(
                    s.consume_auth_code("c1", 100).await.unwrap(),
                    Some(code("c1", 1000))
                );
                assert_eq!(
                    s.consume_auth_code("c1", 100).await.unwrap(),
                    None,
                    "an authorization code must never be redeemable twice"
                );
            }

            #[tokio::test]
            async fn expired_and_unknown_auth_codes_are_not_redeemable() {
                let (s, _g) = $setup().await;
                assert_eq!(
                    s.consume_auth_code("never-issued", 100).await.unwrap(),
                    None
                );

                s.put_auth_code(code("c2", 500)).await.unwrap();
                assert_eq!(
                    s.consume_auth_code("c2", 501).await.unwrap(),
                    None,
                    "an expired code must not be redeemable"
                );
            }

            /// Concurrent redemptions of one code: exactly one may succeed.
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn concurrent_auth_code_redemption_yields_one_winner() {
                let (s, _g) = $setup().await;
                s.put_auth_code(code("race", 1_000_000)).await.unwrap();

                let mut tasks = Vec::new();
                for _ in 0..8 {
                    let s = s.clone();
                    tasks.push(tokio::spawn(async move {
                        s.consume_auth_code("race", 100).await.unwrap().is_some()
                    }));
                }
                let mut wins = 0;
                for t in tasks {
                    if t.await.unwrap() {
                        wins += 1;
                    }
                }
                assert_eq!(wins, 1, "exactly one concurrent redemption may succeed");
            }

            // --- OAuth: refresh tokens ------------------------------------

            fn refresh(hash: &str, session: &str, expires_at: u64) -> RefreshTokenRecord {
                RefreshTokenRecord {
                    token_hash: hash.into(),
                    session_id: session.into(),
                    did: "did:plc:user".into(),
                    client_id: "https://app.test/client-metadata.json".into(),
                    scope: "atproto".into(),
                    dpop_jkt: "jkt".into(),
                    issued_at: 100,
                    expires_at,
                }
            }

            #[tokio::test]
            async fn refresh_token_rotation_detects_reuse() {
                let (s, _g) = $setup().await;
                s.put_refresh_token(refresh("r1", "sess-1", 1000))
                    .await
                    .unwrap();

                match s.consume_refresh_token("r1", 200).await.unwrap() {
                    ConsumeResult::Consumed(rec) => assert_eq!(rec.session_id, "sess-1"),
                    other => panic!("first use must consume, got {other:?}"),
                }

                // Presenting it again must report reuse, not absence — the
                // caller needs the session_id to revoke the whole chain.
                match s.consume_refresh_token("r1", 200).await.unwrap() {
                    ConsumeResult::Reused { session_id } => assert_eq!(session_id, "sess-1"),
                    other => panic!("a spent token must report Reused, got {other:?}"),
                }
            }

            #[tokio::test]
            async fn unknown_and_expired_refresh_tokens_are_not_found() {
                let (s, _g) = $setup().await;
                assert_eq!(
                    s.consume_refresh_token("nope", 200).await.unwrap(),
                    ConsumeResult::NotFound
                );

                s.put_refresh_token(refresh("r-exp", "s", 500))
                    .await
                    .unwrap();
                assert_eq!(
                    s.consume_refresh_token("r-exp", 501).await.unwrap(),
                    ConsumeResult::NotFound,
                    "an expired token is NotFound, not Reused"
                );
            }

            #[tokio::test]
            async fn revoking_a_session_kills_every_token_in_the_chain() {
                let (s, _g) = $setup().await;
                s.put_refresh_token(refresh("a1", "sess-a", 1000))
                    .await
                    .unwrap();
                s.put_refresh_token(refresh("a2", "sess-a", 1000))
                    .await
                    .unwrap();
                s.put_refresh_token(refresh("b1", "sess-b", 1000))
                    .await
                    .unwrap();

                assert_eq!(s.revoke_session("sess-a").await.unwrap(), 2);
                assert_eq!(
                    s.consume_refresh_token("a2", 200).await.unwrap(),
                    ConsumeResult::NotFound
                );
                // An unrelated chain survives.
                assert!(matches!(
                    s.consume_refresh_token("b1", 200).await.unwrap(),
                    ConsumeResult::Consumed(_)
                ));
            }

            #[tokio::test]
            async fn revoking_one_token_revokes_its_chain() {
                let (s, _g) = $setup().await;
                s.put_refresh_token(refresh("c1", "sess-c", 1000))
                    .await
                    .unwrap();
                s.put_refresh_token(refresh("c2", "sess-c", 1000))
                    .await
                    .unwrap();

                assert!(s.revoke_refresh_token("c1").await.unwrap());
                assert_eq!(
                    s.consume_refresh_token("c2", 200).await.unwrap(),
                    ConsumeResult::NotFound,
                    "revoking one token must end the whole session"
                );
                assert!(
                    !s.revoke_refresh_token("never-issued").await.unwrap(),
                    "revoking an unknown token reports false, not an error"
                );
            }

            #[tokio::test]
            async fn list_sessions_shows_only_live_unused_tokens_for_the_did() {
                let (s, _g) = $setup().await;
                s.put_refresh_token(refresh("l1", "s1", 1000))
                    .await
                    .unwrap();
                s.put_refresh_token(refresh("l2", "s2", 1000))
                    .await
                    .unwrap();

                let mut other = refresh("l3", "s3", 1000);
                other.did = "did:plc:someone-else".into();
                s.put_refresh_token(other).await.unwrap();

                let sessions = s.list_sessions_for_did("did:plc:user", 200).await.unwrap();
                assert_eq!(sessions.len(), 2, "only this DID's sessions");

                // A spent token drops out of the listing.
                s.consume_refresh_token("l1", 200).await.unwrap();
                assert_eq!(
                    s.list_sessions_for_did("did:plc:user", 200)
                        .await
                        .unwrap()
                        .len(),
                    1
                );
                // As does an expired one.
                assert_eq!(
                    s.list_sessions_for_did("did:plc:user", 5000)
                        .await
                        .unwrap()
                        .len(),
                    0
                );
            }

            // --- OAuth: DPoP replay cache ---------------------------------

            #[tokio::test]
            async fn dpop_jti_is_recorded_once() {
                let (s, _g) = $setup().await;
                assert!(s.record_dpop_jti("jti-1", 1000).await.unwrap());
                assert!(
                    !s.record_dpop_jti("jti-1", 1000).await.unwrap(),
                    "a repeated jti must report replay"
                );
                assert!(s.record_dpop_jti("jti-2", 1000).await.unwrap());
            }

            /// The replay check must hold under real concurrency — a
            /// check-then-insert split would let several callers all win.
            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn concurrent_dpop_jti_yields_one_winner() {
                let (s, _g) = $setup().await;
                let mut tasks = Vec::new();
                for _ in 0..8 {
                    let s = s.clone();
                    tasks.push(tokio::spawn(async move {
                        s.record_dpop_jti("contended", 1_000_000).await.unwrap()
                    }));
                }
                let mut wins = 0;
                for t in tasks {
                    if t.await.unwrap() {
                        wins += 1;
                    }
                }
                assert_eq!(wins, 1, "exactly one caller may record a given jti");
            }

            // --- OAuth: maintenance ---------------------------------------

            #[tokio::test]
            async fn purge_removes_only_expired_records() {
                let (s, _g) = $setup().await;
                s.put_pushed_request(par("p-old", 100)).await.unwrap();
                s.put_pushed_request(par("p-new", 9999)).await.unwrap();
                s.put_auth_code(code("c-old", 100)).await.unwrap();
                s.put_auth_code(code("c-new", 9999)).await.unwrap();
                s.put_refresh_token(refresh("r-old", "s", 100))
                    .await
                    .unwrap();
                s.put_refresh_token(refresh("r-new", "s", 9999))
                    .await
                    .unwrap();
                s.record_dpop_jti("j-old", 100).await.unwrap();
                s.record_dpop_jti("j-new", 9999).await.unwrap();

                assert_eq!(s.purge_expired(500).await.unwrap(), 4, "four expired rows");

                assert!(s.get_pushed_request("p-new", 500).await.unwrap().is_some());
                assert!(s.consume_auth_code("c-new", 500).await.unwrap().is_some());
                assert!(matches!(
                    s.consume_refresh_token("r-new", 500).await.unwrap(),
                    ConsumeResult::Consumed(_)
                ));
                // A purged jti is free to be used again — which is correct, since
                // it can no longer be inside any proof's acceptance window.
                assert!(s.record_dpop_jti("j-old", 9999).await.unwrap());
                assert!(!s.record_dpop_jti("j-new", 9999).await.unwrap());
            }
        }
    };
}
