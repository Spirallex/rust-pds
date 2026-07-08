use std::sync::Arc;

use atrium_api::types::string::Did;
use atrium_crypto::keypair::Secp256k1Keypair;
use atrium_repo::blockstore::DiffBlockStore;
use atrium_repo::Repository;
use cid::Cid;
use ipld_core::ipld::Ipld;
use tokio::sync::Mutex;

use crate::repo::RepoError;
use crate::storage::SqliteStore;

/// Minimal typed repo writer. Phase 3's createRecord handler calls this.
/// Stateless across calls: re-opens the repo from the stored root CID each time.
///
/// `write_lock` serialises the full load_repo_root → build → commit cycle so that
/// concurrent `create_record` calls for the same DID cannot interleave and produce
/// a forked history (WR-01). The lock is an Arc so callers can share a single
/// `RepoWriter` across tasks while still preserving per-DID sequencing.
pub struct RepoWriter {
    pub(crate) store: Arc<SqliteStore>,
    pub(crate) signing_key: Secp256k1Keypair,
    pub(crate) did: Did,
    /// Logical per-writer serialisation lock. Held for the entire
    /// load → open → sign → commit_blocks sequence in `create_record`.
    pub(crate) write_lock: Arc<Mutex<()>>,
    /// Broadcast sender for publishing the encoded #commit frame after commit.
    pub(crate) firehose_tx: tokio::sync::broadcast::Sender<crate::firehose::FirehoseEvent>,
}

/// A single repo mutation for [`RepoWriter::apply_one`].
///
/// `key` is the full MST key (`collection/rkey`). Create and Update carry the
/// decoded record; Delete carries only the key.
pub enum WriteOp {
    Create { key: String, record: Ipld },
    Update { key: String, record: Ipld },
    Delete { key: String },
}

/// Outcome of a single applied write: the firehose op action, the MST key,
/// the new record CID (None for deletes), and the resulting commit CID + rev.
pub struct WriteOutcome {
    pub action: &'static str,
    pub key: String,
    pub record_cid: Option<Cid>,
    pub commit_cid: Cid,
    pub rev: String,
}

impl RepoWriter {
    pub fn new(
        store: Arc<SqliteStore>,
        signing_key: Secp256k1Keypair,
        did: Did,
        firehose_tx: tokio::sync::broadcast::Sender<crate::firehose::FirehoseEvent>,
    ) -> Self {
        Self {
            store,
            signing_key,
            did,
            write_lock: Arc::new(Mutex::new(())),
            firehose_tx,
        }
    }

    /// Like `new`, but shares an externally-supplied write_lock instead of creating a fresh one.
    /// Used by the server's per-DID lock map so that multiple RepoWriter instances constructed
    /// for the same DID across concurrent requests serialize their writes through one lock,
    /// preventing two concurrent commits from forking the repo history.
    pub fn with_lock(
        store: Arc<SqliteStore>,
        signing_key: Secp256k1Keypair,
        did: Did,
        firehose_tx: tokio::sync::broadcast::Sender<crate::firehose::FirehoseEvent>,
        write_lock: Arc<tokio::sync::Mutex<()>>,
    ) -> Self {
        Self {
            store,
            signing_key,
            did,
            write_lock,
            firehose_tx,
        }
    }

    /// Create a record, atomically persist all new blocks + the repo_seq row,
    /// and update the stored root CID. Returns (record_cid, commit_cid).
    ///
    /// Thin wrapper over [`Self::apply_one`] for the common create path.
    pub async fn create_record(&self, key: &str, record: Ipld) -> Result<(Cid, Cid), RepoError> {
        let outcome = self
            .apply_one(WriteOp::Create {
                key: key.to_string(),
                record,
            })
            .await?;
        Ok((
            outcome
                .record_cid
                .expect("create op always yields a record cid"),
            outcome.commit_cid,
        ))
    }

    /// Apply a single create/update/delete to the repo as one signed commit,
    /// atomically persist all new blocks + the repo_seq row, update the stored
    /// root CID, and publish the #commit frame to the firehose.
    ///
    /// The full read-modify-commit cycle is serialised by `write_lock` so that
    /// two concurrent callers for the same DID cannot fork the commit history.
    pub async fn apply_one(&self, op: WriteOp) -> Result<WriteOutcome, RepoError> {
        // Acquire the per-writer logical lock FIRST, before touching repo state.
        // Held until the end of this function — guarantees load → commit is atomic
        // at the application level even when the SQLite writer lock is released
        // between individual operations.
        let _guard = self.write_lock.lock().await;
        // Clone the store handle (Arc bump — cheap, shares the underlying writer mutex + pool).
        let cloned_store = (*self.store).clone();
        // Wrap in DiffBlockStore so we track which CIDs are new this session.
        // DiffBlockStore<SqliteStore> delegates reads and writes to SqliteStore;
        // write_block does INSERT OR IGNORE (idempotent).
        let mut diff = DiffBlockStore::wrap(cloned_store);

        // Open or create the repo. Pass &mut diff so Repository borrows diff by &mut,
        // leaving diff owned by this function for recovery after the borrow ends.
        let maybe_root = self.store.load_repo_root(self.did.as_str()).await?;
        // Track whether a prior committed root existed BEFORE this call, so we can
        // determine the `since` field (None on first user write, prev commit's rev otherwise).
        let had_prior_root = maybe_root.is_some();

        let mut repo = match maybe_root {
            Some(root) => {
                // Subsequent write: open from the stored commit CID (reads one block from SQLite).
                Repository::open(&mut diff, root)
                    .await
                    .map_err(|e| RepoError::Repo(e.to_string()))?
            }
            None => {
                // First write: create an empty repo (writes empty MST node + initial commit block).
                let builder = Repository::create(&mut diff, self.did.clone())
                    .await
                    .map_err(|e| RepoError::Repo(e.to_string()))?;
                let sig = self
                    .signing_key
                    .sign(&builder.bytes())
                    .map_err(|e| RepoError::Crypto(e.to_string()))?;
                builder
                    .finalize(sig)
                    .await
                    .map_err(|e| RepoError::Repo(e.to_string()))?
            }
        };

        // Capture the current commit CID BEFORE mutating so we can set `prev` on the
        // new commit. This is the ATProto requirement: every commit must chain from the
        // previous one via the `prev` field, forming a linear history.
        let prev_cid = repo.root();

        // Apply the requested mutation through the appropriate atrium-repo op.
        // Each op encodes the record (if any), mutates the MST, and yields a
        // CommitBuilder reflecting the new root. We then chain `prev`, sign, and
        // finalize into a single signed commit. `action`/`record_cid` feed the
        // firehose #commit op below ("create"/"update"/"delete").
        let (action, key, record_cid, commit_cid): (&'static str, String, Option<Cid>, Cid) =
            match op {
                WriteOp::Create { key, record } => {
                    let (mut cb, cid) = repo
                        .add_raw(&key, record)
                        .await
                        .map_err(|e| RepoError::Repo(e.to_string()))?;
                    cb.prev(prev_cid);
                    let sig = self
                        .signing_key
                        .sign(&cb.bytes())
                        .map_err(|e| RepoError::Crypto(e.to_string()))?;
                    let commit_cid = cb
                        .finalize(sig)
                        .await
                        .map_err(|e| RepoError::Repo(e.to_string()))?;
                    ("create", key, Some(cid), commit_cid)
                }
                WriteOp::Update { key, record } => {
                    let (mut cb, cid) = repo
                        .update_raw(&key, record)
                        .await
                        .map_err(|e| RepoError::Repo(e.to_string()))?;
                    cb.prev(prev_cid);
                    let sig = self
                        .signing_key
                        .sign(&cb.bytes())
                        .map_err(|e| RepoError::Crypto(e.to_string()))?;
                    let commit_cid = cb
                        .finalize(sig)
                        .await
                        .map_err(|e| RepoError::Repo(e.to_string()))?;
                    ("update", key, Some(cid), commit_cid)
                }
                WriteOp::Delete { key } => {
                    let mut cb = repo
                        .delete_raw(&key)
                        .await
                        .map_err(|e| RepoError::Repo(e.to_string()))?;
                    cb.prev(prev_cid);
                    let sig = self
                        .signing_key
                        .sign(&cb.bytes())
                        .map_err(|e| RepoError::Crypto(e.to_string()))?;
                    let commit_cid = cb
                        .finalize(sig)
                        .await
                        .map_err(|e| RepoError::Repo(e.to_string()))?;
                    ("delete", key, None, commit_cid)
                }
            };

        // BORROW ORDER (critical — borrow checker requires this sequence):
        // 1. drop(repo) — releases the &mut borrow on diff held by Repository<&mut DiffBlockStore<_>>
        // 2. diff.blocks().collect() — safe only after repo is dropped (&self borrow on diff)
        // 3. diff.into_inner() — consumes diff, recovers the cloned SqliteStore handle
        drop(repo);
        let new_cids: Vec<Cid> = diff.blocks().collect();
        let inner = diff.into_inner();

        // Read back the bytes for each new CID. They are already in SQLite from the
        // individual write_block calls (INSERT OR IGNORE is idempotent).
        let mut blocks = Vec::with_capacity(new_cids.len());
        for cid in new_cids {
            let bytes = inner.read_block_bytes(cid).await?;
            blocks.push((cid, bytes));
        }

        // Build the CARv1 bytes in-memory BEFORE the txn (borrow &blocks before move).
        // Root MUST be commit_cid (Pitfall 7 — relay checks the CAR root).
        use iroh_car::{CarHeader, CarWriter};
        let car_header = CarHeader::new_v1(vec![commit_cid]);
        let mut car_buf: Vec<u8> = Vec::new();
        let mut car_writer = CarWriter::new(car_header, &mut car_buf);
        for (cid, bytes) in &blocks {
            car_writer
                .write(*cid, bytes)
                .await
                .map_err(|e| RepoError::Repo(e.to_string()))?;
        }
        car_writer
            .finish()
            .await
            .map_err(|e| RepoError::Repo(e.to_string()))?;

        // Determine `rev` and `since` by decoding the just-written commit block.
        // CommitBuilder does not expose rev/prev publicly, so we decode the stored block.
        use serde::Deserialize;
        // Only `rev` is read; `serde_ipld_dagcbor::from_slice` ignores extra map keys
        // (including `prev`), so the header struct needs only the field we use.
        #[derive(Deserialize)]
        struct CommitHeader {
            rev: atrium_api::types::string::Tid,
        }

        let commit_block_bytes = inner.read_block_bytes(commit_cid).await?;
        let commit_header: CommitHeader = serde_ipld_dagcbor::from_slice(&commit_block_bytes)
            .map_err(|e| RepoError::Repo(format!("decode commit block for rev/prev: {e}")))?;
        let rev = commit_header.rev.as_ref().to_string();

        // `since` = rev of the previous commit, or None on the first user write.
        // `prev_cid` is always a Cid (never None), but `had_prior_root` tells us
        // whether a previously-committed root existed before this call.
        let since: Option<String> = if had_prior_root {
            let prev_bytes = inner.read_block_bytes(prev_cid).await?;
            let prev_header: CommitHeader = serde_ipld_dagcbor::from_slice(&prev_bytes)
                .map_err(|e| RepoError::Repo(format!("decode prev commit block for since: {e}")))?;
            Some(prev_header.rev.as_ref().to_string())
        } else {
            None
        };

        // Build the #commit body. seq=0 is a placeholder — Plan 05's backfill path
        // decodes this blob and injects the real seq from repo_seq.seq at stream time.
        // The broadcast publish below injects the real seq before sending on the wire.
        use crate::firehose::{encode_message_frame, CommitBody, FirehoseEvent, RepoOp};
        let ops = vec![RepoOp {
            action: action.to_string(),
            path: key.clone(),
            cid: record_cid,
        }];
        let time = chrono::Utc::now().to_rfc3339();
        let mut body = CommitBody {
            seq: 0,
            rebase: false,
            too_big: false,
            repo: self.did.as_str().to_string(),
            commit: commit_cid,
            rev: rev.clone(),
            since,
            blocks: car_buf,
            ops,
            blobs: vec![],
            time,
            prev_data: None,
        };
        let event_body = serde_ipld_dagcbor::to_vec(&body)
            .map_err(|e| RepoError::Repo(format!("encode event body: {e}")))?;

        // ONE atomic transaction: INSERT OR IGNORE all blocks + INSERT one repo_seq row
        // + UPDATE repo_roots — all three writes are now committed or rolled back together.
        // `blocks` is moved into commit_blocks here (CAR was built from &blocks above).
        let seq = self
            .store
            .commit_blocks(blocks, self.did.as_str(), commit_cid, event_body)
            .await?;

        // Build the full frame with the real seq and publish to the broadcast channel.
        // Err (no subscribers) is intentionally ignored — not a fault (RESEARCH line 457).
        body.seq = seq;
        let frame = encode_message_frame("#commit", &body);
        let _ = self.firehose_tx.send(FirehoseEvent { seq, frame });

        Ok(WriteOutcome {
            action,
            key,
            record_cid,
            commit_cid,
            rev,
        })
    }

    /// Return the current MST root CID for the repo, by opening the repo from
    /// the stored root and reading `repo.commit().data()`. Returns None if no
    /// commits have been written yet.
    pub async fn current_mst_root(&self) -> Result<Option<Cid>, RepoError> {
        let root = match self.store.load_repo_root(self.did.as_str()).await? {
            None => return Ok(None),
            Some(r) => r,
        };
        // Open is read-only; wrap the store so reads hit SQLite. No new writes occur.
        let cloned_store = (*self.store).clone();
        let mut diff = DiffBlockStore::wrap(cloned_store);
        let repo = Repository::open(&mut diff, root)
            .await
            .map_err(|e| RepoError::Repo(e.to_string()))?;
        // commit().data() returns the MST root CID (Cid is Copy in cid 0.11).
        let mst_root = repo.commit().data();
        Ok(Some(mst_root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::keys::{load_key, store_key};
    use atrium_crypto::keypair::{Did as _, Secp256k1Keypair};
    use atrium_crypto::verify::verify_signature;
    use ipld_core::ipld::Ipld;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    const SIGNING_SCALAR: [u8; 32] = [0x11u8; 32];

    fn post(text: &str) -> Ipld {
        let mut m = BTreeMap::new();
        m.insert(
            "$type".to_string(),
            Ipld::String("app.bsky.feed.post".into()),
        );
        m.insert("text".to_string(), Ipld::String(text.into()));
        m.insert(
            "createdAt".to_string(),
            Ipld::String("2026-06-16T00:00:00.000Z".into()),
        );
        Ipld::Map(m)
    }

    async fn writer_with_store() -> (
        RepoWriter,
        SqliteStore,
        tempfile::NamedTempFile,
        tokio::sync::broadcast::Receiver<crate::firehose::FirehoseEvent>,
    ) {
        let (store, tmp) = SqliteStore::open_in_memory().await.expect("open");
        let passphrase = b"test-signing-passphrase";
        store_key(&store, "signing", &SIGNING_SCALAR, passphrase)
            .await
            .expect("store_key");
        let scalar = load_key(&store, "signing", passphrase)
            .await
            .expect("load_key");
        let key = Secp256k1Keypair::import(&scalar).expect("import key");
        let did = Did::from_str("did:web:example.com").unwrap();
        let store_arc = Arc::new(store.clone());
        let (tx, rx) = tokio::sync::broadcast::channel(16);
        let writer = RepoWriter::new(store_arc, key, did, tx);
        (writer, store, tmp, rx)
    }

    use serde::{Deserialize, Serialize};

    /// Local mirror of atrium's private schema::SignedCommit for deserialization
    /// of stored commit blocks. Fields must match the wire format exactly.
    #[derive(Deserialize)]
    struct SignedCommit {
        pub did: Did,
        pub version: i64,
        pub data: Cid,
        pub rev: atrium_api::types::string::Tid,
        pub prev: Option<Cid>,
        #[serde(with = "serde_bytes")]
        pub sig: Vec<u8>,
    }

    /// Reconstruct the unsigned Commit bytes (all fields except `sig`) by
    /// re-serializing the non-sig fields as a Commit struct. This mirrors what
    /// atrium's CommitBuilder::bytes() does internally.
    fn reconstruct_unsigned_commit_bytes(signed: &SignedCommit) -> Vec<u8> {
        #[derive(Serialize)]
        struct Commit {
            did: Did,
            version: i64,
            data: Cid,
            rev: atrium_api::types::string::Tid,
            prev: Option<Cid>,
        }
        let commit = Commit {
            did: signed.did.clone(),
            version: signed.version,
            data: signed.data,
            rev: signed.rev.clone(),
            prev: signed.prev,
        };
        serde_ipld_dagcbor::to_vec(&commit).expect("serialize Commit")
    }

    /// REPO-01: create_record produces a signed commit; the STORED commit block's
    /// signature verifies against the signer's did:key.
    #[tokio::test]
    async fn signed_commit_signature_verifies() {
        let (writer, store, _tmp, _rx) = writer_with_store().await;
        let (record_cid, commit_cid) = writer
            .create_record("app.bsky.feed.post/3kaaaa", post("hi"))
            .await
            .expect("create_record must succeed");
        assert_ne!(record_cid, commit_cid, "record and commit CIDs must differ");

        // Read the REAL stored commit block and verify its signature against the did:key.
        let bytes = store
            .read_block_bytes(commit_cid)
            .await
            .expect("commit block stored");
        let signed: SignedCommit =
            serde_ipld_dagcbor::from_slice(&bytes).expect("decode SignedCommit");
        let unsigned = reconstruct_unsigned_commit_bytes(&signed);
        let key = Secp256k1Keypair::import(&SIGNING_SCALAR).unwrap();
        verify_signature(&key.did(), &unsigned, &signed.sig)
            .expect("stored commit signature must verify against signer did:key");
    }

    /// REPO-02: a record survives write -> SQLite -> read unchanged.
    #[tokio::test]
    async fn record_roundtrips_through_mst() {
        let (writer, _store, _tmp, _rx) = writer_with_store().await;
        let original = post("round trip me");
        let (record_cid, _commit) = writer
            .create_record("app.bsky.feed.post/3kaaaa", original.clone())
            .await
            .expect("create_record");
        // Read the record block straight back from SQLite and decode.
        let bytes = writer
            .store
            .read_block_bytes(record_cid)
            .await
            .expect("read block");
        let got: Ipld = serde_ipld_dagcbor::from_slice(&bytes).expect("decode dag-cbor");
        assert_eq!(
            got, original,
            "record did not survive write -> SQLite -> read"
        );
    }

    /// REPO-03: building the same record set in two different orders yields the
    /// same MST root CID.
    #[tokio::test]
    async fn mst_root_is_insertion_order_independent() {
        async fn root_for(order: &[(&str, &str)]) -> Cid {
            let (writer, _store, _tmp, _rx) = writer_with_store().await;
            for (k, t) in order {
                writer
                    .create_record(k, post(t))
                    .await
                    .expect("create_record");
            }
            writer
                .current_mst_root()
                .await
                .expect("root")
                .expect("has root")
        }
        let a = root_for(&[
            ("app.bsky.feed.post/3kaaaa", "one"),
            ("app.bsky.feed.post/3kbbbb", "two"),
            ("app.bsky.feed.post/3kcccc", "three"),
        ])
        .await;
        let b = root_for(&[
            ("app.bsky.feed.post/3kcccc", "three"),
            ("app.bsky.feed.post/3kaaaa", "one"),
            ("app.bsky.feed.post/3kbbbb", "two"),
        ])
        .await;
        assert_eq!(a, b, "MST root must be insertion-order independent");
    }

    /// REPO-01+03 (atomicity): exactly one repo_seq row is produced per
    /// create_record call, even on the very first call (which also writes
    /// the empty-repo root commit).
    #[tokio::test]
    async fn create_record_produces_one_seq_row() {
        let (writer, store, _tmp, _rx) = writer_with_store().await;
        let before = store.repo_seq_count().await.expect("count");
        writer
            .create_record("app.bsky.feed.post/3kaaaa", post("hi"))
            .await
            .expect("create_record");
        let after = store.repo_seq_count().await.expect("count");
        assert_eq!(
            after - before,
            1,
            "one create_record must produce exactly one repo_seq row"
        );
    }

    /// WR-01: two concurrent create_record calls for the same DID must produce a
    /// linear commit chain — no forked history. Verified by asserting:
    ///   1. Both commits are reachable from the final repo_roots entry.
    ///   2. The repo_seq table has exactly two rows (no lost update).
    ///   3. Each commit's `prev` field forms a chain: commit2.prev == commit1 (or vice versa).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_create_record_produces_linear_chain() {
        let (writer, store, _tmp, _rx) = writer_with_store().await;
        let writer = Arc::new(writer);

        let w1 = writer.clone();
        let w2 = writer.clone();

        // Fire two concurrent create_record calls. The write_lock ensures they
        // are serialised at the application level, so one must fully complete
        // before the other begins its load_repo_root.
        let t1 = tokio::spawn(async move {
            w1.create_record("app.bsky.feed.post/3kaaaa", post("concurrent first"))
                .await
                .expect("create_record 1")
        });
        let t2 = tokio::spawn(async move {
            w2.create_record("app.bsky.feed.post/3kbbbb", post("concurrent second"))
                .await
                .expect("create_record 2")
        });

        let (r1, r2) = tokio::join!(t1, t2);
        let (_rec1, commit1) = r1.expect("task 1 panicked");
        let (_rec2, commit2) = r2.expect("task 2 panicked");

        // Both commits must be distinct.
        assert_ne!(
            commit1, commit2,
            "two creates must produce different commit CIDs"
        );

        // Exactly two repo_seq rows — no lost update.
        let seq_count = store.repo_seq_count().await.expect("seq count");
        assert_eq!(
            seq_count, 2,
            "expected exactly 2 repo_seq rows, got {}",
            seq_count
        );

        // The final repo_roots must point to one of the two commit CIDs.
        let final_root = store
            .load_repo_root("did:web:example.com")
            .await
            .expect("load_repo_root")
            .expect("must have a root after two writes");
        assert!(
            final_root == commit1 || final_root == commit2,
            "repo_roots must point to one of the two commit CIDs, got {:?}",
            final_root
        );

        // The commit that is NOT the final root must be the `prev` of the final root.
        // Read the final commit block and check its `prev`.
        let final_bytes = store
            .read_block_bytes(final_root)
            .await
            .expect("read final commit block");
        let final_commit: SignedCommit =
            serde_ipld_dagcbor::from_slice(&final_bytes).expect("decode final commit");

        let expected_prev = if final_root == commit1 {
            commit2
        } else {
            commit1
        };
        assert_eq!(
            final_commit.prev,
            Some(expected_prev),
            "final commit's prev must point to the other commit, forming a linear chain"
        );
    }

    /// FED-01 (stored event): the repo_seq event BLOB decodes to a #commit body
    /// whose `commit` == the returned commit CID, `repo` == the writer DID,
    /// and `ops` path == the MST key (collection/rkey), action == "create".
    #[tokio::test]
    async fn create_record_stores_real_commit_event() {
        let (writer, store, _tmp, _rx) = writer_with_store().await;
        let mst_key = "app.bsky.feed.post/3kaaaa";
        let (record_cid, commit_cid) = writer
            .create_record(mst_key, post("event body test"))
            .await
            .expect("create_record");

        // Read the stored event BLOB from the last repo_seq row.
        let event_blob = store
            .last_event_body()
            .await
            .expect("last_event_body")
            .expect("event BLOB must be present after create_record");

        // Decode the DAG-CBOR event body into CommitBody.
        let body: crate::firehose::CommitBody =
            serde_ipld_dagcbor::from_slice(&event_blob).expect("decode CommitBody from event blob");

        assert_eq!(
            body.commit, commit_cid,
            "CommitBody.commit must equal commit_cid"
        );
        assert_eq!(
            body.repo, "did:web:example.com",
            "CommitBody.repo must equal writer DID"
        );
        assert_eq!(body.ops.len(), 1, "must have exactly one op");
        assert_eq!(body.ops[0].action, "create", "op action must be 'create'");
        assert_eq!(
            body.ops[0].path, mst_key,
            "op path must be the full MST key"
        );
        assert_eq!(
            body.ops[0].cid,
            Some(record_cid),
            "op cid must equal record_cid"
        );

        // CAR blocks must decode with root == commit_cid.
        use iroh_car::CarReader;
        let cursor = tokio::io::BufReader::new(std::io::Cursor::new(body.blocks));
        let reader = CarReader::new(cursor)
            .await
            .expect("CAR blocks must be valid CARv1");
        let header = reader.header().clone();
        assert_eq!(
            header.roots(),
            &[commit_cid],
            "CAR root must be commit_cid (Pitfall 7)"
        );
    }

    /// FED-01 (broadcast): a subscriber created before create_record receives exactly
    /// one FirehoseEvent whose `seq` matches the seq returned by commit_blocks, and
    /// whose `frame` decodes to a #commit with the injected seq.
    #[tokio::test]
    async fn create_record_publishes_to_broadcast() {
        let (writer, _store, _tmp, mut rx) = writer_with_store().await;

        let (_record_cid, _commit_cid) = writer
            .create_record("app.bsky.feed.post/3kaaaa", post("broadcast test"))
            .await
            .expect("create_record");

        // The broadcast channel must have received exactly one event.
        let event = rx
            .try_recv()
            .expect("FirehoseEvent must be published to broadcast channel");

        // seq must be positive (autoincrement starts at 1).
        assert!(event.seq > 0, "seq must be positive, got {}", event.seq);

        // The frame must decode as header + body with the injected seq.
        use std::io::{BufReader, Cursor};
        let mut buf_reader = BufReader::new(Cursor::new(&event.frame[..]));
        let header: ipld_core::ipld::Ipld =
            serde_ipld_dagcbor::de::from_reader_once(&mut buf_reader)
                .expect("frame header must decode as CBOR");
        if let ipld_core::ipld::Ipld::Map(map) = &header {
            assert_eq!(
                map.get("op"),
                Some(&ipld_core::ipld::Ipld::Integer(1)),
                "frame header op must be 1"
            );
            assert_eq!(
                map.get("t"),
                Some(&ipld_core::ipld::Ipld::String("#commit".to_string())),
                "frame header t must be #commit"
            );
        } else {
            panic!("frame header must be an IPLD map");
        }
        let body: crate::firehose::CommitBody =
            serde_ipld_dagcbor::de::from_reader_once(&mut buf_reader)
                .expect("frame body must decode as CommitBody");
        assert_eq!(
            body.seq, event.seq,
            "CommitBody.seq must equal FirehoseEvent.seq"
        );
    }
}
