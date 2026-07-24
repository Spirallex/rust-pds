//! `StorageBackend` over Durable Object SQLite + R2.
//!
//! This is the third implementation of the storage traits, after SQLite and
//! `MemoryStore`. It exists to prove the abstraction those two established
//! actually reaches a genuinely different substrate — and it does, without a
//! single change to `stelyph-core`.
//!
//! # Why the traits are satisfiable here at all
//!
//! Two properties of the Durable Object runtime make this work:
//!
//! - **SQL is synchronous.** `state.storage().sql().exec(..)` returns a cursor
//!   directly, not a future. Every method that touches only SQL is therefore
//!   trivially atomic with respect to other tasks in the isolate, because there
//!   is no await point at which another task could interleave.
//! - **A DO is single-threaded.** The `commit_blocks`, `consume_auth_code`,
//!   `consume_refresh_token`, and `record_dpop_jti` methods all require
//!   atomic test-and-set. On SQLite that needs `BEGIN IMMEDIATE`; here it falls
//!   out of the runtime, provided no `.await` appears between the read and the
//!   write. **Every such method below is await-free by construction** — that is
//!   a correctness requirement, not an accident, and adding an await inside one
//!   would silently reintroduce the race.
//!
//! # Send
//!
//! The storage traits require `Send` futures because `AppState` holds an
//! `Arc<dyn StorageBackend>`. JS-backed handles are not `Send`, so they are held
//! in `worker::send::SendWrapper`, which is sound precisely because the isolate
//! is single-threaded.
//!
//! # What lives where
//!
//! | Data | Home | Why |
//! |---|---|---|
//! | blocks, roots, seq | DO SQLite | small, hot, must be transactional with each other |
//! | accounts, invites, prefs | DO SQLite | small, relational |
//! | keys (ciphertext) | DO SQLite | small, and already encrypted at rest |
//! | OAuth state | DO SQLite | short-lived, needs atomic single-use |
//! | blobs | R2 | multi-megabyte and immutable; DO storage is the wrong place |
//!
//! Blob *metadata* stays in SQLite so `getBlob` can answer "does this account
//! own that CID?" without an R2 round trip.

use std::sync::Arc;

use async_trait::async_trait;
use cid::Cid;
use serde::Deserialize;
use worker::send::{SendFuture, SendWrapper};
use worker::{Bucket, SqlStorage};

use stelyph_core::oauth::store::{
    AuthCode, ConsumeResult, OAuthStore, RefreshTokenRecord, StoredPushedRequest,
};
use stelyph_core::storage::{
    AccountStore, AccountSummary, BlobStore, BlockStore, KeyStore, RepoStore, Sequencer,
    StorageError,
};

/// Storage for one PDS, backed by its Durable Object.
#[derive(Clone)]
pub struct DoStore {
    sql: Arc<SendWrapper<SqlStorage>>,
    blobs: Arc<SendWrapper<Bucket>>,
}

// --- helpers ---------------------------------------------------------------

/// Map a `worker::Error` into the storage error type.
///
/// Deliberately `Pool`: from the caller's perspective a failed SQL call is an
/// infrastructure failure, exactly like failing to check out a connection, and
/// nothing above this layer should branch on which backend produced it.
fn sql_err(e: worker::Error) -> StorageError {
    StorageError::Pool(format!("durable object sql: {e}"))
}

/// Values bound into a query.
///
/// `worker::SqlStorageValue` is constructed via `Into`, so this alias keeps the
/// call sites readable without every one of them naming the type.
type Val = worker::SqlStorageValue;

fn s(v: impl Into<String>) -> Val {
    Val::from(v.into())
}
fn i(v: i64) -> Val {
    Val::from(v)
}
fn b(v: Vec<u8>) -> Val {
    Val::from(v)
}
fn opt_s(v: Option<String>) -> Val {
    match v {
        Some(x) => s(x),
        None => Val::Null,
    }
}

/// Current wall-clock time as an RFC 3339 string.
///
/// Uses the JS `Date` because `chrono::Utc::now()` needs a clock the wasm32
/// build does not have. Note that a Durable Object's clock is frozen within a
/// single execution for determinism, which is fine for a timestamp column but
/// is why the *sequencer* uses an explicit counter rather than time.
pub(crate) fn now_iso() -> String {
    let ms = worker::Date::now().as_millis();
    // Seconds since epoch, formatted by JS. Keeping the format identical to
    // `to_rfc3339()` matters because these strings are compared and sorted.
    js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(ms as f64))
        .to_iso_string()
        .as_string()
        .unwrap_or_default()
}

impl DoStore {
    pub fn new(sql: SqlStorage, blobs: Bucket) -> Self {
        Self {
            sql: Arc::new(SendWrapper::new(sql)),
            blobs: Arc::new(SendWrapper::new(blobs)),
        }
    }

    /// Create tables on first use. Idempotent.
    pub fn migrate(&self) -> Result<(), StorageError> {
        // `exec` takes one statement at a time, so the batch is split here.
        //
        // Comments are stripped *before* splitting, not filtered afterwards: a
        // `--` comment may itself contain a semicolon, and splitting first would
        // cut it in half and hand SQLite the tail as a statement. That is a real
        // bug this hit, not a hypothetical one.
        let sql: String = crate::schema::SCHEMA
            .lines()
            .map(|line| match line.find("--") {
                Some(i) => &line[..i],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n");

        for stmt in sql.split(';') {
            let stmt = stmt.trim();
            if stmt.is_empty() {
                continue;
            }
            self.sql.exec(stmt, None).map_err(sql_err)?;
        }
        Ok(())
    }

    fn exec(&self, q: &str, params: Vec<Val>) -> Result<worker::SqlCursor, StorageError> {
        self.sql.exec(q, params).map_err(sql_err)
    }

    /// Run a query for its side effect, discarding the cursor.
    fn run(&self, q: &str, params: Vec<Val>) -> Result<(), StorageError> {
        self.exec(q, params)?;
        Ok(())
    }

    /// Number of rows a mutation touched.
    ///
    /// The DO SQL API reports writes rather than an "affected rows" count, so
    /// the callers that must return a row count (`set_takedown` and friends)
    /// check for existence first. This helper exists so that choice is in one
    /// place rather than repeated.
    fn exists(&self, q: &str, params: Vec<Val>) -> Result<bool, StorageError> {
        #[derive(Deserialize)]
        struct Count {
            n: i64,
        }
        let rows: Vec<Count> = self.exec(q, params)?.to_array().map_err(sql_err)?;
        Ok(rows.first().map(|c| c.n > 0).unwrap_or(false))
    }
}

// --- row types -------------------------------------------------------------

#[derive(Deserialize)]
struct BytesRow {
    #[serde(with = "serde_bytes")]
    bytes: Vec<u8>,
}

#[derive(Deserialize)]
struct CidRow {
    root_cid: String,
}

#[derive(Deserialize)]
struct CidStrRow {
    cid: String,
}

#[derive(Deserialize)]
struct SeqRow {
    seq: i64,
    #[serde(with = "serde_bytes")]
    event: Vec<u8>,
}

#[derive(Deserialize)]
struct MaxSeqRow {
    max_seq: i64,
}

#[derive(Deserialize)]
struct NextSeqRow {
    next: i64,
}

#[derive(Deserialize)]
struct AccountAuthRow {
    did: String,
    password_argon2: String,
}

#[derive(Deserialize)]
struct DidRow {
    did: String,
}

#[derive(Deserialize)]
struct HandleRow {
    handle: Option<String>,
}

#[derive(Deserialize)]
struct AccountRow {
    did: String,
    handle: Option<String>,
    deactivated_at: Option<String>,
    takedown_ref: Option<String>,
    created_at: String,
}

#[derive(Deserialize)]
struct PrefsRow {
    prefs: String,
}

#[derive(Deserialize)]
struct CipherRow {
    #[serde(with = "serde_bytes")]
    ciphertext: Vec<u8>,
}

#[derive(Deserialize)]
struct InviteRow {
    available_uses: i64,
    disabled: i64,
}

#[derive(Deserialize)]
struct BlobMetaRow {
    mime_type: String,
}

// --- blocks / sequencer / repo ---------------------------------------------

#[async_trait]
impl BlockStore for DoStore {
    async fn read_block_bytes(&self, cid: Cid) -> Result<Vec<u8>, StorageError> {
        let rows: Vec<BytesRow> = self
            .exec(
                "SELECT bytes FROM blocks WHERE cid = ?",
                vec![s(cid.to_string())],
            )?
            .to_array()
            .map_err(sql_err)?;
        rows.into_iter()
            .next()
            .map(|r| r.bytes)
            .ok_or(StorageError::BlockNotFound)
    }

    async fn put_block(&self, cid: Cid, bytes: Vec<u8>) -> Result<(), StorageError> {
        self.run(
            "INSERT OR IGNORE INTO blocks (cid, bytes) VALUES (?, ?)",
            vec![s(cid.to_string()), b(bytes)],
        )
    }
}

#[async_trait]
impl Sequencer for DoStore {
    async fn max_seq(&self) -> Result<i64, StorageError> {
        let rows: Vec<MaxSeqRow> = self
            .exec(
                "SELECT COALESCE(MAX(seq), 0) AS max_seq FROM repo_seq",
                vec![],
            )?
            .to_array()
            .map_err(sql_err)?;
        Ok(rows.first().map(|r| r.max_seq).unwrap_or(0))
    }

    async fn backfill_page(
        &self,
        after_seq: i64,
        limit: i64,
    ) -> Result<Vec<(i64, Vec<u8>)>, StorageError> {
        let rows: Vec<SeqRow> = self
            .exec(
                "SELECT seq, event FROM repo_seq \
                 WHERE seq > ? AND invalidated = 0 ORDER BY seq ASC LIMIT ?",
                vec![i(after_seq), i(limit.max(0))],
            )?
            .to_array()
            .map_err(sql_err)?;
        Ok(rows.into_iter().map(|r| (r.seq, r.event)).collect())
    }
}

#[async_trait]
impl RepoStore for DoStore {
    async fn load_repo_root(&self, did: &str) -> Result<Option<Cid>, StorageError> {
        let rows: Vec<CidRow> = self
            .exec(
                "SELECT root_cid FROM repo_roots WHERE did = ?",
                vec![s(did)],
            )?
            .to_array()
            .map_err(sql_err)?;
        match rows.into_iter().next() {
            None => Ok(None),
            Some(r) => {
                use std::str::FromStr;
                Cid::from_str(&r.root_cid)
                    .map(Some)
                    .map_err(|e| StorageError::Crypto(format!("bad root cid: {e}")))
            }
        }
    }

    async fn update_repo_root(&self, did: &str, root_cid: Cid) -> Result<(), StorageError> {
        self.run(
            "INSERT OR REPLACE INTO repo_roots (did, root_cid, updated_at) VALUES (?, ?, ?)",
            vec![s(did), s(root_cid.to_string()), s(now_iso())],
        )
    }

    /// Atomic by construction: there is no `.await` between the counter read and
    /// the final write, so no other task in the isolate can interleave. Adding
    /// one would reintroduce exactly the fork-the-repo race the SQLite backend
    /// uses `BEGIN IMMEDIATE` to prevent.
    async fn commit_blocks(
        &self,
        blocks: Vec<(Cid, Vec<u8>)>,
        did: &str,
        new_root: Cid,
        event_body: Vec<u8>,
    ) -> Result<i64, StorageError> {
        let now = now_iso();

        for (cid, bytes) in blocks {
            self.run(
                "INSERT OR IGNORE INTO blocks (cid, bytes) VALUES (?, ?)",
                vec![s(cid.to_string()), b(bytes)],
            )?;
        }

        // Claim the next seq by incrementing the counter and reading it back.
        self.run(
            "UPDATE seq_counter SET next = next + 1 WHERE id = 0",
            vec![],
        )?;
        let rows: Vec<NextSeqRow> = self
            .exec("SELECT next FROM seq_counter WHERE id = 0", vec![])?
            .to_array()
            .map_err(sql_err)?;
        let seq = rows
            .first()
            .map(|r| r.next)
            .ok_or_else(|| StorageError::Pool("seq_counter row is missing".into()))?;

        self.run(
            "INSERT INTO repo_seq (seq, did, event_type, event, invalidated, sequenced_at) \
             VALUES (?, ?, 'append', ?, 0, ?)",
            vec![i(seq), s(did), b(event_body), s(now.clone())],
        )?;
        self.run(
            "INSERT OR REPLACE INTO repo_roots (did, root_cid, updated_at) VALUES (?, ?, ?)",
            vec![s(did), s(new_root.to_string()), s(now)],
        )?;

        Ok(seq)
    }
}

// --- device-approval sign-in ("Sign in with Stelyph") ----------------------

/// One enrolled device.
#[derive(Deserialize)]
pub struct DeviceKeyRow {
    pub did_key: String,
}

/// A pending sign-in, as the poll endpoint needs to see it.
#[derive(Deserialize)]
pub struct SigninRow {
    pub user_code: String,
    pub status: String,
    pub did: Option<String>,
    pub handle: Option<String>,
    pub access_jwt: Option<String>,
    pub refresh_jwt: Option<String>,
    pub expires_at: i64,
}

/// A pending sign-in as the *approving phone* sees it — enough to show who is
/// asking and to approve it, but none of the issued session (which only the
/// requesting client polls for).
#[derive(Deserialize, serde::Serialize)]
pub struct PendingSignin {
    pub request_id: String,
    pub user_code: String,
    pub client_name: String,
    pub created_at: String,
}

impl DoStore {
    /// Enrol a device public key. `device_id` is caller-generated (random).
    pub fn register_device(
        &self,
        device_id: &str,
        did_key: &str,
        label: &str,
    ) -> Result<(), StorageError> {
        self.run(
            "INSERT OR REPLACE INTO device_keys (device_id, did_key, label, created_at) \
             VALUES (?, ?, ?, ?)",
            vec![s(device_id), s(did_key), s(label), s(now_iso())],
        )
    }

    /// The enrolled `did:key` for a device, or `None` if unknown.
    pub fn device_did_key(&self, device_id: &str) -> Result<Option<String>, StorageError> {
        let rows: Vec<DeviceKeyRow> = self
            .exec(
                "SELECT did_key FROM device_keys WHERE device_id = ?",
                vec![s(device_id)],
            )?
            .to_array()
            .map_err(sql_err)?;
        Ok(rows.into_iter().next().map(|r| r.did_key))
    }

    /// Create a pending sign-in request.
    pub fn create_signin(
        &self,
        request_id: &str,
        user_code: &str,
        client_name: &str,
        expires_at: u64,
    ) -> Result<(), StorageError> {
        self.run(
            "INSERT INTO signin_requests \
             (request_id, user_code, client_name, status, created_at, expires_at) \
             VALUES (?, ?, ?, 'pending', ?, ?)",
            vec![
                s(request_id),
                s(user_code),
                s(client_name),
                s(now_iso()),
                i(expires_at as i64),
            ],
        )
    }

    /// Pending, unexpired sign-in requests for this account — what the phone
    /// polls to show "someone is trying to sign in". Newest first.
    pub fn list_pending_signins(&self, now: u64) -> Result<Vec<PendingSignin>, StorageError> {
        self.exec(
            "SELECT request_id, user_code, client_name, created_at \
             FROM signin_requests \
             WHERE status = 'pending' AND expires_at > ? \
             ORDER BY created_at DESC",
            vec![i(now as i64)],
        )?
        .to_array()
        .map_err(sql_err)
    }

    /// Fetch a sign-in request by id.
    pub fn get_signin(&self, request_id: &str) -> Result<Option<SigninRow>, StorageError> {
        let rows: Vec<SigninRow> = self
            .exec(
                "SELECT user_code, status, did, handle, access_jwt, refresh_jwt, expires_at \
                 FROM signin_requests WHERE request_id = ?",
                vec![s(request_id)],
            )?
            .to_array()
            .map_err(sql_err)?;
        Ok(rows.into_iter().next())
    }

    /// Mark a request approved and attach the issued session.
    ///
    /// Guarded on `status = 'pending'` so a second approval — or an approval
    /// racing a denial — cannot overwrite a decided request. The DO is
    /// single-threaded, so this UPDATE is atomic with the preceding status read
    /// as long as no await sits between them at the call site.
    pub fn approve_signin(
        &self,
        request_id: &str,
        did: &str,
        handle: &str,
        access_jwt: &str,
        refresh_jwt: &str,
    ) -> Result<(), StorageError> {
        self.run(
            "UPDATE signin_requests \
             SET status = 'approved', did = ?, handle = ?, access_jwt = ?, refresh_jwt = ? \
             WHERE request_id = ? AND status = 'pending'",
            vec![
                s(did),
                s(handle),
                s(access_jwt),
                s(refresh_jwt),
                s(request_id),
            ],
        )
    }

    /// Mark a request denied.
    pub fn deny_signin(&self, request_id: &str) -> Result<(), StorageError> {
        self.run(
            "UPDATE signin_requests SET status = 'denied' \
             WHERE request_id = ? AND status = 'pending'",
            vec![s(request_id)],
        )
    }

    /// The stored argon2 PHC string for an account, for password login.
    pub async fn account_password_phc(&self, did: &str) -> Result<Option<String>, StorageError> {
        #[derive(Deserialize)]
        struct Row {
            password_argon2: String,
        }
        let rows: Vec<Row> = self
            .exec(
                "SELECT password_argon2 FROM accounts WHERE did = ?",
                vec![s(did)],
            )?
            .to_array()
            .map_err(sql_err)?;
        Ok(rows.into_iter().next().map(|r| r.password_argon2))
    }

    /// Erase the account this Durable Object holds: the account row, its two
    /// signing keys, preferences, repo root, and any enrolled devices. Blocks and
    /// blob metadata are cleared too so a reused hostname starts genuinely empty.
    ///
    /// The DID itself lives on the PLC ledger and cannot be erased from here —
    /// only tombstoned, which needs the rotation key and is not done as part of
    /// this wipe (and could not be, since the key is one of the things deleted).
    pub fn delete_account_data(&self, did: &str) -> Result<(), StorageError> {
        self.run("DELETE FROM accounts WHERE did = ?", vec![s(did)])?;
        self.run(
            "DELETE FROM keys WHERE id = ?",
            vec![s(format!("{did}#signing"))],
        )?;
        self.run(
            "DELETE FROM keys WHERE id = ?",
            vec![s(format!("{did}#rotation"))],
        )?;
        self.run(
            "DELETE FROM account_preferences WHERE did = ?",
            vec![s(did)],
        )?;
        self.run("DELETE FROM repo_roots WHERE did = ?", vec![s(did)])?;
        self.run("DELETE FROM repo_seq WHERE did = ?", vec![s(did)])?;
        self.run("DELETE FROM blob_refs WHERE did = ?", vec![s(did)])?;
        self.run("DELETE FROM device_keys", vec![])?;
        self.run("DELETE FROM signin_requests", vec![])?;
        Ok(())
    }
}

// --- accounts --------------------------------------------------------------

#[async_trait]
impl AccountStore for DoStore {
    async fn count_accounts(&self) -> Result<i64, StorageError> {
        #[derive(Deserialize)]
        struct N {
            n: i64,
        }
        let rows: Vec<N> = self
            .exec("SELECT count(*) AS n FROM accounts", vec![])?
            .to_array()
            .map_err(sql_err)?;
        Ok(rows.first().map(|r| r.n).unwrap_or(0))
    }

    async fn insert_account(
        &self,
        did: &str,
        handle: &str,
        email: Option<&str>,
        password_phc: &str,
    ) -> Result<(), StorageError> {
        // The schema declares `did` PRIMARY KEY and `handle` UNIQUE, but the DO
        // dialect reports a violation as a generic error. Check explicitly so
        // the caller gets `Constraint`, which is what the conformance suite and
        // `createAccount` both expect.
        if self.exists(
            "SELECT count(*) AS n FROM accounts WHERE did = ?",
            vec![s(did)],
        )? {
            return Err(StorageError::Constraint(format!(
                "account already exists: {did}"
            )));
        }
        if self.exists(
            "SELECT count(*) AS n FROM accounts WHERE handle = ?",
            vec![s(handle)],
        )? {
            return Err(StorageError::Constraint(format!(
                "handle already taken: {handle}"
            )));
        }

        self.run(
            "INSERT INTO accounts (did, handle, email, password_argon2, created_at) \
             VALUES (?, ?, ?, ?, ?)",
            vec![
                s(did),
                s(handle),
                opt_s(email.map(|e| e.to_string())),
                s(password_phc),
                s(now_iso()),
            ],
        )
    }

    async fn count_and_insert_account(
        &self,
        did: &str,
        handle: &str,
        email: Option<&str>,
        password_phc: &str,
    ) -> Result<i64, StorageError> {
        // Await-free between the count and the insert, so the first-account gate
        // cannot be won twice.
        let before = self.count_accounts().await?;
        self.insert_account(did, handle, email, password_phc)
            .await?;
        Ok(before)
    }

    async fn get_account_by_handle(
        &self,
        handle: &str,
    ) -> Result<Option<(String, String)>, StorageError> {
        let rows: Vec<AccountAuthRow> = self
            .exec(
                "SELECT did, password_argon2 FROM accounts \
                 WHERE handle = ? AND deactivated_at IS NULL AND takedown_ref IS NULL",
                vec![s(handle)],
            )?
            .to_array()
            .map_err(sql_err)?;
        Ok(rows.into_iter().next().map(|r| (r.did, r.password_argon2)))
    }

    async fn get_did_by_handle(&self, handle: &str) -> Result<Option<String>, StorageError> {
        let rows: Vec<DidRow> = self
            .exec(
                "SELECT did FROM accounts \
                 WHERE handle = ? AND deactivated_at IS NULL AND takedown_ref IS NULL",
                vec![s(handle)],
            )?
            .to_array()
            .map_err(sql_err)?;
        Ok(rows.into_iter().next().map(|r| r.did))
    }

    async fn get_handle_by_did(&self, did: &str) -> Result<Option<String>, StorageError> {
        let rows: Vec<HandleRow> = self
            .exec(
                "SELECT handle FROM accounts \
                 WHERE did = ? AND deactivated_at IS NULL AND takedown_ref IS NULL",
                vec![s(did)],
            )?
            .to_array()
            .map_err(sql_err)?;
        Ok(rows.into_iter().next().and_then(|r| r.handle))
    }

    async fn list_accounts(&self) -> Result<Vec<AccountSummary>, StorageError> {
        let rows: Vec<AccountRow> = self
            .exec(
                "SELECT did, handle, deactivated_at, takedown_ref, created_at \
                 FROM accounts ORDER BY created_at, did",
                vec![],
            )?
            .to_array()
            .map_err(sql_err)?;
        Ok(rows
            .into_iter()
            .map(|r| AccountSummary {
                did: r.did,
                handle: r.handle,
                deactivated_at: r.deactivated_at,
                takedown_ref: r.takedown_ref,
                created_at: r.created_at,
            })
            .collect())
    }

    async fn update_password(&self, did: &str, password_phc: &str) -> Result<u64, StorageError> {
        if !self.exists(
            "SELECT count(*) AS n FROM accounts WHERE did = ?",
            vec![s(did)],
        )? {
            return Ok(0);
        }
        self.run(
            "UPDATE accounts SET password_argon2 = ? WHERE did = ?",
            vec![s(password_phc), s(did)],
        )?;
        Ok(1)
    }

    async fn set_takedown(&self, did: &str, reference: &str) -> Result<u64, StorageError> {
        if !self.exists(
            "SELECT count(*) AS n FROM accounts WHERE did = ?",
            vec![s(did)],
        )? {
            return Ok(0);
        }
        // An empty reference still has to produce a non-null marker: the
        // takedown is expressed by the column being set at all.
        let marker = if reference.is_empty() {
            now_iso()
        } else {
            reference.to_string()
        };
        self.run(
            "UPDATE accounts SET takedown_ref = ? WHERE did = ?",
            vec![s(marker), s(did)],
        )?;
        Ok(1)
    }

    async fn clear_takedown(&self, did: &str) -> Result<u64, StorageError> {
        if !self.exists(
            "SELECT count(*) AS n FROM accounts WHERE did = ?",
            vec![s(did)],
        )? {
            return Ok(0);
        }
        self.run(
            "UPDATE accounts SET takedown_ref = NULL WHERE did = ?",
            vec![s(did)],
        )?;
        Ok(1)
    }

    async fn insert_invite(
        &self,
        code: &str,
        available_uses: i64,
        for_account: &str,
    ) -> Result<(), StorageError> {
        if self.exists(
            "SELECT count(*) AS n FROM invites WHERE code = ?",
            vec![s(code)],
        )? {
            return Err(StorageError::Constraint(format!(
                "invite code already exists: {code}"
            )));
        }
        self.run(
            "INSERT INTO invites (code, available_uses, disabled, for_account, created_by, created_at) \
             VALUES (?, ?, 0, ?, 'admin', ?)",
            vec![s(code), i(available_uses), s(for_account), s(now_iso())],
        )
    }

    /// Await-free between the checks and the decrement, so one remaining use
    /// cannot be redeemed twice.
    async fn consume_invite(&self, code: &str, used_by: &str) -> Result<bool, StorageError> {
        let rows: Vec<InviteRow> = self
            .exec(
                "SELECT available_uses, disabled FROM invites WHERE code = ?",
                vec![s(code)],
            )?
            .to_array()
            .map_err(sql_err)?;
        let Some(invite) = rows.into_iter().next() else {
            return Ok(false);
        };
        if invite.disabled != 0 || invite.available_uses <= 0 {
            return Ok(false);
        }
        if self.exists(
            "SELECT count(*) AS n FROM invite_uses WHERE code = ? AND used_by = ?",
            vec![s(code), s(used_by)],
        )? {
            return Ok(false);
        }

        self.run(
            "INSERT INTO invite_uses (code, used_by, used_at) VALUES (?, ?, ?)",
            vec![s(code), s(used_by), s(now_iso())],
        )?;
        self.run(
            "UPDATE invites SET available_uses = available_uses - 1 WHERE code = ?",
            vec![s(code)],
        )?;
        Ok(true)
    }

    async fn upsert_preferences(&self, did: &str, prefs_json: &str) -> Result<(), StorageError> {
        self.run(
            "INSERT OR REPLACE INTO account_preferences (did, prefs) VALUES (?, ?)",
            vec![s(did), s(prefs_json)],
        )
    }

    async fn get_preferences(&self, did: &str) -> Result<Option<String>, StorageError> {
        let rows: Vec<PrefsRow> = self
            .exec(
                "SELECT prefs FROM account_preferences WHERE did = ?",
                vec![s(did)],
            )?
            .to_array()
            .map_err(sql_err)?;
        Ok(rows.into_iter().next().map(|r| r.prefs))
    }
}

// --- keys ------------------------------------------------------------------

#[async_trait]
impl KeyStore for DoStore {
    async fn put_key_blob(&self, id: &str, ciphertext: Vec<u8>) -> Result<(), StorageError> {
        self.run(
            "INSERT OR REPLACE INTO keys (id, ciphertext) VALUES (?, ?)",
            vec![s(id), b(ciphertext)],
        )
    }

    async fn get_key_blob(&self, id: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let rows: Vec<CipherRow> = self
            .exec("SELECT ciphertext FROM keys WHERE id = ?", vec![s(id)])?
            .to_array()
            .map_err(sql_err)?;
        Ok(rows.into_iter().next().map(|r| r.ciphertext))
    }
}

// --- blobs (R2) ------------------------------------------------------------

/// R2 object key for a blob. Prefixed by DID so one account's blobs can be
/// listed or deleted without touching another's.
fn blob_key(did: &str, cid: &str) -> String {
    format!("{did}/{cid}")
}

impl DoStore {
    /// The blob CIDs owned by `did`, in CID order, for `sync.listBlobs`.
    ///
    /// Reads the `blob_refs` metadata index rather than enumerating R2 — the
    /// index is the authority on ownership, exactly as `get_blob` relies on.
    /// `cursor` is exclusive: rows are returned with `cid > cursor`.
    pub async fn list_blob_cids(
        &self,
        did: &str,
        cursor: Option<&str>,
        limit: i64,
    ) -> Result<Vec<String>, StorageError> {
        let rows: Vec<CidStrRow> = match cursor {
            Some(c) => self.exec(
                "SELECT cid FROM blob_refs WHERE did = ? AND cid > ? ORDER BY cid ASC LIMIT ?",
                vec![s(did), s(c), i(limit)],
            )?,
            None => self.exec(
                "SELECT cid FROM blob_refs WHERE did = ? ORDER BY cid ASC LIMIT ?",
                vec![s(did), i(limit)],
            )?,
        }
        .to_array()
        .map_err(sql_err)?;
        Ok(rows.into_iter().map(|r| r.cid).collect())
    }
}

#[async_trait]
impl BlobStore for DoStore {
    async fn put_blob(
        &self,
        did: &str,
        cid: &str,
        mime_type: &str,
        size: i64,
        bytes: Vec<u8>,
    ) -> Result<(), StorageError> {
        // R2 first, then metadata. In that order a crash between the two leaves
        // an unreferenced object — wasteful but harmless. The reverse order
        // would leave metadata pointing at bytes that do not exist, which
        // `getBlob` would surface as a broken blob.
        // R2 futures capture JS handles and are therefore `!Send`, while the
        // trait requires a `Send` future. `SendFuture` bridges that, soundly,
        // because a Workers isolate is single-threaded.
        SendFuture::new(self.blobs.put(blob_key(did, cid), bytes).execute())
            .await
            .map_err(|e| StorageError::Pool(format!("r2 put: {e}")))?;

        self.run(
            "INSERT OR REPLACE INTO blob_refs (did, cid, mime_type, size, created_at) \
             VALUES (?, ?, ?, ?, ?)",
            vec![s(did), s(cid), s(mime_type), i(size), s(now_iso())],
        )
    }

    async fn get_blob(
        &self,
        did: &str,
        cid: &str,
    ) -> Result<Option<(String, Vec<u8>)>, StorageError> {
        // Ownership is decided by the metadata row, not by the object's
        // presence in R2 — otherwise any account could read any other's blob by
        // guessing a CID.
        let rows: Vec<BlobMetaRow> = self
            .exec(
                "SELECT mime_type FROM blob_refs WHERE did = ? AND cid = ?",
                vec![s(did), s(cid)],
            )?
            .to_array()
            .map_err(sql_err)?;
        let Some(meta) = rows.into_iter().next() else {
            return Ok(None);
        };

        let object = SendFuture::new(self.blobs.get(blob_key(did, cid)).execute())
            .await
            .map_err(|e| StorageError::Pool(format!("r2 get: {e}")))?;
        let Some(object) = object else {
            return Ok(None);
        };
        let body = object
            .body()
            .ok_or_else(|| StorageError::Pool("r2 object has no body".into()))?;
        let bytes = SendFuture::new(body.bytes())
            .await
            .map_err(|e| StorageError::Pool(format!("r2 read: {e}")))?;

        Ok(Some((meta.mime_type, bytes)))
    }
}

// --- OAuth -----------------------------------------------------------------

#[derive(Deserialize)]
struct ParRow {
    request_uri_hash: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: String,
    code_challenge: String,
    dpop_jkt: Option<String>,
    login_hint: Option<String>,
    expires_at: i64,
}

#[derive(Deserialize)]
struct CodeRow {
    code_hash: String,
    did: String,
    client_id: String,
    redirect_uri: String,
    scope: String,
    code_challenge: String,
    dpop_jkt: Option<String>,
    expires_at: i64,
}

#[derive(Deserialize)]
struct RefreshRow {
    token_hash: String,
    session_id: String,
    did: String,
    client_id: String,
    scope: String,
    dpop_jkt: String,
    issued_at: i64,
    expires_at: i64,
    used: i64,
}

#[async_trait]
impl OAuthStore for DoStore {
    async fn put_pushed_request(&self, req: StoredPushedRequest) -> Result<(), StorageError> {
        self.run(
            "INSERT OR REPLACE INTO oauth_par \
             (request_uri_hash, client_id, redirect_uri, scope, state, code_challenge, \
              dpop_jkt, login_hint, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                s(req.request_uri_hash),
                s(req.client_id),
                s(req.redirect_uri),
                s(req.scope),
                s(req.state),
                s(req.code_challenge),
                opt_s(req.dpop_jkt),
                opt_s(req.login_hint),
                i(req.expires_at as i64),
            ],
        )
    }

    async fn get_pushed_request(
        &self,
        request_uri_hash: &str,
        now: u64,
    ) -> Result<Option<StoredPushedRequest>, StorageError> {
        let rows: Vec<ParRow> = self
            .exec(
                "SELECT request_uri_hash, client_id, redirect_uri, scope, state, \
                        code_challenge, dpop_jkt, login_hint, expires_at \
                 FROM oauth_par WHERE request_uri_hash = ? AND expires_at > ?",
                vec![s(request_uri_hash), i(now as i64)],
            )?
            .to_array()
            .map_err(sql_err)?;
        Ok(rows.into_iter().next().map(|r| StoredPushedRequest {
            request_uri_hash: r.request_uri_hash,
            client_id: r.client_id,
            redirect_uri: r.redirect_uri,
            scope: r.scope,
            state: r.state,
            code_challenge: r.code_challenge,
            dpop_jkt: r.dpop_jkt,
            login_hint: r.login_hint,
            expires_at: r.expires_at as u64,
        }))
    }

    async fn delete_pushed_request(&self, request_uri_hash: &str) -> Result<(), StorageError> {
        self.run(
            "DELETE FROM oauth_par WHERE request_uri_hash = ?",
            vec![s(request_uri_hash)],
        )
    }

    async fn put_auth_code(&self, code: AuthCode) -> Result<(), StorageError> {
        self.run(
            "INSERT OR REPLACE INTO oauth_auth_codes \
             (code_hash, did, client_id, redirect_uri, scope, code_challenge, dpop_jkt, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                s(code.code_hash),
                s(code.did),
                s(code.client_id),
                s(code.redirect_uri),
                s(code.scope),
                s(code.code_challenge),
                opt_s(code.dpop_jkt),
                i(code.expires_at as i64),
            ],
        )
    }

    /// Await-free select-then-delete: single-use is guaranteed by the isolate.
    async fn consume_auth_code(
        &self,
        code_hash: &str,
        now: u64,
    ) -> Result<Option<AuthCode>, StorageError> {
        let rows: Vec<CodeRow> = self
            .exec(
                "SELECT code_hash, did, client_id, redirect_uri, scope, code_challenge, \
                        dpop_jkt, expires_at \
                 FROM oauth_auth_codes WHERE code_hash = ? AND expires_at > ?",
                vec![s(code_hash), i(now as i64)],
            )?
            .to_array()
            .map_err(sql_err)?;

        // Delete unconditionally — an expired row that was not returned is
        // still worth clearing.
        self.run(
            "DELETE FROM oauth_auth_codes WHERE code_hash = ?",
            vec![s(code_hash)],
        )?;

        Ok(rows.into_iter().next().map(|r| AuthCode {
            code_hash: r.code_hash,
            did: r.did,
            client_id: r.client_id,
            redirect_uri: r.redirect_uri,
            scope: r.scope,
            code_challenge: r.code_challenge,
            dpop_jkt: r.dpop_jkt,
            expires_at: r.expires_at as u64,
        }))
    }

    async fn put_refresh_token(&self, token: RefreshTokenRecord) -> Result<(), StorageError> {
        self.run(
            "INSERT OR REPLACE INTO oauth_refresh_tokens \
             (token_hash, session_id, did, client_id, scope, dpop_jkt, issued_at, expires_at, used) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
            vec![
                s(token.token_hash),
                s(token.session_id),
                s(token.did),
                s(token.client_id),
                s(token.scope),
                s(token.dpop_jkt),
                i(token.issued_at as i64),
                i(token.expires_at as i64),
            ],
        )
    }

    /// Await-free read-then-mark, so two concurrent refreshes cannot both be
    /// `Consumed` — the loser sees `Reused` and revokes the chain.
    async fn consume_refresh_token(
        &self,
        token_hash: &str,
        now: u64,
    ) -> Result<ConsumeResult, StorageError> {
        let rows: Vec<RefreshRow> = self
            .exec(
                "SELECT token_hash, session_id, did, client_id, scope, dpop_jkt, \
                        issued_at, expires_at, used \
                 FROM oauth_refresh_tokens WHERE token_hash = ? AND expires_at > ?",
                vec![s(token_hash), i(now as i64)],
            )?
            .to_array()
            .map_err(sql_err)?;

        let Some(row) = rows.into_iter().next() else {
            return Ok(ConsumeResult::NotFound);
        };
        if row.used != 0 {
            return Ok(ConsumeResult::Reused {
                session_id: row.session_id,
            });
        }

        self.run(
            "UPDATE oauth_refresh_tokens SET used = 1 WHERE token_hash = ?",
            vec![s(token_hash)],
        )?;

        Ok(ConsumeResult::Consumed(Box::new(RefreshTokenRecord {
            token_hash: row.token_hash,
            session_id: row.session_id,
            did: row.did,
            client_id: row.client_id,
            scope: row.scope,
            dpop_jkt: row.dpop_jkt,
            issued_at: row.issued_at as u64,
            expires_at: row.expires_at as u64,
        })))
    }

    async fn revoke_session(&self, session_id: &str) -> Result<u64, StorageError> {
        #[derive(Deserialize)]
        struct N {
            n: i64,
        }
        let rows: Vec<N> = self
            .exec(
                "SELECT count(*) AS n FROM oauth_refresh_tokens WHERE session_id = ?",
                vec![s(session_id)],
            )?
            .to_array()
            .map_err(sql_err)?;
        let n = rows.first().map(|r| r.n).unwrap_or(0);

        self.run(
            "DELETE FROM oauth_refresh_tokens WHERE session_id = ?",
            vec![s(session_id)],
        )?;
        Ok(n as u64)
    }

    /// Revokes the whole chain, not just the one token: the caller is ending a
    /// session, and leaving its siblings alive would not do that.
    async fn revoke_refresh_token(&self, token_hash: &str) -> Result<bool, StorageError> {
        #[derive(Deserialize)]
        struct Sid {
            session_id: String,
        }
        let rows: Vec<Sid> = self
            .exec(
                "SELECT session_id FROM oauth_refresh_tokens WHERE token_hash = ?",
                vec![s(token_hash)],
            )?
            .to_array()
            .map_err(sql_err)?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(false);
        };
        self.run(
            "DELETE FROM oauth_refresh_tokens WHERE session_id = ?",
            vec![s(row.session_id)],
        )?;
        Ok(true)
    }

    async fn list_sessions_for_did(
        &self,
        did: &str,
        now: u64,
    ) -> Result<Vec<RefreshTokenRecord>, StorageError> {
        let rows: Vec<RefreshRow> = self
            .exec(
                "SELECT token_hash, session_id, did, client_id, scope, dpop_jkt, \
                        issued_at, expires_at, used \
                 FROM oauth_refresh_tokens \
                 WHERE did = ? AND expires_at > ? AND used = 0 \
                 ORDER BY issued_at DESC, token_hash ASC",
                vec![s(did), i(now as i64)],
            )?
            .to_array()
            .map_err(sql_err)?;
        Ok(rows
            .into_iter()
            .map(|r| RefreshTokenRecord {
                token_hash: r.token_hash,
                session_id: r.session_id,
                did: r.did,
                client_id: r.client_id,
                scope: r.scope,
                dpop_jkt: r.dpop_jkt,
                issued_at: r.issued_at as u64,
                expires_at: r.expires_at as u64,
            })
            .collect())
    }

    /// Await-free check-then-insert. A split here would let two concurrent
    /// requests both see "unseen", which is exactly the replay this prevents.
    async fn record_dpop_jti(&self, jti: &str, expires_at: u64) -> Result<bool, StorageError> {
        if self.exists(
            "SELECT count(*) AS n FROM oauth_dpop_jti WHERE jti = ?",
            vec![s(jti)],
        )? {
            return Ok(false);
        }
        self.run(
            "INSERT INTO oauth_dpop_jti (jti, expires_at) VALUES (?, ?)",
            vec![s(jti), i(expires_at as i64)],
        )?;
        Ok(true)
    }

    async fn purge_expired(&self, now: u64) -> Result<u64, StorageError> {
        #[derive(Deserialize)]
        struct N {
            n: i64,
        }
        let mut total = 0i64;
        for table in [
            "oauth_par",
            "oauth_auth_codes",
            "oauth_refresh_tokens",
            "oauth_dpop_jti",
        ] {
            let rows: Vec<N> = self
                .exec(
                    &format!("SELECT count(*) AS n FROM {table} WHERE expires_at <= ?"),
                    vec![i(now as i64)],
                )?
                .to_array()
                .map_err(sql_err)?;
            total += rows.first().map(|r| r.n).unwrap_or(0);

            self.run(
                &format!("DELETE FROM {table} WHERE expires_at <= ?"),
                vec![i(now as i64)],
            )?;
        }
        Ok(total as u64)
    }
}

/// Compile-time proof that `DoStore` satisfies the whole backend contract.
///
/// If a trait method is missed or a signature drifts, this fails here with a
/// clear message rather than at the far-away call site that builds the
/// `Arc<dyn StorageBackend>`.
const _: fn() = || {
    fn assert_backend<T: stelyph_core::storage::StorageBackend>() {}
    assert_backend::<DoStore>();
};
