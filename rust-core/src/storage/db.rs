use std::sync::Arc;

use deadpool_sqlite::{Config, Hook, HookError, Runtime};
use tokio::sync::Mutex;
use tokio_rusqlite::Connection;

use crate::storage::{schema, StorageError};

/// Single-writer, multi-reader SQLite store.
///
/// `Clone` produces a cheap handle clone: both instances share the same
/// underlying writer mutex and reader pool. This is NOT a database copy.
///
/// The writer is a single `tokio_rusqlite::Connection` behind a `Mutex` — only
/// one async task may hold the write lock at a time, which guarantees
/// `Immediate`-behavior transactions never race for the write lock from within
/// the same process.
///
/// The readers are a `deadpool_sqlite::Pool` — concurrent reads execute on
/// separate connections without blocking writes (WAL mode).
#[derive(Clone)]
pub struct SqliteStore {
    pub(crate) writer: Arc<Mutex<Connection>>,
    pub(crate) readers: deadpool_sqlite::Pool,
}

impl SqliteStore {
    /// Open (or create) a WAL-mode SQLite database at `path` and run schema migrations.
    pub async fn open(path: &str) -> Result<Self, StorageError> {
        // Writer: single connection, WAL + busy_timeout
        let writer = Connection::open(path).await?;
        writer
            .call(|conn| {
                conn.execute_batch(
                    // mmap_size lets SQLite serve reads from clean, file-backed
                    // pages (256 MiB cap). On a device host these don't count
                    // toward the Jetsam phys_footprint ceiling; on a server it's
                    // a straight read-path win.
                    "PRAGMA journal_mode=WAL;
                     PRAGMA busy_timeout=5000;
                     PRAGMA synchronous=NORMAL;
                     PRAGMA mmap_size=268435456;
                     PRAGMA foreign_keys=ON;",
                )?;
                Ok(())
            })
            .await?;

        // Readers: pool with post-create hook to apply the same pragmas as the writer.
        // WAL mode is DB-level so new connections already inherit it, but busy_timeout
        // and foreign_keys are connection-level and must be set explicitly.
        let cfg = Config::new(path);
        let readers = cfg
            .builder(Runtime::Tokio1)
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .post_create(Hook::async_fn(|conn, _metrics| {
                Box::pin(async move {
                    conn.interact(|c| {
                        c.execute_batch(
                            "PRAGMA busy_timeout=5000;
                             PRAGMA mmap_size=268435456;
                             PRAGMA foreign_keys=ON;",
                        )
                    })
                    .await
                    .map_err(|e| HookError::message(e.to_string()))?
                    .map_err(HookError::Backend)?;
                    Ok(())
                })
            }))
            .build()
            .map_err(|e| StorageError::Pool(e.to_string()))?;

        let store = SqliteStore {
            writer: Arc::new(Mutex::new(writer)),
            readers,
        };
        store.run_migrations().await?;
        Ok(store)
    }

    /// Run DDL migrations — currently a single static schema batch.
    async fn run_migrations(&self) -> Result<(), StorageError> {
        let writer = self.writer.lock().await;
        writer
            .call(|conn| {
                conn.execute_batch(schema::SCHEMA)?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Test helper: open a store backed by a named temp file so the writer and
    /// reader pool share the same on-disk WAL database.
    ///
    /// NOTE: `:memory:` is intentionally NOT used — in-memory mode disables WAL
    /// and each pool connection gets its own empty database.
    #[cfg(any(test, feature = "testing"))]
    pub async fn open_in_memory() -> Result<(Self, tempfile::NamedTempFile), StorageError> {
        let tmp = tempfile::NamedTempFile::new().map_err(|e| StorageError::Pool(e.to_string()))?;
        let path = tmp
            .path()
            .to_str()
            .ok_or_else(|| StorageError::Pool("temp path is not valid UTF-8".into()))?
            .to_string();
        let store = Self::open(&path).await?;
        // Return `tmp` to keep the file alive for the duration of the test.
        Ok((store, tmp))
    }

    /// Persist the latest signed-commit CID for `did`. Called after every
    /// successful commit_blocks so the next create_record can re-open the repo.
    pub async fn update_repo_root(
        &self,
        did: &str,
        root_cid: cid::Cid,
    ) -> Result<(), StorageError> {
        let did = did.to_string();
        let root = root_cid.to_string();
        let now_iso = chrono::Utc::now().to_rfc3339();
        let writer = self.writer.lock().await;
        writer
            .call(move |conn| {
                conn.execute(
                "INSERT OR REPLACE INTO repo_roots (did, root_cid, updated_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![did, root, now_iso],
            )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Load the latest commit CID for `did`, or None if the repo has no commits yet.
    ///
    /// Uses the writer connection (not the reader pool) so that the read always
    /// sees the latest committed state without any WAL snapshot lag. This is
    /// safe because the caller (`create_record`) holds the per-DID write_lock,
    /// ensuring no concurrent write is in flight for the same DID.
    pub async fn load_repo_root(&self, did: &str) -> Result<Option<cid::Cid>, StorageError> {
        let did = did.to_string();
        let writer = self.writer.lock().await;
        let s: Option<String> = writer
            .call(move |c| {
                use rusqlite::OptionalExtension;
                c.query_row(
                    "SELECT root_cid FROM repo_roots WHERE did = ?1",
                    rusqlite::params![did],
                    |row| row.get::<_, String>(0),
                )
                .optional()
            })
            .await?;
        match s {
            None => Ok(None),
            Some(cid_str) => {
                use std::str::FromStr;
                let cid = cid::Cid::from_str(&cid_str)
                    .map_err(|e| StorageError::Crypto(format!("bad root cid: {e}")))?;
                Ok(Some(cid))
            }
        }
    }

    /// Upsert the opaque preferences JSON array for `did` (XRPC-05).
    pub async fn upsert_preferences(
        &self,
        did: &str,
        prefs_json: &str,
    ) -> Result<(), StorageError> {
        let did = did.to_string();
        let prefs = prefs_json.to_string();
        let writer = self.writer.lock().await;
        writer
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO account_preferences (did, prefs) VALUES (?1, ?2)",
                    rusqlite::params![did, prefs],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Load the stored preferences JSON array for `did`, or None if no row exists.
    pub async fn get_preferences(&self, did: &str) -> Result<Option<String>, StorageError> {
        let did = did.to_string();
        let conn = self
            .readers
            .get()
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?;
        let prefs: Option<String> = conn
            .interact(move |c| {
                use rusqlite::OptionalExtension;
                c.query_row(
                    "SELECT prefs FROM account_preferences WHERE did = ?1",
                    rusqlite::params![did],
                    |row| row.get::<_, String>(0),
                )
                .optional()
            })
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?;
        Ok(prefs)
    }

    /// Read a single block's raw bytes by CID (public helper for the repo
    /// writer, which lives outside the storage module and cannot use the
    /// pub(crate) reader pool directly). Mirrors read_block_into.
    pub async fn read_block_bytes(&self, cid: cid::Cid) -> Result<Vec<u8>, StorageError> {
        let cid_str = cid.to_string();
        let conn = self
            .readers
            .get()
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?;
        let bytes: Option<Vec<u8>> = conn
            .interact(move |c| {
                use rusqlite::OptionalExtension;
                c.query_row(
                    "SELECT bytes FROM blocks WHERE cid = ?1",
                    [&cid_str],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
            })
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?;
        bytes.ok_or(StorageError::BlockNotFound)
    }

    /// Store a content-addressed blob for an account (idempotent). Re-uploading
    /// the same (did, cid) replaces the row.
    pub async fn put_blob(
        &self,
        did: &str,
        cid: &str,
        mime_type: &str,
        size: i64,
        bytes: Vec<u8>,
    ) -> Result<(), StorageError> {
        let did = did.to_string();
        let cid = cid.to_string();
        let mime_type = mime_type.to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let writer = self.writer.lock().await;
        writer
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO blobs (did, cid, mime_type, size, bytes, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![did, cid, mime_type, size, bytes, now],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Fetch a blob's mime type and raw bytes by (did, cid). Returns None if the
    /// account does not have that blob.
    pub async fn get_blob(
        &self,
        did: &str,
        cid: &str,
    ) -> Result<Option<(String, Vec<u8>)>, StorageError> {
        let did = did.to_string();
        let cid = cid.to_string();
        let conn = self
            .readers
            .get()
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?;
        let row: Option<(String, Vec<u8>)> = conn
            .interact(move |c| {
                use rusqlite::OptionalExtension;
                c.query_row(
                    "SELECT mime_type, bytes FROM blobs WHERE did = ?1 AND cid = ?2",
                    rusqlite::params![did, cid],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)),
                )
                .optional()
            })
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?;
        Ok(row)
    }

    /// Return the event BLOB of the most recently inserted repo_seq row.
    /// Used in tests to assert that the stored event body is the real #commit body.
    #[cfg(test)]
    pub async fn last_event_body(&self) -> Result<Option<Vec<u8>>, StorageError> {
        let conn = self
            .readers
            .get()
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?;
        let blob: Option<Vec<u8>> = conn
            .interact(|c| {
                use rusqlite::OptionalExtension;
                c.query_row(
                    "SELECT event FROM repo_seq ORDER BY seq DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .optional()
            })
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?;
        Ok(blob)
    }

    /// Count the number of rows in repo_seq. Used in tests to verify atomicity.
    #[cfg(any(test, feature = "testing"))]
    pub async fn repo_seq_count(&self) -> Result<i64, StorageError> {
        let conn = self
            .readers
            .get()
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?;
        let n: i64 = conn
            .interact(|c| c.query_row("SELECT count(*) FROM repo_seq", [], |r| r.get(0)))
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?;
        Ok(n)
    }

    /// Highest assigned firehose sequence number, or 0 if the log is empty.
    /// Used for the FutureCursor check (cursor > max_seq → error frame).
    /// Reads via the reader pool — does not block the writer.
    pub async fn max_seq(&self) -> Result<i64, StorageError> {
        let conn = self
            .readers
            .get()
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?;
        let n: i64 = conn
            .interact(|c| {
                c.query_row("SELECT COALESCE(MAX(seq), 0) FROM repo_seq", [], |r| {
                    r.get(0)
                })
            })
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?;
        Ok(n)
    }

    /// One page of backfill rows for a subscriber: events with seq > `after_seq`,
    /// not invalidated, in ascending seq order, capped at `limit`.
    /// Returns `(seq, event_blob)` pairs. Uses the reader pool — does not block the writer.
    ///
    /// Recommended call-site limit is 500 rows per page (see RESEARCH §Cursor Semantics SQL).
    /// The cursor integer is bound as a parameterized query value — no string interpolation
    /// (T-04-03: prevents SQL injection from untrusted subscriber cursors).
    /// The LIMIT cap prevents loading the full table into memory (T-04-04: DoS mitigation).
    pub async fn backfill_page(
        &self,
        after_seq: i64,
        limit: i64,
    ) -> Result<Vec<(i64, Vec<u8>)>, StorageError> {
        let conn = self
            .readers
            .get()
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?;
        let rows = conn
            .interact(move |c| {
                let mut stmt = c.prepare(
                    "SELECT seq, event FROM repo_seq \
                     WHERE seq > ?1 AND invalidated = 0 \
                     ORDER BY seq ASC LIMIT ?2",
                )?;
                let mapped = stmt.query_map(rusqlite::params![after_seq, limit], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
                })?;
                mapped.collect::<Result<Vec<_>, rusqlite::Error>>()
            })
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?;
        Ok(rows)
    }

    // -------------------------------------------------------------------------
    // Account helpers (Plan 03-02)
    // -------------------------------------------------------------------------

    /// Return the total number of accounts in the `accounts` table.
    /// Used by createAccount to detect the "first account claims the server" case.
    ///
    /// NOTE: this reader-pool count is NOT serialized with subsequent inserts. For
    /// the first-account gate use `insert_account_atomic` which performs the count
    /// inside the writer transaction. This method is kept for diagnostic use only.
    pub async fn count_accounts(&self) -> Result<i64, StorageError> {
        let conn = self
            .readers
            .get()
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?;
        let n: i64 = conn
            .interact(|c| c.query_row("SELECT count(*) FROM accounts", [], |r| r.get(0)))
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?;
        Ok(n)
    }

    /// Insert a new account row. `password_phc` must be an argon2id PHC string
    /// produced by `auth::jwt::hash_password`.
    pub async fn insert_account(
        &self,
        did: &str,
        handle: &str,
        email: Option<&str>,
        password_phc: &str,
    ) -> Result<(), StorageError> {
        let did = did.to_string();
        let handle = handle.to_string();
        let email = email.map(|e| e.to_string());
        let phc = password_phc.to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let writer = self.writer.lock().await;
        writer
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO accounts (did, handle, email, password_argon2, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![did, handle, email, phc, now],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Atomically count existing accounts and insert a new one in a single writer
    /// transaction (WR-02: first-account TOCTOU fix).
    ///
    /// Returns the account count BEFORE the insert, so the caller can check
    /// whether this was the first account. The count and insert are wrapped in an
    /// Immediate-behavior transaction (rollback-on-drop) so two concurrent
    /// first-registrations cannot both observe count == 0.
    pub async fn count_and_insert_account(
        &self,
        did: &str,
        handle: &str,
        email: Option<&str>,
        password_phc: &str,
    ) -> Result<i64, StorageError> {
        let did = did.to_string();
        let handle = handle.to_string();
        let email = email.map(|e| e.to_string());
        let phc = password_phc.to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let writer = self.writer.lock().await;
        let count_before = writer
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let n: i64 = tx.query_row("SELECT count(*) FROM accounts", [], |r| r.get(0))?;
                tx.execute(
                    "INSERT INTO accounts (did, handle, email, password_argon2, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![did, handle, email, phc, now],
                )?;
                tx.commit()?;
                Ok(n)
            })
            .await?;
        Ok(count_before)
    }

    /// Look up an account by handle. Returns `(did, password_phc)` if found.
    pub async fn get_account_by_handle(
        &self,
        handle: &str,
    ) -> Result<Option<(String, String)>, StorageError> {
        let handle = handle.to_string();
        let conn = self
            .readers
            .get()
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?;
        let row: Option<(String, String)> = conn.interact(move |c| {
            use rusqlite::OptionalExtension;
            c.query_row(
                "SELECT did, password_argon2 FROM accounts WHERE handle = ?1 AND deactivated_at IS NULL AND takedown_ref IS NULL",
                rusqlite::params![handle],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            ).optional()
        })
        .await.map_err(|e| StorageError::Pool(e.to_string()))?
        .map_err(StorageError::Sqlite)?;
        Ok(row)
    }

    /// Look up a DID by handle. Used by resolveHandle to return the DID for a
    /// known handle. Returns `None` if no active account exists with that handle.
    pub async fn get_did_by_handle(&self, handle: &str) -> Result<Option<String>, StorageError> {
        let handle = handle.to_string();
        let conn = self
            .readers
            .get()
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?;
        let did: Option<String> = conn.interact(move |c| {
            use rusqlite::OptionalExtension;
            c.query_row(
                "SELECT did FROM accounts WHERE handle = ?1 AND deactivated_at IS NULL AND takedown_ref IS NULL",
                rusqlite::params![handle],
                |row| row.get::<_, String>(0),
            ).optional()
        })
        .await.map_err(|e| StorageError::Pool(e.to_string()))?
        .map_err(StorageError::Sqlite)?;
        Ok(did)
    }

    /// Look up a handle by DID. Used by createSession/refreshSession to return
    /// the handle in the session response.
    ///
    /// Returns `None` if the account does not exist, has been deactivated, or has
    /// been taken down — matching the same gate applied by `get_account_by_handle`.
    pub async fn get_handle_by_did(&self, did: &str) -> Result<Option<String>, StorageError> {
        let did = did.to_string();
        let conn = self
            .readers
            .get()
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?;
        let handle: Option<String> = conn
            .interact(move |c| {
                use rusqlite::OptionalExtension;
                c.query_row(
                    "SELECT handle FROM accounts WHERE did = ?1 \
                 AND deactivated_at IS NULL AND takedown_ref IS NULL",
                    rusqlite::params![did],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
            })
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?
            .flatten();
        Ok(handle)
    }

    /// Atomically consume one use of an invite code for `used_by`.
    ///
    /// This runs inside the writer mutex AND an explicit Immediate-behavior
    /// transaction (WR-03, B1) so that the SELECT → INSERT → UPDATE sequence is
    /// crash-safe: if the process dies between the INSERT and the UPDATE, SQLite
    /// rolls back both statements on restart. The transaction guard also rolls
    /// back automatically on `Drop` if any early `?` returns before `tx.commit()`,
    /// so the singleton writer connection is never left with a stuck-open
    /// transaction after a failure.
    ///
    /// Returns `true` on success, `false` if the code is unknown, disabled,
    /// exhausted, or already used by this DID.
    pub async fn consume_invite(&self, code: &str, used_by: &str) -> Result<bool, StorageError> {
        let code = code.to_string();
        let used_by = used_by.to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let writer = self.writer.lock().await;
        let consumed = writer
            .call(move |conn| {
                // WR-03: wrap in an explicit transaction so the SELECT + INSERT + UPDATE
                // are atomic with respect to crashes. The un-committed `tx` rolls back
                // automatically on Drop if the closure returns without `tx.commit()`.
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

                // Check invite is valid and has remaining uses.
                let row: Option<(i64, i64)> = {
                    use rusqlite::OptionalExtension;
                    tx.query_row(
                        "SELECT available_uses, disabled FROM invites WHERE code = ?1",
                        rusqlite::params![code],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .optional()?
                };

                let (available_uses, _disabled) = match row {
                    None => {
                        return Ok(false); // code not found
                    }
                    Some((_, 1)) => {
                        return Ok(false); // disabled
                    }
                    Some((0, _)) => {
                        return Ok(false); // no uses left
                    }
                    Some(v) => v,
                };

                if available_uses <= 0 {
                    return Ok(false);
                }

                // Check if already used by this DID
                let already_used: i64 = tx.query_row(
                    "SELECT count(*) FROM invite_uses WHERE code = ?1 AND used_by = ?2",
                    rusqlite::params![code, used_by],
                    |row| row.get(0),
                )?;
                if already_used > 0 {
                    return Ok(false);
                }

                // INSERT invite_uses — the PK constraint prevents double-use
                let inserted = tx.execute(
                "INSERT OR IGNORE INTO invite_uses (code, used_by, used_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![code, used_by, now],
            )?;
                if inserted == 0 {
                    return Ok(false); // PK conflict — already used
                }

                // Decrement available_uses
                tx.execute(
                    "UPDATE invites SET available_uses = available_uses - 1 WHERE code = ?1",
                    rusqlite::params![code],
                )?;

                tx.commit()?;
                Ok(true)
            })
            .await?;
        Ok(consumed)
    }

    /// Mark an account as taken down by setting `takedown_ref`. A non-null
    /// `takedown_ref` excludes the account from auth/session/handle lookups.
    /// `reference` is an operator-supplied marker (reason / ticket id); when
    /// empty a timestamp is stored so the column is still non-null. Returns the
    /// number of rows affected (0 if the DID was not found).
    pub async fn set_takedown(&self, did: &str, reference: &str) -> Result<u64, StorageError> {
        let did = did.to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let reference = if reference.is_empty() {
            now
        } else {
            reference.to_string()
        };
        let writer = self.writer.lock().await;
        let n = writer
            .call(move |conn| {
                let n = conn.execute(
                    "UPDATE accounts SET takedown_ref = ?1 WHERE did = ?2",
                    rusqlite::params![reference, did],
                )?;
                Ok(n)
            })
            .await?;
        Ok(n as u64)
    }

    /// Clear an account's takedown, restoring it to active. Returns the number
    /// of rows affected (0 if the DID was not found / not taken down).
    pub async fn clear_takedown(&self, did: &str) -> Result<u64, StorageError> {
        let did = did.to_string();
        let writer = self.writer.lock().await;
        let n = writer
            .call(move |conn| {
                let n = conn.execute(
                    "UPDATE accounts SET takedown_ref = NULL WHERE did = ?1",
                    rusqlite::params![did],
                )?;
                Ok(n)
            })
            .await?;
        Ok(n as u64)
    }

    /// Update an account's password hash. `password_phc` must be an argon2id PHC
    /// string from `auth::jwt::hash_password`. Returns rows affected (0 if no
    /// such DID).
    pub async fn update_password(
        &self,
        did: &str,
        password_phc: &str,
    ) -> Result<u64, StorageError> {
        let did = did.to_string();
        let phc = password_phc.to_string();
        let writer = self.writer.lock().await;
        let n = writer
            .call(move |conn| {
                let n = conn.execute(
                    "UPDATE accounts SET password_argon2 = ?1 WHERE did = ?2",
                    rusqlite::params![phc, did],
                )?;
                Ok(n)
            })
            .await?;
        Ok(n as u64)
    }

    /// List every account for operator/admin tooling: (did, handle,
    /// deactivated_at, takedown_ref, created_at), ordered by creation time.
    /// Unlike the auth lookups, this does NOT filter out deactivated/taken-down
    /// rows — the admin needs to see them.
    pub async fn list_accounts(&self) -> Result<Vec<AccountSummary>, StorageError> {
        let conn = self
            .readers
            .get()
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?;
        let rows = conn
            .interact(|c| {
                let mut stmt = c.prepare(
                    "SELECT did, handle, deactivated_at, takedown_ref, created_at \
                     FROM accounts ORDER BY created_at",
                )?;
                let mapped = stmt
                    .query_map([], |r| {
                        Ok(AccountSummary {
                            did: r.get(0)?,
                            handle: r.get(1)?,
                            deactivated_at: r.get(2)?,
                            takedown_ref: r.get(3)?,
                            created_at: r.get(4)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;
                Ok(mapped)
            })
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?;
        Ok(rows)
    }

    /// Seed an invite code row (admin `create-invite`; also used by tests).
    pub async fn insert_invite(
        &self,
        code: &str,
        available_uses: i64,
        for_account: &str,
    ) -> Result<(), StorageError> {
        let code = code.to_string();
        let for_account = for_account.to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let writer = self.writer.lock().await;
        writer.call(move |conn| {
            conn.execute(
                "INSERT INTO invites (code, available_uses, disabled, for_account, created_by, created_at)
                 VALUES (?1, ?2, 0, ?3, 'admin', ?4)",
                rusqlite::params![code, available_uses, for_account, now],
            )?;
            Ok(())
        }).await?;
        Ok(())
    }
}

/// One row of `list_accounts` — an account as the operator sees it, including
/// deactivated / taken-down accounts (which the auth-path lookups hide).
#[derive(Debug, Clone)]
pub struct AccountSummary {
    pub did: String,
    pub handle: Option<String>,
    pub deactivated_at: Option<String>,
    pub takedown_ref: Option<String>,
    pub created_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_open_creates_wal_and_tables() {
        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");

        // Verify WAL mode
        let journal_mode: String = store
            .writer
            .lock()
            .await
            .call(|conn| {
                conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))
                    .map_err(tokio_rusqlite::Error::Error)
            })
            .await
            .expect("pragma query failed");
        assert_eq!(journal_mode, "wal", "journal_mode must be wal");

        // Verify all expected tables exist
        let table_count: i64 = store
            .writer
            .lock()
            .await
            .call(|conn| {
                conn.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table'",
                    [],
                    |row| row.get(0),
                )
                .map_err(tokio_rusqlite::Error::Error)
            })
            .await
            .expect("table count query failed");

        // blocks, repo_seq, accounts, keys, invites, invite_uses, schema_version = 7
        assert!(
            table_count >= 7,
            "expected >= 7 tables, got {}",
            table_count
        );
    }

    /// FED-02: max_seq returns 0 on an empty repo_seq table.
    #[tokio::test]
    async fn max_seq_empty_is_zero() {
        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");
        let seq = store.max_seq().await.expect("max_seq failed");
        assert_eq!(seq, 0, "max_seq on empty table must return 0");
    }

    /// FED-02: max_seq returns the committed seq after one commit.
    #[tokio::test]
    async fn max_seq_after_commit() {
        use atrium_repo::blockstore::DAG_CBOR;
        use sha2::Digest;

        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");

        // Compute a dummy CID
        let data = b"max_seq test block";
        let digest = sha2::Sha256::digest(data);
        let mh =
            cid::multihash::Multihash::wrap(atrium_repo::blockstore::SHA2_256, digest.as_slice())
                .expect("multihash");
        let root = cid::Cid::new_v1(DAG_CBOR, mh);

        let seq = store
            .commit_blocks(
                vec![(root, data.to_vec())],
                "did:example:max-seq",
                root,
                vec![0xa0],
            )
            .await
            .expect("commit_blocks failed");

        let max = store.max_seq().await.expect("max_seq failed");
        assert_eq!(
            max, seq,
            "max_seq must equal the seq returned by commit_blocks"
        );
    }

    /// FED-02: backfill_page returns all rows in ascending seq order, carrying
    /// the correct event bytes for each row.
    #[tokio::test]
    async fn backfill_returns_rows_in_order() {
        use atrium_repo::blockstore::DAG_CBOR;
        use sha2::Digest;

        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");

        let bodies: Vec<Vec<u8>> = vec![vec![1, 2], vec![3, 4], vec![5, 6]];
        let mut written_seqs = Vec::new();

        for (i, body) in bodies.iter().enumerate() {
            let data = format!("block {i}").into_bytes();
            let digest = sha2::Sha256::digest(&data);
            let mh = cid::multihash::Multihash::wrap(
                atrium_repo::blockstore::SHA2_256,
                digest.as_slice(),
            )
            .expect("multihash");
            let root = cid::Cid::new_v1(DAG_CBOR, mh);

            let seq = store
                .commit_blocks(
                    vec![(root, data)],
                    "did:example:backfill-order",
                    root,
                    body.clone(),
                )
                .await
                .expect("commit_blocks failed");
            written_seqs.push(seq);
        }

        let rows = store
            .backfill_page(0, 500)
            .await
            .expect("backfill_page failed");

        assert_eq!(rows.len(), 3, "expected 3 backfill rows");

        // Verify ascending order and correct event bytes.
        for (i, (seq, event)) in rows.iter().enumerate() {
            assert_eq!(*seq, written_seqs[i], "seq at position {i} is wrong");
            assert_eq!(*event, bodies[i], "event bytes at position {i} are wrong");
        }
    }

    /// XRPC-05: preferences round-trip — upsert/get/overwrite.
    #[tokio::test]
    async fn preferences_round_trip() {
        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");

        // No row yet → None
        let initial = store
            .get_preferences("did:plc:x")
            .await
            .expect("get failed");
        assert_eq!(initial, None, "expected None for unknown DID");

        // Upsert and verify round-trip
        let prefs_v1 = r#"[{"$type":"a"}]"#;
        store
            .upsert_preferences("did:plc:x", prefs_v1)
            .await
            .expect("upsert failed");
        let got_v1 = store
            .get_preferences("did:plc:x")
            .await
            .expect("get v1 failed");
        assert_eq!(
            got_v1,
            Some(prefs_v1.to_string()),
            "expected stored prefs_v1"
        );

        // Overwrite and verify new value
        store
            .upsert_preferences("did:plc:x", "[]")
            .await
            .expect("upsert v2 failed");
        let got_v2 = store
            .get_preferences("did:plc:x")
            .await
            .expect("get v2 failed");
        assert_eq!(
            got_v2,
            Some("[]".to_string()),
            "expected overwritten prefs '[]'"
        );
    }

    /// FED-02: backfill_page respects the limit and cursor for paging.
    #[tokio::test]
    async fn backfill_paging() {
        use atrium_repo::blockstore::DAG_CBOR;
        use sha2::Digest;

        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");

        // Write 4 rows.
        let mut all_seqs = Vec::new();
        for i in 0..4u8 {
            let data = format!("paging block {i}").into_bytes();
            let digest = sha2::Sha256::digest(&data);
            let mh = cid::multihash::Multihash::wrap(
                atrium_repo::blockstore::SHA2_256,
                digest.as_slice(),
            )
            .expect("multihash");
            let root = cid::Cid::new_v1(DAG_CBOR, mh);

            let seq = store
                .commit_blocks(vec![(root, data)], "did:example:paging", root, vec![i])
                .await
                .expect("commit_blocks failed");
            all_seqs.push(seq);
        }

        // First page: limit=2, cursor=0 → should return first 2 rows.
        let page1 = store
            .backfill_page(0, 2)
            .await
            .expect("backfill_page page1 failed");
        assert_eq!(page1.len(), 2, "page1 must have 2 rows");
        assert_eq!(page1[0].0, all_seqs[0]);
        assert_eq!(page1[1].0, all_seqs[1]);

        // Second page: cursor=last seq of page1 → should return remaining rows.
        let last_seq_p1 = page1.last().unwrap().0;
        let page2 = store
            .backfill_page(last_seq_p1, 500)
            .await
            .expect("backfill_page page2 failed");
        assert_eq!(page2.len(), 2, "page2 must have 2 rows");
        assert_eq!(page2[0].0, all_seqs[2]);
        assert_eq!(page2[1].0, all_seqs[3]);
    }

    // --- admin operations (stelyph admin) ---

    /// takedown hides the account from auth lookups; untakedown restores it.
    #[tokio::test]
    async fn takedown_and_clear_roundtrip() {
        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");
        store
            .insert_account("did:plc:t1", "alice.test", None, "phc")
            .await
            .expect("insert");

        // Active → handle resolves.
        assert!(store
            .get_handle_by_did("did:plc:t1")
            .await
            .unwrap()
            .is_some());

        let n = store.set_takedown("did:plc:t1", "spam-42").await.unwrap();
        assert_eq!(n, 1, "one row taken down");
        // Taken-down → hidden from the auth-path lookup.
        assert!(store
            .get_handle_by_did("did:plc:t1")
            .await
            .unwrap()
            .is_none());

        let n = store.clear_takedown("did:plc:t1").await.unwrap();
        assert_eq!(n, 1, "one row restored");
        assert!(store
            .get_handle_by_did("did:plc:t1")
            .await
            .unwrap()
            .is_some());
    }

    /// takedown/clear on an unknown DID affects 0 rows (admin reports "not found").
    #[tokio::test]
    async fn takedown_unknown_did_affects_zero_rows() {
        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");
        assert_eq!(store.set_takedown("did:plc:nope", "x").await.unwrap(), 0);
        assert_eq!(store.clear_takedown("did:plc:nope").await.unwrap(), 0);
    }

    /// update_password swaps the stored PHC; the new hash is what auth reads back.
    #[tokio::test]
    async fn update_password_changes_stored_hash() {
        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");
        store
            .insert_account("did:plc:p1", "bob.test", None, "old-phc")
            .await
            .expect("insert");

        let n = store
            .update_password("did:plc:p1", "new-phc")
            .await
            .unwrap();
        assert_eq!(n, 1);
        let (_did, phc) = store
            .get_account_by_handle("bob.test")
            .await
            .unwrap()
            .expect("account present");
        assert_eq!(phc, "new-phc", "password hash must be updated");
        assert_eq!(store.update_password("did:plc:none", "x").await.unwrap(), 0);
    }

    /// list_accounts returns every account INCLUDING taken-down ones (auth-path
    /// lookups hide those; the admin view must not).
    #[tokio::test]
    async fn list_accounts_includes_taken_down() {
        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");
        store
            .insert_account("did:plc:a", "a.test", None, "phc")
            .await
            .unwrap();
        store
            .insert_account("did:plc:b", "b.test", None, "phc")
            .await
            .unwrap();
        store.set_takedown("did:plc:b", "reason").await.unwrap();

        let accounts = store.list_accounts().await.unwrap();
        assert_eq!(accounts.len(), 2, "both accounts listed, incl. taken-down");
        let b = accounts
            .iter()
            .find(|a| a.did == "did:plc:b")
            .expect("b present");
        assert_eq!(b.takedown_ref.as_deref(), Some("reason"));
    }

    /// insert_invite persists a redeemable code row.
    #[tokio::test]
    async fn insert_invite_persists_code() {
        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");
        store
            .insert_invite("stelyph-abc123", 5, "admin")
            .await
            .unwrap();
        let conn = store.readers.get().await.unwrap();
        let uses: i64 = conn
            .interact(|c| {
                c.query_row(
                    "SELECT available_uses FROM invites WHERE code = 'stelyph-abc123'",
                    [],
                    |r| r.get(0),
                )
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(uses, 5);
    }

    /// B1: a forced mid-transaction failure inside `count_and_insert_account`
    /// (duplicate `did` violates the PRIMARY KEY constraint) must NOT leave the
    /// singleton writer connection stuck with an open transaction. A subsequent,
    /// independent write on the same store must still succeed.
    ///
    /// Mirrors `block_store.rs::tests::test_atomic_rollback`'s two-phase structure:
    /// phase 1 forces an `Err`, phase 2 proves the writer is still usable.
    #[tokio::test]
    async fn txn_leak_writer_stays_usable() {
        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");

        // Phase 1: insert one account, then force a mid-transaction failure by
        // inserting a SECOND account with the same `did` (PRIMARY KEY violation).
        // With the old raw begin/commit-string implementation this would leave
        // an open transaction on the writer connection because the early `?`
        // error skips the commit statement with no rollback ever issued.
        store
            .count_and_insert_account("did:plc:dup", "first.test", None, "phc-1")
            .await
            .expect("first insert must succeed");

        let result = store
            .count_and_insert_account("did:plc:dup", "second.test", None, "phc-2")
            .await;
        assert!(
            result.is_err(),
            "duplicate did must violate the PRIMARY KEY constraint and return Err"
        );

        // Phase 2: an independent write on the same store (different did/handle)
        // must still succeed — proving the writer connection was NOT left stuck
        // with an open transaction after the phase-1 failure.
        let count_before = store
            .count_and_insert_account("did:plc:fresh", "fresh.test", None, "phc-3")
            .await
            .expect("independent write after a forced failure must still succeed");
        assert_eq!(
            count_before, 1,
            "count_before should reflect the one account inserted in phase 1"
        );
    }
}
