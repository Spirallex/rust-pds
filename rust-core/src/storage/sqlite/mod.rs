//! SQLite storage backend — the production implementation of
//! [`crate::storage::StorageBackend`].
//!
//! Layout mirrors the trait slicing: [`repo`] implements the block / root /
//! sequencer path, [`account`] the account and invite path, [`keys`] the
//! encrypted key-blob path, and [`blob`] user uploads. [`backup`] holds the one
//! operation that is deliberately *not* on a trait — the SQLite online-backup
//! API has no cross-backend meaning.

pub mod account;
pub mod backup;
pub mod blob;
pub mod keys;
pub mod oauth;
pub mod repo;
pub mod schema;

#[cfg(test)]
mod concurrency;

use std::sync::Arc;

use deadpool_sqlite::{Config, Hook, HookError, Runtime};
use tokio::sync::Mutex;
use tokio_rusqlite::Connection;

use crate::storage::StorageError;

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

    /// Acquire a pooled reader connection, mapping pool errors to [`StorageError::Pool`].
    ///
    /// Every read path goes through here so the pool-error mapping exists in one
    /// place rather than being repeated at ~15 call sites.
    pub(crate) async fn reader(&self) -> Result<deadpool_sqlite::Object, StorageError> {
        self.readers
            .get()
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))
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

    /// Return the event BLOB of the most recently inserted repo_seq row.
    /// Used in tests to assert that the stored event body is the real #commit body.
    #[cfg(test)]
    pub async fn last_event_body(&self) -> Result<Option<Vec<u8>>, StorageError> {
        let conn = self.reader().await?;
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
        let conn = self.reader().await?;
        let n: i64 = conn
            .interact(|c| c.query_row("SELECT count(*) FROM repo_seq", [], |r| r.get(0)))
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?;
        Ok(n)
    }
}

/// Build a SQLite backend for the shared conformance suite.
///
/// The returned guard is the backing `NamedTempFile` — dropping it deletes the
/// database, so each generated test must hold it for its duration.
#[cfg(test)]
async fn conformance_setup() -> (
    Arc<dyn crate::storage::StorageBackend>,
    Box<dyn std::any::Any + Send>,
) {
    let (store, tmp) = SqliteStore::open_in_memory()
        .await
        .expect("open_in_memory failed");
    (Arc::new(store), Box::new(tmp))
}

#[cfg(test)]
crate::storage_conformance_tests!(conformance_setup);

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
}
