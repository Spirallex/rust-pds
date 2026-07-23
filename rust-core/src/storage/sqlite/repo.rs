//! SQLite implementations of [`BlockStore`], [`Sequencer`], and [`RepoStore`].

use async_trait::async_trait;
use cid::Cid;
use rusqlite::OptionalExtension;

use crate::storage::sqlite::SqliteStore;
use crate::storage::{BlockStore, RepoStore, Sequencer, StorageError};

#[async_trait]
impl BlockStore for SqliteStore {
    async fn read_block_bytes(&self, cid: Cid) -> Result<Vec<u8>, StorageError> {
        let cid_str = cid.to_string();
        let conn = self.reader().await?;
        let bytes: Option<Vec<u8>> = conn
            .interact(move |c| {
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

    async fn put_block(&self, cid: Cid, bytes: Vec<u8>) -> Result<(), StorageError> {
        let cid_str = cid.to_string();
        let writer = self.writer.lock().await;
        writer
            .call(move |conn| {
                conn.execute(
                    "INSERT OR IGNORE INTO blocks (cid, bytes) VALUES (?1, ?2)",
                    rusqlite::params![cid_str, bytes],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }
}

#[async_trait]
impl Sequencer for SqliteStore {
    async fn max_seq(&self) -> Result<i64, StorageError> {
        let conn = self.reader().await?;
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

    /// Uses the reader pool — does not block the writer. The cursor is bound as a
    /// query parameter, never interpolated, because it arrives from an untrusted
    /// subscriber. The `LIMIT` cap keeps a `cursor=0` subscriber from pulling the
    /// entire log into memory.
    async fn backfill_page(
        &self,
        after_seq: i64,
        limit: i64,
    ) -> Result<Vec<(i64, Vec<u8>)>, StorageError> {
        let conn = self.reader().await?;
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
}

#[async_trait]
impl RepoStore for SqliteStore {
    /// Reads through the *writer* connection, not the reader pool, so the result
    /// never lags behind the latest commit by a WAL snapshot. Safe because the
    /// caller holds the per-DID write lock, so no concurrent write for this DID
    /// is in flight.
    async fn load_repo_root(&self, did: &str) -> Result<Option<Cid>, StorageError> {
        let did = did.to_string();
        let writer = self.writer.lock().await;
        let s: Option<String> = writer
            .call(move |c| {
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
                let cid = Cid::from_str(&cid_str)
                    .map_err(|e| StorageError::Crypto(format!("bad root cid: {e}")))?;
                Ok(Some(cid))
            }
        }
    }

    async fn update_repo_root(&self, did: &str, root_cid: Cid) -> Result<(), StorageError> {
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

    /// All three effects land in a single `BEGIN IMMEDIATE` transaction. If any
    /// step fails the whole thing rolls back, leaving zero new rows in any table —
    /// which is what prevents the split-brain gap that existed when the root
    /// update was a separate transaction from the block + seq write.
    async fn commit_blocks(
        &self,
        blocks: Vec<(Cid, Vec<u8>)>,
        did: &str,
        new_root: Cid,
        event_body: Vec<u8>,
    ) -> Result<i64, StorageError> {
        // Compute the ISO 8601 timestamp BEFORE entering the blocking closure —
        // no async calls are allowed inside `call()`.
        let now_iso = chrono::Utc::now().to_rfc3339();
        let did = did.to_string();
        let root_str = new_root.to_string();

        let writer = self.writer.lock().await;
        let seq = writer
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                for (cid, bytes) in blocks {
                    tx.execute(
                        "INSERT OR IGNORE INTO blocks (cid, bytes) VALUES (?1, ?2)",
                        rusqlite::params![cid.to_string(), bytes],
                    )?;
                }
                tx.execute(
                    "INSERT INTO repo_seq (did, event_type, event, invalidated, sequenced_at) \
                     VALUES (?1, 'append', ?2, 0, ?3)",
                    rusqlite::params![did, event_body, now_iso.clone()],
                )?;
                // Capture the assigned AUTOINCREMENT seq BEFORE commit().
                // rusqlite's Transaction derefs to Connection; last_insert_rowid()
                // returns the rowid of the most recent INSERT on this connection —
                // which is the repo_seq row because seq is INTEGER PRIMARY KEY AUTOINCREMENT.
                let seq = tx.last_insert_rowid();
                tx.execute(
                    "INSERT OR REPLACE INTO repo_roots (did, root_cid, updated_at) \
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![did, root_str, now_iso],
                )?;
                tx.commit()?;
                Ok(seq)
            })
            .await?;
        Ok(seq)
    }
}

/// SQLite-specific tests only.
///
/// The behavioural contract (read/write round-trips, idempotency, seq ordering,
/// backfill paging, root updates) is asserted once for every backend in
/// [`crate::storage::conformance`]. What remains here is the part that has no
/// cross-backend meaning: transaction rollback observed through the raw writer
/// connection, and the on-disk column layout.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::cid_of;
    use atrium_repo::blockstore::DAG_CBOR;

    /// STOR-03: a multi-block write that fails partway leaves zero blocks committed.
    #[tokio::test]
    async fn test_atomic_rollback() {
        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");

        let bytes_a = b"block A";
        let cid_a = cid_of(DAG_CBOR, bytes_a);
        let bytes_b = b"block B";
        let cid_b = cid_of(DAG_CBOR, bytes_b);

        // Force a mid-transaction failure by driving the writer directly and
        // returning Err after the block inserts. The un-committed transaction
        // rolls back on Drop, which is the property under test.
        let writer = store.writer.lock().await;
        let result = writer
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                tx.execute(
                    "INSERT OR IGNORE INTO blocks (cid, bytes) VALUES (?1, ?2)",
                    rusqlite::params![cid_a.to_string(), bytes_a.to_vec()],
                )?;
                tx.execute(
                    "INSERT OR IGNORE INTO blocks (cid, bytes) VALUES (?1, ?2)",
                    rusqlite::params![cid_b.to_string(), bytes_b.to_vec()],
                )?;
                Err::<(), rusqlite::Error>(rusqlite::Error::QueryReturnedNoRows)
            })
            .await;

        assert!(result.is_err(), "expected an error to trigger rollback");
        drop(writer);

        let block_count: i64 = store
            .writer
            .lock()
            .await
            .call(|conn| {
                conn.query_row("SELECT count(*) FROM blocks", [], |row| row.get(0))
                    .map_err(tokio_rusqlite::Error::Error)
            })
            .await
            .expect("count query failed");

        assert_eq!(
            block_count, 0,
            "rollback failed: {} blocks remain in the table after a failed transaction",
            block_count
        );

        // A SUCCESSFUL commit_blocks must insert all blocks + the repo_seq row.
        let blocks_success = vec![
            (cid_of(DAG_CBOR, b"success A"), b"success A".to_vec()),
            (cid_of(DAG_CBOR, b"success B"), b"success B".to_vec()),
        ];
        let dummy_root = cid_of(DAG_CBOR, b"success A");
        let _seq = store
            .commit_blocks(blocks_success, "did:example:test", dummy_root, vec![0xa0])
            .await
            .expect("successful commit_blocks failed");

        let (block_count_after, seq_count): (i64, i64) = store
            .writer
            .lock()
            .await
            .call(|conn| {
                let bc: i64 =
                    conn.query_row("SELECT count(*) FROM blocks", [], |row| row.get(0))?;
                let sc: i64 =
                    conn.query_row("SELECT count(*) FROM repo_seq", [], |row| row.get(0))?;
                Ok::<(i64, i64), rusqlite::Error>((bc, sc))
            })
            .await
            .expect("count query after commit failed");

        assert_eq!(
            block_count_after, 2,
            "expected 2 blocks after successful commit"
        );
        assert_eq!(
            seq_count, 1,
            "expected 1 repo_seq row after successful commit"
        );
    }

    /// commit_blocks stores the passed event_body bytes and returns a positive seq.
    #[tokio::test]
    async fn commit_blocks_stores_event_blob() {
        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");

        let event_body = vec![1u8, 2, 3, 4];
        let dummy_root = cid_of(DAG_CBOR, b"root block");
        let blocks = vec![(dummy_root, b"root block".to_vec())];

        let seq = store
            .commit_blocks(
                blocks,
                "did:example:blob-test",
                dummy_root,
                event_body.clone(),
            )
            .await
            .expect("commit_blocks failed");

        assert!(seq > 0, "returned seq must be positive, got {seq}");

        let stored_event: Vec<u8> = store
            .writer
            .lock()
            .await
            .call(move |conn| {
                conn.query_row(
                    "SELECT event FROM repo_seq WHERE seq = ?1",
                    rusqlite::params![seq],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(tokio_rusqlite::Error::Error)
            })
            .await
            .expect("query event failed");

        assert_eq!(
            stored_event, event_body,
            "stored event BLOB does not match passed event_body"
        );
    }
}
