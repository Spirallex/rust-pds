//! SQLite online backup — deliberately *not* part of the storage traits.
//!
//! `sqlite3_backup` has no cross-backend meaning: an R2 or Durable Object
//! backend would snapshot by entirely different means. Keeping this off the
//! trait avoids inventing a lowest-common-denominator `backup()` that every
//! future backend would have to fake.
//!
//! Portable key export/import lives in [`crate::storage::crypto`] instead, since
//! that genuinely works against any [`crate::storage::KeyStore`].

use crate::storage::sqlite::SqliteStore;
use crate::storage::StorageError;

/// Backup the source store to `dest_path` using the SQLite online backup API.
///
/// WAL-safe: uses `rusqlite::backup::Backup::run_to_completion`, which takes a
/// snapshot-consistent incremental copy of the live database — including any
/// WAL frames not yet checkpointed. This is the only correct way to backup a
/// WAL-mode SQLite database. Raw filesystem copy operations must never be used
/// because the -wal sidecar represents uncommitted state and is not captured
/// atomically with the main file.
///
/// The implementation acquires the single writer mutex so that the backup
/// connection is the sole writer during the call closure, matching the
/// single-writer invariant of `SqliteStore`.
pub async fn backup_to_path(store: &SqliteStore, dest_path: &str) -> Result<(), StorageError> {
    let dest_path = dest_path.to_string();
    let writer = store.writer.lock().await;
    writer
        .call(move |src_conn| {
            let mut dest = rusqlite::Connection::open(&dest_path)?;
            let backup = rusqlite::backup::Backup::new(src_conn, &mut dest)?;
            // TODO: for large DBs the backup should step with periodic
            // mutex release so live firehose writes are not stalled for minutes.
            // Replace run_to_completion with a manual step loop that releases and
            // re-acquires the writer mutex between steps.
            backup.run_to_completion(
                200,                       // larger step = fewer round-trips
                std::time::Duration::ZERO, // no artificial sleep — backup as fast as possible
                None::<fn(rusqlite::backup::Progress)>,
            )?;
            Ok(())
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::cid_of;
    use crate::storage::BlockStore;
    use atrium_repo::blockstore::DAG_CBOR;

    /// STOR-04: backup file must be a readable SQLite DB with the same block count as source.
    #[tokio::test]
    async fn test_backup_roundtrip() {
        let (store, _tmp) = SqliteStore::open_in_memory()
            .await
            .expect("open store failed");

        for payload in [b"block 1 data".as_slice(), b"block 2 data".as_slice()] {
            store
                .put_block(cid_of(DAG_CBOR, payload), payload.to_vec())
                .await
                .expect("put_block failed");
        }

        let dest_tmp = tempfile::NamedTempFile::new().expect("temp file creation failed");
        let dest_path = dest_tmp.path().to_str().unwrap().to_string();

        backup_to_path(&store, &dest_path)
            .await
            .expect("backup_to_path failed");

        let backup_conn = rusqlite::Connection::open(&dest_path).expect("open backup db failed");
        let count: i64 = backup_conn
            .query_row("SELECT count(*) FROM blocks", [], |row| row.get(0))
            .expect("count query on backup failed");

        assert_eq!(count, 2, "backup should have 2 blocks, found {}", count);
    }
}
