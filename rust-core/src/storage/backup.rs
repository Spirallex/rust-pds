use crate::storage::StorageError;

/// Export the encrypted key blob for `id` from the store as a portable byte sequence.
///
/// Validates the passphrase before emitting any output. The passphrase is never
/// serialized into the output blob — the blob carries only ciphertext.
///
/// See `crate::storage::keys::export_keys` for the detailed blob layout.
pub async fn export_keys(
    store: &crate::storage::SqliteStore,
    id: &str,
    passphrase: &[u8],
) -> Result<Vec<u8>, StorageError> {
    crate::storage::keys::export_keys(store, id, passphrase).await
}

/// Import a key blob produced by `export_keys` into this store under `id`.
///
/// Parses the portable layout, validates the passphrase by attempting decryption,
/// then writes the ciphertext via `INSERT OR REPLACE INTO keys`. Returns
/// `StorageError::Crypto` on wrong passphrase or malformed blob — never panics.
///
/// Portable layout (same as `export_keys` output):
/// ```text
/// [ id_len: u32 le ] [ id_bytes ] [ cipher_len: u32 le ] [ ciphertext ]
/// ```
pub async fn import_keys(
    store: &crate::storage::SqliteStore,
    id: &str,
    export_blob: &[u8],
    passphrase: &[u8],
) -> Result<(), StorageError> {
    use crate::storage::keys::decrypt_key;

    // Parse the portable layout to extract the embedded ciphertext.
    if export_blob.len() < 8 {
        return Err(StorageError::Crypto("export blob too short".into()));
    }
    let id_len = u32::from_le_bytes(export_blob[0..4].try_into().unwrap()) as usize;
    let id_end = 4 + id_len;
    if export_blob.len() < id_end + 4 {
        return Err(StorageError::Crypto("export blob truncated at id".into()));
    }
    let cipher_len =
        u32::from_le_bytes(export_blob[id_end..id_end + 4].try_into().unwrap()) as usize;
    let cipher_start = id_end + 4;
    let cipher_end = cipher_start + cipher_len;
    if export_blob.len() < cipher_end {
        return Err(StorageError::Crypto(
            "export blob truncated at ciphertext".into(),
        ));
    }
    let ciphertext = export_blob[cipher_start..cipher_end].to_vec();

    // Validate the passphrase before writing — fail cleanly on wrong passphrase.
    let _ = decrypt_key(&ciphertext, passphrase)?;

    // Persist the validated ciphertext into this store.
    let id_owned = id.to_string();
    let writer = store.writer.lock().await;
    writer
        .call(move |conn| {
            conn.execute(
                "INSERT OR REPLACE INTO keys (id, ciphertext) VALUES (?1, ?2)",
                rusqlite::params![id_owned, ciphertext],
            )?;
            Ok::<(), rusqlite::Error>(())
        })
        .await?;
    Ok(())
}

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
pub async fn backup_to_path(
    store: &crate::storage::SqliteStore,
    dest_path: &str,
) -> Result<(), StorageError> {
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
    use crate::storage::SqliteStore;
    use atrium_repo::blockstore::{AsyncBlockStoreWrite, DAG_CBOR, SHA2_256};

    /// STOR-04: backup file must be a readable SQLite DB with the same block count as source.
    #[tokio::test]
    async fn test_backup_roundtrip() {
        let (mut store, _tmp) = SqliteStore::open_in_memory()
            .await
            .expect("open store failed");

        // Write a couple of blocks to the source store.
        store
            .write_block(DAG_CBOR, SHA2_256, b"block 1 data")
            .await
            .expect("write block 1 failed");
        store
            .write_block(DAG_CBOR, SHA2_256, b"block 2 data")
            .await
            .expect("write block 2 failed");

        // Create a named temp file for the backup destination.
        let dest_tmp = tempfile::NamedTempFile::new().expect("temp file creation failed");
        let dest_path = dest_tmp.path().to_str().unwrap().to_string();

        backup_to_path(&store, &dest_path)
            .await
            .expect("backup_to_path failed");

        // Open the backup and verify the block count matches.
        let backup_conn = rusqlite::Connection::open(&dest_path).expect("open backup db failed");
        let count: i64 = backup_conn
            .query_row("SELECT count(*) FROM blocks", [], |row| row.get(0))
            .expect("count query on backup failed");

        assert_eq!(count, 2, "backup should have 2 blocks, found {}", count);
    }
}
