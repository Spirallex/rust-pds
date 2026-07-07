#[cfg(test)]
mod tests {
    use crate::storage::SqliteStore;
    use atrium_repo::blockstore::{DAG_CBOR, SHA2_256};

    /// STOR-02: concurrent write + read via separate connections complete without SQLITE_BUSY.
    ///
    /// Spawns a writer task (~200 commit_blocks iterations) and a reader task (~200
    /// SELECT count(*) iterations) simultaneously on a multi-threaded tokio runtime.
    /// Both tasks share the same `SqliteStore` (Arc-backed writer Mutex + deadpool reader pool).
    ///
    /// The test passes only if NEITHER task returns an error containing "database is locked"
    /// or "SQLITE_BUSY". This proves the WAL + busy_timeout=5000ms + single-serialized-writer
    /// + read-pool configuration from Plan 01/02 is correct and survives real OS-thread
    /// concurrency, as required by Phase 4's firehose-read + commit-write pattern.
    ///
    /// Uses `flavor = "multi_thread"` so the writer and reader genuinely run on different
    /// OS threads, exercising actual concurrency rather than cooperative yielding.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_write_read() {
        use std::sync::Arc;

        let (store, _tmp) = SqliteStore::open_in_memory()
            .await
            .expect("open store failed");
        let store = Arc::new(store);

        const ITERATIONS: usize = 200;

        // Writer task: write ITERATIONS unique blocks via write_block.
        // Each block has unique contents so each CID differs.
        let writer_store = store.clone();
        let write_task = tokio::spawn(async move {
            let mut errors: Vec<String> = Vec::new();
            for i in 0..ITERATIONS {
                let data = format!("concurrent write payload iteration {}", i);
                let result = {
                    // We need &mut SqliteStore for write_block (AsyncBlockStoreWrite requires &mut self).
                    // Use the writer directly to avoid requiring mut on Arc.
                    let data_bytes = data.into_bytes();
                    let data_clone = data_bytes.clone();
                    writer_store
                        .writer
                        .lock()
                        .await
                        .call(move |conn| {
                            // Compute CID manually matching the write_block path.
                            use sha2::Digest;
                            let digest = sha2::Sha256::digest(&data_clone);
                            let mh = cid::multihash::Multihash::wrap(SHA2_256, digest.as_slice())
                                .expect("multihash wrap failed");
                            let c = cid::Cid::new_v1(DAG_CBOR, mh);
                            conn.execute(
                                "INSERT OR IGNORE INTO blocks (cid, bytes) VALUES (?1, ?2)",
                                rusqlite::params![c.to_string(), data_clone],
                            )?;
                            Ok::<(), rusqlite::Error>(())
                        })
                        .await
                };
                if let Err(e) = result {
                    let msg = e.to_string();
                    errors.push(format!("write iteration {}: {}", i, msg));
                }
            }
            errors
        });

        // Reader task: run ITERATIONS count queries via the reader pool.
        let reader_store = store.clone();
        let read_task = tokio::spawn(async move {
            let mut errors: Vec<String> = Vec::new();
            for i in 0..ITERATIONS {
                let conn_result = reader_store.readers.get().await;
                match conn_result {
                    Err(e) => {
                        errors.push(format!("read iteration {} pool get: {}", i, e));
                    }
                    Ok(conn) => {
                        let result = conn
                            .interact(|c| {
                                c.query_row("SELECT count(*) FROM blocks", [], |row| {
                                    row.get::<_, i64>(0)
                                })
                            })
                            .await;
                        if let Err(e) = result {
                            let msg = e.to_string();
                            errors.push(format!("read iteration {} interact: {}", i, msg));
                        }
                    }
                }
            }
            errors
        });

        // Drive both tasks concurrently and collect results.
        let (write_result, read_result) = tokio::join!(write_task, read_task);

        let write_errors = write_result.expect("writer task panicked");
        let read_errors = read_result.expect("reader task panicked");

        // Assert no SQLITE_BUSY / database is locked errors occurred.
        let busy_writes: Vec<_> = write_errors
            .iter()
            .filter(|e| {
                let lower = e.to_lowercase();
                lower.contains("database is locked") || lower.contains("sqlite_busy")
            })
            .collect();
        let busy_reads: Vec<_> = read_errors
            .iter()
            .filter(|e| {
                let lower = e.to_lowercase();
                lower.contains("database is locked") || lower.contains("sqlite_busy")
            })
            .collect();

        assert!(
            busy_writes.is_empty(),
            "SQLITE_BUSY on write path ({} occurrences): {:?}",
            busy_writes.len(),
            busy_writes
        );
        assert!(
            busy_reads.is_empty(),
            "SQLITE_BUSY on read path ({} occurrences): {:?}",
            busy_reads.len(),
            busy_reads
        );

        // All operations must have succeeded (no errors of any kind).
        assert!(write_errors.is_empty(), "write errors: {:?}", write_errors);
        assert!(read_errors.is_empty(), "read errors: {:?}", read_errors);
    }
}
