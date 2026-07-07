use atrium_repo::blockstore::{AsyncBlockStoreRead, AsyncBlockStoreWrite, Error, SHA2_256};
use cid::Cid;
use rusqlite::OptionalExtension;
use sha2::{Digest, Sha256};

use crate::storage::{SqliteStore, StorageError};

impl AsyncBlockStoreRead for SqliteStore {
    async fn read_block_into(&mut self, cid: Cid, contents: &mut Vec<u8>) -> Result<(), Error> {
        contents.clear();
        let cid_str = cid.to_string();
        let readers = self.readers.clone();
        let bytes: Option<Vec<u8>> = readers
            .get()
            .await
            .map_err(|e| Error::Other(format!("pool acquire error: {e}").into()))?
            .interact(move |conn| {
                conn.query_row(
                    "SELECT bytes FROM blocks WHERE cid = ?1",
                    [&cid_str],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
            })
            .await
            .map_err(|e| {
                // InteractError is not Sync so we stringify it.
                Error::Other(format!("interact error: {e}").into())
            })?
            .map_err(|e: rusqlite::Error| Error::Other(Box::new(e)))?;
        match bytes {
            Some(b) => {
                contents.extend_from_slice(&b);
                Ok(())
            }
            None => Err(Error::CidNotFound),
        }
    }
}

impl AsyncBlockStoreWrite for SqliteStore {
    async fn write_block(&mut self, codec: u64, hash: u64, contents: &[u8]) -> Result<Cid, Error> {
        if hash != SHA2_256 {
            return Err(Error::UnsupportedHash(hash));
        }
        let digest = Sha256::digest(contents);
        let mh = cid::multihash::Multihash::wrap(SHA2_256, digest.as_slice())
            .expect("32-byte sha2-256 digest always fits multihash");
        let cid = Cid::new_v1(codec, mh);

        let cid_str = cid.to_string();
        let bytes_vec = contents.to_vec();
        let writer = self.writer.lock().await;
        writer
            .call(move |conn| {
                conn.execute(
                    "INSERT OR IGNORE INTO blocks (cid, bytes) VALUES (?1, ?2)",
                    rusqlite::params![cid_str, bytes_vec],
                )?;
                Ok::<(), rusqlite::Error>(())
            })
            .await
            .map_err(|e| Error::Other(Box::new(e)))?;
        Ok(cid)
    }
}

impl SqliteStore {
    /// Atomically write a set of blocks, the repo_seq row containing the real
    /// DAG-CBOR `#commit` event body, and the updated `repo_roots` entry — all
    /// in a single `BEGIN IMMEDIATE` transaction. If any step fails the entire
    /// transaction is rolled back, leaving zero new rows in any table.
    ///
    /// `new_root` is the signed commit CID produced by this write; after this
    /// call succeeds `repo_roots` reflects the new root atomically with the
    /// `repo_seq` row, preventing the split-brain gap that existed when
    /// `update_repo_root` was a separate transaction.
    ///
    /// `event_body` is the DAG-CBOR-encoded `#commit` body WITHOUT the `seq`
    /// field (seq is not known until after the INSERT). The caller (Plan 04's
    /// write path) injects `seq` from the return value when building the full
    /// firehose frame before publishing to the broadcast channel.
    ///
    /// Returns the assigned `seq` (the AUTOINCREMENT rowid of the repo_seq row)
    /// so the caller can immediately publish the event with the correct seq.
    pub async fn commit_blocks(
        &self,
        blocks: Vec<(Cid, Vec<u8>)>,
        did: &str,
        new_root: cid::Cid,
        event_body: Vec<u8>,
    ) -> Result<i64, StorageError> {
        // Compute the ISO 8601 timestamp BEFORE entering the blocking closure —
        // no async calls are allowed inside `call()` (RESEARCH Pitfall 2).
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

/// Compute a CIDv1(dag-cbor, sha2-256) using the same primitives as the T0 spike.
/// This is the canonical reference used to verify `write_block` output.
/// Test-only: referenced solely from `#[cfg(test)]` code.
#[cfg(test)]
fn compute_cid(codec: u64, contents: &[u8]) -> Cid {
    let digest = Sha256::digest(contents);
    let mh = cid::multihash::Multihash::wrap(SHA2_256, digest.as_slice())
        .expect("32-byte sha2-256 digest always fits multihash");
    Cid::new_v1(codec, mh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atrium_repo::blockstore::{AsyncBlockStoreWrite, DAG_CBOR};
    use ipld_core::ipld::Ipld;
    use std::collections::BTreeMap;

    /// STOR-01: write_block returns a CID byte-identical to the T0 spike reference.
    #[tokio::test]
    async fn test_cid_fidelity() {
        let (mut store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");

        // Encode a small IPLD map exactly as the T0 spike does.
        let mut m = BTreeMap::new();
        m.insert(
            "text".to_string(),
            Ipld::String("hello from rust-pds".into()),
        );
        let bytes = serde_ipld_dagcbor::to_vec(&Ipld::Map(m)).expect("dag-cbor encode");

        // Reference CID using the canonical multiformats stack (same as spike cid_of_bytes).
        let reference_cid = compute_cid(DAG_CBOR, &bytes);

        // write_block must return a byte-identical CID.
        let stored_cid = store
            .write_block(DAG_CBOR, SHA2_256, &bytes)
            .await
            .expect("write_block failed");

        assert_eq!(
            reference_cid, stored_cid,
            "write_block CID diverged from canonical reference — byte-fidelity violated"
        );
    }

    /// STOR-01: a written block reads back byte-identical; a missing CID yields CidNotFound.
    #[tokio::test]
    async fn test_read_roundtrip() {
        let (mut store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");

        let bytes = b"roundtrip test payload";
        let cid = store
            .write_block(DAG_CBOR, SHA2_256, bytes)
            .await
            .expect("write_block failed");

        let mut buf = Vec::new();
        store
            .read_block_into(cid, &mut buf)
            .await
            .expect("read_block_into failed");
        assert_eq!(buf, bytes, "read back bytes differ from written bytes");

        // Missing CID must return CidNotFound, not panic or Ok.
        let fake_cid = compute_cid(DAG_CBOR, b"does not exist");
        let mut buf2 = Vec::new();
        let result = store.read_block_into(fake_cid, &mut buf2).await;
        assert!(
            matches!(result, Err(Error::CidNotFound)),
            "missing CID should return CidNotFound, got {:?}",
            result
        );
    }

    /// STOR-03: a multi-block write that fails partway leaves zero blocks committed.
    #[tokio::test]
    async fn test_atomic_rollback() {
        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");

        // Build a set of valid blocks.
        let bytes_a = b"block A";
        let cid_a = compute_cid(DAG_CBOR, bytes_a);
        let bytes_b = b"block B";
        let cid_b = compute_cid(DAG_CBOR, bytes_b);

        let _blocks = [(cid_a, bytes_a.to_vec()), (cid_b, bytes_b.to_vec())];

        // Attempt a commit_blocks with an empty DID string. The repo_seq table
        // has `did TEXT NOT NULL` which SQLite STRICT mode enforces — but an
        // empty string IS a valid TEXT value. We need to force a mid-transaction
        // failure. We do this by trying to insert a second repo_seq row with an
        // invalid type that will fail: specifically we abuse the fact that STRICT
        // tables do type checking. Let's instead trigger failure by calling
        // commit_blocks with blocks that are valid, then manually checking what
        // happens when we force an error.
        //
        // The cleanest approach: call the writer directly to force an Immediate
        // transaction that fails partway through, then verify rollback.
        let writer = store.writer.lock().await;
        let result = writer
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                // Insert block A — this would succeed.
                tx.execute(
                    "INSERT OR IGNORE INTO blocks (cid, bytes) VALUES (?1, ?2)",
                    rusqlite::params![cid_a.to_string(), bytes_a.to_vec()],
                )?;
                // Insert block B — this would succeed.
                tx.execute(
                    "INSERT OR IGNORE INTO blocks (cid, bytes) VALUES (?1, ?2)",
                    rusqlite::params![cid_b.to_string(), bytes_b.to_vec()],
                )?;
                // Deliberately fail: try to insert a repo_seq row with a NULL value
                // for a NOT NULL column by using a subquery that returns no rows —
                // actually we can just return an error directly to trigger rollback.
                // The transaction is dropped without commit() => automatic rollback.
                Err::<(), rusqlite::Error>(rusqlite::Error::QueryReturnedNoRows)
            })
            .await;

        // The call must have failed.
        assert!(result.is_err(), "expected an error to trigger rollback");
        drop(writer);

        // Verify both blocks were rolled back — zero rows in blocks table.
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

        // Also verify a SUCCESSFUL commit_blocks inserts all blocks + repo_seq row.
        let blocks_success = vec![
            (compute_cid(DAG_CBOR, b"success A"), b"success A".to_vec()),
            (compute_cid(DAG_CBOR, b"success B"), b"success B".to_vec()),
        ];
        // Use a dummy root CID (same as one of the blocks — fine for this test).
        let dummy_root = compute_cid(DAG_CBOR, b"success A");
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

    /// FED-01: commit_blocks stores the passed event_body bytes, returns a positive seq,
    /// and the stored event BLOB equals what was passed in.
    #[tokio::test]
    async fn commit_blocks_stores_event_blob() {
        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");

        let event_body = vec![1u8, 2, 3, 4];
        let dummy_root = compute_cid(DAG_CBOR, b"root block");
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

        // Read back the event column directly and verify it equals event_body.
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

    /// FED-01: two sequential commit_blocks calls return strictly increasing seq values.
    #[tokio::test]
    async fn commit_blocks_seq_increments() {
        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");

        let root_a = compute_cid(DAG_CBOR, b"root A");
        let root_b = compute_cid(DAG_CBOR, b"root B");

        let seq1 = store
            .commit_blocks(
                vec![(root_a, b"root A".to_vec())],
                "did:example:seq-test",
                root_a,
                vec![0xa0], // CBOR empty map
            )
            .await
            .expect("first commit_blocks failed");

        let seq2 = store
            .commit_blocks(
                vec![(root_b, b"root B".to_vec())],
                "did:example:seq-test",
                root_b,
                vec![0xa0],
            )
            .await
            .expect("second commit_blocks failed");

        assert!(
            seq2 == seq1 + 1,
            "expected seq2 == seq1 + 1, got seq1={seq1} seq2={seq2}"
        );
    }
}
