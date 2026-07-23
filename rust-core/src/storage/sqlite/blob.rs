//! SQLite implementation of [`BlobStore`] — user uploads keyed by `(did, cid)`.

use async_trait::async_trait;
use rusqlite::OptionalExtension;

use crate::storage::sqlite::SqliteStore;
use crate::storage::{BlobStore, StorageError};

#[async_trait]
impl BlobStore for SqliteStore {
    async fn put_blob(
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

    async fn get_blob(
        &self,
        did: &str,
        cid: &str,
    ) -> Result<Option<(String, Vec<u8>)>, StorageError> {
        let did = did.to_string();
        let cid = cid.to_string();
        let conn = self.reader().await?;
        let row: Option<(String, Vec<u8>)> = conn
            .interact(move |c| {
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
}
