//! SQLite implementation of [`KeyStore`].
//!
//! Ciphertext in, ciphertext out — the argon2id + AES-256-GCM envelope lives in
//! [`crate::storage::crypto`] so no backend can accidentally persist plaintext
//! key material.

use async_trait::async_trait;
use rusqlite::OptionalExtension;

use crate::storage::sqlite::SqliteStore;
use crate::storage::{KeyStore, StorageError};

#[async_trait]
impl KeyStore for SqliteStore {
    async fn put_key_blob(&self, id: &str, ciphertext: Vec<u8>) -> Result<(), StorageError> {
        let id = id.to_string();
        let writer = self.writer.lock().await;
        writer
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO keys (id, ciphertext) VALUES (?1, ?2)",
                    rusqlite::params![id, ciphertext],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    async fn get_key_blob(&self, id: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let id = id.to_string();
        let conn = self.reader().await?;
        let blob: Option<Vec<u8>> = conn
            .interact(move |c| {
                c.query_row(
                    "SELECT ciphertext FROM keys WHERE id = ?1",
                    rusqlite::params![id],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()
            })
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?;
        Ok(blob)
    }
}
