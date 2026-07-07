pub mod backup;
pub mod block_store;
pub mod db;
pub mod keys;
pub mod schema;

#[cfg(test)]
mod concurrency;

pub use db::{AccountSummary, SqliteStore};

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("async sqlite error: {0}")]
    AsyncSqlite(#[from] tokio_rusqlite::Error),
    #[error("pool error: {0}")]
    Pool(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("block not found")]
    BlockNotFound,
}
