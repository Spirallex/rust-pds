use crate::storage::StorageError;

/// Errors from the repo write path. Crypto messages NEVER contain key bytes
/// (Security Domain V7 — established in Phase 1 keys.rs).
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("atrium repo error: {0}")]
    Repo(String),
    #[error("crypto error: {0}")]
    Crypto(String),
}
