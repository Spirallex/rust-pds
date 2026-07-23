//! Storage: backend-agnostic traits plus the backends that implement them.
//!
//! The rest of the crate talks to [`StorageBackend`] and never names a concrete
//! backend. [`sqlite::SqliteStore`] is production; [`memory::MemoryStore`] is for
//! tests and for hosts that cannot link a C SQLite.
//!
//! See [`traits`] for why the traits are sliced the way they are, and
//! [`conformance`] for the shared behavioural suite both backends must pass.

pub mod adapter;
pub mod conformance;
pub mod crypto;
pub mod memory;
pub mod traits;

#[cfg(feature = "sqlite")]
pub mod sqlite;

pub use adapter::{cid_of, BlockStoreAdapter};
pub use memory::MemoryStore;
pub use traits::{
    AccountStore, AccountSummary, BlobStore, BlockStore, KeyStore, RepoStore, Sequencer,
    StorageBackend,
};

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteStore;

/// Errors returned by every storage backend.
///
/// Backend-specific variants are feature-gated; everything the rest of the crate
/// matches on ([`StorageError::BlockNotFound`], [`StorageError::Constraint`],
/// [`StorageError::Crypto`]) is backend-neutral, so call sites never need to know
/// which backend is underneath.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[cfg(feature = "sqlite")]
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[cfg(feature = "sqlite")]
    #[error("async sqlite error: {0}")]
    AsyncSqlite(#[from] tokio_rusqlite::Error),
    #[error("pool error: {0}")]
    Pool(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("block not found")]
    BlockNotFound,
    /// A uniqueness or referential constraint was violated — a duplicate DID or
    /// an already-taken handle. Backend-neutral so callers can distinguish "this
    /// row already exists" from a genuine backend failure without matching on
    /// SQLite error codes.
    #[error("constraint violation: {0}")]
    Constraint(String),
}
