//! Storage backend traits.
//!
//! These describe everything the repo engine, auth layer, and XRPC handlers need
//! from persistence — and nothing about *how* it is persisted. `SqliteStore` is
//! the production implementation; `MemoryStore` is the in-process one used by
//! tests and by builds that cannot link a C SQLite (notably `wasm32-*`).
//!
//! # Why the traits are sliced this way
//!
//! The cut lines follow transaction boundaries, not tidiness. [`RepoStore`] owns
//! blocks, roots, and the sequencer together because [`RepoStore::commit_blocks`]
//! must write all three atomically — a backend that could not do so would fork
//! repo history on a partial failure, which is precisely the bug the single
//! writer transaction exists to prevent. Splitting `commit_blocks` across
//! [`BlockStore`] and [`Sequencer`] would make that atomicity unexpressible, so
//! those two traits carry only the independently-safe read paths.
//!
//! [`AccountStore`], [`KeyStore`], and [`BlobStore`] are genuinely independent
//! domains and are split accordingly.
//!
//! # Dyn-safety
//!
//! Every trait here is object-safe via `#[async_trait]`, because `AppState` holds
//! one `Arc<dyn StorageBackend>` rather than being generic over the backend. That
//! keeps the type parameter out of ~30 handler signatures and the axum extractors
//! at the cost of one vtable dispatch per call — negligible next to the I/O each
//! call performs.
//!
//! Note that `atrium_repo`'s `AsyncBlockStoreRead`/`AsyncBlockStoreWrite` are
//! *not* object-safe (they use `async fn` in trait / RPITIT). The bridge lives in
//! [`crate::storage::adapter::BlockStoreAdapter`], which is a concrete type
//! wrapping `Arc<dyn StorageBackend>`.

use async_trait::async_trait;
use cid::Cid;

use crate::storage::StorageError;

/// One row of [`AccountStore::list_accounts`] — an account as the operator sees
/// it, including deactivated / taken-down rows that the auth-path lookups hide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSummary {
    pub did: String,
    pub handle: Option<String>,
    pub deactivated_at: Option<String>,
    pub takedown_ref: Option<String>,
    pub created_at: String,
}

/// Content-addressed block storage: the raw CID → bytes map underneath the MST.
///
/// Implementations must treat writes as idempotent — writing the same CID twice
/// is a no-op, never an error — because the MST re-emits unchanged interior
/// nodes on every commit.
#[async_trait]
pub trait BlockStore: Send + Sync {
    /// Read one block's raw bytes by CID.
    ///
    /// Returns [`StorageError::BlockNotFound`] if the CID is absent, never a
    /// backend-specific "no rows" error.
    async fn read_block_bytes(&self, cid: Cid) -> Result<Vec<u8>, StorageError>;

    /// Persist one block. Idempotent: re-writing an existing CID succeeds
    /// without modifying the stored bytes.
    ///
    /// The CID is supplied by the caller rather than computed here so that the
    /// hashing stays in one place ([`crate::storage::adapter`]) and cannot drift
    /// between backends.
    async fn put_block(&self, cid: Cid, bytes: Vec<u8>) -> Result<(), StorageError>;
}

/// Firehose event-log reads.
///
/// The log is append-only and totally ordered by `seq`. Writes go exclusively
/// through [`RepoStore::commit_blocks`], which is what makes `seq` monotonic —
/// there is deliberately no standalone `append` method here.
#[async_trait]
pub trait Sequencer: Send + Sync {
    /// Highest assigned sequence number, or 0 if the log is empty.
    ///
    /// Used for the `subscribeRepos` FutureCursor check (a cursor beyond
    /// `max_seq` is a client error, not an empty backfill).
    async fn max_seq(&self) -> Result<i64, StorageError>;

    /// One page of backfill for a subscriber: events with `seq > after_seq`, not
    /// invalidated, ascending, capped at `limit`.
    ///
    /// `limit` is a hard cap the implementation must honour — it is the only
    /// thing standing between a `cursor=0` subscriber and the whole log in
    /// memory.
    async fn backfill_page(
        &self,
        after_seq: i64,
        limit: i64,
    ) -> Result<Vec<(i64, Vec<u8>)>, StorageError>;
}

/// The repo write path: blocks, root pointers, and the firehose log as one
/// transactional domain.
#[async_trait]
pub trait RepoStore: BlockStore + Sequencer {
    /// Latest signed-commit CID for `did`, or `None` if the repo has no commits.
    ///
    /// Must observe the most recent successful [`Self::commit_blocks`] with no
    /// replication or snapshot lag — the write path reads this to build the next
    /// commit, so a stale answer forks history. Callers hold a per-DID lock
    /// across load → commit, but that lock cannot compensate for a backend that
    /// serves a stale root.
    async fn load_repo_root(&self, did: &str) -> Result<Option<Cid>, StorageError>;

    /// Overwrite the stored root CID for `did`.
    ///
    /// Only for out-of-band repair (imports, admin tooling). The normal write
    /// path updates the root inside [`Self::commit_blocks`] instead, so that the
    /// root and the firehose row can never disagree.
    async fn update_repo_root(&self, did: &str, root_cid: Cid) -> Result<(), StorageError>;

    /// Atomically persist `blocks`, append one `repo_seq` row carrying
    /// `event_body`, and set `repo_roots[did] = new_root`.
    ///
    /// Returns the assigned `seq` so the caller can inject it into the `#commit`
    /// frame before publishing. `event_body` is the DAG-CBOR `#commit` body
    /// *without* `seq`, since `seq` is not known until the row is appended.
    ///
    /// # Atomicity
    ///
    /// All three effects commit together or none do. A backend that cannot
    /// guarantee this must not implement `RepoStore`: a partial apply leaves the
    /// root pointing at a commit whose blocks or firehose row are missing, which
    /// breaks `getRepo` and desynchronises every downstream relay.
    async fn commit_blocks(
        &self,
        blocks: Vec<(Cid, Vec<u8>)>,
        did: &str,
        new_root: Cid,
        event_body: Vec<u8>,
    ) -> Result<i64, StorageError>;
}

/// Accounts, invite codes, and per-account AppView preferences.
#[async_trait]
pub trait AccountStore: Send + Sync {
    /// Total account count. Diagnostic only.
    ///
    /// Do **not** use this to gate first-account registration — the read is not
    /// serialized against a subsequent insert. [`Self::count_and_insert_account`]
    /// exists for that and closes the TOCTOU window.
    async fn count_accounts(&self) -> Result<i64, StorageError>;

    /// Insert an account. `password_phc` must be an argon2id PHC string from
    /// [`crate::auth::jwt::hash_password`].
    async fn insert_account(
        &self,
        did: &str,
        handle: &str,
        email: Option<&str>,
        password_phc: &str,
    ) -> Result<(), StorageError>;

    /// Atomically count existing accounts and insert a new one, returning the
    /// count *before* the insert.
    ///
    /// The count and the insert must be one transaction so two concurrent
    /// first-registrations cannot both observe 0 and both claim the server.
    async fn count_and_insert_account(
        &self,
        did: &str,
        handle: &str,
        email: Option<&str>,
        password_phc: &str,
    ) -> Result<i64, StorageError>;

    /// Look up `(did, password_phc)` by handle, for the login path.
    ///
    /// Must exclude deactivated and taken-down accounts — this is an auth-path
    /// lookup and a taken-down account must not be able to authenticate.
    async fn get_account_by_handle(
        &self,
        handle: &str,
    ) -> Result<Option<(String, String)>, StorageError>;

    /// Resolve handle → DID. Excludes deactivated / taken-down accounts.
    async fn get_did_by_handle(&self, handle: &str) -> Result<Option<String>, StorageError>;

    /// Resolve DID → handle. Excludes deactivated / taken-down accounts.
    async fn get_handle_by_did(&self, did: &str) -> Result<Option<String>, StorageError>;

    /// Every account including deactivated and taken-down ones, oldest first.
    /// Operator view — deliberately unfiltered, unlike the auth-path lookups.
    async fn list_accounts(&self) -> Result<Vec<AccountSummary>, StorageError>;

    /// Replace an account's password hash. Returns rows affected (0 = no such DID).
    async fn update_password(&self, did: &str, password_phc: &str) -> Result<u64, StorageError>;

    /// Mark an account taken down. A non-null `takedown_ref` must hide the
    /// account from every auth-path lookup above. Returns rows affected.
    async fn set_takedown(&self, did: &str, reference: &str) -> Result<u64, StorageError>;

    /// Clear a takedown, restoring the account. Returns rows affected.
    async fn clear_takedown(&self, did: &str) -> Result<u64, StorageError>;

    /// Seed an invite code.
    async fn insert_invite(
        &self,
        code: &str,
        available_uses: i64,
        for_account: &str,
    ) -> Result<(), StorageError>;

    /// Atomically consume one use of `code` on behalf of `used_by`.
    ///
    /// Returns `false` — not an error — when the code is unknown, disabled,
    /// exhausted, or already used by this DID. The check and the decrement must
    /// be one transaction, or a code with one remaining use can be redeemed
    /// twice concurrently.
    async fn consume_invite(&self, code: &str, used_by: &str) -> Result<bool, StorageError>;

    /// Replace the opaque preferences JSON array for `did`.
    async fn upsert_preferences(&self, did: &str, prefs_json: &str) -> Result<(), StorageError>;

    /// Stored preferences JSON array for `did`, or `None` if never set.
    async fn get_preferences(&self, did: &str) -> Result<Option<String>, StorageError>;
}

/// Encrypted key-blob storage.
///
/// This trait moves *ciphertext* only. Encryption and decryption live in
/// [`crate::storage::crypto`] so that every backend gets identical, audited
/// crypto and a backend can never accidentally persist plaintext key material.
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Store a ciphertext blob under `id`, replacing any existing entry.
    async fn put_key_blob(&self, id: &str, ciphertext: Vec<u8>) -> Result<(), StorageError>;

    /// Fetch the ciphertext blob for `id`, or `None` if absent.
    async fn get_key_blob(&self, id: &str) -> Result<Option<Vec<u8>>, StorageError>;
}

/// User-uploaded blob storage (avatars, images, video) keyed by `(did, cid)`.
///
/// Keyed per-account rather than globally so two accounts holding the same
/// content-addressed bytes remain independently deletable.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Store a blob, replacing any existing `(did, cid)` entry.
    async fn put_blob(
        &self,
        did: &str,
        cid: &str,
        mime_type: &str,
        size: i64,
        bytes: Vec<u8>,
    ) -> Result<(), StorageError>;

    /// Fetch `(mime_type, bytes)` for `(did, cid)`, or `None`.
    async fn get_blob(
        &self,
        did: &str,
        cid: &str,
    ) -> Result<Option<(String, Vec<u8>)>, StorageError>;
}

/// Everything a PDS needs from persistence, in one object-safe bundle.
///
/// `AppState` holds an `Arc<dyn StorageBackend>`. The blanket impl below means
/// any type implementing the component traits is automatically a
/// `StorageBackend` — implementors never name this trait.
///
/// [`crate::oauth::OAuthStore`] is included so the OAuth endpoints can reach
/// their state through the same handle as everything else, rather than the
/// server having to thread a second store around.
pub trait StorageBackend:
    RepoStore + AccountStore + KeyStore + BlobStore + crate::oauth::OAuthStore
{
}

impl<T> StorageBackend for T where
    T: RepoStore + AccountStore + KeyStore + BlobStore + crate::oauth::OAuthStore
{
}
