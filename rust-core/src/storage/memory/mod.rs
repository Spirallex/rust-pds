//! In-memory storage backend.
//!
//! Two jobs. First, it is the second implementation that keeps
//! [`crate::storage::traits`] honest — a trait with a single implementor
//! inevitably leaks that implementor's assumptions, and the shared conformance
//! suite in [`crate::storage::conformance`] runs against both backends to catch
//! exactly that. Second, it gives tests a backend with no C dependency and no
//! temp files, and gives `stelyph-core` a build path that does not link SQLite.
//!
//! # Concurrency model
//!
//! Everything lives under one `tokio::sync::Mutex<Inner>`. That is a stricter
//! discipline than the SQLite backend (which allows concurrent readers), but it
//! makes the multi-table atomicity that [`crate::storage::RepoStore::commit_blocks`]
//! and `consume_invite` require fall out for free: a single guard held across the
//! whole mutation is exactly a `BEGIN IMMEDIATE` transaction. Since the guard is
//! never held across an `.await` on anything but itself, it cannot deadlock.
//!
//! # Not for production
//!
//! Nothing here is durable. It is for tests and for hosts that supply durability
//! at another layer.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use cid::Cid;
use tokio::sync::Mutex;

use crate::storage::{
    AccountStore, AccountSummary, BlobStore, BlockStore, KeyStore, RepoStore, Sequencer,
    StorageError,
};

/// An account row.
#[derive(Debug, Clone)]
struct Account {
    did: String,
    handle: Option<String>,
    #[allow(dead_code)] // stored for parity with the SQLite schema; no reader yet
    email: Option<String>,
    password_phc: String,
    created_at: String,
    deactivated_at: Option<String>,
    takedown_ref: Option<String>,
    /// Monotonic insertion index. `list_accounts` sorts by `(created_at, ordinal)`
    /// so that accounts created within the same clock tick still come back in a
    /// stable, insertion-consistent order — an ISO-8601 timestamp alone is not a
    /// total order at this granularity.
    ordinal: u64,
}

/// An invite code row.
#[derive(Debug, Clone)]
struct Invite {
    available_uses: i64,
    disabled: bool,
}

/// One appended firehose event.
#[derive(Debug, Clone)]
struct SeqRow {
    seq: i64,
    event: Vec<u8>,
    invalidated: bool,
}

#[derive(Default)]
struct Inner {
    blocks: HashMap<Cid, Vec<u8>>,
    repo_seq: Vec<SeqRow>,
    next_seq: i64,
    repo_roots: HashMap<String, Cid>,
    accounts: HashMap<String, Account>,
    next_ordinal: u64,
    invites: HashMap<String, Invite>,
    invite_uses: HashSet<(String, String)>,
    keys: HashMap<String, Vec<u8>>,
    blobs: HashMap<(String, String), (String, Vec<u8>)>,
    prefs: HashMap<String, String>,
}

impl Inner {
    /// Resolve an account that is visible to the auth path — i.e. neither
    /// deactivated nor taken down. Every auth-facing lookup goes through this so
    /// the visibility rule exists once and cannot drift between methods.
    fn active(&self, did: &str) -> Option<&Account> {
        self.accounts
            .get(did)
            .filter(|a| a.deactivated_at.is_none() && a.takedown_ref.is_none())
    }

    fn active_by_handle(&self, handle: &str) -> Option<&Account> {
        self.accounts
            .values()
            .find(|a| a.handle.as_deref() == Some(handle))
            .filter(|a| a.deactivated_at.is_none() && a.takedown_ref.is_none())
    }
}

/// In-memory [`crate::storage::StorageBackend`]. Cloning shares the same data.
#[derive(Clone, Default)]
pub struct MemoryStore {
    inner: Arc<Mutex<Inner>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// Repo path: blocks, roots, sequencer
// ---------------------------------------------------------------------------

#[async_trait]
impl BlockStore for MemoryStore {
    async fn read_block_bytes(&self, cid: Cid) -> Result<Vec<u8>, StorageError> {
        self.inner
            .lock()
            .await
            .blocks
            .get(&cid)
            .cloned()
            .ok_or(StorageError::BlockNotFound)
    }

    async fn put_block(&self, cid: Cid, bytes: Vec<u8>) -> Result<(), StorageError> {
        // `or_insert` not `insert`: idempotent, matching INSERT OR IGNORE. Blocks
        // are content-addressed, so an existing entry already holds these bytes.
        self.inner.lock().await.blocks.entry(cid).or_insert(bytes);
        Ok(())
    }
}

#[async_trait]
impl Sequencer for MemoryStore {
    async fn max_seq(&self) -> Result<i64, StorageError> {
        let g = self.inner.lock().await;
        Ok(g.repo_seq.last().map(|r| r.seq).unwrap_or(0))
    }

    async fn backfill_page(
        &self,
        after_seq: i64,
        limit: i64,
    ) -> Result<Vec<(i64, Vec<u8>)>, StorageError> {
        let g = self.inner.lock().await;
        Ok(g.repo_seq
            .iter()
            .filter(|r| r.seq > after_seq && !r.invalidated)
            .take(limit.max(0) as usize)
            .map(|r| (r.seq, r.event.clone()))
            .collect())
    }
}

#[async_trait]
impl RepoStore for MemoryStore {
    async fn load_repo_root(&self, did: &str) -> Result<Option<Cid>, StorageError> {
        Ok(self.inner.lock().await.repo_roots.get(did).copied())
    }

    async fn update_repo_root(&self, did: &str, root_cid: Cid) -> Result<(), StorageError> {
        self.inner
            .lock()
            .await
            .repo_roots
            .insert(did.to_string(), root_cid);
        Ok(())
    }

    async fn commit_blocks(
        &self,
        blocks: Vec<(Cid, Vec<u8>)>,
        did: &str,
        new_root: Cid,
        event_body: Vec<u8>,
    ) -> Result<i64, StorageError> {
        // One guard across all three mutations == one transaction. Nothing here
        // can fail partway, so there is no rollback path to get wrong.
        let mut g = self.inner.lock().await;
        for (cid, bytes) in blocks {
            g.blocks.entry(cid).or_insert(bytes);
        }
        g.next_seq += 1;
        let seq = g.next_seq;
        g.repo_seq.push(SeqRow {
            seq,
            event: event_body,
            invalidated: false,
        });
        g.repo_roots.insert(did.to_string(), new_root);
        Ok(seq)
    }
}

// ---------------------------------------------------------------------------
// Accounts, invites, preferences
// ---------------------------------------------------------------------------

#[async_trait]
impl AccountStore for MemoryStore {
    async fn count_accounts(&self) -> Result<i64, StorageError> {
        Ok(self.inner.lock().await.accounts.len() as i64)
    }

    async fn insert_account(
        &self,
        did: &str,
        handle: &str,
        email: Option<&str>,
        password_phc: &str,
    ) -> Result<(), StorageError> {
        let mut g = self.inner.lock().await;
        insert_account_locked(&mut g, did, handle, email, password_phc)
    }

    async fn count_and_insert_account(
        &self,
        did: &str,
        handle: &str,
        email: Option<&str>,
        password_phc: &str,
    ) -> Result<i64, StorageError> {
        let mut g = self.inner.lock().await;
        let before = g.accounts.len() as i64;
        insert_account_locked(&mut g, did, handle, email, password_phc)?;
        Ok(before)
    }

    async fn get_account_by_handle(
        &self,
        handle: &str,
    ) -> Result<Option<(String, String)>, StorageError> {
        let g = self.inner.lock().await;
        Ok(g.active_by_handle(handle)
            .map(|a| (a.did.clone(), a.password_phc.clone())))
    }

    async fn get_did_by_handle(&self, handle: &str) -> Result<Option<String>, StorageError> {
        let g = self.inner.lock().await;
        Ok(g.active_by_handle(handle).map(|a| a.did.clone()))
    }

    async fn get_handle_by_did(&self, did: &str) -> Result<Option<String>, StorageError> {
        let g = self.inner.lock().await;
        Ok(g.active(did).and_then(|a| a.handle.clone()))
    }

    async fn list_accounts(&self) -> Result<Vec<AccountSummary>, StorageError> {
        let g = self.inner.lock().await;
        let mut rows: Vec<&Account> = g.accounts.values().collect();
        rows.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.ordinal.cmp(&b.ordinal))
        });
        Ok(rows
            .into_iter()
            .map(|a| AccountSummary {
                did: a.did.clone(),
                handle: a.handle.clone(),
                deactivated_at: a.deactivated_at.clone(),
                takedown_ref: a.takedown_ref.clone(),
                created_at: a.created_at.clone(),
            })
            .collect())
    }

    async fn update_password(&self, did: &str, password_phc: &str) -> Result<u64, StorageError> {
        let mut g = self.inner.lock().await;
        match g.accounts.get_mut(did) {
            Some(a) => {
                a.password_phc = password_phc.to_string();
                Ok(1)
            }
            None => Ok(0),
        }
    }

    async fn set_takedown(&self, did: &str, reference: &str) -> Result<u64, StorageError> {
        let now = chrono::Utc::now().to_rfc3339();
        let mut g = self.inner.lock().await;
        match g.accounts.get_mut(did) {
            Some(a) => {
                // An empty reference still has to produce a non-null marker —
                // the takedown is expressed by the field being set at all.
                a.takedown_ref = Some(if reference.is_empty() {
                    now
                } else {
                    reference.to_string()
                });
                Ok(1)
            }
            None => Ok(0),
        }
    }

    async fn clear_takedown(&self, did: &str) -> Result<u64, StorageError> {
        let mut g = self.inner.lock().await;
        match g.accounts.get_mut(did) {
            Some(a) => {
                a.takedown_ref = None;
                Ok(1)
            }
            None => Ok(0),
        }
    }

    async fn insert_invite(
        &self,
        code: &str,
        available_uses: i64,
        _for_account: &str,
    ) -> Result<(), StorageError> {
        let mut g = self.inner.lock().await;
        if g.invites.contains_key(code) {
            return Err(StorageError::Constraint(format!(
                "invite code already exists: {code}"
            )));
        }
        g.invites.insert(
            code.to_string(),
            Invite {
                available_uses,
                disabled: false,
            },
        );
        Ok(())
    }

    async fn consume_invite(&self, code: &str, used_by: &str) -> Result<bool, StorageError> {
        let mut g = self.inner.lock().await;
        let key = (code.to_string(), used_by.to_string());

        match g.invites.get(code) {
            None => return Ok(false),                             // unknown code
            Some(i) if i.disabled => return Ok(false),            // disabled
            Some(i) if i.available_uses <= 0 => return Ok(false), // exhausted
            Some(_) => {}
        }
        if g.invite_uses.contains(&key) {
            return Ok(false); // already redeemed by this DID
        }

        g.invite_uses.insert(key);
        if let Some(i) = g.invites.get_mut(code) {
            i.available_uses -= 1;
        }
        Ok(true)
    }

    async fn upsert_preferences(&self, did: &str, prefs_json: &str) -> Result<(), StorageError> {
        self.inner
            .lock()
            .await
            .prefs
            .insert(did.to_string(), prefs_json.to_string());
        Ok(())
    }

    async fn get_preferences(&self, did: &str) -> Result<Option<String>, StorageError> {
        Ok(self.inner.lock().await.prefs.get(did).cloned())
    }
}

/// Shared insert used by both `insert_account` and `count_and_insert_account`,
/// so the uniqueness rules cannot drift between the two entry points.
///
/// Enforces the same two constraints the SQLite schema does: `did` PRIMARY KEY
/// and `handle` UNIQUE.
fn insert_account_locked(
    g: &mut Inner,
    did: &str,
    handle: &str,
    email: Option<&str>,
    password_phc: &str,
) -> Result<(), StorageError> {
    if g.accounts.contains_key(did) {
        return Err(StorageError::Constraint(format!(
            "account already exists: {did}"
        )));
    }
    if g.accounts
        .values()
        .any(|a| a.handle.as_deref() == Some(handle))
    {
        return Err(StorageError::Constraint(format!(
            "handle already taken: {handle}"
        )));
    }
    let ordinal = g.next_ordinal;
    g.next_ordinal += 1;
    g.accounts.insert(
        did.to_string(),
        Account {
            did: did.to_string(),
            handle: Some(handle.to_string()),
            email: email.map(|e| e.to_string()),
            password_phc: password_phc.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            deactivated_at: None,
            takedown_ref: None,
            ordinal,
        },
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Keys and blobs
// ---------------------------------------------------------------------------

#[async_trait]
impl KeyStore for MemoryStore {
    async fn put_key_blob(&self, id: &str, ciphertext: Vec<u8>) -> Result<(), StorageError> {
        self.inner
            .lock()
            .await
            .keys
            .insert(id.to_string(), ciphertext);
        Ok(())
    }

    async fn get_key_blob(&self, id: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.inner.lock().await.keys.get(id).cloned())
    }
}

#[async_trait]
impl BlobStore for MemoryStore {
    async fn put_blob(
        &self,
        did: &str,
        cid: &str,
        mime_type: &str,
        _size: i64,
        bytes: Vec<u8>,
    ) -> Result<(), StorageError> {
        self.inner.lock().await.blobs.insert(
            (did.to_string(), cid.to_string()),
            (mime_type.to_string(), bytes),
        );
        Ok(())
    }

    async fn get_blob(
        &self,
        did: &str,
        cid: &str,
    ) -> Result<Option<(String, Vec<u8>)>, StorageError> {
        Ok(self
            .inner
            .lock()
            .await
            .blobs
            .get(&(did.to_string(), cid.to_string()))
            .cloned())
    }
}

/// Build an in-memory backend for the shared conformance suite. No guard is
/// needed — nothing outlives the store itself.
#[cfg(test)]
async fn conformance_setup() -> (
    Arc<dyn crate::storage::StorageBackend>,
    Box<dyn std::any::Any + Send>,
) {
    (Arc::new(MemoryStore::new()), Box::new(()))
}

#[cfg(test)]
crate::storage_conformance_tests!(conformance_setup);

#[cfg(test)]
mod tests {
    use super::*;

    /// Clones share one dataset — the type is a handle, not a value.
    #[tokio::test]
    async fn clone_shares_state() {
        let a = MemoryStore::new();
        let b = a.clone();
        a.insert_account("did:plc:x", "x.test", None, "phc")
            .await
            .unwrap();
        assert!(b.get_did_by_handle("x.test").await.unwrap().is_some());
    }

    /// A concurrent burst of commits assigns each caller a distinct seq and
    /// leaves the log with no gaps — the property the single guard exists for.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_commits_assign_unique_seqs() {
        use crate::storage::cid_of;
        use atrium_repo::blockstore::DAG_CBOR;

        let store = Arc::new(MemoryStore::new());
        let mut tasks = Vec::new();
        for i in 0..64u32 {
            let s = store.clone();
            tasks.push(tokio::spawn(async move {
                let payload = format!("payload {i}").into_bytes();
                let cid = cid_of(DAG_CBOR, &payload);
                s.commit_blocks(vec![(cid, payload)], "did:plc:race", cid, vec![0xa0])
                    .await
                    .expect("commit failed")
            }));
        }

        let mut seqs = Vec::new();
        for t in tasks {
            seqs.push(t.await.expect("task panicked"));
        }
        seqs.sort_unstable();
        let expected: Vec<i64> = (1..=64).collect();
        assert_eq!(seqs, expected, "seqs must be exactly 1..=64 with no gaps");
    }
}
