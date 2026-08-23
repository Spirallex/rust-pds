//! Repo reads: fetch one record, or page a collection.
//!
//! These sit beside [`crate::repo::RepoWriter`] for the same reason it exists:
//! the logic is a few MST operations over a [`StorageBackend`], and every
//! deployment needs it. Keeping it here rather than inside one server's handler
//! module means the single-process server and the Workers port read a repo the
//! same way, instead of each traversing the MST itself.
//!
//! Everything here is read-only — no locking, no commits.

use std::sync::Arc;

use atrium_repo::blockstore::DiffBlockStore;
use atrium_repo::Repository;
use cid::Cid;
use futures_util::TryStreamExt;

use crate::repo::RepoError;
use crate::storage::{BlockStoreAdapter, StorageBackend};

/// One record as the XRPC read methods report it.
///
/// `key` is the full MST key (`collection/rkey`), which is what an AT-URI needs
/// after the DID, so callers can build `at://{did}/{key}` without re-splitting.
pub struct RecordEntry {
    pub key: String,
    pub cid: Cid,
    pub value: serde_json::Value,
}

/// A page of [`RecordEntry`], plus the cursor to resume after.
///
/// `cursor` is `None` when the page was not filled — that is the end of the
/// collection, and handing back a cursor there would invite a pointless
/// round-trip that returns nothing.
pub struct RecordPage {
    pub records: Vec<RecordEntry>,
    pub cursor: Option<String>,
}

/// Fetch a single record by its MST key (`collection/rkey`).
///
/// `Ok(None)` covers both "no such repo" and "no such key": to a caller they are
/// the same 404, and distinguishing them would leak whether a DID exists.
pub async fn get_record(
    store: Arc<dyn StorageBackend>,
    did: &str,
    mst_key: &str,
) -> Result<Option<RecordEntry>, RepoError> {
    let Some(root) = store.load_repo_root(did).await? else {
        return Ok(None);
    };
    let mut diff = DiffBlockStore::wrap(BlockStoreAdapter::new(store.clone()));
    let mut repo = Repository::open(&mut diff, root)
        .await
        .map_err(|e| RepoError::Repo(e.to_string()))?;
    let mut tree = repo.tree();
    let Some(cid) = tree
        .get(mst_key)
        .await
        .map_err(|e| RepoError::Repo(e.to_string()))?
    else {
        return Ok(None);
    };
    let bytes = store.read_block_bytes(cid).await?;
    let value: serde_json::Value = serde_ipld_dagcbor::from_slice(&bytes)
        .map_err(|e| RepoError::Repo(format!("decode record {cid}: {e}")))?;
    Ok(Some(RecordEntry {
        key: mst_key.to_string(),
        cid,
        value,
    }))
}

/// Page through one collection in MST key order.
///
/// `cursor` is the last key of the previous page, exclusive. `limit` is clamped
/// to 1..=100 so a caller cannot ask the MST stream to materialise a repo.
pub async fn list_records(
    store: Arc<dyn StorageBackend>,
    did: &str,
    collection: &str,
    limit: usize,
    cursor: Option<&str>,
) -> Result<RecordPage, RepoError> {
    let limit = limit.clamp(1, 100);
    let Some(root) = store.load_repo_root(did).await? else {
        return Ok(RecordPage {
            records: Vec::new(),
            cursor: None,
        });
    };
    let mut diff = DiffBlockStore::wrap(BlockStoreAdapter::new(store.clone()));
    let mut repo = Repository::open(&mut diff, root)
        .await
        .map_err(|e| RepoError::Repo(e.to_string()))?;

    let prefix = format!("{collection}/");
    let mut tree = repo.tree();
    let mut stream = Box::pin(tree.entries_prefixed(&prefix));

    let mut records: Vec<RecordEntry> = Vec::with_capacity(limit);
    let mut last_key: Option<String> = None;

    while let Some((key, cid)) = stream
        .try_next()
        .await
        .map_err(|e| RepoError::Repo(e.to_string()))?
    {
        // Skip forward to the cursor. The MST yields in key order, so a simple
        // string comparison is the whole of pagination.
        if let Some(c) = cursor {
            if key.as_str() <= c {
                continue;
            }
        }
        let bytes = store.read_block_bytes(cid).await?;
        let value: serde_json::Value = serde_ipld_dagcbor::from_slice(&bytes)
            .map_err(|e| RepoError::Repo(format!("decode record {cid}: {e}")))?;
        records.push(RecordEntry {
            key: key.clone(),
            cid,
            value,
        });
        last_key = Some(key);
        if records.len() >= limit {
            break;
        }
    }

    // Only hand back a cursor on a full page: a short page is the end.
    let next = if records.len() == limit {
        last_key
    } else {
        None
    };
    Ok(RecordPage {
        records,
        cursor: next,
    })
}

/// Distinct collection NSIDs present in the repo, in MST order.
///
/// `describeRepo` reports this. It walks every key, which is fine at the sizes
/// this runs at and is the only way to answer without a separate index.
pub async fn list_collections(
    store: Arc<dyn StorageBackend>,
    did: &str,
) -> Result<Vec<String>, RepoError> {
    let Some(root) = store.load_repo_root(did).await? else {
        return Ok(Vec::new());
    };
    let mut diff = DiffBlockStore::wrap(BlockStoreAdapter::new(store.clone()));
    let mut repo = Repository::open(&mut diff, root)
        .await
        .map_err(|e| RepoError::Repo(e.to_string()))?;
    let mut tree = repo.tree();
    let mut stream = Box::pin(tree.entries());

    let mut out: Vec<String> = Vec::new();
    while let Some((key, _cid)) = stream
        .try_next()
        .await
        .map_err(|e| RepoError::Repo(e.to_string()))?
    {
        if let Some((collection, _)) = key.split_once('/') {
            // Keys arrive in order, so equal collections are adjacent and only
            // the last entry needs checking.
            if out.last().map(String::as_str) != Some(collection) {
                out.push(collection.to_string());
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::RepoWriter;
    use crate::storage::crypto::store_key;
    use crate::storage::MemoryStore;
    use atrium_api::types::string::Did;
    use atrium_crypto::keypair::{Export, Secp256k1Keypair};
    use ipld_core::ipld::Ipld;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    const DID: &str = "did:plc:readtestreadtestread";

    fn post(text: &str) -> Ipld {
        let mut m = BTreeMap::new();
        m.insert(
            "$type".to_string(),
            Ipld::String("app.bsky.feed.post".into()),
        );
        m.insert("text".to_string(), Ipld::String(text.into()));
        Ipld::Map(m)
    }

    async fn writer_with_store() -> (RepoWriter, Arc<dyn StorageBackend>) {
        let store: Arc<dyn StorageBackend> = Arc::new(MemoryStore::new());
        let key = Secp256k1Keypair::create(&mut rand::thread_rng());
        store_key(
            store.as_ref(),
            &format!("{DID}#signing"),
            &key.export(),
            b"pw",
        )
        .await
        .expect("store key");
        let (tx, _rx) = tokio::sync::broadcast::channel(8);
        let writer = RepoWriter::new(store.clone(), key, Did::from_str(DID).expect("did"), tx);
        (writer, store)
    }

    #[tokio::test]
    async fn get_record_round_trips_a_written_record() {
        let (writer, store) = writer_with_store().await;
        writer
            .create_record("app.bsky.feed.post/3kaaaa", post("hello"))
            .await
            .expect("write");

        let got = get_record(store, DID, "app.bsky.feed.post/3kaaaa")
            .await
            .expect("get_record")
            .expect("record must exist");
        assert_eq!(got.value["text"], "hello");
        assert_eq!(got.key, "app.bsky.feed.post/3kaaaa");
    }

    #[tokio::test]
    async fn missing_repo_and_missing_key_are_both_none() {
        let (writer, store) = writer_with_store().await;
        // No repo at all yet.
        assert!(get_record(store.clone(), DID, "app.bsky.feed.post/nope")
            .await
            .expect("get_record")
            .is_none());

        writer
            .create_record("app.bsky.feed.post/3kaaaa", post("hi"))
            .await
            .expect("write");

        // Repo exists, key does not. Same answer -- a caller must not be able to
        // tell an absent DID from an absent record.
        assert!(get_record(store, DID, "app.bsky.feed.post/nope")
            .await
            .expect("get_record")
            .is_none());
    }

    #[tokio::test]
    async fn list_records_pages_by_cursor_without_repeating() {
        let (writer, store) = writer_with_store().await;
        for i in 0..5 {
            writer
                .create_record(
                    &format!("app.bsky.feed.post/3ka{i:03}"),
                    post(&format!("p{i}")),
                )
                .await
                .expect("write");
        }

        let first = list_records(store.clone(), DID, "app.bsky.feed.post", 2, None)
            .await
            .expect("page 1");
        assert_eq!(first.records.len(), 2);
        let cursor = first.cursor.clone().expect("full page must yield a cursor");

        let second = list_records(store.clone(), DID, "app.bsky.feed.post", 2, Some(&cursor))
            .await
            .expect("page 2");
        assert_eq!(second.records.len(), 2);

        // The cursor is exclusive: no key may appear in both pages.
        for a in &first.records {
            assert!(
                !second.records.iter().any(|b| b.key == a.key),
                "cursor must not repeat {}",
                a.key
            );
        }

        // Final short page ends the walk rather than handing back a cursor that
        // would fetch nothing.
        let third = list_records(
            store,
            DID,
            "app.bsky.feed.post",
            2,
            second.cursor.as_deref(),
        )
        .await
        .expect("page 3");
        assert_eq!(third.records.len(), 1);
        assert!(third.cursor.is_none(), "short page must not yield a cursor");
    }

    #[tokio::test]
    async fn list_records_is_scoped_to_its_collection() {
        let (writer, store) = writer_with_store().await;
        writer
            .create_record("app.bsky.feed.post/3kaaaa", post("a post"))
            .await
            .expect("write post");
        writer
            .create_record("app.bsky.feed.like/3kbbbb", post("a like"))
            .await
            .expect("write like");

        let posts = list_records(store.clone(), DID, "app.bsky.feed.post", 50, None)
            .await
            .expect("list");
        assert_eq!(posts.records.len(), 1);
        assert!(posts.records[0].key.starts_with("app.bsky.feed.post/"));

        let collections = list_collections(store, DID).await.expect("collections");
        assert_eq!(
            collections,
            vec!["app.bsky.feed.like", "app.bsky.feed.post"]
        );
    }
}
