//! Blobs: content-addressing, size policy, and the lexicon shape.
//!
//! A blob is not a repo record — it is opaque bytes referenced *by* a record —
//! so it lives beside `repo` rather than inside it. What is here is the part
//! every deployment must agree on: how a blob's CID is derived, how large one
//! may be, and the JSON a client gets back and then embeds in a record.
//!
//! Getting any of those three subtly different between deployments produces
//! blobs that cannot be verified or referenced across them.

use cid::Cid;
use sha2::{Digest, Sha256};

use crate::storage::{BlobStore, StorageError};

/// Largest blob accepted, in bytes.
///
/// A ceiling has to exist because the bytes are buffered in memory to be
/// hashed. 2 MiB matches the production server's body limit (axum's default),
/// so a blob accepted on desktop is accepted on-device and in a Worker too —
/// the point being that the same upload does not succeed on one deployment and
/// fail on another. It also stays well inside a Workers isolate's budget.
pub const MAX_BLOB_BYTES: usize = 2 * 1024 * 1024;

/// Multihash code for sha2-256.
const SHA2_256: u64 = 0x12;
/// Multicodec for `raw` — blobs are opaque bytes, not dag-cbor.
const RAW_CODEC: u64 = 0x55;

/// The CID a blob is addressed by: CIDv1, `raw` codec, sha2-256.
///
/// This is the whole of blob identity in atproto. Two deployments that derive
/// it differently cannot reference each other's blobs, so it is defined once
/// here rather than at each call site.
pub fn blob_cid(bytes: &[u8]) -> Cid {
    let digest = Sha256::digest(bytes);
    let mh = cid::multihash::Multihash::wrap(SHA2_256, digest.as_slice())
        .expect("a 32-byte sha2-256 digest always fits a multihash");
    Cid::new_v1(RAW_CODEC, mh)
}

/// A stored blob, in the shape a record embeds it.
pub struct BlobRef {
    pub cid: Cid,
    pub mime_type: String,
    pub size: i64,
}

impl BlobRef {
    /// The `blob` lexicon value: what `uploadBlob` returns and what a client
    /// then puts inside a record.
    pub fn to_lex_json(&self) -> serde_json::Value {
        serde_json::json!({
            "$type": "blob",
            "ref": { "$link": self.cid.to_string() },
            "mimeType": self.mime_type,
            "size": self.size,
        })
    }
}

/// Why a blob was rejected before it was stored.
#[derive(Debug)]
pub enum BlobError {
    /// Zero bytes. Nothing references an empty blob, and every empty blob would
    /// share one CID.
    Empty,
    /// Larger than [`MAX_BLOB_BYTES`]; carries the actual size for the message.
    TooLarge(usize),
    Storage(StorageError),
}

impl std::fmt::Display for BlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlobError::Empty => write!(f, "blob is empty"),
            BlobError::TooLarge(n) => {
                write!(f, "blob is {n} bytes, over the {MAX_BLOB_BYTES} limit")
            }
            BlobError::Storage(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BlobError {}

/// Validate, content-address and store a blob, returning the ref to hand back.
///
/// Rejects before touching storage, so an oversized or empty upload cannot
/// leave a partial object behind.
pub async fn store_blob(
    store: &dyn BlobStore,
    did: &str,
    mime_type: &str,
    bytes: Vec<u8>,
) -> Result<BlobRef, BlobError> {
    if bytes.is_empty() {
        return Err(BlobError::Empty);
    }
    if bytes.len() > MAX_BLOB_BYTES {
        return Err(BlobError::TooLarge(bytes.len()));
    }
    let cid = blob_cid(&bytes);
    let size = bytes.len() as i64;
    store
        .put_blob(did, &cid.to_string(), mime_type, size, bytes)
        .await
        .map_err(BlobError::Storage)?;
    Ok(BlobRef {
        cid,
        mime_type: mime_type.to_string(),
        size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStore;

    #[test]
    fn blob_cid_is_stable_and_content_addressed() {
        // Same bytes must always give the same CID, or a re-upload would
        // duplicate rather than deduplicate.
        assert_eq!(blob_cid(b"hello"), blob_cid(b"hello"));
        assert_ne!(blob_cid(b"hello"), blob_cid(b"hello!"));
        // CIDv1 raw + sha2-256 is what other implementations expect.
        let cid = blob_cid(b"hello");
        assert_eq!(cid.codec(), RAW_CODEC);
        assert_eq!(cid.hash().code(), SHA2_256);
    }

    #[tokio::test]
    async fn store_blob_round_trips_and_rejects_before_storing() {
        let store = MemoryStore::new();

        let r = store_blob(&store, "did:plc:x", "image/png", b"bytes".to_vec())
            .await
            .expect("store");
        assert_eq!(r.size, 5);
        let (mime, bytes) = store
            .get_blob("did:plc:x", &r.cid.to_string())
            .await
            .unwrap()
            .expect("stored");
        assert_eq!(mime, "image/png");
        assert_eq!(bytes, b"bytes");

        // Rejections must happen before storage, so nothing partial is left.
        assert!(matches!(
            store_blob(&store, "did:plc:x", "image/png", vec![]).await,
            Err(BlobError::Empty)
        ));
        let huge = vec![0u8; MAX_BLOB_BYTES + 1];
        assert!(matches!(
            store_blob(&store, "did:plc:x", "image/png", huge).await,
            Err(BlobError::TooLarge(_))
        ));
        assert_eq!(
            store.list_blobs("did:plc:x", 50, None).await.unwrap().len(),
            1,
            "a rejected upload must not be stored"
        );
    }

    #[test]
    fn lex_json_matches_the_blob_lexicon() {
        let r = BlobRef {
            cid: blob_cid(b"x"),
            mime_type: "image/jpeg".into(),
            size: 1,
        };
        let v = r.to_lex_json();
        assert_eq!(v["$type"], "blob");
        assert_eq!(v["ref"]["$link"], r.cid.to_string());
        assert_eq!(v["mimeType"], "image/jpeg");
        assert_eq!(v["size"], 1);
    }
}
