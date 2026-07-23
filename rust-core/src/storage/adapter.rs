//! Bridge between the object-safe [`StorageBackend`] traits and `atrium_repo`'s
//! blockstore traits.
//!
//! `atrium_repo::blockstore::{AsyncBlockStoreRead, AsyncBlockStoreWrite}` use
//! `async fn` in trait (RPITIT), which makes them **not** object-safe — they
//! cannot be implemented for `dyn StorageBackend`. [`BlockStoreAdapter`] is the
//! concrete shim that closes that gap: it owns an `Arc<dyn StorageBackend>` and
//! implements both atrium traits by delegating to the object-safe methods.
//!
//! It is also the single place a CID is computed from bytes. Keeping [`cid_of`]
//! here — rather than letting each backend hash its own blocks — is what
//! guarantees two backends cannot disagree about the CID of the same block, a
//! divergence that would silently fork repo history on migration.

use std::sync::Arc;

use atrium_repo::blockstore::{AsyncBlockStoreRead, AsyncBlockStoreWrite, Error, SHA2_256};
use cid::Cid;
use sha2::{Digest, Sha256};

use crate::storage::{StorageBackend, StorageError};

/// Compute a CIDv1 with the given codec over the sha2-256 digest of `contents`.
///
/// This is the canonical CID computation for the whole crate — the MST, the
/// firehose CAR frames, and every storage backend must agree with it byte for
/// byte.
pub fn cid_of(codec: u64, contents: &[u8]) -> Cid {
    let digest = Sha256::digest(contents);
    let mh = cid::multihash::Multihash::wrap(SHA2_256, digest.as_slice())
        .expect("32-byte sha2-256 digest always fits multihash");
    Cid::new_v1(codec, mh)
}

/// Adapts any [`StorageBackend`] to `atrium_repo`'s blockstore traits.
///
/// Cloning is an `Arc` bump and shares the underlying backend — matching the
/// previous behaviour of cloning a `SqliteStore` handle, which shared the writer
/// mutex and reader pool rather than copying the database.
#[derive(Clone)]
pub struct BlockStoreAdapter {
    backend: Arc<dyn StorageBackend>,
}

impl BlockStoreAdapter {
    pub fn new(backend: Arc<dyn StorageBackend>) -> Self {
        Self { backend }
    }

    /// Borrow the wrapped backend — used to reach the non-block parts of the
    /// backend after `DiffBlockStore::into_inner` hands the adapter back.
    pub fn backend(&self) -> &Arc<dyn StorageBackend> {
        &self.backend
    }

    /// Read a block's raw bytes, surfacing [`StorageError`] rather than atrium's
    /// `Error` — used by the commit path, which reports `StorageError`.
    pub async fn read_block_bytes(&self, cid: Cid) -> Result<Vec<u8>, StorageError> {
        self.backend.read_block_bytes(cid).await
    }
}

impl AsyncBlockStoreRead for BlockStoreAdapter {
    async fn read_block_into(&mut self, cid: Cid, contents: &mut Vec<u8>) -> Result<(), Error> {
        contents.clear();
        match self.backend.read_block_bytes(cid).await {
            Ok(b) => {
                contents.extend_from_slice(&b);
                Ok(())
            }
            // atrium distinguishes "absent" from "broken"; the MST relies on
            // CidNotFound to detect a missing node rather than treating it as an
            // I/O failure, so this mapping must not be collapsed into Other.
            Err(StorageError::BlockNotFound) => Err(Error::CidNotFound),
            Err(e) => Err(Error::Other(Box::new(e))),
        }
    }
}

impl AsyncBlockStoreWrite for BlockStoreAdapter {
    async fn write_block(&mut self, codec: u64, hash: u64, contents: &[u8]) -> Result<Cid, Error> {
        if hash != SHA2_256 {
            return Err(Error::UnsupportedHash(hash));
        }
        let cid = cid_of(codec, contents);
        self.backend
            .put_block(cid, contents.to_vec())
            .await
            .map_err(|e| Error::Other(Box::new(e)))?;
        Ok(cid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStore;
    use atrium_repo::blockstore::DAG_CBOR;
    use ipld_core::ipld::Ipld;
    use std::collections::BTreeMap;

    fn adapter() -> BlockStoreAdapter {
        BlockStoreAdapter::new(Arc::new(MemoryStore::new()))
    }

    /// STOR-01: write_block returns a CID byte-identical to the canonical
    /// multiformats reference used by the T0 spike.
    #[tokio::test]
    async fn test_cid_fidelity() {
        let mut store = adapter();

        // Encode a small IPLD map exactly as the T0 spike does.
        let mut m = BTreeMap::new();
        m.insert(
            "text".to_string(),
            Ipld::String("hello from stelyph".into()),
        );
        let bytes = serde_ipld_dagcbor::to_vec(&Ipld::Map(m)).expect("dag-cbor encode");

        let reference_cid = cid_of(DAG_CBOR, &bytes);
        let stored_cid = store
            .write_block(DAG_CBOR, SHA2_256, &bytes)
            .await
            .expect("write_block failed");

        assert_eq!(
            reference_cid, stored_cid,
            "write_block CID diverged from canonical reference — byte-fidelity violated"
        );
    }

    /// STOR-01: a written block reads back byte-identical; a missing CID maps to
    /// atrium's `CidNotFound` rather than a generic error.
    #[tokio::test]
    async fn test_read_roundtrip() {
        let mut store = adapter();

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

        let fake_cid = cid_of(DAG_CBOR, b"does not exist");
        let mut buf2 = Vec::new();
        let result = store.read_block_into(fake_cid, &mut buf2).await;
        assert!(
            matches!(result, Err(Error::CidNotFound)),
            "missing CID should return CidNotFound, got {:?}",
            result
        );
    }

    /// An unsupported multihash is rejected rather than silently stored under a
    /// CID the rest of the stack would not reproduce.
    #[tokio::test]
    async fn rejects_unsupported_hash() {
        let mut store = adapter();
        // 0x12 is sha2-256; 0x13 (sha2-512) is not supported by this stack.
        let result = store.write_block(DAG_CBOR, 0x13, b"payload").await;
        assert!(
            matches!(result, Err(Error::UnsupportedHash(0x13))),
            "expected UnsupportedHash, got {:?}",
            result
        );
    }

    /// read_block_into clears any pre-existing buffer contents rather than
    /// appending to them.
    #[tokio::test]
    async fn read_clears_buffer() {
        let mut store = adapter();
        let cid = store
            .write_block(DAG_CBOR, SHA2_256, b"fresh")
            .await
            .unwrap();

        let mut buf = b"stale data that must be discarded".to_vec();
        store.read_block_into(cid, &mut buf).await.unwrap();
        assert_eq!(buf, b"fresh", "buffer must be cleared before the read");
    }
}
