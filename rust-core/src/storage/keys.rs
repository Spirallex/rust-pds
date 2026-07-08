use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroize;

use crate::storage::StorageError;

/// Argon2id memory cost in KiB for at-rest key encryption. Mirrors the auth
/// hash: 19456 KiB by default, 4096 KiB under `lean-auth` for device hosts.
///
/// CRITICAL: this value participates in the KDF, so a key encrypted under one
/// m_cost can only be decrypted under the same m_cost. A `lean-auth` build and a
/// default build are NOT key-compatible — keep a device on one setting.
#[cfg(not(feature = "lean-auth"))]
const ARGON2_M_COST_KIB: u32 = 19_456;
#[cfg(feature = "lean-auth")]
const ARGON2_M_COST_KIB: u32 = 4_096;

/// Construct a pinned Argon2id instance with explicit parameters
/// (m=`ARGON2_M_COST_KIB`, t=2, p=1, output_len=32).
///
/// Pinning prevents a semver bump in the `argon2` crate from silently changing
/// KDF strength. Both `encrypt_key` and `decrypt_key` must use this constructor
/// to guarantee interoperability.
fn argon2_instance() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(ARGON2_M_COST_KIB, 2, 1, Some(32)).expect("static argon2 params are valid"),
    )
}

/// Encrypt `plaintext` (a key blob) under a passphrase-derived key.
/// Layout: salt(16) ++ nonce(12) ++ AES-256-GCM ciphertext.
///
/// A fresh 16-byte salt and 12-byte nonce are generated via `OsRng` for every call.
/// The salt is used with Argon2id to derive a 32-byte AES key. No key material
/// appears in error messages (Security Domain V7).
pub fn encrypt_key(plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, StorageError> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut key_bytes = [0u8; 32];
    argon2_instance()
        .hash_password_into(passphrase, &salt, &mut key_bytes)
        .map_err(|e| StorageError::Crypto(e.to_string()))?;

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    key_bytes.zeroize(); // erase derived key material from stack memory
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| StorageError::Crypto("AES-GCM encrypt failed".into()))?;

    // Layout: salt(16) ++ nonce(12) ++ ciphertext
    let mut blob = Vec::with_capacity(16 + 12 + ciphertext.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt a blob produced by `encrypt_key`. Returns `StorageError::Crypto` on
/// wrong passphrase or corrupted data — never panics.
pub fn decrypt_key(blob: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, StorageError> {
    if blob.len() < 28 {
        return Err(StorageError::Crypto("blob too short".into()));
    }
    let (salt, rest) = blob.split_at(16);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    let mut key_bytes = [0u8; 32];
    argon2_instance()
        .hash_password_into(passphrase, salt, &mut key_bytes)
        .map_err(|e| StorageError::Crypto(e.to_string()))?;

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    key_bytes.zeroize(); // erase derived key material from stack memory
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| StorageError::Crypto("wrong passphrase or corrupted key".into()))
}

/// Encrypt `plaintext` and persist it as a ciphertext blob under `id` in the
/// `keys` table. Uses `INSERT OR REPLACE` so re-keying an existing id is safe.
pub async fn store_key(
    store: &crate::storage::SqliteStore,
    id: &str,
    plaintext: &[u8],
    passphrase: &[u8],
) -> Result<(), StorageError> {
    let plaintext = plaintext.to_vec();
    let passphrase = passphrase.to_vec();
    let blob = tokio::task::spawn_blocking(move || encrypt_key(&plaintext, &passphrase))
        .await
        .map_err(|e| StorageError::Crypto(format!("blocking key-encrypt task panicked: {e}")))??;
    let id_owned = id.to_string();
    let writer = store.writer.lock().await;
    writer
        .call(move |conn| {
            conn.execute(
                "INSERT OR REPLACE INTO keys (id, ciphertext) VALUES (?1, ?2)",
                rusqlite::params![id_owned, blob],
            )?;
            Ok(())
        })
        .await?;
    Ok(())
}

/// Load the encrypted blob for `id` from the `keys` table and decrypt it with
/// `passphrase`. Returns `StorageError::Crypto` if the id is not found or the
/// passphrase is wrong.
pub async fn load_key(
    store: &crate::storage::SqliteStore,
    id: &str,
    passphrase: &[u8],
) -> Result<Vec<u8>, StorageError> {
    let id_owned = id.to_string();
    let conn = store
        .readers
        .get()
        .await
        .map_err(|e| StorageError::Pool(e.to_string()))?;

    let blob: Option<Vec<u8>> = conn
        .interact(move |c| {
            use rusqlite::OptionalExtension;
            c.query_row(
                "SELECT ciphertext FROM keys WHERE id = ?1",
                rusqlite::params![id_owned],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
        })
        .await
        .map_err(|e| StorageError::Pool(e.to_string()))?
        .map_err(StorageError::Sqlite)?;

    match blob {
        None => Err(StorageError::Crypto("key not found".into())),
        Some(b) => {
            let passphrase = passphrase.to_vec();
            tokio::task::spawn_blocking(move || decrypt_key(&b, &passphrase))
                .await
                .map_err(|e| {
                    StorageError::Crypto(format!("blocking key-decrypt task panicked: {e}"))
                })?
        }
    }
}

/// Export the encrypted key blob for `id` from the store as a portable byte sequence.
///
/// # Portable layout
///
/// The exported blob is a length-prefixed entry:
/// ```text
/// [ id_len: u32 le ] [ id_bytes ] [ cipher_len: u32 le ] [ ciphertext ]
/// ```
/// The `ciphertext` is the raw `salt(16) ++ nonce(12) ++ aes-gcm-ciphertext` blob
/// already stored in the `keys` table — it is self-contained for decryption (salt
/// and nonce are embedded). The passphrase is validated by attempting decryption
/// before emitting any output, so an export with the wrong passphrase fails cleanly
/// with `StorageError::Crypto`. The passphrase itself is never written to the blob.
///
/// ACCT-05 portability: this blob can be transferred to any machine and imported
/// into a fresh database with `import_keys` using the same passphrase.
pub async fn export_keys(
    store: &crate::storage::SqliteStore,
    id: &str,
    passphrase: &[u8],
) -> Result<Vec<u8>, StorageError> {
    // Load the raw ciphertext from the store (SELECT ciphertext FROM keys WHERE id = ?)
    let id_owned = id.to_string();
    let conn = store
        .readers
        .get()
        .await
        .map_err(|e| StorageError::Pool(e.to_string()))?;

    let ciphertext: Option<Vec<u8>> = conn
        .interact(move |c| {
            use rusqlite::OptionalExtension;
            c.query_row(
                "SELECT ciphertext FROM keys WHERE id = ?1",
                rusqlite::params![id_owned],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
        })
        .await
        .map_err(|e| StorageError::Pool(e.to_string()))?
        .map_err(StorageError::Sqlite)?;

    let ciphertext = match ciphertext {
        None => return Err(StorageError::Crypto("key not found".into())),
        Some(c) => c,
    };

    // Validate the passphrase before producing output — fail cleanly on wrong passphrase.
    // decrypt_key returns Err(StorageError::Crypto) on wrong passphrase; no panic.
    let _ = decrypt_key(&ciphertext, passphrase)?;

    // Serialize the portable blob: [ id_len(4) ][ id_bytes ][ cipher_len(4) ][ ciphertext ]
    let id_bytes = id.as_bytes();
    let mut blob = Vec::with_capacity(4 + id_bytes.len() + 4 + ciphertext.len());
    blob.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
    blob.extend_from_slice(id_bytes);
    blob.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Import a key blob produced by `export_keys` into this store under `id`.
///
/// Validates the passphrase before writing. Returns `StorageError::Crypto` on
/// wrong passphrase or malformed blob — no panic (T-01-14 mitigated).
///
/// Note: `id` overrides the id embedded in the blob, allowing re-keying a slot.
/// Delegates to `crate::storage::backup::import_keys` (authoritative implementation).
pub async fn import_keys(
    store: &crate::storage::SqliteStore,
    id: &str,
    export_blob: &[u8],
    passphrase: &[u8],
) -> Result<(), StorageError> {
    crate::storage::backup::import_keys(store, id, export_blob, passphrase).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SqliteStore;

    /// ACCT-05: the ciphertext blob stored for a key must not contain the plaintext bytes.
    #[tokio::test]
    async fn test_ciphertext_not_plaintext() {
        let plaintext = b"super-secret-signing-key-32bytes";
        let passphrase = b"correct horse battery staple";

        let blob = encrypt_key(plaintext, passphrase).expect("encrypt_key failed");

        // The blob must NOT contain the plaintext bytes as a contiguous subsequence.
        let blob_contains_plaintext = blob
            .windows(plaintext.len())
            .any(|w| w == plaintext.as_ref());
        assert!(
            !blob_contains_plaintext,
            "plaintext key bytes found verbatim inside the ciphertext blob — key is not encrypted"
        );
    }

    /// ACCT-05: decrypting with the wrong passphrase returns Err, never panics.
    #[tokio::test]
    async fn test_wrong_passphrase() {
        let plaintext = b"super-secret-signing-key-32bytes";
        let correct = b"correct horse battery staple";
        let wrong = b"wrong passphrase entirely";

        let blob = encrypt_key(plaintext, correct).expect("encrypt_key failed");
        let result = decrypt_key(&blob, wrong);
        assert!(result.is_err(), "expected Err for wrong passphrase, got Ok");
    }

    /// Verify encrypt/decrypt round-trips with correct passphrase.
    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"my-32-byte-signing-key-material!";
        let passphrase = b"a strong passphrase";

        let blob = encrypt_key(plaintext, passphrase).expect("encrypt_key failed");
        // Blob must be at least salt(16) + nonce(12) + tag(16) = 44 bytes for empty plaintext.
        assert!(blob.len() >= 28, "blob too short: {}", blob.len());

        let recovered = decrypt_key(&blob, passphrase).expect("decrypt_key failed");
        assert_eq!(recovered, plaintext, "round-trip mismatch");
    }

    /// Task 2: store_key/load_key round-trip through the keys table.
    #[tokio::test]
    async fn test_store_load_roundtrip() {
        let (store, _tmp) = SqliteStore::open_in_memory()
            .await
            .expect("open store failed");

        let key_id = "signing";
        let passphrase = b"test-passphrase-for-store-load";
        // 32 random-looking bytes as the plaintext key.
        let plaintext: Vec<u8> = (0u8..32).collect();

        // Store the key.
        store_key(&store, key_id, &plaintext, passphrase)
            .await
            .expect("store_key failed");

        // Load and decrypt back.
        let recovered = load_key(&store, key_id, passphrase)
            .await
            .expect("load_key failed");
        assert_eq!(recovered, plaintext, "load_key returned wrong bytes");

        // Verify the persisted row is ciphertext, not plaintext.
        let id_owned = key_id.to_string();
        let raw_blob: Vec<u8> = store
            .readers
            .get()
            .await
            .expect("get reader failed")
            .interact(move |c| {
                c.query_row(
                    "SELECT ciphertext FROM keys WHERE id = ?1",
                    rusqlite::params![id_owned],
                    |row| row.get::<_, Vec<u8>>(0),
                )
            })
            .await
            .expect("interact failed")
            .expect("query failed");

        let blob_contains_plaintext = raw_blob
            .windows(plaintext.len())
            .any(|w| w == plaintext.as_slice());
        assert!(
            !blob_contains_plaintext,
            "persisted ciphertext row contains plaintext key bytes"
        );
    }

    /// load_key for a missing id returns Err, not panic.
    #[tokio::test]
    async fn test_load_missing_key() {
        let (store, _tmp) = SqliteStore::open_in_memory()
            .await
            .expect("open store failed");

        let result = load_key(&store, "nonexistent", b"any-passphrase").await;
        assert!(result.is_err(), "expected Err for missing key, got Ok");
    }

    /// ACCT-05: export → import into a fresh DB yields the same key bytes.
    ///
    /// Also verifies that importing with the wrong passphrase fails cleanly (Err,
    /// no panic), satisfying the T-01-14 panic mitigation.
    #[tokio::test]
    async fn test_export_import_roundtrip() {
        let (store_src, _tmp_src) = SqliteStore::open_in_memory()
            .await
            .expect("open source store failed");
        let (store_dst, _tmp_dst) = SqliteStore::open_in_memory()
            .await
            .expect("open dest store failed");

        let key_id = "signing";
        let passphrase = b"export-import-passphrase";
        // 32 bytes of key material to be stored, exported, and re-imported.
        let original_key: Vec<u8> = (0u8..32).collect();

        // Store the key in the source DB.
        store_key(&store_src, key_id, &original_key, passphrase)
            .await
            .expect("store_key failed");

        // Export the key from the source DB.
        let blob = export_keys(&store_src, key_id, passphrase)
            .await
            .expect("export_keys failed");

        // Import the key into the destination (fresh) DB.
        import_keys(&store_dst, key_id, &blob, passphrase)
            .await
            .expect("import_keys failed");

        // Verify the imported key decrypts to the same bytes as the original.
        let recovered = load_key(&store_dst, key_id, passphrase)
            .await
            .expect("load_key after import failed");
        assert_eq!(
            recovered, original_key,
            "imported key must round-trip to the same bytes as the original"
        );

        // Wrong-passphrase import case: must return Err, never panic (T-01-14).
        let wrong_result = import_keys(&store_dst, key_id, &blob, b"wrong-passphrase").await;
        assert!(
            wrong_result.is_err(),
            "import_keys with wrong passphrase must return Err"
        );
    }
}
