//! At-rest key encryption, and the portable key export/import format.
//!
//! Everything here is backend-agnostic: it is generic over any [`KeyStore`],
//! which moves ciphertext only. Centralising the envelope means a new storage
//! backend inherits the audited crypto for free and has no opportunity to
//! persist plaintext key material by mistake.
//!
//! The `?Sized` bound on each function is deliberate: it lets callers pass a
//! `&dyn StorageBackend` straight through (since `StorageBackend: KeyStore`)
//! without needing trait upcasting.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroize;

use crate::storage::{KeyStore, StorageError};

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

/// Encrypt `plaintext` and persist it under `id`. Re-keying an existing id is safe.
///
/// The argon2id KDF runs on a blocking thread: at the default 19 MiB / t=2 it
/// takes tens of milliseconds, which is long enough to stall other tasks on the
/// async worker it would otherwise occupy.
pub async fn store_key<S: KeyStore + ?Sized>(
    store: &S,
    id: &str,
    plaintext: &[u8],
    passphrase: &[u8],
) -> Result<(), StorageError> {
    let plaintext = plaintext.to_vec();
    let passphrase = passphrase.to_vec();
    let blob = tokio::task::spawn_blocking(move || encrypt_key(&plaintext, &passphrase))
        .await
        .map_err(|e| StorageError::Crypto(format!("blocking key-encrypt task panicked: {e}")))??;
    store.put_key_blob(id, blob).await
}

/// Load the encrypted blob for `id` and decrypt it with `passphrase`.
///
/// Returns `StorageError::Crypto` if the id is not found or the passphrase is
/// wrong — the two cases are deliberately indistinguishable to the caller.
pub async fn load_key<S: KeyStore + ?Sized>(
    store: &S,
    id: &str,
    passphrase: &[u8],
) -> Result<Vec<u8>, StorageError> {
    match store.get_key_blob(id).await? {
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

/// Export the encrypted key blob for `id` as a portable byte sequence.
///
/// # Portable layout
///
/// ```text
/// [ id_len: u32 le ] [ id_bytes ] [ cipher_len: u32 le ] [ ciphertext ]
/// ```
///
/// The `ciphertext` is the raw `salt(16) ++ nonce(12) ++ aes-gcm-ciphertext` blob
/// as stored — self-contained for decryption, since salt and nonce are embedded.
/// The passphrase is validated by attempting decryption before emitting any
/// output, so an export with the wrong passphrase fails cleanly rather than
/// producing a blob nobody can open. The passphrase itself never enters the blob.
///
/// The result is portable across backends: exported from SQLite, importable into
/// any other [`KeyStore`].
pub async fn export_keys<S: KeyStore + ?Sized>(
    store: &S,
    id: &str,
    passphrase: &[u8],
) -> Result<Vec<u8>, StorageError> {
    let ciphertext = store
        .get_key_blob(id)
        .await?
        .ok_or_else(|| StorageError::Crypto("key not found".into()))?;

    // Validate the passphrase before producing output.
    let _ = decrypt_key(&ciphertext, passphrase)?;

    let id_bytes = id.as_bytes();
    let mut blob = Vec::with_capacity(4 + id_bytes.len() + 4 + ciphertext.len());
    blob.extend_from_slice(&(id_bytes.len() as u32).to_le_bytes());
    blob.extend_from_slice(id_bytes);
    blob.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Import a key blob produced by [`export_keys`] under `id`.
///
/// Validates the passphrase before writing. Returns `StorageError::Crypto` on
/// wrong passphrase or malformed blob — never panics.
///
/// Note: `id` overrides the id embedded in the blob, allowing re-keying a slot.
pub async fn import_keys<S: KeyStore + ?Sized>(
    store: &S,
    id: &str,
    export_blob: &[u8],
    passphrase: &[u8],
) -> Result<(), StorageError> {
    // Parse the portable layout to extract the embedded ciphertext. Every length
    // is bounds-checked before use — this blob arrives from a file the operator
    // supplies, so a truncated or hostile one must produce an error, not a panic.
    if export_blob.len() < 8 {
        return Err(StorageError::Crypto("export blob too short".into()));
    }
    let id_len = u32::from_le_bytes(export_blob[0..4].try_into().unwrap()) as usize;
    let id_end = 4usize
        .checked_add(id_len)
        .ok_or_else(|| StorageError::Crypto("export blob id length overflows".into()))?;
    if export_blob.len() < id_end + 4 {
        return Err(StorageError::Crypto("export blob truncated at id".into()));
    }
    let cipher_len =
        u32::from_le_bytes(export_blob[id_end..id_end + 4].try_into().unwrap()) as usize;
    let cipher_start = id_end + 4;
    let cipher_end = cipher_start
        .checked_add(cipher_len)
        .ok_or_else(|| StorageError::Crypto("export blob cipher length overflows".into()))?;
    if export_blob.len() < cipher_end {
        return Err(StorageError::Crypto(
            "export blob truncated at ciphertext".into(),
        ));
    }
    let ciphertext = export_blob[cipher_start..cipher_end].to_vec();

    // Validate the passphrase before writing — fail cleanly on wrong passphrase.
    let _ = decrypt_key(&ciphertext, passphrase)?;

    store.put_key_blob(id, ciphertext).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ciphertext blob stored for a key must not contain the plaintext bytes.
    #[test]
    fn test_ciphertext_not_plaintext() {
        let plaintext = b"super-secret-signing-key-32bytes";
        let passphrase = b"correct horse battery staple";

        let blob = encrypt_key(plaintext, passphrase).expect("encrypt_key failed");

        let blob_contains_plaintext = blob
            .windows(plaintext.len())
            .any(|w| w == plaintext.as_ref());
        assert!(
            !blob_contains_plaintext,
            "plaintext key bytes found verbatim inside the ciphertext blob — key is not encrypted"
        );
    }

    /// Decrypting with the wrong passphrase returns Err, never panics.
    #[test]
    fn test_wrong_passphrase() {
        let plaintext = b"super-secret-signing-key-32bytes";
        let correct = b"correct horse battery staple";
        let wrong = b"wrong passphrase entirely";

        let blob = encrypt_key(plaintext, correct).expect("encrypt_key failed");
        assert!(
            decrypt_key(&blob, wrong).is_err(),
            "expected Err for wrong passphrase, got Ok"
        );
    }

    /// Verify encrypt/decrypt round-trips with correct passphrase.
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"my-32-byte-signing-key-material!";
        let passphrase = b"a strong passphrase";

        let blob = encrypt_key(plaintext, passphrase).expect("encrypt_key failed");
        // Blob must be at least salt(16) + nonce(12) = 28 bytes before any ciphertext.
        assert!(blob.len() >= 28, "blob too short: {}", blob.len());

        let recovered = decrypt_key(&blob, passphrase).expect("decrypt_key failed");
        assert_eq!(recovered, plaintext, "round-trip mismatch");
    }

    /// A truncated or malformed export blob is an error, not a panic.
    #[tokio::test]
    async fn malformed_export_blob_errors_cleanly() {
        let store = crate::storage::MemoryStore::new();

        for bad in [
            vec![],
            vec![0u8; 4],
            // id_len claims 0xFFFF_FFFF bytes follow; nothing does.
            vec![0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0],
        ] {
            assert!(
                import_keys(&store, "signing", &bad, b"pass").await.is_err(),
                "malformed blob {bad:?} must return Err, not panic"
            );
        }
    }
}
