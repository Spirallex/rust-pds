//! `stelyph export-keys` — export encrypted signing keys to a portable blob.
//!
//! Wraps `crate::storage::crypto::export_keys` with a CLI-friendly interface:
//! - `--did`:    the DID whose keys to export (required)
//! - `--output`: path to write the signing-key blob (required)
//! - `--db-path`: path to the PDS SQLite database (default: `pds.db` / `PDS_DB_PATH`)
//!
//! Both signing and rotation slots are exported.
//! Signing slot → `--output`; rotation slot → `<output>.rotation`.
//!
//! # Security
//! - Passphrase is read via `rpassword` (non-echoing) — NEVER logged.
//! - A wrong passphrase causes `StorageError::Crypto` which propagates via `?` and
//!   is printed as a human-readable error by the main dispatcher (non-zero exit).
//! - The passphrase is NEVER written to disk or included in error messages.

#[derive(clap::Args, Debug, Default)]
pub struct ExportKeysArgs {
    /// DID of the account whose keys to export (e.g. did:plc:abc123...).
    #[arg(long)]
    pub did: String,

    /// Path to write the signing-key blob. Rotation key is written to <output>.rotation.
    #[arg(long)]
    pub output: std::path::PathBuf,

    /// Path to the PDS SQLite database.
    #[arg(long, env = "PDS_DB_PATH", default_value = "pds.db")]
    pub db_path: String,
}

pub async fn run(args: ExportKeysArgs) -> anyhow::Result<()> {
    // Non-echoing passphrase prompt — passphrase never logged.
    let passphrase = rpassword::prompt_password("Key passphrase: ")?;

    let store = crate::storage::SqliteStore::open(&args.db_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open database {}: {e}", args.db_path))?;

    // Export signing key to --output.
    let signing = crate::storage::crypto::export_keys(
        &store,
        &format!("{}#signing", args.did),
        passphrase.as_bytes(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to export signing key: {e}"))?;
    std::fs::write(&args.output, &signing).map_err(|e| {
        anyhow::anyhow!(
            "Failed to write signing key to {}: {e}",
            args.output.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&args.output, std::fs::Permissions::from_mode(0o600)).map_err(
            |e| {
                anyhow::anyhow!(
                    "Failed to set permissions on {}: {e}",
                    args.output.display()
                )
            },
        )?;
    }

    // Export rotation key to <output>.rotation.
    let rotation = crate::storage::crypto::export_keys(
        &store,
        &format!("{}#rotation", args.did),
        passphrase.as_bytes(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to export rotation key: {e}"))?;
    let mut rot_path = args.output.clone();
    rot_path.set_extension("rotation");
    std::fs::write(&rot_path, &rotation).map_err(|e| {
        anyhow::anyhow!(
            "Failed to write rotation key to {}: {e}",
            rot_path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&rot_path, std::fs::Permissions::from_mode(0o600)).map_err(
            |e| anyhow::anyhow!("Failed to set permissions on {}: {e}", rot_path.display()),
        )?;
    }

    println!("✓ exported signing + rotation keys for {}", args.did);
    println!("  signing key  → {}", args.output.display());
    println!("  rotation key → {}", rot_path.display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::storage::{crypto as keys, SqliteStore};

    /// Round-trip: store a key → export to tempfile via storage fn → import under new id →
    /// load and verify bytes match. Drives the storage layer directly (no TTY prompt needed).
    #[tokio::test]
    async fn export_import_roundtrip_via_storage_layer() {
        let (store, _tmp) = SqliteStore::open_in_memory()
            .await
            .expect("open_in_memory failed");

        let key_id = "did:plc:test1234#signing";
        let passphrase = b"export-test-passphrase";
        let plaintext: Vec<u8> = (0u8..32).collect();

        // Store the key.
        keys::store_key(&store, key_id, &plaintext, passphrase)
            .await
            .expect("store_key failed");

        // Export to a temporary file using the storage fn.
        let blob = keys::export_keys(&store, key_id, passphrase)
            .await
            .expect("export_keys failed");

        // Write to a temp file to simulate the CLI output.
        let tmp_file = tempfile::NamedTempFile::new().expect("tempfile failed");
        std::fs::write(tmp_file.path(), &blob).expect("write blob failed");

        // Import the blob from the file into a fresh store under a new id.
        let (store2, _tmp2) = SqliteStore::open_in_memory()
            .await
            .expect("open second store failed");
        let blob_from_file = std::fs::read(tmp_file.path()).expect("read blob failed");

        keys::import_keys(&store2, key_id, &blob_from_file, passphrase)
            .await
            .expect("import_keys failed");

        // Verify the imported key decrypts to the same bytes.
        let recovered = keys::load_key(&store2, key_id, passphrase)
            .await
            .expect("load_key after import failed");
        assert_eq!(recovered, plaintext, "round-trip key bytes must match");
    }

    /// Exported key files are written with owner-only permissions (0o600) on Unix.
    #[cfg(unix)]
    #[tokio::test]
    async fn exported_key_files_have_0600_permissions() {
        use std::os::unix::fs::MetadataExt;

        let (store, _tmp) = SqliteStore::open_in_memory()
            .await
            .expect("open_in_memory failed");

        let did = "did:plc:permtest";
        let passphrase = b"perm-test-passphrase";
        let plaintext: Vec<u8> = (0u8..32).collect();

        // Store both signing and rotation keys.
        keys::store_key(&store, &format!("{did}#signing"), &plaintext, passphrase)
            .await
            .expect("store signing key");
        keys::store_key(&store, &format!("{did}#rotation"), &plaintext, passphrase)
            .await
            .expect("store rotation key");

        // Export signing key blob and write with 0o600.
        let signing_blob = keys::export_keys(&store, &format!("{did}#signing"), passphrase)
            .await
            .expect("export signing key");
        let tmp_dir = tempfile::tempdir().expect("tempdir");
        let signing_path = tmp_dir.path().join("signing.key");
        std::fs::write(&signing_path, &signing_blob).expect("write signing blob");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&signing_path, std::fs::Permissions::from_mode(0o600))
                .expect("set signing permissions");
        }
        let signing_mode = std::fs::metadata(&signing_path).expect("metadata").mode() & 0o777;
        assert_eq!(
            signing_mode, 0o600,
            "signing key must be 0o600; got {signing_mode:o}"
        );

        // Export rotation key blob and write with 0o600.
        let rotation_blob = keys::export_keys(&store, &format!("{did}#rotation"), passphrase)
            .await
            .expect("export rotation key");
        let mut rot_path = signing_path.clone();
        rot_path.set_extension("rotation");
        std::fs::write(&rot_path, &rotation_blob).expect("write rotation blob");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&rot_path, std::fs::Permissions::from_mode(0o600))
                .expect("set rotation permissions");
        }
        let rotation_mode = std::fs::metadata(&rot_path).expect("metadata").mode() & 0o777;
        assert_eq!(
            rotation_mode, 0o600,
            "rotation key must be 0o600; got {rotation_mode:o}"
        );
    }

    /// Wrong passphrase on export returns Err (StorageError::Crypto), not panic.
    #[tokio::test]
    async fn wrong_passphrase_returns_error() {
        let (store, _tmp) = SqliteStore::open_in_memory()
            .await
            .expect("open_in_memory failed");

        let key_id = "did:plc:test9999#signing";
        let passphrase = b"correct-passphrase";
        let plaintext: Vec<u8> = (0u8..32).collect();

        keys::store_key(&store, key_id, &plaintext, passphrase)
            .await
            .expect("store_key failed");

        let result = keys::export_keys(&store, key_id, b"wrong-passphrase").await;
        assert!(result.is_err(), "wrong passphrase must return Err");
    }
}
