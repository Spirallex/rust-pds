//! `rust-pds import-keys` — import keys from a portable blob (ACCT-05 surface).
//!
//! Wraps `crate::storage::keys::import_keys` with a CLI-friendly interface:
//! - `--did`:    the DID to import keys under (required; overrides embedded id in blob)
//! - `--input`:  path to the signing-key blob produced by `export-keys` (required)
//! - `--db-path`: path to the PDS SQLite database (default: `pds.db` / `PDS_DB_PATH`)
//!
//! Both signing and rotation slots are imported: `--input` is the signing blob;
//! the rotation blob is expected at `<input>.rotation`. If the rotation file is
//! absent, only the signing slot is imported (rotation import is best-effort).
//!
//! # Security
//! - Passphrase is read via `rpassword` (non-echoing) — NEVER logged (T-7-04-01).
//! - Wrong passphrase → `StorageError::Crypto` propagates via `?` (non-zero exit).
//! - The passphrase is NEVER logged or written to disk.

#[derive(clap::Args, Debug, Default)]
pub struct ImportKeysArgs {
    /// DID of the account to import keys for (e.g. did:plc:abc123...).
    #[arg(long)]
    pub did: String,

    /// Path to the signing-key blob produced by `export-keys`.
    /// Rotation blob is expected at <input>.rotation (imported if present).
    #[arg(long)]
    pub input: std::path::PathBuf,

    /// Path to the PDS SQLite database.
    #[arg(long, env = "PDS_DB_PATH", default_value = "pds.db")]
    pub db_path: String,
}

pub async fn run(args: ImportKeysArgs) -> anyhow::Result<()> {
    // Non-echoing passphrase prompt (T-7-04-01 — passphrase never logged).
    let passphrase = rpassword::prompt_password("Key passphrase: ")?;

    let store = crate::storage::SqliteStore::open(&args.db_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open database {}: {e}", args.db_path))?;

    // Import signing key from --input.
    let signing_blob = std::fs::read(&args.input).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read signing key from {}: {e}",
            args.input.display()
        )
    })?;

    crate::storage::keys::import_keys(
        &store,
        &format!("{}#signing", args.did),
        &signing_blob,
        passphrase.as_bytes(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to import signing key: {e}"))?;

    println!("  ✓ imported signing key for {}", args.did);

    // Import rotation key from <input>.rotation (best-effort — absent is non-fatal).
    let mut rot_path = args.input.clone();
    rot_path.set_extension("rotation");

    if rot_path.exists() {
        let rotation_blob = std::fs::read(&rot_path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to read rotation key from {}: {e}",
                rot_path.display()
            )
        })?;

        crate::storage::keys::import_keys(
            &store,
            &format!("{}#rotation", args.did),
            &rotation_blob,
            passphrase.as_bytes(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to import rotation key: {e}"))?;

        println!("  ✓ imported rotation key for {}", args.did);
    } else {
        println!(
            "  (no rotation key file at {} — skipping)",
            rot_path.display()
        );
    }

    println!("✓ import complete for {}", args.did);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::storage::{keys, SqliteStore};

    /// Round-trip through export → import, then load to verify bytes match.
    /// Drives the storage layer directly (no TTY prompt needed in tests).
    #[tokio::test]
    async fn import_roundtrip_via_storage_layer() {
        let (store_src, _tmp_src) = SqliteStore::open_in_memory()
            .await
            .expect("open source store failed");
        let (store_dst, _tmp_dst) = SqliteStore::open_in_memory()
            .await
            .expect("open dest store failed");

        let key_id = "did:plc:importtest#signing";
        let passphrase = b"import-test-passphrase";
        let original_key: Vec<u8> = (64u8..96u8).collect();

        // Store key in source.
        keys::store_key(&store_src, key_id, &original_key, passphrase)
            .await
            .expect("store_key failed");

        // Export from source.
        let blob = keys::export_keys(&store_src, key_id, passphrase)
            .await
            .expect("export_keys failed");

        // Import into dest.
        keys::import_keys(&store_dst, key_id, &blob, passphrase)
            .await
            .expect("import_keys failed");

        // Verify the imported key decrypts to the same bytes.
        let recovered = keys::load_key(&store_dst, key_id, passphrase)
            .await
            .expect("load_key after import failed");
        assert_eq!(
            recovered, original_key,
            "imported key must round-trip to original bytes"
        );
    }

    /// Wrong passphrase on import returns Err (StorageError::Crypto), not panic.
    #[tokio::test]
    async fn wrong_passphrase_import_returns_error() {
        let (store_src, _tmp_src) = SqliteStore::open_in_memory()
            .await
            .expect("open source store failed");
        let (store_dst, _tmp_dst) = SqliteStore::open_in_memory()
            .await
            .expect("open dest store failed");

        let key_id = "did:plc:importfail#signing";
        let passphrase = b"correct-passphrase";
        let original_key: Vec<u8> = (0u8..32).collect();

        keys::store_key(&store_src, key_id, &original_key, passphrase)
            .await
            .expect("store_key failed");
        let blob = keys::export_keys(&store_src, key_id, passphrase)
            .await
            .expect("export_keys failed");

        // Import with wrong passphrase must fail.
        let result = keys::import_keys(&store_dst, key_id, &blob, b"wrong-passphrase").await;
        assert!(
            result.is_err(),
            "wrong passphrase on import must return Err"
        );
    }
}
