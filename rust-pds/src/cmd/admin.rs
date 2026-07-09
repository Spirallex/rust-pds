//! `stelyph admin` — local operator tooling against the PDS SQLite database.
//!
//! These commands operate **directly on the database file** (like `init` /
//! `export-keys`), not over the network — so they require filesystem access to
//! the PDS, not an admin token. That keeps the server's HTTP surface free of
//! privileged endpoints. Run them on the host (or via `docker exec` / the
//! Coolify terminal) pointing at the same `--db-path` the server uses.
//!
//! Subcommands:
//!   - `create-invite`   generate an invite code (for the invite-gated registration)
//!   - `list-accounts`   show every account + status (active / deactivated / takedown)
//!   - `takedown`        hide an account from auth/sessions/handle resolution
//!   - `untakedown`      restore a taken-down account
//!   - `reset-password`  set a new password for an account (handle or DID)

use crate::auth::jwt::hash_password;
use crate::storage::SqliteStore;

#[derive(clap::Args, Debug)]
pub struct AdminArgs {
    /// Path to the PDS SQLite database.
    #[arg(long, env = "PDS_DB_PATH", default_value = "pds.db", global = true)]
    pub db_path: String,

    #[command(subcommand)]
    pub command: AdminCommand,
}

#[derive(clap::Subcommand, Debug)]
pub enum AdminCommand {
    /// Generate an invite code for invite-gated account creation.
    CreateInvite {
        /// How many times the code may be redeemed.
        #[arg(long, default_value_t = 1)]
        uses: i64,
        /// DID/label the invite is credited to (free-form; defaults to "admin").
        #[arg(long)]
        for_account: Option<String>,
    },
    /// List every account with its status.
    ListAccounts,
    /// Take down an account: it is hidden from login, sessions, and handle resolution.
    Takedown {
        /// The account DID (e.g. did:plc:...).
        did: String,
        /// Optional reason / ticket reference stored as the takedown marker.
        #[arg(long, default_value = "")]
        reference: String,
    },
    /// Restore a previously taken-down account.
    Untakedown {
        /// The account DID (e.g. did:plc:...).
        did: String,
    },
    /// Reset an account's password (prompts for the new password, non-echoing).
    ResetPassword {
        /// Account handle (e.g. alice.pds.example.com) or DID.
        identifier: String,
    },
}

pub async fn run(args: AdminArgs) -> anyhow::Result<()> {
    if !std::path::Path::new(&args.db_path).exists() {
        anyhow::bail!(
            "no database at {} — did you mean to point --db-path at your existing pds.db?",
            args.db_path
        );
    }

    let store = SqliteStore::open(&args.db_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open database {}: {e}", args.db_path))?;

    match args.command {
        AdminCommand::CreateInvite { uses, for_account } => {
            if uses < 1 {
                anyhow::bail!("--uses must be >= 1");
            }
            let code = generate_invite_code();
            let for_account = for_account.unwrap_or_else(|| "admin".to_string());
            store
                .insert_invite(&code, uses, &for_account)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to create invite: {e}"))?;
            println!("invite code: {code}");
            println!("  uses: {uses}");
            println!("  for:  {for_account}");
        }

        AdminCommand::ListAccounts => {
            let accounts = store
                .list_accounts()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to list accounts: {e}"))?;
            if accounts.is_empty() {
                println!("(no accounts)");
                return Ok(());
            }
            println!("{:<32}  {:<8}  {:<24}  HANDLE", "DID", "STATUS", "CREATED");
            for a in &accounts {
                let status = if a.takedown_ref.is_some() {
                    "takedown"
                } else if a.deactivated_at.is_some() {
                    "inactive"
                } else {
                    "active"
                };
                println!(
                    "{:<32}  {:<8}  {:<24}  {}",
                    a.did,
                    status,
                    a.created_at,
                    a.handle.as_deref().unwrap_or("-"),
                );
            }
            println!("\n{} account(s)", accounts.len());
        }

        AdminCommand::Takedown { did, reference } => {
            let n = store
                .set_takedown(&did, &reference)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to take down account: {e}"))?;
            if n == 0 {
                anyhow::bail!("no account found with DID {did}");
            }
            println!("✓ took down {did}");
        }

        AdminCommand::Untakedown { did } => {
            let n = store
                .clear_takedown(&did)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to restore account: {e}"))?;
            if n == 0 {
                anyhow::bail!("no account found with DID {did} (or it was not taken down)");
            }
            println!("✓ restored {did}");
        }

        AdminCommand::ResetPassword { identifier } => {
            // Resolve handle → DID; a value starting with "did:" is used as-is.
            let did = if identifier.starts_with("did:") {
                identifier.clone()
            } else {
                store
                    .get_did_by_handle(&identifier)
                    .await
                    .map_err(|e| anyhow::anyhow!("lookup failed: {e}"))?
                    .ok_or_else(|| anyhow::anyhow!("no account with handle '{identifier}'"))?
            };

            // Non-echoing prompt + confirmation — password never logged.
            let pw = rpassword::prompt_password("New password (min 8 chars): ")?;
            if pw.len() < 8 {
                anyhow::bail!("password must be at least 8 characters");
            }
            let confirm = rpassword::prompt_password("Confirm new password: ")?;
            if pw != confirm {
                anyhow::bail!("passwords do not match");
            }

            let phc = hash_password(&pw).map_err(|e| anyhow::anyhow!("hash failed: {e}"))?;
            let n = store
                .update_password(&did, &phc)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to update password: {e}"))?;
            if n == 0 {
                anyhow::bail!("no account found for {did}");
            }
            println!("✓ password reset for {did}");
        }
    }

    Ok(())
}

/// Generate an opaque invite code: `stelyph-` + 10 lowercase base32 chars from
/// 50 random bits. Vary by entropy, not time, so it is unguessable.
pub(crate) fn generate_invite_code() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let enc = data_encoding::BASE32_NOPAD
        .encode(&bytes)
        .to_ascii_lowercase();
    format!("stelyph-{}", &enc[..10])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B6 regression: a `--db-path` that does not exist must error with an
    /// actionable message *before* any store is opened, and must leave no
    /// database (or WAL/SHM) file behind. Guards against `SqliteStore::open`'s
    /// create-if-missing behavior silently producing a decoy empty DB.
    #[tokio::test]
    async fn admin_missing_db_path_errors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db_path = tmp.path().join("does-not-exist.db");
        let db_path_str = db_path.to_str().unwrap().to_string();

        assert!(
            !db_path.exists(),
            "precondition: db path must not exist before the call"
        );

        let args = AdminArgs {
            db_path: db_path_str,
            command: AdminCommand::ListAccounts,
        };

        let result = run(args).await;

        assert!(result.is_err(), "expected an error for a missing db-path");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("did you mean to point --db-path"),
            "error message did not contain the expected guidance: {err_msg}"
        );

        assert!(
            !db_path.exists(),
            "no database file should have been created at the missing path"
        );
        assert!(
            !tmp.path().join("does-not-exist.db-wal").exists(),
            "no WAL file should have been created at the missing path"
        );
        assert!(
            !tmp.path().join("does-not-exist.db-shm").exists(),
            "no SHM file should have been created at the missing path"
        );
    }
}
