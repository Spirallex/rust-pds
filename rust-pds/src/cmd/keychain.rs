//! `stelyph keychain` — manage the macOS Keychain copies of the serve secrets.
//!
//! `set` stores `PDS_JWT_SECRET` / `PDS_KEY_PASSPHRASE` (prompted, non-echoing) so
//! `stelyph serve` reads them automatically without an `export`. `status` reports which
//! are present; `clear` removes them. Scoped by hostname (from `--hostname`/config).
//!
//! macOS-only: on other platforms these commands report that Keychain storage is
//! unavailable and exit non-zero (use env vars there).

use std::path::PathBuf;

use crate::config::PdsConfig;
use crate::keychain;

#[derive(clap::Args, Debug)]
pub struct KeychainArgs {
    #[command(subcommand)]
    pub command: KeychainCommand,
    /// Hostname whose secrets to manage. Defaults to the one in stelyph.toml.
    #[arg(long, env = "PDS_HOSTNAME", global = true)]
    pub hostname: Option<String>,
}

#[derive(clap::Subcommand, Debug)]
pub enum KeychainCommand {
    /// Store the JWT secret and key passphrase in the Keychain (prompts, non-echoing).
    Set,
    /// Show which secrets are stored for this hostname.
    Status,
    /// Remove both stored secrets for this hostname.
    Clear,
}

fn resolve_hostname(explicit: Option<String>, config: Option<&PathBuf>) -> anyhow::Result<String> {
    if let Some(h) = explicit {
        return Ok(h);
    }
    let path = crate::cmd::resolve_config_path(config.map(|p| p.as_path()));
    PdsConfig::load_or_default(path.exists().then_some(path.as_path()))?
        .hostname
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no hostname — pass --hostname or run from a directory with stelyph.toml"
            )
        })
}

pub async fn run(args: KeychainArgs, config: Option<PathBuf>) -> anyhow::Result<()> {
    if !keychain::SUPPORTED {
        anyhow::bail!(
            "Keychain storage is only available on macOS. On this platform set \
             PDS_JWT_SECRET / PDS_KEY_PASSPHRASE via the environment instead."
        );
    }
    let hostname = resolve_hostname(args.hostname, config.as_ref())?;

    match args.command {
        KeychainCommand::Set => {
            // JWT secret: paste, or blank to generate a fresh one.
            let jwt = rpassword::prompt_password(
                "PDS_JWT_SECRET (paste the one from init, or blank to generate): ",
            )?;
            let jwt = if jwt.trim().is_empty() {
                use rand::RngCore;
                let mut bytes = vec![0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut bytes);
                let encoded = data_encoding::BASE64URL_NOPAD.encode(&bytes);
                println!("  generated a new 32-byte JWT secret");
                encoded
            } else if jwt.len() < 32 {
                anyhow::bail!(
                    "PDS_JWT_SECRET must be at least 32 bytes (got {})",
                    jwt.len()
                );
            } else {
                jwt
            };
            // Key passphrase: must match the one used at init (not verifiable here).
            let passphrase = rpassword::prompt_password(
                "PDS_KEY_PASSPHRASE (the passphrase you set at init): ",
            )?;
            if passphrase.is_empty() {
                anyhow::bail!("PDS_KEY_PASSPHRASE must not be empty");
            }

            keychain::set(&hostname, keychain::JWT_SECRET, &jwt)?;
            keychain::set(&hostname, keychain::KEY_PASSPHRASE, &passphrase)?;
            println!("✓ stored JWT secret + key passphrase for {hostname} in the Keychain.");
            println!("  `stelyph serve` will now read them automatically — no export needed.");
            Ok(())
        }
        KeychainCommand::Status => {
            let has = |k: &str| keychain::get(&hostname, k).is_some();
            let mark = |b: bool| if b { "present" } else { "absent" };
            println!("Keychain secrets for {hostname}:");
            println!("  PDS_JWT_SECRET     {}", mark(has(keychain::JWT_SECRET)));
            println!(
                "  PDS_KEY_PASSPHRASE {}",
                mark(has(keychain::KEY_PASSPHRASE))
            );
            Ok(())
        }
        KeychainCommand::Clear => {
            keychain::delete(&hostname, keychain::JWT_SECRET)?;
            keychain::delete(&hostname, keychain::KEY_PASSPHRASE)?;
            println!("✓ removed stored secrets for {hostname} from the Keychain.");
            Ok(())
        }
    }
}
