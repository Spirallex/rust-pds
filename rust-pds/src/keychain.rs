//! macOS Keychain storage for `serve` secrets.
//!
//! Lets `stelyph serve` read `PDS_JWT_SECRET` / `PDS_KEY_PASSPHRASE` from the login
//! Keychain instead of requiring them exported into the environment each run. `init`
//! saves them here; `serve` reads them (env/flag still win, so CI/Docker can override).
//!
//! Secrets are scoped by hostname (`{hostname}/{key}`) so several PDSes on one machine
//! don't collide. Values live in the user's **login Keychain** — encrypted at rest and
//! unlocked with the macOS login. That makes it the guard for the signing-key passphrase,
//! which is stronger than env vars (no exposure in `ps` / shell history).
//!
//! macOS-only. On other platforms every function is a no-op (`get` → None, `set`/`delete`
//! → an "unsupported" error), so the fully-static Linux musl build pulls in no
//! Secret-Service / dbus stack and callers transparently fall back to env + prompt.

/// Keychain "service" name shared by all stelyph entries.
#[cfg(target_os = "macos")]
const SERVICE: &str = "stelyph";

/// Logical secret names (the account half of the Keychain entry).
pub const JWT_SECRET: &str = "jwt-secret";
pub const KEY_PASSPHRASE: &str = "key-passphrase";

/// Whether Keychain storage is compiled in on this platform.
pub const SUPPORTED: bool = cfg!(target_os = "macos");

#[cfg(target_os = "macos")]
fn account(hostname: &str, key: &str) -> String {
    format!("{hostname}/{key}")
}

/// Read a stored secret. Returns `None` if absent, or if Keychain access fails/denied
/// (callers then fall back to prompting) — never an error, so a locked Keychain can't
/// break startup.
#[cfg(target_os = "macos")]
pub fn get(hostname: &str, key: &str) -> Option<String> {
    let entry = keyring::Entry::new(SERVICE, &account(hostname, key)).ok()?;
    match entry.get_password() {
        Ok(v) => Some(v),
        Err(keyring::Error::NoEntry) => None,
        Err(_) => None,
    }
}

/// Store (or overwrite) a secret.
#[cfg(target_os = "macos")]
pub fn set(hostname: &str, key: &str, value: &str) -> anyhow::Result<()> {
    let entry = keyring::Entry::new(SERVICE, &account(hostname, key))
        .map_err(|e| anyhow::anyhow!("keychain open failed: {e}"))?;
    entry
        .set_password(value)
        .map_err(|e| anyhow::anyhow!("keychain write failed: {e}"))
}

/// Remove a secret. Absent is treated as success (idempotent clear).
#[cfg(target_os = "macos")]
pub fn delete(hostname: &str, key: &str) -> anyhow::Result<()> {
    let entry = keyring::Entry::new(SERVICE, &account(hostname, key))
        .map_err(|e| anyhow::anyhow!("keychain open failed: {e}"))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("keychain delete failed: {e}")),
    }
}

// ---- non-macOS fallbacks: keychain unavailable, callers use env/prompt --------------

#[cfg(not(target_os = "macos"))]
pub fn get(_hostname: &str, _key: &str) -> Option<String> {
    None
}

#[cfg(not(target_os = "macos"))]
pub fn set(_hostname: &str, _key: &str, _value: &str) -> anyhow::Result<()> {
    anyhow::bail!("keychain storage is only available on macOS; set the secret via env instead")
}

#[cfg(not(target_os = "macos"))]
pub fn delete(_hostname: &str, _key: &str) -> anyhow::Result<()> {
    Ok(())
}
