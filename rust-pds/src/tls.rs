use std::net::SocketAddr;
use std::path::Path;

use rustls_acme::{caches::DirCache, AcmeConfig};
use tokio_stream::StreamExt;

use crate::xrpc::AppState;

/// DOOR-05: map ACME environment to the rustls-acme directory flag.
/// true = Let's Encrypt PRODUCTION; false = STAGING (rehearsal, no rate limits).
pub fn acme_directory_is_production(env: crate::cmd::AcmeEnv) -> bool {
    matches!(env, crate::cmd::AcmeEnv::Production)
}

/// Create the ACME cert-cache dir (beside the DB) with owner-only perms (account key is sensitive).
fn ensure_cache_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// DOOR-01: serve the router over TLS via rustls-acme (TLS-ALPN-01) on :443.
/// `prod` selects production vs staging (DOOR-05). CryptoProvider is installed in main() (Plan 01).
pub async fn serve_standalone(
    app_state: AppState,
    hostname: String,
    acme_cache_dir: String,
    prod: bool,
) -> anyhow::Result<()> {
    ensure_cache_dir(Path::new(&acme_cache_dir))?;
    let mut acme_state = AcmeConfig::new(vec![hostname.clone()])
        .contact(Vec::<String>::new())
        .cache(DirCache::new(acme_cache_dir))
        .directory_lets_encrypt(prod)
        .state();
    let acceptor = acme_state.axum_acceptor(acme_state.default_rustls_config());
    // Pitfall 4: certs never acquire unless next() is polled in a spawned task.
    tokio::spawn(async move {
        loop {
            match acme_state.next().await.unwrap() {
                Ok(ok) => eprintln!("acme: {:?}", ok),
                Err(err) => eprintln!("acme error: {:?}", err),
            }
        }
    });
    let addr: SocketAddr = ([0, 0, 0, 0], 443).into();
    eprintln!("standalone TLS listening on {addr} (hostname={hostname}, production={prod})");
    axum_server::bind(addr)
        .acceptor(acceptor)
        .serve(crate::xrpc::app(app_state).into_make_service())
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::AcmeEnv;

    // DOOR-05: production mapping is deterministic
    #[test]
    fn production_env_maps_to_true() {
        assert!(
            acme_directory_is_production(AcmeEnv::Production),
            "AcmeEnv::Production must map to true (production directory)"
        );
    }

    // DOOR-05: staging mapping is deterministic
    #[test]
    fn staging_env_maps_to_false() {
        assert!(
            !acme_directory_is_production(AcmeEnv::Staging),
            "AcmeEnv::Staging must map to false (staging directory)"
        );
    }

    // Threat T-7-03-01: cache dir created with owner-only permissions
    #[test]
    fn ensure_cache_dir_creates_with_0700() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let cache_path = tmp.path().join("acme");
        ensure_cache_dir(&cache_path).expect("ensure_cache_dir");
        assert!(
            cache_path.exists(),
            "cache dir must exist after ensure_cache_dir"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::metadata(&cache_path).expect("metadata");
            let mode = meta.mode() & 0o777;
            assert_eq!(
                mode, 0o700,
                "cache dir must have owner-only perms (0700); got {mode:o}"
            );
        }
    }
}
