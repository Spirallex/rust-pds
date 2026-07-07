//! `rust-pds serve` — start the PDS server.
//!
//! Proxy mode (default): binds a plain TcpListener and serves the existing axum router.
//! Standalone mode: TLS via rustls-acme (ACME TLS-ALPN-01). Wired in Plan 03.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::firehose::ReqwestRelayClient;
use crate::identity::plc::ReqwestPlcClient;
use crate::identity::web_resolver::{DidWebResolver, ReqwestDidWebResolver};
use crate::storage::SqliteStore;
use crate::xrpc::appview::client::ReqwestAppViewClient;
use crate::xrpc::{app, AppState};

use crate::config::PdsConfig;

#[derive(clap::Args, Debug, Default)]
pub struct ServeArgs {
    #[arg(long, env = "PDS_HOSTNAME")]
    pub hostname: Option<String>,
    #[arg(long, env = "PDS_MODE")]
    pub mode: Option<super::Mode>,
    #[arg(long, env = "PDS_ACME_ENV")]
    pub acme: Option<super::AcmeEnv>,
    #[arg(long, env = "PDS_DB_PATH")]
    pub db_path: Option<String>,
    #[arg(long, env = "PDS_PORT")]
    pub port: Option<u16>,
    #[arg(long, env = "PDS_JWT_SECRET")]
    pub jwt_secret: Option<String>,
    #[arg(long, env = "PDS_KEY_PASSPHRASE")]
    pub key_passphrase: Option<String>,
    #[arg(long, env = "PDS_PLC_URL")]
    pub plc_url: Option<String>,
    #[arg(long, env = "PDS_RELAY_URL")]
    pub relay_url: Option<String>,
    #[arg(long, env = "PDS_APPVIEW_URL")]
    pub appview_url: Option<String>,
    #[arg(long, env = "PDS_APPVIEW_DID")]
    pub appview_did: Option<String>,
    #[arg(long)]
    pub open_registration: bool,
}

pub async fn run(args: ServeArgs, config: Option<PathBuf>) -> anyhow::Result<()> {
    // 1. Load config file (file < env < flag precedence).
    let cfg = PdsConfig::load_or_default(config.as_deref())?;

    // 2. Resolve effective values: flag/env (already folded by clap) > file > default.
    let hostname = args.hostname.or(cfg.hostname).unwrap_or_else(|| {
        eprintln!("FATAL: PDS_HOSTNAME is required (set via env, flag, or rust-pds.toml)");
        std::process::exit(1);
    });

    // T-7-01-02/T-7-01-03: jwt_secret and key_passphrase are never in config file.
    // T-7-01-03: Only the byte LENGTH is printed, never the value itself.
    let jwt_secret = args
        .jwt_secret
        .unwrap_or_else(|| {
            eprintln!("FATAL: PDS_JWT_SECRET is required");
            std::process::exit(1);
        })
        .into_bytes();
    if jwt_secret.len() < 32 {
        eprintln!(
            "FATAL: PDS_JWT_SECRET must be at least 32 bytes (got {}). \
             Set a strong secret before starting the server.",
            jwt_secret.len()
        );
        std::process::exit(1);
    }

    let key_passphrase = args
        .key_passphrase
        .unwrap_or_else(|| {
            eprintln!("FATAL: PDS_KEY_PASSPHRASE is required");
            std::process::exit(1);
        })
        .into_bytes();
    if key_passphrase.is_empty() {
        eprintln!("FATAL: PDS_KEY_PASSPHRASE must not be empty.");
        std::process::exit(1);
    }

    let db_path = args
        .db_path
        .or(cfg.db_path)
        .unwrap_or_else(|| "pds.db".to_string());
    let port: u16 = args.port.or(cfg.port).unwrap_or(3000);
    let plc_url = args
        .plc_url
        .or(cfg.plc_url)
        .unwrap_or_else(|| "https://plc.directory".to_string());
    let relay_url = args
        .relay_url
        .or(cfg.relay_url)
        .unwrap_or_else(|| "https://bsky.network".to_string());
    let appview_url = args
        .appview_url
        .or(cfg.appview_url)
        .unwrap_or_else(|| "https://api.bsky.app".to_string());
    let appview_did = args
        .appview_did
        .or(cfg.appview_did)
        .unwrap_or_else(|| "did:web:api.bsky.app".to_string());
    // IDEN-04: compose-network plain-HTTP dev mode for the did:web resolver.
    // Defaults false (HTTPS) — NEVER set true in production.
    let did_web_http_dev = cfg.did_web_http_dev.unwrap_or(false);
    let pds_endpoint = format!("https://{hostname}");

    // 3. Determine mode.
    let mode = args
        .mode
        .or_else(|| {
            cfg.mode.as_deref().and_then(|m| match m {
                "standalone" => Some(super::Mode::Standalone),
                "proxy" => Some(super::Mode::Proxy),
                _ => None,
            })
        })
        .unwrap_or(super::Mode::Proxy);

    // 3a. Determine ACME environment (DOOR-05: production is the default).
    let acme_env = args
        .acme
        .or_else(|| {
            cfg.acme_env.as_deref().and_then(|e| match e {
                "staging" => Some(super::AcmeEnv::Staging),
                "production" => Some(super::AcmeEnv::Production),
                _ => None,
            })
        })
        .unwrap_or(super::AcmeEnv::Production);

    // 3b. Derive the ACME cert-cache dir beside the DB (locked decision).
    let db_dir = std::path::Path::new(&db_path)
        .parent()
        .and_then(|p| p.to_str())
        .map(|s| if s.is_empty() { "." } else { s })
        .unwrap_or(".")
        .to_string();
    let acme_cache_dir = cfg
        .acme_cache_dir
        .unwrap_or_else(|| format!("{db_dir}/acme"));

    // 4. Build AppState (verbatim from original main.rs).
    let store = SqliteStore::open(&db_path)
        .await
        .map_err(|e| anyhow::anyhow!("FATAL: Failed to open SQLite database {db_path}: {e}"))?;

    let plc_client = ReqwestPlcClient::with_url(&plc_url)
        .map_err(|e| anyhow::anyhow!("FATAL: Failed to create PLC client ({plc_url}): {e}"))?;

    let relay_client: Arc<dyn crate::firehose::RelayClient> = Arc::new(
        ReqwestRelayClient::new()
            .map_err(|e| anyhow::anyhow!("FATAL: Failed to create relay client: {e}"))?,
    );

    let appview_client: Arc<dyn crate::xrpc::appview::client::AppViewClient> = Arc::new(
        ReqwestAppViewClient::new()
            .map_err(|e| anyhow::anyhow!("FATAL: Failed to create AppView client: {e}"))?,
    );

    let did_web_resolver: Arc<dyn DidWebResolver> = Arc::new(
        ReqwestDidWebResolver::new(did_web_http_dev)
            .map_err(|e| anyhow::anyhow!("FATAL: Failed to create did:web resolver: {e}"))?,
    );

    let open_registration = args.open_registration;

    let state = AppState {
        store: Arc::new(store),
        jwt_secret: Arc::new(jwt_secret),
        hostname: hostname.clone(),
        pds_endpoint,
        open_registration,
        plc_client: Arc::new(plc_client),
        did_web_resolver,
        key_passphrase: Arc::new(key_passphrase),
        firehose_tx: tokio::sync::broadcast::channel(512).0,
        relay_client: Arc::clone(&relay_client),
        relay_url: relay_url.clone(),
        appview_client,
        appview_url,
        appview_did,
    };

    match mode {
        super::Mode::Proxy => {
            // PROXY branch: today's code (main.rs lines 93–119) reproduced verbatim.
            let router = app(state);
            let addr = SocketAddr::from(([0, 0, 0, 0], port));
            println!("rust-pds listening on {addr} (hostname={hostname}, open_registration={open_registration})");

            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| anyhow::anyhow!("FATAL: Failed to bind to {addr}: {e}"))?;

            // Kick off the relay handshake so the relay begins crawling this PDS (FED-03).
            // Non-fatal: relay outage must not crash the PDS.
            {
                let relay_client_startup = Arc::clone(&relay_client);
                let relay_url_startup = relay_url.clone();
                let hostname_startup = hostname.clone();
                tokio::spawn(async move {
                    if let Err(e) = relay_client_startup
                        .request_crawl(&relay_url_startup, &hostname_startup)
                        .await
                    {
                        eprintln!("requestCrawl to relay failed (non-fatal): {e}");
                    }
                });
            }

            axum::serve(listener, router)
                .await
                .map_err(|e| anyhow::anyhow!("FATAL: Server error: {e}"))?;
        }
        super::Mode::Standalone => {
            let prod = crate::tls::acme_directory_is_production(acme_env);

            // Kick off the relay handshake so the relay begins crawling this PDS (FED-03).
            // Non-fatal: relay outage must not crash the PDS.
            {
                let relay_client_startup = Arc::clone(&relay_client);
                let relay_url_startup = relay_url.clone();
                let hostname_startup = hostname.clone();
                tokio::spawn(async move {
                    if let Err(e) = relay_client_startup
                        .request_crawl(&relay_url_startup, &hostname_startup)
                        .await
                    {
                        eprintln!("requestCrawl to relay failed (non-fatal): {e}");
                    }
                });
            }

            if let Err(e) =
                crate::tls::serve_standalone(state, hostname.clone(), acme_cache_dir, prod).await
            {
                // Pitfall 6: a :443 PermissionDenied surfaces here.
                eprintln!(
                    "FATAL: standalone serve failed: {e}\n\
                     If this is a port-443 permission error, either run behind a reverse proxy \
                     (--mode proxy) or grant the bind capability:\n  \
                     sudo setcap 'cap_net_bind_service=+ep' <path-to-rust-pds>"
                );
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
