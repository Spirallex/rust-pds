//! stelyph binary entry point.
//!
//! Thin clap dispatcher. Installs the rustls CryptoProvider once before any TLS
//! code runs (Pitfall 1 / T-7-01-05), then dispatches to the appropriate subcommand.
//!
//! Subcommands:
//!   serve        — Run the PDS server (proxy or standalone mode)
//!   init         — Interactive setup wizard (Plan 04)
//!   export-keys  — Export encrypted signing keys (Plan 04)
//!   import-keys  — Import keys from a portable blob (Plan 04)

use clap::Parser;
use stelyph::cmd::{Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // T-7-01-05: Install the rustls CryptoProvider exactly once, BEFORE any
    // TLS/reqwest/axum construction. rustls 0.23 requires an explicit provider.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("rustls CryptoProvider already installed");

    let cli = Cli::parse();
    match cli.command {
        Command::Serve(args) => stelyph::cmd::serve::run(args, cli.config).await,
        Command::Init(args) => stelyph::cmd::init::run(args, cli.config).await,
        Command::ExportKeys(args) => stelyph::cmd::export_keys::run(args).await,
        Command::ImportKeys(args) => stelyph::cmd::import_keys::run(args).await,
        Command::Admin(args) => stelyph::cmd::admin::run(args).await,
    }
}
