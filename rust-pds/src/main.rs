//! stelyph binary entry point.
//!
//! Thin clap dispatcher. Installs the rustls CryptoProvider once before any TLS
//! code runs — rustls 0.23 requires an explicit provider and panics if none is
//! installed before the first TLS/reqwest/axum construction — then dispatches
//! to the appropriate subcommand.
//!
//! Subcommands:
//!   serve        — Run the PDS server (proxy or standalone mode)
//!   init         — Interactive setup wizard
//!   export-keys  — Export encrypted signing keys
//!   import-keys  — Import keys from a portable blob

use clap::Parser;
use stelyph::cmd::{Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install the rustls CryptoProvider exactly once, BEFORE any
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
