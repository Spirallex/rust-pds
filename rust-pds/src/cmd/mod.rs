pub mod admin;
pub mod export_keys;
pub mod import_keys;
pub mod init;
pub mod serve;

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

pub use export_keys::ExportKeysArgs;
pub use import_keys::ImportKeysArgs;
pub use init::InitArgs;
pub use serve::ServeArgs;

#[derive(Parser)]
#[command(name = "stelyph", version, about = "ATProto Personal Data Server")]
pub struct Cli {
    #[arg(long, global = true, env = "PDS_CONFIG")]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Interactive setup wizard
    Init(init::InitArgs),
    /// Run the PDS server
    Serve(serve::ServeArgs),
    /// Export encrypted signing keys to a portable blob
    ExportKeys(export_keys::ExportKeysArgs),
    /// Import keys from a portable blob
    ImportKeys(import_keys::ImportKeysArgs),
    /// Local admin tooling (invites, accounts, takedown, password reset)
    Admin(admin::AdminArgs),
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Standalone,
    Proxy,
}

#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AcmeEnv {
    #[default]
    Production,
    Staging,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_debug_assert() {
        Cli::command().debug_assert();
    }

    #[test]
    fn invalid_mode_is_rejected() {
        let result = Cli::try_parse_from(["stelyph", "serve", "--mode", "bogus"]);
        assert!(result.is_err(), "invalid --mode value must be rejected");
    }

    #[test]
    fn invalid_acme_is_rejected() {
        let result = Cli::try_parse_from(["stelyph", "serve", "--acme", "bogus"]);
        assert!(result.is_err(), "invalid --acme value must be rejected");
    }
}
