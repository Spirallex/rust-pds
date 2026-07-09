pub mod auth;
pub mod cmd;
pub mod config;
pub mod detect;
pub mod dns;
pub mod firehose;
pub mod identity;
pub mod keychain;
pub mod proxy_snippet;
pub mod tls;
pub mod xrpc;

// Device-portable core, extracted into the `stelyph-core` crate. Re-exported at
// the crate root so existing `crate::storage::*` / `crate::repo::*` paths across
// the server continue to resolve unchanged.
pub use stelyph_core::{repo, storage};
