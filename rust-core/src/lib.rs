//! # stelyph-core
//!
//! Device-portable AT Protocol core, extracted from the `stelyph` PDS so it can
//! compile for non-server targets (notably `aarch64-apple-ios`) and be exposed
//! to Swift via UniFFI.
//!
//! What lives here: the signed repo / MST write engine, ES256K + AES-GCM crypto,
//! the encrypted key store, dag-cbor / CAR encoding + decoding, did:plc genesis
//! signing, did:web document building, JWT mint/verify, and the SQLite-backed
//! block + account store.
//!
//! What deliberately does NOT live here: the axum HTTP server, the
//! `subscribeRepos` WebSocket server, ACME/TLS provisioning, the relay
//! `requestCrawl` client, the reqwest-based PLC network client, and the CLI.
//! Those stay in the `stelyph` server crate, which depends on this one.
//!
//! Error handling: core APIs return [`error::CoreError`]; the server maps that
//! into its HTTP-facing `XrpcError` via a `From` impl.

pub mod auth;
pub mod error;
pub mod firehose;
pub mod identity;
/// AT Protocol OAuth 2.0 authorization server — protocol layer only. The HTTP
/// routes and login/consent UI live in the `stelyph` server crate.
pub mod oauth;
pub mod repo;
/// Minimal in-process `hyper` server for on-device hosting. Feature-gated
/// (`embedded-server`) so it never touches the default device-portable build.
#[cfg(feature = "embedded-server")]
pub mod server;
pub mod storage;

pub use error::CoreError;
