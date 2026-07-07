//! Firehose: the com.atproto.sync.subscribeRepos event stream + requestCrawl handshake.
//!
//! The wire-format primitives (frame encode/decode, `CommitBody`, `RepoOp`,
//! `FirehoseEvent`, commit-sig verification) are device-portable and live in
//! `stelyph-core`; they are re-exported here so `crate::firehose::*` keeps
//! resolving. The `subscribeRepos` WebSocket *server* and the relay
//! `requestCrawl` *client* are server-only and stay in this crate.

pub mod crawl;
pub mod subscribe;

pub use stelyph_core::firehose::{
    decode_commit_frame, encode_error_frame, encode_message_frame, frame, tail, verify_commit_sig,
    CommitBody, FirehoseEvent, RepoOp, TailError,
};

pub use crawl::{MockRelayClient, RelayClient, ReqwestRelayClient};
