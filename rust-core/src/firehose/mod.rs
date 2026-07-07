//! Firehose encoding + decoding primitives (device-portable).
//!
//! This is the wire-format half of the firehose: building `#commit` frames from
//! a repo write, and decoding/verifying frames produced elsewhere. The
//! `subscribeRepos` WebSocket *server* and the relay `requestCrawl` *client*
//! live in the server crate.

pub mod frame;
pub mod tail;

pub use frame::{encode_error_frame, encode_message_frame, CommitBody, RepoOp};
pub use tail::{decode_commit_frame, verify_commit_sig, TailError};

/// One broadcast unit: the fully-encoded binary frame plus its seq for cutover dedup.
#[derive(Clone)]
pub struct FirehoseEvent {
    pub seq: i64,
    pub frame: Vec<u8>,
}
