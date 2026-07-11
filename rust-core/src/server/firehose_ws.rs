//! `com.atproto.sync.subscribeRepos` for the embedded server — a hand-rolled
//! RFC 6455 WebSocket host over hyper's HTTP/1.1 upgrade.
//!
//! No tungstenite/TLS stack: the firehose is effectively SEND-ONLY binary
//! frames, so the entire protocol surface we need is the handshake
//! (SHA-1 + base64 accept key), unmasked server frames out, and just enough
//! client-frame parsing to answer ping with pong and close with close.
//!
//! The streaming state machine mirrors the production server
//! (`stelyph/src/firehose/subscribe.rs`): subscribe to the broadcast BEFORE
//! backfill, FutureCursor check, page backfill from `repo_seq` injecting seq,
//! then live with cutover dedup and one Lagged recovery before
//! ConsumerTooSlow.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::firehose::{encode_error_frame, encode_message_frame, CommitBody};
use crate::storage::SqliteStore;

use super::{query_param, xrpc_error, AppState};

/// How many repo_seq rows to fetch per backfill page (matches production).
const BACKFILL_PAGE: i64 = 500;

/// RFC 6455 §1.3 handshake GUID.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// WebSocket opcodes.
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// GET /xrpc/com.atproto.sync.subscribeRepos — validate, upgrade, stream.
///
/// Cursor validation happens BEFORE the upgrade (a bad cursor is a plain HTTP
/// 400). The 101 response is returned to hyper while the streaming runs on the
/// upgraded connection in a spawned task.
pub(super) fn subscribe(
    state: AppState,
    mut req: Request<Incoming>,
    query: &str,
) -> Response<Full<Bytes>> {
    // V5 input validation before the handshake.
    let cursor = match query_param(query, "cursor") {
        None => None,
        Some(s) => match s.parse::<i64>() {
            Ok(v) if v >= 0 => Some(v),
            _ => {
                return xrpc_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "cursor must be a non-negative integer",
                )
            }
        },
    };

    // Handshake: Upgrade + Sec-WebSocket-Key are required.
    let is_ws_upgrade = req
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let Some(key) = req
        .headers()
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
    else {
        return xrpc_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "subscribeRepos requires a WebSocket upgrade",
        );
    };
    if !is_ws_upgrade {
        return xrpc_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "subscribeRepos requires a WebSocket upgrade",
        );
    }

    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    let accept = data_encoding::BASE64.encode(&hasher.finalize());

    // Drive the stream once hyper hands us the raw connection.
    let on_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        if let Ok(upgraded) = on_upgrade.await {
            handle_firehose(TokioIo::new(upgraded), state, cursor).await;
        }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("upgrade", "websocket")
        .header("connection", "Upgrade")
        .header("sec-websocket-accept", accept)
        .body(Full::new(Bytes::new()))
        .expect("static response builder never fails")
}

/// Write one unmasked server frame (FIN set) to `w`.
async fn write_frame<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let mut header = Vec::with_capacity(10);
    header.push(0x80 | (opcode & 0x0f));
    match payload.len() {
        n if n < 126 => header.push(n as u8),
        n if n <= 0xffff => {
            header.push(126);
            header.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            header.push(127);
            header.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    w.write_all(&header).await?;
    w.write_all(payload).await?;
    w.flush().await
}

/// One parsed client frame: opcode + unmasked payload.
struct ClientFrame {
    opcode: u8,
    payload: Vec<u8>,
}

/// Cap on a client frame we'll buffer. Clients only ever send ping/close
/// (tiny); this bounds a hostile peer, not real traffic.
const MAX_CLIENT_FRAME: u64 = 64 * 1024;

/// Read one client frame. Client frames are masked per RFC 6455 §5.1.
/// Fragmented control frames are illegal; fragmented data frames are read and
/// handed up as-is (callers ignore data frames anyway).
async fn read_frame<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> std::io::Result<ClientFrame> {
    let mut head = [0u8; 2];
    r.read_exact(&mut head).await?;
    let opcode = head[0] & 0x0f;
    let masked = head[1] & 0x80 != 0;
    let mut len = (head[1] & 0x7f) as u64;
    if len == 126 {
        let mut ext = [0u8; 2];
        r.read_exact(&mut ext).await?;
        len = u16::from_be_bytes(ext) as u64;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        r.read_exact(&mut ext).await?;
        len = u64::from_be_bytes(ext);
    }
    if len > MAX_CLIENT_FRAME {
        return Err(std::io::Error::other("client frame too large"));
    }
    let mut mask = [0u8; 4];
    if masked {
        r.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).await?;
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Ok(ClientFrame { opcode, payload })
}

/// Backfill + live streaming, mirroring the production state machine.
async fn handle_firehose<S>(io: S, state: AppState, cursor: Option<i64>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(io);

    // Subscribe BEFORE backfill so no live event can fall into the gap.
    let mut rx = state.firehose_tx.subscribe();

    // FutureCursor check.
    if let Some(c) = cursor {
        let max = match state.store.max_seq().await {
            Ok(m) => m,
            Err(_) => return,
        };
        if c > max {
            let frame = encode_error_frame("FutureCursor", Some("Cursor in the future."));
            let _ = write_frame(&mut writer, OP_BINARY, &frame).await;
            let _ = write_frame(&mut writer, OP_CLOSE, &[]).await;
            return;
        }
    }

    // Backfill only when a cursor was provided.
    let mut last_sent_seq = cursor.unwrap_or(0);
    if cursor.is_some() {
        match run_backfill(&mut writer, &state.store, last_sent_seq).await {
            Some(s) => last_sent_seq = s,
            None => return,
        }
    }

    // Live: relay broadcast events; answer ping/close between them.
    let mut recovered_from_lag = false;
    loop {
        tokio::select! {
            evt = rx.recv() => match evt {
                Ok(evt) => {
                    if evt.seq <= last_sent_seq {
                        continue; // cutover dedup with the backfill
                    }
                    if write_frame(&mut writer, OP_BINARY, &evt.frame).await.is_err() {
                        return;
                    }
                    last_sent_seq = evt.seq;
                    recovered_from_lag = false;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    if !recovered_from_lag {
                        // One deterministic DB recovery before declaring the
                        // consumer too slow (same policy as production).
                        recovered_from_lag = true;
                        rx = state.firehose_tx.subscribe();
                        match run_backfill(&mut writer, &state.store, last_sent_seq).await {
                            Some(s) => { last_sent_seq = s; continue; }
                            None => return,
                        }
                    }
                    let frame = encode_error_frame(
                        "ConsumerTooSlow",
                        Some("Stream consumer too slow."),
                    );
                    let _ = write_frame(&mut writer, OP_BINARY, &frame).await;
                    let _ = write_frame(&mut writer, OP_CLOSE, &[]).await;
                    return;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            },
            frame = read_frame(&mut reader) => match frame {
                Ok(ClientFrame { opcode: OP_PING, payload }) => {
                    if write_frame(&mut writer, OP_PONG, &payload).await.is_err() {
                        return;
                    }
                }
                Ok(ClientFrame { opcode: OP_CLOSE, payload }) => {
                    let _ = write_frame(&mut writer, OP_CLOSE, &payload).await;
                    return;
                }
                Ok(_) => {} // firehose clients have nothing else to say — ignore
                Err(_) => return, // client disconnected
            },
        }
    }
}

/// Page through `repo_seq` from `after_seq`, sending each row as a framed
/// `#commit`. Returns the highest seq sent/skipped, or None on disconnect or
/// store error.
async fn run_backfill<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    store: &Arc<SqliteStore>,
    after_seq: i64,
) -> Option<i64> {
    let mut last_sent_seq = after_seq;
    loop {
        let page = match store.backfill_page(last_sent_seq, BACKFILL_PAGE).await {
            Ok(p) => p,
            Err(_) => return None,
        };
        if page.is_empty() {
            break;
        }
        for (seq, event) in page {
            // Decode the stored body (without seq), inject seq, re-encode, frame.
            let mut body: CommitBody = match serde_ipld_dagcbor::from_slice(&event) {
                Ok(b) => b,
                // Skip the corrupt row but STILL advance the cursor: otherwise
                // the same page is re-fetched forever (busy-spin) when a page
                // contains only bad rows.
                Err(_) => {
                    last_sent_seq = seq;
                    continue;
                }
            };
            body.seq = seq;
            let frame = encode_message_frame("#commit", &body);
            if write_frame(writer, OP_BINARY, &frame).await.is_err() {
                return None;
            }
            last_sent_seq = seq;
        }
    }
    Some(last_sent_seq)
}
