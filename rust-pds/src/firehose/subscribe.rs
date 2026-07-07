//! subscribeRepos WebSocket handler.
//!
//! State machine:
//! 1. Validate cursor (ASVS V5 — before upgrade).
//! 2. Subscribe to broadcast channel BEFORE backfill (Pitfall 5 — eliminates gap).
//! 3. FutureCursor check: cursor > max_seq → error frame + close.
//! 4. Backfill: page through repo_seq with backfill_page, inject seq, send binary frames.
//! 5. Live: drain rx with cutover dedup (seq > last_sent_seq), handle Lagged → ConsumerTooSlow.
//! 6. No cursor: subscribe-only, no backfill, stream live events.

use std::collections::HashMap;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use bytes::Bytes;

use crate::firehose::{encode_error_frame, encode_message_frame, CommitBody};
use crate::xrpc::{AppState, XrpcError};

/// How many repo_seq rows to fetch per backfill page (T-04-14 DoS — bounded).
const BACKFILL_PAGE: i64 = 500;

/// Register the subscribeRepos route.
pub fn routes() -> Router<AppState> {
    Router::new().route(
        "/xrpc/com.atproto.sync.subscribeRepos",
        get(subscribe_repos),
    )
}

/// Parse and validate the optional `cursor` query parameter.
///
/// Returns `Ok(None)` when the parameter is absent.
/// Returns `Ok(Some(v))` for a valid non-negative integer.
/// Returns `Err(XrpcError::InvalidRequest)` for non-integer or negative values (ASVS V5).
fn parse_cursor(params: &HashMap<String, String>) -> Result<Option<i64>, XrpcError> {
    match params.get("cursor") {
        None => Ok(None),
        Some(s) => {
            let v: i64 = s
                .parse()
                .map_err(|_| XrpcError::InvalidRequest("cursor must be an integer".into()))?;
            if v < 0 {
                return Err(XrpcError::InvalidRequest(
                    "cursor must be non-negative".into(),
                ));
            }
            Ok(Some(v))
        }
    }
}

/// GET /xrpc/com.atproto.sync.subscribeRepos — WebSocket upgrade handler.
///
/// Input validation is performed BEFORE the upgrade handshake (T-04-12).
pub async fn subscribe_repos(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, XrpcError> {
    // V5 input validation: cursor must parse as a non-negative i64 BEFORE upgrade.
    let cursor = parse_cursor(&params)?;
    Ok(ws.on_upgrade(move |socket| handle_firehose(socket, state, cursor)))
}

/// Core handler: backfill + live streaming state machine.
async fn handle_firehose(mut socket: WebSocket, state: AppState, cursor: Option<i64>) {
    // Step 1: Subscribe to broadcast FIRST (before backfill query) so we never
    // miss live events published between the backfill query finishing and us
    // starting to receive from the channel (Pitfall 5).
    let mut rx = state.firehose_tx.subscribe();

    // Step 2: FutureCursor check — requires a cursor to be present.
    if let Some(c) = cursor {
        let max = match state.store.max_seq().await {
            Ok(m) => m,
            Err(_) => return,
        };
        if c > max {
            let frame = encode_error_frame("FutureCursor", Some("Cursor in the future."));
            let _ = socket.send(Message::Binary(Bytes::from(frame))).await;
            return; // close
        }
    }

    // Step 3: Backfill pages (only when a cursor is provided).
    let mut last_sent_seq = cursor.unwrap_or(0);
    if cursor.is_some() {
        match run_backfill(&mut socket, &state, last_sent_seq).await {
            Some(s) => last_sent_seq = s,
            None => return, // client disconnected or DB error
        }
    }

    // Step 4 + 5: Live stream with cutover dedup and a single backfill-recovery on Lagged.
    //
    // WR-04: a subscriber that requested a large backfill can let the bounded broadcast
    // channel overflow with live events before reaching this loop, so the first `recv()`
    // returns `Lagged` even though the client made forward progress. Rather than closing
    // such legitimate backfilling clients with `ConsumerTooSlow`, we recover ONCE by
    // re-querying the DB from `last_sent_seq` to fill the gap, then resume live streaming.
    // A second `Lagged` (after the channel has been re-subscribed and the backfill replayed)
    // indicates genuine steady-state slowness and is treated as `ConsumerTooSlow` + close.
    let mut recovered_from_lag = false;
    loop {
        match rx.recv().await {
            Ok(evt) => {
                // Dedup: skip events already sent during backfill (Pitfall 5).
                if evt.seq <= last_sent_seq {
                    continue;
                }
                if socket
                    .send(Message::Binary(Bytes::from(evt.frame.clone())))
                    .await
                    .is_err()
                {
                    return; // client disconnected
                }
                last_sent_seq = evt.seq;
                // A successful live send means we are caught up; allow one future recovery.
                recovered_from_lag = false;
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                if !recovered_from_lag {
                    // Cutover lag: re-subscribe (reset the channel cursor to "now") and
                    // re-query the DB from last_sent_seq to fill the gap deterministically.
                    recovered_from_lag = true;
                    rx = state.firehose_tx.subscribe();
                    match run_backfill(&mut socket, &state, last_sent_seq).await {
                        Some(s) => {
                            last_sent_seq = s;
                            continue;
                        }
                        None => return, // client disconnected or DB error
                    }
                }
                // Steady-state slow consumer fell behind channel capacity — close (Pitfall 6).
                let frame =
                    encode_error_frame("ConsumerTooSlow", Some("Stream consumer too slow."));
                let _ = socket.send(Message::Binary(Bytes::from(frame))).await;
                return;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        }
    }
}

/// Page through `repo_seq` from `after_seq`, sending each row as a framed `#commit`.
///
/// Returns `Some(last_sent_seq)` on completion (the highest seq sent or skipped), or `None`
/// if the client disconnected or the store returned an error (caller should close).
async fn run_backfill(socket: &mut WebSocket, state: &AppState, after_seq: i64) -> Option<i64> {
    let mut last_sent_seq = after_seq;
    loop {
        let page = match state
            .store
            .backfill_page(last_sent_seq, BACKFILL_PAGE)
            .await
        {
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
                // backfill_page(last_sent_seq, …) re-fetches the same after_seq
                // forever (busy-spin / DoS) when a page contains only bad rows.
                Err(_) => {
                    last_sent_seq = seq;
                    continue;
                }
            };
            body.seq = seq; // inject seq at stream time (RESEARCH lines 282-312)
            let frame = encode_message_frame("#commit", &body);
            if socket
                .send(Message::Binary(Bytes::from(frame)))
                .await
                .is_err()
            {
                return None; // client disconnected
            }
            last_sent_seq = seq;
        }
    }
    Some(last_sent_seq)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Valid non-negative integer → Ok(Some(v)).
    #[test]
    fn parse_cursor_valid() {
        let mut p = HashMap::new();
        p.insert("cursor".into(), "42".into());
        assert_eq!(parse_cursor(&p).unwrap(), Some(42));
    }

    /// Zero is a valid cursor (replays the entire log).
    #[test]
    fn parse_cursor_zero() {
        let mut p = HashMap::new();
        p.insert("cursor".into(), "0".into());
        assert_eq!(parse_cursor(&p).unwrap(), Some(0));
    }

    /// Absent cursor → Ok(None).
    #[test]
    fn parse_cursor_absent() {
        let p = HashMap::new();
        assert_eq!(parse_cursor(&p).unwrap(), None);
    }

    /// Negative integer → InvalidRequest.
    #[test]
    fn parse_cursor_negative() {
        let mut p = HashMap::new();
        p.insert("cursor".into(), "-1".into());
        assert!(parse_cursor(&p).is_err());
    }

    /// Non-integer → InvalidRequest.
    #[test]
    fn parse_cursor_non_integer() {
        let mut p = HashMap::new();
        p.insert("cursor".into(), "abc".into());
        assert!(parse_cursor(&p).is_err());
    }

    /// Float string → InvalidRequest (i64::parse fails).
    #[test]
    fn parse_cursor_float() {
        let mut p = HashMap::new();
        p.insert("cursor".into(), "1.5".into());
        assert!(parse_cursor(&p).is_err());
    }
}
