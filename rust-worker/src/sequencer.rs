//! The firehose sequencer: one central Durable Object for the whole PDS.
//!
//! # Why this exists
//!
//! atproto exposes a single `com.atproto.sync.subscribeRepos` stream per PDS,
//! with a strictly monotonic `seq` across every account. But in this deployment
//! each account is its own Durable Object with its own local sequence, so those
//! per-account sequences must be *merged* into one PDS-wide stream. A relay
//! connects once, to the shared host, and expects one ordered log.
//!
//! This DO is that merge point. Exactly like the account DOs give a repo a
//! single writer, this single instance gives the whole PDS a single sequencer:
//! it owns the one global counter, assigns every event its PDS-wide `seq`,
//! persists it for backfill, and fans it out to live subscribers.
//!
//! # Flow
//!
//! - An account DO, on committing a repo change, POSTs the commit's fields to
//!   `/enqueue`. The sequencer allocates the next global `seq`, encodes the
//!   `#commit` frame with that seq, appends it to the log, and pushes it to
//!   every connected WebSocket.
//! - A relay opens `GET /xrpc/com.atproto.sync.subscribeRepos` (a WebSocket). If
//!   it passes `?cursor=N`, the sequencer first replays every logged frame with
//!   `seq > N`, then leaves the socket connected for live events.
//!
//! # Atomicity
//!
//! Allocating `seq` and appending the log are one synchronous, await-free step
//! on the DO's single thread, so two concurrent enqueues cannot be assigned the
//! same `seq` or logged out of order — the same guarantee the account DOs rely
//! on for their own sequence.

use serde::Deserialize;
use worker::*;

use stelyph_core::firehose::{encode_message_frame, CommitBody, RepoOp};

/// Fixed name of the single sequencer instance.
pub const SEQUENCER_DO_NAME: &str = "__sequencer__";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS seq_counter (id INTEGER PRIMARY KEY, next INTEGER NOT NULL);
INSERT OR IGNORE INTO seq_counter (id, next) VALUES (0, 1);
CREATE TABLE IF NOT EXISTS firehose_log (
    seq        INTEGER PRIMARY KEY,
    repo       TEXT NOT NULL,
    frame      BLOB NOT NULL,
    created_at TEXT NOT NULL
);
";

/// Fields of a repo commit, as an account DO hands them over — everything the
/// `#commit` body needs except `seq`, which is the sequencer's to assign.
#[derive(Deserialize)]
struct EnqueueReq {
    repo: String,
    /// The signed commit CID, as a string.
    commit: String,
    rev: String,
    #[serde(default)]
    since: Option<String>,
    /// CAR blocks for this commit, base64.
    #[serde(default)]
    blocks_b64: String,
    #[serde(default)]
    ops: Vec<EnqueueOp>,
    #[serde(default)]
    too_big: bool,
}

#[derive(Deserialize)]
struct EnqueueOp {
    action: String,
    path: String,
    #[serde(default)]
    cid: Option<String>,
}

#[derive(Deserialize)]
struct CountRow {
    n: i64,
}

#[derive(Deserialize)]
struct FrameRow {
    #[serde(with = "serde_bytes")]
    frame: Vec<u8>,
}

#[durable_object]
pub struct SequencerDurableObject {
    state: State,
}

impl DurableObject for SequencerDurableObject {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        match self.route(req).await {
            Ok(resp) => Ok(resp),
            Err(e) => Response::error(format!("sequencer error: {e}"), 500),
        }
    }
}

impl SequencerDurableObject {
    fn sql(&self) -> Result<SqlStorage> {
        let sql = self.state.storage().sql();
        for stmt in SCHEMA.split(';') {
            let stmt = stmt.trim();
            if !stmt.is_empty() {
                sql.exec(stmt, None)?;
            }
        }
        Ok(sql)
    }

    async fn route(&self, mut req: Request) -> Result<Response> {
        let url = req.url()?;
        let path = url.path().to_string();

        // The firehose subscription is a WebSocket upgrade.
        if path == "/xrpc/com.atproto.sync.subscribeRepos" {
            let cursor = url
                .query_pairs()
                .find(|(k, _)| k == "cursor")
                .and_then(|(_, v)| v.parse::<i64>().ok());
            return self.subscribe(cursor);
        }

        match path.as_str() {
            "/enqueue" => {
                let body: EnqueueReq = req.json().await?;
                self.enqueue(body)
            }
            // Test-only: inject a synthetic commit to exercise the sequencer end
            // to end while the write path that would feed it for real is not yet
            // on the Worker. Reachable only via the front Worker's admin path.
            "/_test-inject" => {
                let body: EnqueueReq = req.json().await?;
                self.enqueue(body)
            }
            _ => Response::error("unknown sequencer endpoint", 404),
        }
    }

    /// Allocate the next global seq, encode + log the frame, broadcast it.
    ///
    /// **Await-free.** The seq read, its bump, and the log append are one
    /// indivisible step; nothing suspends between them, so the global order is
    /// total and gap-free.
    fn enqueue(&self, ev: EnqueueReq) -> Result<Response> {
        let sql = self.sql()?;

        // Allocate seq.
        let rows: Vec<CountRow> = sql
            .exec("SELECT next AS n FROM seq_counter WHERE id = 0", vec![])?
            .to_array()?;
        let seq = rows.first().map(|r| r.n).unwrap_or(1);
        sql.exec(
            "UPDATE seq_counter SET next = ? WHERE id = 0",
            vec![SqlStorageValue::from(seq + 1)],
        )?;

        // Build the #commit body with the assigned seq and encode the frame.
        let commit_cid = cid::Cid::try_from(ev.commit.as_str())
            .map_err(|e| Error::RustError(format!("bad commit cid: {e}")))?;
        let blocks = data_encoding::BASE64
            .decode(ev.blocks_b64.as_bytes())
            .unwrap_or_default();
        let ops = ev
            .ops
            .iter()
            .map(|o| {
                Ok(RepoOp {
                    action: o.action.clone(),
                    path: o.path.clone(),
                    cid: match &o.cid {
                        Some(c) => Some(
                            cid::Cid::try_from(c.as_str())
                                .map_err(|e| Error::RustError(format!("bad op cid: {e}")))?,
                        ),
                        None => None,
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let body = CommitBody {
            seq,
            rebase: false,
            too_big: ev.too_big,
            repo: ev.repo.clone(),
            commit: commit_cid,
            rev: ev.rev.clone(),
            since: ev.since.clone(),
            blocks,
            ops,
            blobs: vec![],
            time: now_iso(),
            prev_data: None,
        };
        let frame = encode_message_frame("#commit", &body);

        // Persist for backfill.
        sql.exec(
            "INSERT INTO firehose_log (seq, repo, frame, created_at) VALUES (?, ?, ?, ?)",
            vec![
                SqlStorageValue::from(seq),
                SqlStorageValue::from(ev.repo),
                SqlStorageValue::from(frame.clone()),
                SqlStorageValue::from(now_iso()),
            ],
        )?;

        // Fan out to live subscribers. A send failure means a dead socket; the
        // subscriber will reconnect with its cursor and backfill, so dropping it
        // here loses nothing.
        for ws in self.state.get_websockets() {
            let _ = ws.send_with_bytes(&frame);
        }

        Response::from_json(&serde_json::json!({ "ok": true, "seq": seq }))
    }

    /// Accept a firehose WebSocket. Backfill from `cursor`, then stay connected
    /// for live events (delivered by `enqueue` via `get_websockets`).
    fn subscribe(&self, cursor: Option<i64>) -> Result<Response> {
        let pair = WebSocketPair::new()?;
        let server = pair.server;

        // Hibernatable: the runtime holds the socket and hands it back via
        // `get_websockets`, so the DO need not stay resident between events.
        self.state.accept_web_socket(&server);

        // Replay the backlog the new subscriber missed. A cursor beyond the head
        // simply yields nothing, which is the correct "you're caught up".
        if let Some(after) = cursor {
            let sql = self.sql()?;
            let rows: Vec<FrameRow> = sql
                .exec(
                    "SELECT frame FROM firehose_log WHERE seq > ? ORDER BY seq ASC",
                    vec![SqlStorageValue::from(after)],
                )?
                .to_array()?;
            for row in rows {
                let _ = server.send_with_bytes(&row.frame);
            }
        }

        Response::from_websocket(pair.client)
    }
}

fn now_iso() -> String {
    let ms = worker::Date::now().as_millis();
    js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(ms as f64))
        .to_iso_string()
        .as_string()
        .unwrap_or_default()
}
