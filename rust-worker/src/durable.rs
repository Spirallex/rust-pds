//! The per-hostname Durable Object.
//!
//! One instance per PDS. It is the single writer for that repo, which is what
//! makes the sequencer monotonic and the root pointer safe to update — the
//! guarantee that no fan-out of stateless isolates can provide, and the reason
//! this design uses a DO at all rather than D1.
//!
//! Everything that mutates repo state runs here. The Worker in front is a
//! router: it maps `Host` to a DO name and forwards.

use worker::*;

use crate::store::DoStore;

/// Name of the R2 binding declared in `wrangler.toml`.
const BLOBS_BINDING: &str = "BLOBS";

#[durable_object]
pub struct PdsDurableObject {
    state: State,
    env: Env,
}

impl DurableObject for PdsDurableObject {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        match self.route(req).await {
            Ok(resp) => Ok(resp),
            // A DO that returns an error tears down the isolate and loses any
            // in-flight WebSocket. Convert to a response instead so a bad
            // request cannot take the whole PDS down with it.
            Err(e) => Response::error(format!("durable object error: {e}"), 500),
        }
    }
}

impl PdsDurableObject {
    /// Storage handle for this instance, with the schema applied.
    ///
    /// Migration runs on every construction rather than being gated on a flag:
    /// the statements are all `IF NOT EXISTS`, and a DO can be evicted and
    /// rebuilt at any time, so a "have I migrated?" flag would need to live in
    /// the very storage it guards.
    fn store(&self) -> Result<DoStore> {
        let sql = self.state.storage().sql();
        let blobs = self.env.bucket(BLOBS_BINDING)?;
        let store = DoStore::new(sql, blobs);
        store
            .migrate()
            .map_err(|e| Error::RustError(format!("schema migration failed: {e}")))?;
        Ok(store)
    }

    async fn route(&self, req: Request) -> Result<Response> {
        let url = req.url()?;
        match url.path() {
            "/_stelyph/health" => self.health().await,
            _ => Response::error("not found", 404),
        }
    }

    /// Diagnostic endpoint: proves the DO can reach both storage substrates.
    ///
    /// Exercises a real round trip through the trait impls — a SQL write and
    /// read, plus an R2 write and read — rather than merely reporting that the
    /// bindings exist. A binding can be present and still fail on first use
    /// (missing bucket, unapplied migration), and this is what catches that.
    async fn health(&self) -> Result<Response> {
        use stelyph_core::storage::{BlobStore, BlockStore, Sequencer};

        let store = self.store()?;
        let mut checks = Vec::new();

        // SQL round trip through BlockStore.
        let payload = b"stelyph health probe".to_vec();
        let cid = stelyph_core::storage::cid_of(0x71, &payload);
        let sql_ok = match store.put_block(cid, payload.clone()).await {
            Ok(()) => matches!(store.read_block_bytes(cid).await, Ok(b) if b == payload),
            Err(_) => false,
        };
        checks.push(("do_sqlite", sql_ok));

        // Sequencer read — cheap, and confirms the counter row exists.
        let seq_ok = store.max_seq().await.is_ok();
        checks.push(("sequencer", seq_ok));

        // R2 round trip through BlobStore.
        let r2_ok = match store
            .put_blob("did:plc:health", "probe", "text/plain", 5, b"probe".to_vec())
            .await
        {
            Ok(()) => matches!(
                store.get_blob("did:plc:health", "probe").await,
                Ok(Some((mime, bytes))) if mime == "text/plain" && bytes == b"probe"
            ),
            Err(_) => false,
        };
        checks.push(("r2", r2_ok));

        let healthy = checks.iter().all(|(_, ok)| *ok);
        let body = serde_json::json!({
            "healthy": healthy,
            "checks": checks
                .iter()
                .map(|(k, v)| (k.to_string(), serde_json::Value::Bool(*v)))
                .collect::<serde_json::Map<String, serde_json::Value>>(),
            "schema_version": crate::schema::SCHEMA_VERSION,
        });

        let mut resp = Response::from_json(&body)?;
        if !healthy {
            resp = resp.with_status(503);
        }
        Ok(resp)
    }
}
