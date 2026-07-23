//! The registry Durable Object: one instance for the whole deployment.
//!
//! # Why this exists at all
//!
//! Every PDS gets its own Durable Object, named after its hostname. That is what
//! makes each account a single-writer repo — and it is also why the invite gate
//! inside the ordinary `createAccount` path cannot work here. That gate asks
//! whether the *current* object has zero accounts, and a hostname nobody has
//! claimed always answers zero. Every registration would look like the first
//! one, skip the invite, and claim the server. Anyone could take any unclaimed
//! label and spawn Durable Objects without bound.
//!
//! So the gate has to sit somewhere that sees every hostname at once. This is
//! that place: a single named instance, `__registry__`, holding claimed labels
//! and invite codes.
//!
//! # Atomicity
//!
//! A Durable Object handles one request at a time, and DO SQL is synchronous, so
//! a read followed by a write with no `.await` between them cannot interleave
//! with anything. `claim` depends on that: checking the label, burning the
//! invite, and inserting the reservation are one indivisible step **because no
//! await appears between them**. That is a correctness requirement, not an
//! incidental property — introducing an await inside `claim` would silently
//! reintroduce the double-claim race.

use serde::{Deserialize, Serialize};
use worker::*;

/// Fixed name of the single registry instance.
pub const REGISTRY_DO_NAME: &str = "__registry__";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS claims (
    label       TEXT PRIMARY KEY,
    did         TEXT,
    state       TEXT NOT NULL,
    invite_code TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invites (
    code           TEXT PRIMARY KEY,
    available_uses INTEGER NOT NULL,
    disabled       INTEGER NOT NULL DEFAULT 0
);
";

/// Added after `claims` already existed in a deployed registry, where
/// `CREATE TABLE IF NOT EXISTS` is a no-op and would leave the column missing.
/// Expected to fail with "duplicate column name" on every run after the first,
/// which is why the error is discarded rather than propagated.
const MIGRATIONS: &[&str] = &["ALTER TABLE claims ADD COLUMN invite_code TEXT"];

#[derive(Deserialize)]
struct LabelReq {
    label: String,
}

#[derive(Deserialize)]
struct ClaimReq {
    label: String,
    #[serde(default)]
    invite_code: Option<String>,
}

#[derive(Deserialize)]
struct BindReq {
    label: String,
    did: String,
}

#[derive(Deserialize)]
struct InviteReq {
    code: String,
    #[serde(default = "one")]
    uses: i64,
}
fn one() -> i64 {
    1
}

#[derive(Serialize)]
struct CheckResp {
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Serialize)]
struct OkResp {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct CountRow {
    n: i64,
}

#[derive(Deserialize)]
struct InviteRow {
    available_uses: i64,
    disabled: i64,
}

#[derive(Deserialize)]
struct ReleaseRow {
    invite_code: Option<String>,
}

#[durable_object]
pub struct RegistryDurableObject {
    state: State,
}

impl DurableObject for RegistryDurableObject {
    // No `env`: the registry reads no bindings, secrets, or vars. Everything it
    // needs is in its own storage.
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        match self.route(req).await {
            Ok(resp) => Ok(resp),
            Err(e) => Response::error(format!("registry error: {e}"), 500),
        }
    }
}

impl RegistryDurableObject {
    fn sql(&self) -> Result<SqlStorage> {
        let sql = self.state.storage().sql();
        for stmt in SCHEMA.split(';') {
            let stmt = stmt.trim();
            if !stmt.is_empty() {
                sql.exec(stmt, None)?;
            }
        }
        for stmt in MIGRATIONS {
            let _ = sql.exec(stmt, None);
        }
        Ok(sql)
    }

    async fn route(&self, mut req: Request) -> Result<Response> {
        let path = req.url()?.path().to_string();
        match path.as_str() {
            "/check" => {
                let body: LabelReq = req.json().await?;
                self.check(&body.label)
            }
            "/claim" => {
                let body: ClaimReq = req.json().await?;
                self.claim(&body.label, body.invite_code.as_deref())
            }
            "/release" => {
                let body: LabelReq = req.json().await?;
                self.release(&body.label)
            }
            "/bind" => {
                let body: BindReq = req.json().await?;
                self.bind(&body.label, &body.did)
            }
            "/invite" => {
                let body: InviteReq = req.json().await?;
                self.seed_invite(&body.code, body.uses)
            }
            _ => Response::error("unknown registry endpoint", 404),
        }
    }

    fn is_taken(&self, sql: &SqlStorage, label: &str) -> Result<bool> {
        let rows: Vec<CountRow> = sql
            .exec(
                "SELECT count(*) AS n FROM claims WHERE label = ?",
                vec![SqlStorageValue::from(label.to_string())],
            )?
            .to_array()?;
        Ok(rows.first().map(|r| r.n).unwrap_or(0) > 0)
    }

    fn check(&self, label: &str) -> Result<Response> {
        let sql = self.sql()?;
        if self.is_taken(&sql, label)? {
            return Response::from_json(&CheckResp {
                available: false,
                reason: Some("taken".into()),
            });
        }
        Response::from_json(&CheckResp {
            available: true,
            reason: None,
        })
    }

    /// Reserve `label`, burning one use of `invite_code`.
    ///
    /// **Await-free by construction.** See the module note: the atomicity of the
    /// whole check-burn-insert sequence rests on there being no suspension point
    /// anywhere in this function.
    fn claim(&self, label: &str, invite_code: Option<&str>) -> Result<Response> {
        let sql = self.sql()?;

        if self.is_taken(&sql, label)? {
            return Response::from_json(&OkResp {
                ok: false,
                error: Some("HandleNotAvailable".into()),
            });
        }

        // The invite is checked and decremented before the reservation row
        // exists, but within the same uninterrupted step, so a code with one
        // remaining use cannot be redeemed by two concurrent signups.
        let Some(code) = invite_code else {
            return Response::from_json(&OkResp {
                ok: false,
                error: Some("InvalidInviteCode".into()),
            });
        };

        let rows: Vec<InviteRow> = sql
            .exec(
                "SELECT available_uses, disabled FROM invites WHERE code = ?",
                vec![SqlStorageValue::from(code.to_string())],
            )?
            .to_array()?;
        let valid = rows
            .first()
            .map(|r| r.disabled == 0 && r.available_uses > 0)
            .unwrap_or(false);
        if !valid {
            return Response::from_json(&OkResp {
                ok: false,
                error: Some("InvalidInviteCode".into()),
            });
        }

        sql.exec(
            "UPDATE invites SET available_uses = available_uses - 1 WHERE code = ?",
            vec![SqlStorageValue::from(code.to_string())],
        )?;
        // The code is recorded on the reservation so `release` can give the use
        // back. Without it a signup that fails downstream — an unreachable PLC
        // directory, say — would silently cost the person their invite.
        sql.exec(
            "INSERT INTO claims (label, did, state, invite_code, created_at) \
             VALUES (?, NULL, 'reserved', ?, ?)",
            vec![
                SqlStorageValue::from(label.to_string()),
                SqlStorageValue::from(code.to_string()),
                SqlStorageValue::from(now_iso()),
            ],
        )?;

        Response::from_json(&OkResp {
            ok: true,
            error: None,
        })
    }

    /// Undo a reservation whose provisioning failed, returning the invite use.
    ///
    /// Only `reserved` rows are released. A row that reached `active` has a DID
    /// inscribed on a public ledger behind it, and deleting the reservation
    /// would let a second person claim a handle that already resolves.
    ///
    /// Await-free, like `claim`: the refund and the delete have to be one step,
    /// or a release interrupted between them either loses the use or, worse,
    /// hands it back twice.
    fn release(&self, label: &str) -> Result<Response> {
        let sql = self.sql()?;

        let rows: Vec<ReleaseRow> = sql
            .exec(
                "SELECT invite_code FROM claims WHERE label = ? AND state = 'reserved'",
                vec![SqlStorageValue::from(label.to_string())],
            )?
            .to_array()?;

        // Nothing reserved under that label — either never claimed, or already
        // active. Both are no-ops, and neither should refund anything.
        let Some(row) = rows.into_iter().next() else {
            return Response::from_json(&OkResp {
                ok: true,
                error: None,
            });
        };

        if let Some(code) = row.invite_code {
            sql.exec(
                "UPDATE invites SET available_uses = available_uses + 1 WHERE code = ?",
                vec![SqlStorageValue::from(code)],
            )?;
        }
        sql.exec(
            "DELETE FROM claims WHERE label = ? AND state = 'reserved'",
            vec![SqlStorageValue::from(label.to_string())],
        )?;

        Response::from_json(&OkResp {
            ok: true,
            error: None,
        })
    }

    fn bind(&self, label: &str, did: &str) -> Result<Response> {
        let sql = self.sql()?;
        sql.exec(
            "UPDATE claims SET did = ?, state = 'active' WHERE label = ?",
            vec![
                SqlStorageValue::from(did.to_string()),
                SqlStorageValue::from(label.to_string()),
            ],
        )?;
        Response::from_json(&OkResp {
            ok: true,
            error: None,
        })
    }

    fn seed_invite(&self, code: &str, uses: i64) -> Result<Response> {
        let sql = self.sql()?;
        sql.exec(
            "INSERT OR REPLACE INTO invites (code, available_uses, disabled) VALUES (?, ?, 0)",
            vec![
                SqlStorageValue::from(code.to_string()),
                SqlStorageValue::from(uses),
            ],
        )?;
        Response::from_json(&OkResp {
            ok: true,
            error: None,
        })
    }
}

fn now_iso() -> String {
    let ms = worker::Date::now().as_millis();
    js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(ms as f64))
        .to_iso_string()
        .as_string()
        .unwrap_or_default()
}
