//! The per-hostname Durable Object.
//!
//! One instance per PDS. It is the single writer for that repo, which is what
//! makes the sequencer monotonic and the root pointer safe to update — the
//! guarantee that no fan-out of stateless isolates can provide, and the reason
//! this design uses a DO at all rather than D1.
//!
//! Everything that mutates repo state runs here. The Worker in front is a
//! router: it maps `Host` to a DO name and forwards.

use serde::Deserialize;
use worker::*;

use crate::handlers::{self as h, Ctx};
use crate::store::DoStore;

/// Body of the internal `/_stelyph/provision` call.
#[derive(Deserialize)]
struct ProvisionInput {
    handle: String,
    #[serde(default)]
    email: Option<String>,
    password: String,
}

#[derive(Deserialize)]
struct CreateSessionInput {
    identifier: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceRegisterInput {
    handle: String,
    password: String,
    device_did_key: String,
    #[serde(default)]
    label: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SigninStartInput {
    #[serde(default)]
    client_name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeviceDecisionInput {
    request_id: String,
    device_id: String,
    /// Base64 signature over the approval challenge.
    signature: String,
}

/// The bearer token from an Authorization header, if present.
fn bearer(req: &Request) -> Result<Option<String>> {
    Ok(req
        .headers()
        .get("authorization")?
        .and_then(|v| v.strip_prefix("Bearer ").map(|s| s.to_string())))
}

/// Decode a base64 approval signature, mapping a bad value to a 400 rather than
/// a 500 — a malformed signature is a client error, not a server fault.
fn decode_b64(s: &str) -> Result<Vec<u8>> {
    data_encoding::BASE64
        .decode(s.as_bytes())
        .map_err(|_| Error::RustError("signature is not valid base64".into()))
}

/// Name of the R2 binding declared in `wrangler.toml`.
const BLOBS_BINDING: &str = "BLOBS";

/// Header the front Worker uses to pass the real hostname through. The
/// forwarding URL carries an opaque authority (see lib.rs), so this is the only
/// place the DO learns which PDS it is serving.
const HOST_HEADER: &str = "X-Stelyph-Host";

#[durable_object]
pub struct PdsDurableObject {
    state: State,
    env: Env,
    /// One write lock for this account's repo. A DO can have several requests in
    /// flight at once, so without this two concurrent writes could each load the
    /// same root and fork history. Every write path holds it across load→commit.
    write_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

impl DurableObject for PdsDurableObject {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            write_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        }
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

    async fn route(&self, mut req: Request) -> Result<Response> {
        let url = req.url()?;
        // The host this request arrived on, e.g. `alice.pds.spirallex.com`. Used
        // only to resolve *which handle* is being asked about — its own DO.
        let request_host = req
            .headers()
            .get(HOST_HEADER)?
            .unwrap_or_else(|| "unknown.invalid".to_string());

        // Multi-tenant: every account presents the SAME service identity, the
        // shared PDS host `pds.spirallex.com`, not its own subdomain. So the
        // service context — describeServer's `did`, the OAuth issuer, and the
        // `serviceEndpoint` written into each new account's DID document — is
        // built from the zone suffix, not from `request_host`. The account data
        // still lives in this account's own Durable Object; only the advertised
        // address is shared. Handle resolution (atproto-did) is the one thing
        // that stays per-host, because it answers "who is THIS subdomain?".
        let hostname = request_host;
        let ctx = Ctx::from_host(&self.zone_suffix());

        match url.path() {
            // --- discovery -------------------------------------------------
            "/.well-known/oauth-authorization-server" => h::oauth_as_metadata(&ctx),
            "/.well-known/oauth-protected-resource" => h::oauth_protected_resource(&ctx),
            "/.well-known/did.json" => h::did_web_document(&ctx),
            "/.well-known/atproto-did" => {
                let store = self.store()?;
                h::atproto_did(&store, &hostname).await
            }
            "/oauth/jwks" => {
                let store = self.store()?;
                h::jwks(&store, &self.key_passphrase()?).await
            }

            // --- Sign in with Stelyph: device-approval sign-in -------------
            "/oauth/device/register" => {
                let b: DeviceRegisterInput = req.json().await?;
                let store = self.store()?;
                h::device_register(&store, &b.handle, &b.password, &b.device_did_key, &b.label)
                    .await
            }
            "/oauth/signin/start" => {
                let b: SigninStartInput = req.json().await?;
                let store = self.store()?;
                h::signin_start(&store, &b.client_name).await
            }
            "/oauth/signin/poll" => {
                let request_id = url
                    .query_pairs()
                    .find(|(k, _)| k == "requestId")
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_default();
                let store = self.store()?;
                h::signin_poll(&store, &request_id).await
            }
            "/oauth/signin/pending" => {
                let store = self.store()?;
                h::signin_pending(&store).await
            }
            "/oauth/device/approve" => {
                let b: DeviceDecisionInput = req.json().await?;
                let sig = decode_b64(&b.signature)?;
                let store = self.store()?;
                h::device_approve(
                    &store,
                    &ctx,
                    &b.request_id,
                    &b.device_id,
                    &sig,
                    &self.jwt_secret()?,
                )
                .await
            }
            "/oauth/device/deny" => {
                let b: DeviceDecisionInput = req.json().await?;
                let sig = decode_b64(&b.signature)?;
                let store = self.store()?;
                h::device_deny(&store, &b.request_id, &b.device_id, &sig).await
            }

            // --- XRPC ------------------------------------------------------
            "/xrpc/com.atproto.server.describeServer" => {
                h::describe_server(&ctx, &self.zone_suffix(), self.open_registration())
            }

            // Repo-scoped read. The front Worker routes it here by `repo`; this
            // DO holds one account and describes it. `ctx` is the shared service
            // identity; `hostname` is this account's own host.
            "/xrpc/com.atproto.repo.describeRepo" => {
                let store = self.store()?;
                h::describe_repo(&store, &ctx, &hostname).await
            }

            // Repo-scoped reads: the front Worker routed each here by `repo`/`did`.
            "/xrpc/com.atproto.repo.getRecord" => {
                match (qp(&url, "collection"), qp(&url, "rkey")) {
                    (Some(collection), Some(rkey)) => {
                        let store = self.store()?;
                        h::get_record(&store, &collection, &rkey).await
                    }
                    _ => xrpc_error(400, "InvalidRequest", "collection and rkey are required"),
                }
            }
            "/xrpc/com.atproto.repo.listRecords" => match qp(&url, "collection") {
                Some(collection) => {
                    let limit = qp(&url, "limit")
                        .and_then(|l| l.parse::<usize>().ok())
                        .unwrap_or(50);
                    let cursor = qp(&url, "cursor");
                    let store = self.store()?;
                    h::list_records(&store, &collection, limit, cursor.as_deref()).await
                }
                None => xrpc_error(400, "InvalidRequest", "collection is required"),
            },
            "/xrpc/com.atproto.sync.getRepo" => {
                let store = self.store()?;
                h::get_repo(&store).await
            }
            "/xrpc/com.atproto.sync.getLatestCommit" => {
                let store = self.store()?;
                h::get_latest_commit(&store).await
            }
            "/xrpc/com.atproto.sync.getBlob" => match (qp(&url, "did"), qp(&url, "cid")) {
                (Some(did), Some(cid)) => {
                    let store = self.store()?;
                    h::get_blob(&store, &did, &cid).await
                }
                _ => xrpc_error(400, "InvalidRequest", "did and cid are required"),
            },
            "/xrpc/com.atproto.sync.listBlobs" => match qp(&url, "did") {
                Some(did) => {
                    let limit = qp(&url, "limit")
                        .and_then(|l| l.parse::<usize>().ok())
                        .unwrap_or(500);
                    let cursor = qp(&url, "cursor");
                    let store = self.store()?;
                    h::list_blobs(&store, &did, limit, cursor.as_deref()).await
                }
                None => xrpc_error(400, "InvalidRequest", "did is required"),
            },

            "/xrpc/com.atproto.server.createSession" => {
                let b: CreateSessionInput = req.json().await?;
                let store = self.store()?;
                h::create_session(&store, &b.identifier, &b.password, &self.jwt_secret()?).await
            }
            "/xrpc/com.atproto.server.getSession" => {
                let bearer = bearer(&req)?;
                let store = self.store()?;
                h::get_session(&store, bearer.as_deref(), &self.jwt_secret()?).await
            }
            "/xrpc/app.bsky.actor.getPreferences" => {
                let bearer = bearer(&req)?;
                let store = self.store()?;
                h::get_preferences(&store, bearer.as_deref(), &self.jwt_secret()?).await
            }
            "/xrpc/app.bsky.actor.putPreferences" => {
                let bearer = bearer(&req)?;
                let body = req.text().await?;
                let store = self.store()?;
                h::put_preferences(&store, bearer.as_deref(), &self.jwt_secret()?, &body).await
            }

            // --- repo writes ----------------------------------------------
            // Authenticated by the bearer token; the front Worker routed here by
            // its `sub`. On commit, each write is enqueued to the sequencer so it
            // reaches the PDS-wide firehose (see `repo_write_route`).
            "/xrpc/com.atproto.repo.createRecord" => {
                self.repo_write_route(req, h::WriteKind::Create).await
            }
            "/xrpc/com.atproto.repo.putRecord" => {
                self.repo_write_route(req, h::WriteKind::Put).await
            }
            "/xrpc/com.atproto.repo.deleteRecord" => {
                self.repo_write_route(req, h::WriteKind::Delete).await
            }
            "/xrpc/com.atproto.repo.applyWrites" => self.apply_writes_route(req).await,

            // --- internal --------------------------------------------------
            // Reachable only from the front Worker: a DO stub cannot be
            // addressed from outside the network, and the Worker never routes a
            // client request to this path.
            "/_stelyph/provision" => {
                let input: ProvisionInput = req.json().await?;
                let store = self.store()?;
                let outcome = h::provision_account(
                    &store,
                    &ctx,
                    &input.handle,
                    input.email.as_deref(),
                    &input.password,
                    &self.key_passphrase()?,
                    &self.jwt_secret()?,
                    &self.plc_directory(),
                )
                .await?;
                match outcome {
                    h::ProvisionOutcome::Created {
                        did,
                        access_jwt,
                        refresh_jwt,
                    } => Response::from_json(&serde_json::json!({
                        "ok": true,
                        "did": did,
                        "accessJwt": access_jwt,
                        "refreshJwt": refresh_jwt,
                    })),
                    h::ProvisionOutcome::Rejected { error, message } => {
                        Response::from_json(&serde_json::json!({
                            "ok": false,
                            "error": error,
                            "message": message,
                        }))
                    }
                }
            }

            "/_stelyph/delete-account" => {
                let store = self.store()?;
                h::delete_account(&store).await
            }

            "/_stelyph/health" => self.health().await,

            // AppView proxy: app.bsky.* / chat.bsky.* are AppView methods; the
            // PDS forwards them with account service auth. Matched last so it
            // does not shadow the com.atproto.* handlers above.
            p if p.starts_with("/xrpc/app.bsky.") || p.starts_with("/xrpc/chat.bsky.") => {
                let nsid = p.trim_start_matches("/xrpc/").to_string();
                let query = url.query().unwrap_or("").to_string();
                let bearer = bearer(&req)?;
                let store = self.store()?;
                h::proxy_appview(
                    &store,
                    bearer.as_deref(),
                    &self.jwt_secret()?,
                    &self.key_passphrase()?,
                    &nsid,
                    &query,
                )
                .await
            }

            _ => xrpc_error(404, "MethodNotImplemented", "unknown endpoint"),
        }
    }

    /// `createRecord` / `putRecord` / `deleteRecord`: one write, then enqueue.
    async fn repo_write_route(&self, mut req: Request, kind: h::WriteKind) -> Result<Response> {
        // Serialise every write to this account so two concurrent requests cannot
        // both load the same root and fork the commit history. Held across the
        // whole commit + enqueue; released when this call returns.
        let _guard = self.write_lock.lock().await;
        let bearer = bearer(&req)?;
        let body = req.text().await?;
        let store = self.store()?;
        let result = h::repo_write(
            store,
            bearer.as_deref(),
            &self.jwt_secret()?,
            &self.key_passphrase()?,
            kind,
            &body,
        )
        .await?;
        self.finish_write(result).await
    }

    /// `applyWrites`: a batch of writes as one call, each its own commit + enqueue.
    async fn apply_writes_route(&self, mut req: Request) -> Result<Response> {
        let _guard = self.write_lock.lock().await;
        let bearer = bearer(&req)?;
        let body = req.text().await?;
        let store = self.store()?;
        let result = h::apply_writes(
            store,
            bearer.as_deref(),
            &self.jwt_secret()?,
            &self.key_passphrase()?,
            &body,
        )
        .await?;
        self.finish_write(result).await
    }

    /// Push each commit to the sequencer, then return the client's response.
    ///
    /// The commit(s) already landed atomically in this DO; only then are they
    /// enqueued for the firehose. A failed enqueue does not undo a commit — the
    /// record exists and this DO's `repo_seq` retains the event — so it is logged
    /// rather than surfaced as a write failure, matching the best-effort stance
    /// the in-process firehose already takes on a dropped subscriber.
    async fn finish_write(&self, result: h::WriteResult) -> Result<Response> {
        match result {
            h::WriteResult::Committed { client, enqueues } => {
                for enqueue in enqueues {
                    if let Err(e) = self.enqueue_to_sequencer(enqueue).await {
                        console_error!("firehose enqueue failed: {e}");
                    }
                }
                Response::from_json(&client)
            }
            h::WriteResult::Error {
                status,
                error,
                message,
            } => xrpc_error(status, error, &message),
        }
    }

    /// POST a commit to the single sequencer DO's `/enqueue`.
    ///
    /// The account DO shares the Worker's bindings, so it addresses the sequencer
    /// by the same fixed name the front Worker uses; the opaque internal authority
    /// avoids the self-loop the runtime would reject for the served zone.
    async fn enqueue_to_sequencer(&self, payload: serde_json::Value) -> Result<()> {
        let stub = self
            .env
            .durable_object(crate::SEQUENCER_BINDING)?
            .id_from_name(crate::sequencer::SEQUENCER_DO_NAME)?
            .get_stub()?;
        let headers = Headers::new();
        headers.set("content-type", "application/json")?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(payload.to_string().into()));
        let req = Request::new_with_init("https://stelyph.internal/enqueue", &init)?;
        let mut resp = stub.fetch_with_request(req).await?;
        if resp.status_code() != 200 {
            let detail = resp.text().await.unwrap_or_default();
            return Err(Error::RustError(format!(
                "sequencer /enqueue returned {}: {detail}",
                resp.status_code()
            )));
        }
        Ok(())
    }

    /// Secret used to sign session JWTs.
    fn jwt_secret(&self) -> Result<Vec<u8>> {
        self.env
            .secret("PDS_JWT_SECRET")
            .map(|s| s.to_string().into_bytes())
            .map_err(|_| Error::RustError("PDS_JWT_SECRET secret is not set".into()))
    }

    /// Whether this deployment advertises open registration in describeServer.
    ///
    /// Read here only to render the discovery document honestly; the front
    /// Worker is what actually enforces the gate. Kept in sync with the
    /// `open_registration` reader there.
    fn open_registration(&self) -> bool {
        self.env
            .var("PDS_OPEN_REGISTRATION")
            .map(|v| v.to_string() == "true")
            .unwrap_or(false)
    }

    /// PLC directory that genesis operations are submitted to.
    ///
    /// Overridable so a staging deployment can point at a throwaway directory —
    /// a genesis op against the real one is public and permanent, which is not
    /// something a test should be able to do by accident.
    fn plc_directory(&self) -> String {
        self.env
            .var("PDS_PLC_DIRECTORY")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| crate::plc::DEFAULT_PLC_DIRECTORY.to_string())
    }

    /// Passphrase wrapping every key this PDS stores at rest.
    ///
    /// Hard failure when unset rather than a default: a predictable passphrase
    /// would leave the OAuth signing key recoverable by anyone who obtains the
    /// Durable Object's storage.
    fn key_passphrase(&self) -> Result<Vec<u8>> {
        self.env
            .secret("PDS_KEY_PASSPHRASE")
            .map(|s| s.to_string().into_bytes())
            .map_err(|_| Error::RustError("PDS_KEY_PASSPHRASE secret is not set".into()))
    }

    /// Zone the handles live under, e.g. `pds.spirallex.net`.
    fn zone_suffix(&self) -> String {
        self.env
            .var("PDS_ZONE_SUFFIX")
            .map(|v| v.to_string())
            .unwrap_or_else(|_| "invalid".to_string())
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
        let mut detail = String::new();
        let sql_ok = match store.put_block(cid, payload.clone()).await {
            Ok(()) => match store.read_block_bytes(cid).await {
                Ok(b) if b == payload => true,
                Ok(b) => {
                    detail = format!("read back {} bytes, expected {}", b.len(), payload.len());
                    false
                }
                Err(e) => {
                    detail = format!("read failed: {e}");
                    false
                }
            },
            Err(e) => {
                detail = format!("write failed: {e}");
                false
            }
        };
        checks.push(("do_sqlite", sql_ok));

        // Sequencer read — cheap, and confirms the counter row exists.
        let seq_ok = store.max_seq().await.is_ok();
        checks.push(("sequencer", seq_ok));

        // R2 round trip through BlobStore.
        let r2_ok = match store
            .put_blob(
                "did:plc:health",
                "probe",
                "text/plain",
                5,
                b"probe".to_vec(),
            )
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
            "detail": detail,
        });

        let mut resp = Response::from_json(&body)?;
        if !healthy {
            resp = resp.with_status(503);
        }
        Ok(resp)
    }
}

/// A query-string parameter from the request URL, decoded.
fn qp(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

/// An XRPC error envelope: `{"error": ..., "message": ...}`.
///
/// atproto clients parse this shape; a bare text body would surface to the user
/// as an opaque failure.
fn xrpc_error(status: u16, error: &str, message: &str) -> Result<Response> {
    Ok(
        Response::from_json(&serde_json::json!({ "error": error, "message": message }))?
            .with_status(status),
    )
}
