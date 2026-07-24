//! AT Protocol PDS on Cloudflare Workers.
//!
//! The Worker is a router. Each request's `Host` names a PDS; that name selects
//! a Durable Object, which owns all state for that PDS and does the work. The
//! indirection is what gives every repo a single writer, and with it a monotonic
//! sequencer and a safely-updated root pointer.
//!
//! Registration is the exception, and has to be. Because a Durable Object is
//! named after a hostname, a hostname nobody has claimed yet resolves to an
//! empty object — so an account-creation gate living inside that object would
//! see a blank slate every time and let anyone claim anything. The gate
//! therefore runs *here*, in front, against a single registry object that sees
//! every hostname at once. See `registry.rs`.

mod durable;
mod handlers;
mod plc;
mod register;
mod registry;
mod schema;
mod store;

use worker::*;

/// Per-PDS Durable Object binding, as declared in `wrangler.toml`.
const PDS_BINDING: &str = "PDS";
/// Registry Durable Object binding.
const REGISTRY_BINDING: &str = "REGISTRY";

#[event(start)]
fn start() {
    // Surface Rust panics as readable stack traces in `wrangler tail` instead of
    // an opaque "unreachable executed".
    console_error_panic_hook::set_once();
}

#[event(fetch)]
async fn fetch(req: HttpRequest, env: Env, _ctx: Context) -> Result<HttpResponse> {
    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        // Strip any port so `example.pds.spirallex.net:8787` in local dev names
        // the same Durable Object as it would in production.
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();

    if host.is_empty() {
        return Response::error("missing Host header", 400)?.try_into();
    }

    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    let method = req.method().clone();
    let zone_suffix = zone_suffix(&env);

    // --- registration surface ---------------------------------------------
    // Served only from the signup host. On an account host these paths fall
    // through to the DO, which 404s them — `alice.pds.example.net/` is Alice's
    // PDS, not a second front door onto the registry.
    if is_signup_host(&host, &zone_suffix, signup_host(&env).as_deref()) {
        let route = path.split('?').next().unwrap_or("/");
        match (&method, route) {
            (&http::Method::GET, "/") => {
                let mut resp = Response::ok(register::registration_page(&zone_suffix))?;
                resp.headers_mut()
                    .set("content-type", "text/html; charset=utf-8")?;
                return resp.try_into();
            }
            (&http::Method::POST, "/register/check") => {
                let body = read_body(req).await?;
                return check_handle(&env, &body).await?.try_into();
            }
            (&http::Method::POST, "/xrpc/com.atproto.server.createAccount") => {
                let body = read_body(req).await?;
                return create_account(&env, &zone_suffix, &body).await?.try_into();
            }
            (&http::Method::POST, "/_stelyph/admin/invite") => {
                let token = req
                    .headers()
                    .get("x-stelyph-admin")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let body = read_body(req).await?;
                return mint_invite(&env, &token, &body).await?.try_into();
            }
            (&http::Method::POST, "/_stelyph/admin/delete-account") => {
                let token = req
                    .headers()
                    .get("x-stelyph-admin")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_string();
                let body = read_body(req).await?;
                return delete_account(&env, &zone_suffix, &token, &body)
                    .await?
                    .try_into();
            }
            _ => {}
        }
    }

    // --- repo-scoped data requests on the shared host ----------------------
    // On the shared PDS host, a read like `getRecord?repo=alice.pds…` names its
    // target account in a query param, not in the Host. Resolve that to the
    // account's own hostname so the request reaches the right Durable Object;
    // without this every such request would land on the DO named after the
    // shared host, which holds no account. On an account host (`alice.pds…`) the
    // Host already selects the DO, so this only applies at the shared host.
    let target_host = if host == zone_suffix {
        match repo_scoped_target(&env, &path, &zone_suffix).await {
            Some(h) => h,
            None => host.clone(),
        }
    } else {
        host.clone()
    };

    // --- forward to the target account's PDS -------------------------------
    let namespace = env.durable_object(PDS_BINDING)?;
    let stub = namespace.id_from_name(&target_host)?.get_stub()?;

    // Rebuild the request for the DO. The authority must NOT be this Worker's
    // own hostname: the runtime treats a subrequest to the zone it is serving
    // as a loop and rejects it with error 1042. The stub is already the routing
    // decision, so an opaque internal authority is correct — the DO learns which
    // PDS it is from `X-Stelyph-Host` below, not from the URL.
    let url = format!("https://stelyph.internal{path}");
    let mut init = RequestInit::new();
    init.with_method(match method {
        http::Method::POST => Method::Post,
        http::Method::PUT => Method::Put,
        http::Method::DELETE => Method::Delete,
        http::Method::PATCH => Method::Patch,
        http::Method::HEAD => Method::Head,
        http::Method::OPTIONS => Method::Options,
        _ => Method::Get,
    });

    // The DO needs the target hostname (the account being addressed, which may
    // differ from the request Host on the shared host) to resolve handles and
    // identity, since the opaque forwarding URL has thrown it away.
    let headers = Headers::new();
    headers.set("X-Stelyph-Host", &target_host)?;
    init.with_headers(headers);

    // Forward the body too. Discovery is all GET, so this went unnoticed until
    // there was a POST worth forwarding.
    if matches!(
        method,
        http::Method::POST | http::Method::PUT | http::Method::PATCH
    ) {
        let body = read_body(req).await?;
        init.with_body(Some(body.into()));
    }

    let forwarded = Request::new_with_init(&url, &init)?;
    let resp = stub.fetch_with_request(forwarded).await?;
    resp.try_into()
}

/// For a repo-scoped XRPC path on the shared host, the hostname of the account
/// its `repo` parameter names — or `None` if the path is not repo-scoped or the
/// target cannot be resolved (in which case the caller falls back to the shared
/// host, whose DO will return a proper not-found).
///
/// The `repo` identifier is either a handle (already a hostname here, used
/// directly) or a DID (resolved to its label via the registry). This is the one
/// place the shared host fans a flat XRPC surface back out to per-account DOs.
async fn repo_scoped_target(env: &Env, path: &str, zone_suffix: &str) -> Option<String> {
    // These are the read methods that carry a `repo`/`did` identifier. Writes
    // are authenticated per-account and not served on the shared host.
    const REPO_SCOPED: &[&str] = &[
        "/xrpc/com.atproto.repo.getRecord",
        "/xrpc/com.atproto.repo.listRecords",
        "/xrpc/com.atproto.repo.describeRepo",
        "/xrpc/com.atproto.sync.getRepo",
        "/xrpc/com.atproto.sync.getLatestCommit",
        "/xrpc/com.atproto.sync.getBlob",
        "/xrpc/com.atproto.sync.listBlobs",
    ];
    let (route, query) = path.split_once('?')?;
    if !REPO_SCOPED.contains(&route) {
        return None;
    }
    // `repo` for repo.* methods, `did` for sync.* methods.
    let ident = query_param(query, "repo").or_else(|| query_param(query, "did"))?;

    if ident.starts_with("did:") {
        // Resolve DID → label via the registry, then compose the hostname.
        let registry = registry_stub(env).ok()?;
        let res = call_do(
            &registry,
            "/resolve-did",
            serde_json::json!({ "did": ident }),
        )
        .await
        .ok()?;
        let label = res.get("label").and_then(|v| v.as_str())?;
        Some(format!("{label}.{zone_suffix}"))
    } else {
        // A handle. Accept it only if it is under this deployment's zone, so the
        // shared host cannot be used to address arbitrary external hosts.
        let h = ident.to_ascii_lowercase();
        if h.ends_with(&format!(".{zone_suffix}")) {
            Some(h)
        } else {
            None
        }
    }
}

/// Extract a query parameter value (percent-decoding the value).
fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            Some(v.replace('+', " ").to_string())
        } else {
            None
        }
    })
}

/// Handles are created under this suffix, e.g. `pds.example.net`.
fn zone_suffix(env: &Env) -> String {
    env.var("PDS_ZONE_SUFFIX")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "invalid".to_string())
}

/// Where the registration page and `createAccount` are served, from
/// `PDS_SIGNUP_HOST`.
///
/// Falls back to the zone suffix, which is the natural choice when nothing else
/// occupies it. On spirallex.com something does — `pds.spirallex.com` runs
/// another app — so the deployed value is a label underneath instead.
fn signup_host(env: &Env) -> Option<String> {
    env.var("PDS_SIGNUP_HOST").ok().map(|v| v.to_string())
}

/// Whether this host serves the registration surface.
///
/// Three hosts qualify:
///   - the zone suffix itself (`pds.spirallex.com`) — the natural landing page,
///     served here once its route points at this Worker;
///   - the configured `PDS_SIGNUP_HOST` (e.g. `signup.pds.spirallex.com`), kept
///     working so existing clients are not broken by the landing page moving;
///   - `*.workers.dev`, the only host that works before any custom DNS/cert,
///     which makes it the one place the flow can always be smoke-tested.
fn is_signup_host(host: &str, zone_suffix: &str, configured: Option<&str>) -> bool {
    host == zone_suffix || configured == Some(host) || host.ends_with(".workers.dev")
}

/// Drain a request body into a string.
///
/// Capped rather than unbounded: this runs before any authentication, so the
/// body size is whatever an anonymous caller chose to send, and a Workers
/// isolate has a hard memory ceiling it would otherwise be trivial to reach.
const MAX_BODY: usize = 64 * 1024;

async fn read_body(req: HttpRequest) -> Result<String> {
    use futures_util::StreamExt;

    let mut body = req.into_body();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        if buf.len() + chunk.len() > MAX_BODY {
            return Err(Error::RustError("request body too large".into()));
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).map_err(|_| Error::RustError("request body was not UTF-8".into()))
}

fn json_error(status: u16, error: &str, message: &str) -> Result<Response> {
    Ok(Response::from_json(&serde_json::json!({
        "error": error,
        "message": message,
    }))?
    .with_status(status))
}

fn registry_stub(env: &Env) -> Result<Stub> {
    env.durable_object(REGISTRY_BINDING)?
        .id_from_name(registry::REGISTRY_DO_NAME)?
        .get_stub()
}

/// POST a JSON body to a Durable Object stub and read the JSON back.
async fn call_do(stub: &Stub, path: &str, body: serde_json::Value) -> Result<serde_json::Value> {
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(body.to_string().into()));
    let req = Request::new_with_init(&format!("https://stelyph.internal{path}"), &init)?;
    let mut resp = stub.fetch_with_request(req).await?;
    resp.json().await
}

/// Same, but addressed to a per-PDS object, which needs to be told its hostname.
async fn call_pds_do(
    env: &Env,
    hostname: &str,
    path: &str,
    body: serde_json::Value,
) -> Result<serde_json::Value> {
    let stub = env
        .durable_object(PDS_BINDING)?
        .id_from_name(hostname)?
        .get_stub()?;
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set("X-Stelyph-Host", hostname)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(body.to_string().into()));
    let req = Request::new_with_init(&format!("https://stelyph.internal{path}"), &init)?;
    let mut resp = stub.fetch_with_request(req).await?;
    resp.json().await
}

/// `POST /_stelyph/admin/invite` — mint an invite code.
///
/// Registration is invite-gated, so without this nothing can ever be created:
/// the registry starts empty and there is no other path that writes to
/// `invites`. It is the operator's only door in.
///
/// Guarded by `PDS_ADMIN_TOKEN`, compared in constant time. A short-circuiting
/// `==` on a secret is a timing oracle, and this endpoint is reachable by anyone
/// who can reach the Worker.
async fn mint_invite(env: &Env, presented: &str, body: &str) -> Result<Response> {
    let Ok(expected) = env.secret("PDS_ADMIN_TOKEN") else {
        return json_error(503, "NotConfigured", "Invites are not configured.");
    };
    if !constant_time_eq(presented.as_bytes(), expected.to_string().as_bytes()) {
        // Deliberately indistinguishable from a missing header: an attacker
        // should not learn that a token was well-formed but wrong.
        return json_error(401, "Unauthorized", "Not authorized.");
    }

    #[derive(serde::Deserialize)]
    struct Req {
        code: String,
        #[serde(default = "default_uses")]
        uses: i64,
    }
    fn default_uses() -> i64 {
        1
    }

    let req: Req = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return json_error(400, "InvalidRequest", "Expected {\"code\", \"uses\"}."),
    };
    // `uses: 0` is how a code is revoked — the registry treats a code with no
    // remaining uses as invalid, so setting it to zero withdraws an invite that
    // has already been handed out. Negative is meaningless and rejected.
    if req.code.trim().is_empty() || req.uses < 0 {
        return json_error(
            400,
            "InvalidRequest",
            "A code and a non-negative use count.",
        );
    }

    let stub = registry_stub(env)?;
    call_do(
        &stub,
        "/invite",
        serde_json::json!({ "code": req.code, "uses": req.uses }),
    )
    .await?;
    Response::from_json(&serde_json::json!({ "ok": true, "code": req.code, "uses": req.uses }))
}

/// Compare two byte strings without an early exit.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `POST /_stelyph/admin/delete-account` — tear down an account.
///
/// Wipes the account's data from its Durable Object and frees its handle in the
/// registry. The DID stays on the PLC ledger — it is immutable and can only be
/// tombstoned (with the rotation key, which this deletes), so a deleted account
/// leaves an orphaned DID pointing at nothing. That is inherent to did:plc, not
/// a shortcut here.
async fn delete_account(
    env: &Env,
    zone_suffix: &str,
    presented: &str,
    body: &str,
) -> Result<Response> {
    let Ok(expected) = env.secret("PDS_ADMIN_TOKEN") else {
        return json_error(503, "NotConfigured", "Admin actions are not configured.");
    };
    if !constant_time_eq(presented.as_bytes(), expected.to_string().as_bytes()) {
        return json_error(401, "Unauthorized", "Not authorized.");
    }

    #[derive(serde::Deserialize)]
    struct Req {
        handle: String,
    }
    let req: Req = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return json_error(400, "InvalidRequest", "Expected {\"handle\"}."),
    };
    let handle = req.handle.trim().to_ascii_lowercase();
    let suffix = format!(".{zone_suffix}");
    let Some(label) = handle.strip_suffix(&suffix) else {
        return json_error(
            400,
            "UnsupportedDomain",
            &format!("Handles end in {suffix}"),
        );
    };

    // Wipe the account's own Durable Object.
    let wiped = call_pds_do(
        env,
        &handle,
        "/_stelyph/delete-account",
        serde_json::json!({}),
    )
    .await?;
    let did = wiped
        .get("did")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    // Free the handle regardless of whether an account row was present — the
    // reservation must not outlive the account.
    let registry = registry_stub(env)?;
    let _ = call_do(
        &registry,
        "/force-release",
        serde_json::json!({ "label": label }),
    )
    .await;

    Response::from_json(&serde_json::json!({
        "ok": wiped.get("ok").and_then(|v| v.as_bool()).unwrap_or(false),
        "handle": handle,
        "did": did,
        "note": "handle freed; DID remains on the PLC ledger (immutable)",
    }))
}

/// `POST /register/check` — live availability for the handle field.
///
/// Advisory only. It answers a keystroke, and the answer can be stale by the
/// time the form is submitted; `create_account` re-checks under the reservation
/// and is the only authority.
async fn check_handle(env: &Env, body: &str) -> Result<Response> {
    let input: register::CheckInput = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return json_error(400, "InvalidRequest", "Expected a JSON body with a label."),
    };
    let label = input.label.trim().to_ascii_lowercase();

    if let Err(msg) = register::validate_label(&label) {
        return Response::from_json(&serde_json::json!({
            "available": false,
            "message": msg,
        }));
    }

    let stub = registry_stub(env)?;
    let res = call_do(&stub, "/check", serde_json::json!({ "label": label })).await?;
    let available = res
        .get("available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Response::from_json(&serde_json::json!({
        "available": available,
        "message": if available { "Available" } else { "That one's taken. Try another." },
    }))
}

/// Whether this deployment lets anyone register without an invite.
///
/// Off unless `PDS_OPEN_REGISTRATION` is exactly `"true"`. A typo or an unset
/// var leaves the gate up, which is the safe direction to fail.
fn open_registration(env: &Env) -> bool {
    env.var("PDS_OPEN_REGISTRATION")
        .map(|v| v.to_string() == "true")
        .unwrap_or(false)
}

/// `POST /xrpc/com.atproto.server.createAccount`.
///
/// Order matters and is the whole design:
///
/// 1. reserve the label (burning an invite unless registration is open),
///    atomically, in the registry;
/// 2. provision the account in its own object, which writes the DID to a public
///    ledger and is the step that cannot be undone;
/// 3. bind the DID to the reservation.
///
/// If step 2 fails the reservation is released and the invite comes back, so a
/// failed signup costs the person nothing. If step 3 fails the account exists
/// and works — the reservation simply stays `reserved`, which still blocks the
/// label. Failing in that direction is deliberate: a label that is held but
/// unbound is a housekeeping problem, whereas a label released while an identity
/// for it exists on the ledger would let a second person claim a handle that
/// already resolves to someone else.
async fn create_account(env: &Env, zone_suffix: &str, body: &str) -> Result<Response> {
    let input: register::CreateAccountInput = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return json_error(400, "InvalidRequest", "Malformed request body."),
    };

    let handle = input.handle.trim().to_ascii_lowercase();
    let suffix = format!(".{zone_suffix}");
    let Some(label) = handle.strip_suffix(&suffix) else {
        return json_error(
            400,
            "UnsupportedDomain",
            &format!("Handles here end in {suffix}"),
        );
    };
    if let Err(msg) = register::validate_label(label) {
        return json_error(400, "InvalidHandle", msg);
    }

    let password = input.password.unwrap_or_default();
    if password.len() < 8 {
        return json_error(
            400,
            "InvalidRequest",
            "Password must be at least 8 characters.",
        );
    }

    // Step 1 — the gate (or, in open mode, just the reservation).
    let open = open_registration(env);
    let registry = registry_stub(env)?;
    let claim = call_do(
        &registry,
        "/claim",
        serde_json::json!({ "label": label, "invite_code": input.invite_code, "open": open }),
    )
    .await?;
    if !claim.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
        let code = claim
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("InvalidRequest");
        let message = match code {
            "HandleNotAvailable" => "That one's taken. Try another.",
            "InvalidInviteCode" => "That invite code isn't valid.",
            _ => "Could not reserve that handle.",
        };
        return json_error(400, code, message);
    }

    // Step 2 — the point of no return.
    let provisioned = call_pds_do(
        env,
        &handle,
        "/_stelyph/provision",
        serde_json::json!({
            "handle": handle,
            "email": input.email,
            "password": password,
        }),
    )
    .await;

    let provisioned = match provisioned {
        Ok(v) if v.get("ok").and_then(|b| b.as_bool()).unwrap_or(false) => v,
        other => {
            // Give the label and the invite back.
            let _ = call_do(&registry, "/release", serde_json::json!({ "label": label })).await;
            let (code, message) = match &other {
                Ok(v) => (
                    v.get("error")
                        .and_then(|s| s.as_str())
                        .unwrap_or("InternalError")
                        .to_string(),
                    v.get("message")
                        .and_then(|s| s.as_str())
                        .unwrap_or("Could not create the account.")
                        .to_string(),
                ),
                Err(_) => (
                    "InternalError".to_string(),
                    "Could not create the account.".to_string(),
                ),
            };
            return json_error(400, &code, &message);
        }
    };

    let did = provisioned
        .get("did")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    // Step 3 — bind. Best effort by design; see the note above.
    let _ = call_do(
        &registry,
        "/bind",
        serde_json::json!({ "label": label, "did": did }),
    )
    .await;

    Response::from_json(&register::CreateAccountResponse {
        access_jwt: provisioned
            .get("accessJwt")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        refresh_jwt: provisioned
            .get("refreshJwt")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        handle,
        did,
    })
}
