//! AT Protocol PDS on Cloudflare Workers.
//!
//! The Worker is a router. Each request's `Host` names a PDS; that name selects
//! a Durable Object, which owns all state for that PDS and does the work. The
//! indirection is what gives every repo a single writer, and with it a monotonic
//! sequencer and a safely-updated root pointer.

mod durable;
mod handlers;
mod schema;
mod store;

use worker::*;

/// Durable Object binding name, as declared in `wrangler.toml`.
const PDS_BINDING: &str = "PDS";

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
        return Ok(Response::error("missing Host header", 400)?.try_into()?);
    }

    // The DO name is the hostname, so every PDS gets its own instance and its
    // own writer. Two requests for one host always land on the same object,
    // wherever they enter the network.
    let namespace = env.durable_object(PDS_BINDING)?;
    let stub = namespace.id_from_name(&host)?.get_stub()?;

    // Rebuild the request for the DO. The authority must NOT be this Worker's
    // own hostname: the runtime treats a subrequest to the zone it is serving
    // as a loop and rejects it with error 1042. The stub is already the routing
    // decision, so an opaque internal authority is correct — the DO learns which
    // PDS it is from `X-Stelyph-Host` below, not from the URL.
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let url = format!("https://stelyph.internal{path}");
    let mut init = RequestInit::new();
    init.with_method(match *req.method() {
        http::Method::POST => Method::Post,
        http::Method::PUT => Method::Put,
        http::Method::DELETE => Method::Delete,
        http::Method::PATCH => Method::Patch,
        http::Method::HEAD => Method::Head,
        http::Method::OPTIONS => Method::Options,
        _ => Method::Get,
    });

    // The DO needs the real hostname to derive its issuer URL and DID, which
    // the opaque forwarding URL has thrown away.
    let mut headers = Headers::new();
    headers.set("X-Stelyph-Host", &host)?;
    init.with_headers(headers);

    let forwarded = Request::new_with_init(&url, &init)?;
    let resp = stub.fetch_with_request(forwarded).await?;
    Ok(resp.try_into()?)
}
