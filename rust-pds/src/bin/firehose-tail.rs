//! firehose-tail — demo consumer binary for the rust-pds firehose.
//!
//! Connects to a `ws://` subscribeRepos endpoint, decodes #commit frames,
//! verifies each commit's signature, and prints one human-readable line per commit.
//!
//! Usage:
//!   cargo run -p stelyph --bin firehose-tail -- [OPTIONS]
//!
//! Options:
//!   --url <ws-url>         WebSocket URL (default: ws://localhost:3000/xrpc/com.atproto.sync.subscribeRepos)
//!   --cursor <N>           Start from seq > N (replays historical commits before going live)
//!   --did-key <did:key:z…> Skip live DID resolution; verify all commits against this key
//!   --demo-did <did:...>   Mark commits from this DID with "<-- MY COMMIT"
//!   --json                 Print machine-readable JSON instead of human-readable lines

use futures_util::StreamExt;
use stelyph::firehose::tail::{decode_commit_frame, verify_commit_sig, TailError};
use tokio_tungstenite::tungstenite::Message;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    // --- CLI argument parsing (manual, no clap — mirrors main.rs style) ---
    let mut url = "ws://localhost:3000/xrpc/com.atproto.sync.subscribeRepos".to_string();
    let mut cursor: Option<i64> = None;
    let mut did_key_flag: Option<String> = None;
    let mut demo_did: Option<String> = None;
    let mut json_flag = false;

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--url" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    url = v.clone();
                } else {
                    eprintln!("error: --url requires a value");
                    std::process::exit(1);
                }
            }
            "--cursor" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    cursor = Some(v.parse::<i64>().unwrap_or_else(|_| {
                        eprintln!("error: --cursor must be an integer");
                        std::process::exit(1);
                    }));
                } else {
                    eprintln!("error: --cursor requires a value");
                    std::process::exit(1);
                }
            }
            "--did-key" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    did_key_flag = Some(v.clone());
                } else {
                    eprintln!("error: --did-key requires a value");
                    std::process::exit(1);
                }
            }
            "--demo-did" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    demo_did = Some(v.clone());
                } else {
                    eprintln!("error: --demo-did requires a value");
                    std::process::exit(1);
                }
            }
            "--json" => {
                json_flag = true;
            }
            other => {
                eprintln!("warning: unknown argument: {other}");
            }
        }
        i += 1;
    }

    // Append cursor query param if supplied.
    let connect_url = match cursor {
        Some(c) => format!("{url}?cursor={c}"),
        None => url.clone(),
    };

    // Connect (Pitfall 7: connect_async requires a tokio runtime — #[tokio::main] above).
    let (mut ws, _) = tokio_tungstenite::connect_async(&connect_url)
        .await
        .unwrap_or_else(|e| {
            eprintln!("error: could not connect to {connect_url}: {e}");
            std::process::exit(1);
        });

    eprintln!("Connected to {connect_url}. Waiting for commits...");

    // --- Main receive loop ---
    while let Some(msg) = ws.next().await {
        match msg {
            Ok(Message::Binary(bytes)) => {
                match decode_commit_frame(&bytes) {
                    // Non-#commit frames (error frames, #identity, etc.) — skip silently (T-06-05).
                    Err(TailError::NotCommit) => continue,
                    // Malformed CBOR — print and continue, never panic (T-06-05).
                    Err(e) => {
                        eprintln!("decode error: {e:?}");
                        continue;
                    }
                    Ok(body) => {
                        // Resolve the verification key: --did-key override, else live DID resolution.
                        let key_res: Result<String, String> = match &did_key_flag {
                            Some(k) => Ok(k.clone()),
                            None => resolve_did_key(&body.repo).await,
                        };

                        let sig_res = match &key_res {
                            Ok(k) => verify_commit_sig(&body, k)
                                .await
                                .map_err(|e| format!("{e:?}")),
                            Err(e) => Err(format!("resolve: {e}")),
                        };

                        // ✓/✗ must be unambiguous (T-06-06: ✓ only when sig_res is Ok).
                        let sig_ok = sig_res.is_ok();
                        let mark = if sig_ok { "✓" } else { "✗" };
                        let mine = if Some(body.repo.as_str()) == demo_did.as_deref() {
                            " <-- MY COMMIT"
                        } else {
                            ""
                        };
                        let detail = sig_res.err().map(|e| format!(" ({e})")).unwrap_or_default();

                        if json_flag {
                            // Serialize with serde_json so attacker-controlled string fields
                            // (repo/rev) are escaped correctly — a stray quote/backslash/control
                            // char must not break downstream consumers of the --json output.
                            let line = serde_json::json!({
                                "seq": body.seq,
                                "repo": body.repo,
                                "rev": body.rev,
                                "ops": body.ops.len(),
                                "sig_ok": sig_ok,
                            });
                            println!("{line}");
                        } else {
                            println!(
                                "[seq={}] {} rev={} ops={} {}{}{}",
                                body.seq,
                                body.repo,
                                body.rev,
                                body.ops.len(),
                                mark,
                                detail,
                                mine
                            );
                        }
                    }
                }
            }
            // Server closed the connection or we got a transport error — exit cleanly.
            Ok(Message::Close(_)) | Err(_) => break,
            // Pitfall 5: tokio-tungstenite surfaces Ping/Pong/Text/Frame at the app layer;
            // handle all of them with continue so the loop never terminates on them.
            Ok(Message::Ping(_))
            | Ok(Message::Pong(_))
            | Ok(Message::Text(_))
            | Ok(Message::Frame(_)) => continue,
        }
    }
}

// ---------------------------------------------------------------------------
// DID-key resolution (demo path only — automated test supplies the key directly)
// ---------------------------------------------------------------------------

/// Resolve the signing did:key for `repo` from its DID document.
///
/// did:plc → GET https://plc.directory/{did}, read verificationMethods.atproto (a did:key string).
/// did:web → derive host from suffix, GET https://{host}/.well-known/did.json, find the
///           verificationMethod entry with id == "{did}#atproto", read publicKeyMultibase,
///           return "did:key:{multibase}".
///
/// All network / parse failures map to Err(String) — the caller prints ✗ and continues
/// (T-06-08: resolve_did_key must not panic on bad JSON).
async fn resolve_did_key(repo: &str) -> Result<String, String> {
    if repo.starts_with("did:plc:") {
        resolve_plc(repo).await
    } else if repo.starts_with("did:web:") {
        resolve_web(repo).await
    } else {
        Err(format!("unsupported DID method: {repo}"))
    }
}

/// SSRF guard: reject did:web hosts that point at loopback / link-local / private /
/// internal targets before issuing any outbound request. `did` is firehose-supplied
/// (attacker-controlled), so a malicious relay could otherwise coerce the tail tool into
/// fetching internal/metadata endpoints (e.g. `did:web:169.254.169.254`).
///
/// Mirrors the host-allow logic of `validate_relay_url` (firehose/crawl.rs) and
/// `validate_appview_url` (xrpc/appview/client.rs). Residual risk: DNS rebinding is NOT
/// mitigated here (would require resolving + re-checking the IP at connect time).
fn is_safe_web_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    // Restrict to plausible DNS hostname / IP-literal characters (no `/`, `@`, `:` paths, etc).
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return false;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let blocked = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    // cloud metadata 169.254.169.254 is covered by link_local, but be explicit.
                    || (v4.octets()[0] == 169 && v4.octets()[1] == 254)
                    || v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        };
        return !blocked;
    }
    !(host == "localhost" || host.ends_with(".local") || host.ends_with(".internal"))
}

async fn resolve_plc(did: &str) -> Result<String, String> {
    // did is interpolated into the request path — character-restrict it to block path
    // traversal segments (e.g. a did containing `..` or `/`) reshaping the request.
    if !did.bytes().all(|b| b.is_ascii_alphanumeric() || b == b':') {
        return Err(format!("invalid did:plc characters: {did}"));
    }
    let url = format!("https://plc.directory/{did}");
    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("plc fetch: {e}"))?;
    let json: serde_json::Value = resp.json().await.map_err(|e| format!("plc json: {e}"))?;
    // plc.directory response has verificationMethods.atproto = "did:key:z..."
    json.get("verificationMethods")
        .and_then(|m| m.get("atproto"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "plc: verificationMethods.atproto not found in response".to_string())
}

async fn resolve_web(did: &str) -> Result<String, String> {
    // did:web:example.com → https://example.com/.well-known/did.json
    // did:web:example.com:user → https://example.com/user/did.json  (path DIDs — rare; skip for demo)
    let suffix = did.strip_prefix("did:web:").unwrap_or(did);
    // For simplicity, only support flat hostname DIDs (no colon-encoded path).
    if suffix.contains(':') {
        return Err(format!(
            "did:web path DIDs not supported in demo resolver: {did}"
        ));
    }
    // SSRF guard: reject loopback / link-local / private / internal hosts before fetching.
    if !is_safe_web_host(suffix) {
        return Err(format!("did:web host not allowed: {did}"));
    }
    let url = format!("https://{suffix}/.well-known/did.json");
    let resp = reqwest::get(&url)
        .await
        .map_err(|e| format!("web fetch: {e}"))?;
    let json: serde_json::Value = resp.json().await.map_err(|e| format!("web json: {e}"))?;

    // Find verificationMethod entry with id == "{did}#atproto" (inverse of identity/web.rs:81-84).
    let vm_array = json
        .get("verificationMethod")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "did:web: verificationMethod array not found".to_string())?;

    let atproto_id = format!("{did}#atproto");
    for entry in vm_array {
        if entry.get("id").and_then(|v| v.as_str()) == Some(&atproto_id) {
            let multibase = entry
                .get("publicKeyMultibase")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "did:web: publicKeyMultibase missing".to_string())?;
            return Ok(format!("did:key:{multibase}"));
        }
    }

    Err(format!(
        "did:web: no verificationMethod with id={atproto_id}"
    ))
}
