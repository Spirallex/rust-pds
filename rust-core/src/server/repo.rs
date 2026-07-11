//! Embedded-server repo surface: record CRUD, blobs, and CAR export.
//!
//! Mirrors the production handlers in `stelyph/src/xrpc/repo.rs` — same
//! validation (shared via [`crate::repo::util`]), same write path
//! ([`crate::repo::RepoWriter`]), same response shapes — minus axum. Anything
//! accepted by the desktop PDS must be accepted here, so the two servers reuse
//! every pure helper rather than re-implementing them.

use std::str::FromStr;
use std::sync::Arc;

use atrium_api::types::string::Did;
use atrium_crypto::keypair::{Did as KeypairDid, Secp256k1Keypair};
use atrium_repo::blockstore::{DiffBlockStore, SHA2_256};
use atrium_repo::Repository;
use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use sha2::{Digest, Sha256};

use crate::repo::util::{json_value_to_ipld, tid_from_micros, validate_collection, validate_rkey};
use crate::repo::writer::{RepoWriter, WriteOp};
use crate::storage::keys::load_key;

use super::{authed_did, json_response, query_param, read_json_body, xrpc_error, AppState};

/// Cap on an uploadBlob body. Matches the production server (axum's default
/// body limit), so a blob accepted on desktop is accepted on-device.
const MAX_BLOB_BYTES: usize = 2 * 1024 * 1024;

fn internal(msg: &str) -> Response<Full<Bytes>> {
    xrpc_error(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", msg)
}

fn invalid(msg: &str) -> Response<Full<Bytes>> {
    xrpc_error(StatusCode::BAD_REQUEST, "InvalidRequest", msg)
}

/// Current wall-clock microseconds for TID rkey generation.
fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

/// Load and import `did`'s signing key, going through the process-local cache
/// so a warm path skips the argon2id KDF. Shared by the write path, the DID
/// document, service-auth minting, and the AppView proxy.
pub(super) async fn load_signing_key(
    state: &AppState,
    did: &str,
) -> Result<Secp256k1Keypair, Response<Full<Bytes>>> {
    let key_id = format!("{did}#signing");

    let cached = state
        .signing_key_cache
        .lock()
        .expect("signing-key cache lock poisoned")
        .get(&key_id)
        .cloned();
    match cached {
        Some(bytes) => Secp256k1Keypair::import(bytes.as_slice())
            .map_err(|_| internal("failed to import signing key")),
        None => {
            let key_bytes = load_key(&state.store, &key_id, &state.config.key_passphrase)
                .await
                .map_err(|_| internal("failed to load signing key"))?;
            let signing = Secp256k1Keypair::import(&key_bytes)
                .map_err(|_| internal("failed to import signing key"))?;
            state
                .signing_key_cache
                .lock()
                .expect("signing-key cache lock poisoned")
                .insert(key_id, Arc::new(zeroize::Zeroizing::new(key_bytes)));
            Ok(signing)
        }
    }
}

/// Build a `RepoWriter` for `did`, loading and importing its signing key.
///
/// Fetches the shared per-DID write lock so concurrent writes serialize
/// instead of forking repo history — same protection as production.
async fn build_writer(state: &AppState, did: &str) -> Result<RepoWriter, Response<Full<Bytes>>> {
    let signing = load_signing_key(state, did).await?;
    let did_typed = Did::from_str(did).map_err(|_| internal("invalid DID"))?;

    let lock = state
        .did_locks
        .lock()
        .expect("did-locks lock poisoned")
        .entry(did.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();

    Ok(RepoWriter::with_lock(
        Arc::clone(&state.store),
        signing,
        did_typed,
        state.firehose_tx.clone(),
        lock,
    ))
}

/// Look up the record CID at an MST key (`collection/rkey`), or None if the
/// repo or key does not exist.
async fn lookup_record_cid(
    state: &AppState,
    did: &str,
    mst_key: &str,
) -> Result<Option<cid::Cid>, Response<Full<Bytes>>> {
    let root_cid = match state.store.load_repo_root(did).await {
        Ok(Some(c)) => c,
        Ok(None) => return Ok(None),
        Err(_) => return Err(internal("store error")),
    };
    let cloned_store = (*state.store).clone();
    let mut diff = DiffBlockStore::wrap(cloned_store);
    let mut repo = Repository::open(&mut diff, root_cid)
        .await
        .map_err(|_| internal("failed to open repo"))?;
    let mut tree = repo.tree();
    tree.get(mst_key)
        .await
        .map_err(|_| internal("MST get error"))
}

/// Resolve a `repo` parameter (DID or handle) to a DID string.
async fn resolve_repo_did(state: &AppState, repo: &str) -> Result<String, Response<Full<Bytes>>> {
    if repo.starts_with("did:") {
        return Ok(repo.to_string());
    }
    match state.store.get_did_by_handle(repo).await {
        Ok(Some(did)) => Ok(did),
        Ok(None) => Err(invalid(&format!("could not resolve repo: {repo}"))),
        Err(_) => Err(internal("store error")),
    }
}

// ---------------------------------------------------------------------------
// createRecord
// ---------------------------------------------------------------------------

/// POST com.atproto.repo.createRecord — signed write into the caller's repo.
pub(super) async fn create_record(
    state: &AppState,
    auth_header: Option<String>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let did = match authed_did(&auth_header, &state.config.jwt_secret, "com.atproto.access") {
        Ok(did) => did,
        Err(resp) => return resp,
    };
    let body = match read_json_body(req).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    if body["repo"].as_str() != Some(did.as_str()) {
        return invalid("repo must match the authenticated DID");
    }
    let Some(collection) = body["collection"].as_str().map(str::to_owned) else {
        return invalid("collection is required");
    };
    if let Err(msg) = validate_collection(&collection) {
        return invalid(&msg);
    }
    let rkey = match body["rkey"].as_str() {
        Some(rk) => {
            if let Err(msg) = validate_rkey(rk) {
                return invalid(&msg);
            }
            rk.to_owned()
        }
        None => tid_from_micros(now_micros()),
    };
    let record = body["record"].clone();
    if record.is_null() {
        return invalid("record is required");
    }
    let ipld = match json_value_to_ipld(record) {
        Ok(v) => v,
        Err(_) => return internal("record encode failed"),
    };

    let writer = match build_writer(state, &did).await {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    let mst_key = format!("{collection}/{rkey}");
    let (record_cid, _commit_cid) = match writer.create_record(&mst_key, ipld).await {
        Ok(v) => v,
        Err(_) => return internal("write failed"),
    };

    json_response(
        StatusCode::OK,
        serde_json::json!({
            "uri": format!("at://{did}/{collection}/{rkey}"),
            "cid": record_cid.to_string(),
        })
        .to_string(),
    )
}

// ---------------------------------------------------------------------------
// putRecord
// ---------------------------------------------------------------------------

/// POST com.atproto.repo.putRecord — create-or-update at a fixed rkey
/// (e.g. `app.bsky.actor.profile/self`).
pub(super) async fn put_record(
    state: &AppState,
    auth_header: Option<String>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let did = match authed_did(&auth_header, &state.config.jwt_secret, "com.atproto.access") {
        Ok(did) => did,
        Err(resp) => return resp,
    };
    let body = match read_json_body(req).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    if body["repo"].as_str() != Some(did.as_str()) {
        return invalid("repo must match the authenticated DID");
    }
    let (Some(collection), Some(rkey)) = (body["collection"].as_str(), body["rkey"].as_str())
    else {
        return invalid("collection and rkey are required");
    };
    if let Err(msg) = validate_collection(collection) {
        return invalid(&msg);
    }
    if let Err(msg) = validate_rkey(rkey) {
        return invalid(&msg);
    }
    let record = body["record"].clone();
    if record.is_null() {
        return invalid("record is required");
    }
    let ipld = match json_value_to_ipld(record) {
        Ok(v) => v,
        Err(_) => return internal("record encode failed"),
    };

    let mst_key = format!("{collection}/{rkey}");
    let exists = match lookup_record_cid(state, &did, &mst_key).await {
        Ok(v) => v.is_some(),
        Err(resp) => return resp,
    };
    let writer = match build_writer(state, &did).await {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    let op = if exists {
        WriteOp::Update {
            key: mst_key.clone(),
            record: ipld,
        }
    } else {
        WriteOp::Create {
            key: mst_key.clone(),
            record: ipld,
        }
    };
    let outcome = match writer.apply_one(op).await {
        Ok(o) => o,
        Err(_) => return internal("write failed"),
    };

    json_response(
        StatusCode::OK,
        serde_json::json!({
            "uri": format!("at://{did}/{mst_key}"),
            "cid": outcome.record_cid.map(|c| c.to_string()).unwrap_or_default(),
            "commit": { "cid": outcome.commit_cid.to_string(), "rev": outcome.rev },
        })
        .to_string(),
    )
}

// ---------------------------------------------------------------------------
// deleteRecord
// ---------------------------------------------------------------------------

/// POST com.atproto.repo.deleteRecord — idempotent: deleting a missing record
/// returns success with no commit.
pub(super) async fn delete_record(
    state: &AppState,
    auth_header: Option<String>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let did = match authed_did(&auth_header, &state.config.jwt_secret, "com.atproto.access") {
        Ok(did) => did,
        Err(resp) => return resp,
    };
    let body = match read_json_body(req).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    if body["repo"].as_str() != Some(did.as_str()) {
        return invalid("repo must match the authenticated DID");
    }
    let (Some(collection), Some(rkey)) = (body["collection"].as_str(), body["rkey"].as_str())
    else {
        return invalid("collection and rkey are required");
    };
    if let Err(msg) = validate_collection(collection) {
        return invalid(&msg);
    }
    if let Err(msg) = validate_rkey(rkey) {
        return invalid(&msg);
    }

    let mst_key = format!("{collection}/{rkey}");
    match lookup_record_cid(state, &did, &mst_key).await {
        Ok(None) => {
            return json_response(
                StatusCode::OK,
                serde_json::json!({ "commit": null }).to_string(),
            )
        }
        Ok(Some(_)) => {}
        Err(resp) => return resp,
    }

    let writer = match build_writer(state, &did).await {
        Ok(w) => w,
        Err(resp) => return resp,
    };
    let outcome = match writer.apply_one(WriteOp::Delete { key: mst_key }).await {
        Ok(o) => o,
        Err(_) => return internal("write failed"),
    };

    json_response(
        StatusCode::OK,
        serde_json::json!({
            "commit": { "cid": outcome.commit_cid.to_string(), "rev": outcome.rev },
        })
        .to_string(),
    )
}

// ---------------------------------------------------------------------------
// applyWrites
// ---------------------------------------------------------------------------

/// POST com.atproto.repo.applyWrites — batched create/update/delete.
///
/// Same deviation as production: atrium-repo can't batch multiple ops into one
/// signed commit through its public API, so each write is its own commit. The
/// chain stays linear and valid for federation.
pub(super) async fn apply_writes(
    state: &AppState,
    auth_header: Option<String>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let did = match authed_did(&auth_header, &state.config.jwt_secret, "com.atproto.access") {
        Ok(did) => did,
        Err(resp) => return resp,
    };
    let body = match read_json_body(req).await {
        Ok(body) => body,
        Err(resp) => return resp,
    };
    if body["repo"].as_str() != Some(did.as_str()) {
        return invalid("repo must match the authenticated DID");
    }
    let Some(writes) = body["writes"].as_array() else {
        return invalid("writes must be an array");
    };
    if writes.is_empty() {
        return json_response(
            StatusCode::OK,
            serde_json::json!({ "commit": null, "results": [] }).to_string(),
        );
    }

    let writer = match build_writer(state, &did).await {
        Ok(w) => w,
        Err(resp) => return resp,
    };

    let mut results = Vec::with_capacity(writes.len());
    let mut last_commit: Option<serde_json::Value> = None;

    for write in writes {
        let type_ = write["$type"].as_str().unwrap_or("");
        let Some(collection) = write["collection"].as_str().map(str::to_owned) else {
            return invalid("write is missing collection");
        };
        if let Err(msg) = validate_collection(&collection) {
            return invalid(&msg);
        }

        let outcome = match type_ {
            "com.atproto.repo.applyWrites#create" => {
                let rkey = match write["rkey"].as_str() {
                    Some(rk) => {
                        if let Err(msg) = validate_rkey(rk) {
                            return invalid(&msg);
                        }
                        rk.to_owned()
                    }
                    None => tid_from_micros(now_micros()),
                };
                let ipld = match json_value_to_ipld(write["value"].clone()) {
                    Ok(v) => v,
                    Err(_) => return internal("record encode failed"),
                };
                let mst_key = format!("{collection}/{rkey}");
                let outcome = match writer
                    .apply_one(WriteOp::Create {
                        key: mst_key,
                        record: ipld,
                    })
                    .await
                {
                    Ok(o) => o,
                    Err(_) => return internal("write failed"),
                };
                results.push(serde_json::json!({
                    "$type": "com.atproto.repo.applyWrites#createResult",
                    "uri": format!("at://{did}/{collection}/{rkey}"),
                    "cid": outcome.record_cid.map(|c| c.to_string()),
                    "validationStatus": "unknown",
                }));
                outcome
            }
            "com.atproto.repo.applyWrites#update" => {
                let Some(rkey) = write["rkey"].as_str() else {
                    return invalid("update write is missing rkey");
                };
                if let Err(msg) = validate_rkey(rkey) {
                    return invalid(&msg);
                }
                let ipld = match json_value_to_ipld(write["value"].clone()) {
                    Ok(v) => v,
                    Err(_) => return internal("record encode failed"),
                };
                let mst_key = format!("{collection}/{rkey}");
                let outcome = match writer
                    .apply_one(WriteOp::Update {
                        key: mst_key,
                        record: ipld,
                    })
                    .await
                {
                    Ok(o) => o,
                    Err(_) => return internal("write failed"),
                };
                results.push(serde_json::json!({
                    "$type": "com.atproto.repo.applyWrites#updateResult",
                    "uri": format!("at://{did}/{collection}/{rkey}"),
                    "cid": outcome.record_cid.map(|c| c.to_string()),
                    "validationStatus": "unknown",
                }));
                outcome
            }
            "com.atproto.repo.applyWrites#delete" => {
                let Some(rkey) = write["rkey"].as_str() else {
                    return invalid("delete write is missing rkey");
                };
                if let Err(msg) = validate_rkey(rkey) {
                    return invalid(&msg);
                }
                let mst_key = format!("{collection}/{rkey}");
                let outcome = match writer.apply_one(WriteOp::Delete { key: mst_key }).await {
                    Ok(o) => o,
                    Err(_) => return internal("write failed"),
                };
                results.push(serde_json::json!({
                    "$type": "com.atproto.repo.applyWrites#deleteResult",
                }));
                outcome
            }
            other => {
                return invalid(&format!("unknown write $type: {other}"));
            }
        };
        last_commit = Some(serde_json::json!({
            "cid": outcome.commit_cid.to_string(),
            "rev": outcome.rev,
        }));
    }

    json_response(
        StatusCode::OK,
        serde_json::json!({ "commit": last_commit, "results": results }).to_string(),
    )
}

// ---------------------------------------------------------------------------
// getRecord / listRecords / describeRepo
// ---------------------------------------------------------------------------

/// GET com.atproto.repo.getRecord — public read of one record.
pub(super) async fn get_record(state: &AppState, query: &str) -> Response<Full<Bytes>> {
    let (Some(repo), Some(collection), Some(rkey)) = (
        query_param(query, "repo"),
        query_param(query, "collection"),
        query_param(query, "rkey"),
    ) else {
        return invalid("repo, collection and rkey are required");
    };
    let did = match resolve_repo_did(state, &repo).await {
        Ok(d) => d,
        Err(resp) => return resp,
    };
    let mst_key = format!("{collection}/{rkey}");
    let cid = match lookup_record_cid(state, &did, &mst_key).await {
        Ok(Some(c)) => c,
        Ok(None) => return invalid("record not found"),
        Err(resp) => return resp,
    };
    let bytes = match state.store.read_block_bytes(cid).await {
        Ok(b) => b,
        Err(_) => return internal("read_block_bytes failed"),
    };
    let value: serde_json::Value = match serde_ipld_dagcbor::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return internal("dagcbor decode failed"),
    };
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "uri": format!("at://{did}/{mst_key}"),
            "cid": cid.to_string(),
            "value": value,
        })
        .to_string(),
    )
}

/// GET com.atproto.repo.listRecords — page through a collection by MST key.
pub(super) async fn list_records(state: &AppState, query: &str) -> Response<Full<Bytes>> {
    let (Some(did), Some(collection)) =
        (query_param(query, "repo"), query_param(query, "collection"))
    else {
        return invalid("repo and collection are required");
    };
    let limit = query_param(query, "limit")
        .and_then(|l| l.parse::<usize>().ok())
        .map(|l| l.clamp(1, 100))
        .unwrap_or(50);
    let cursor = query_param(query, "cursor");

    let root_cid = match state.store.load_repo_root(&did).await {
        Ok(Some(c)) => c,
        Ok(None) => return invalid(&format!("repo not found for did: {did}")),
        Err(_) => return internal("store error"),
    };
    let cloned_store = (*state.store).clone();
    let mut diff = DiffBlockStore::wrap(cloned_store);
    let mut repo = match Repository::open(&mut diff, root_cid).await {
        Ok(r) => r,
        Err(_) => return internal("failed to open repo"),
    };

    let prefix = format!("{collection}/");
    let mut tree = repo.tree();
    let mut stream = Box::pin(tree.entries_prefixed(&prefix));

    let mut records: Vec<serde_json::Value> = Vec::with_capacity(limit);
    let mut last_key: Option<String> = None;

    loop {
        let next = match stream.try_next().await {
            Ok(n) => n,
            Err(_) => return internal("MST stream error"),
        };
        let Some((key, cid)) = next else { break };
        if let Some(ref c) = cursor {
            if key.as_str() <= c.as_str() {
                continue;
            }
        }
        let bytes = match state.store.read_block_bytes(cid).await {
            Ok(b) => b,
            Err(_) => return internal("read_block_bytes failed"),
        };
        let value: serde_json::Value = match serde_ipld_dagcbor::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return internal("dagcbor decode failed"),
        };
        records.push(serde_json::json!({
            "uri": format!("at://{did}/{key}"),
            "cid": cid.to_string(),
            "value": value,
        }));
        last_key = Some(key);
        if records.len() >= limit {
            break;
        }
    }

    let next_cursor = if records.len() == limit {
        last_key
    } else {
        None
    };
    json_response(
        StatusCode::OK,
        serde_json::json!({ "records": records, "cursor": next_cursor }).to_string(),
    )
}

/// GET com.atproto.repo.describeRepo — handle, DID, DID document, collections.
pub(super) async fn describe_repo(state: &AppState, query: &str) -> Response<Full<Bytes>> {
    let Some(repo) = query_param(query, "repo") else {
        return invalid("repo is required");
    };
    let did = match resolve_repo_did(state, &repo).await {
        Ok(d) => d,
        Err(resp) => return resp,
    };
    let handle = match state.store.get_handle_by_did(&did).await {
        Ok(Some(h)) => h,
        Ok(None) => return invalid(&format!("repo not found: {repo}")),
        Err(_) => return internal("store error"),
    };

    // Distinct top-level collection NSIDs present in the MST.
    let mut collections = std::collections::BTreeSet::new();
    if let Ok(Some(root_cid)) = state.store.load_repo_root(&did).await {
        let cloned_store = (*state.store).clone();
        let mut diff = DiffBlockStore::wrap(cloned_store);
        let mut repo = match Repository::open(&mut diff, root_cid).await {
            Ok(r) => r,
            Err(_) => return internal("failed to open repo"),
        };
        let mut tree = repo.tree();
        let mut stream = Box::pin(tree.entries_prefixed(""));
        loop {
            match stream.try_next().await {
                Ok(Some((key, _cid))) => {
                    if let Some((collection, _)) = key.split_once('/') {
                        collections.insert(collection.to_string());
                    }
                }
                Ok(None) => break,
                Err(_) => return internal("MST stream error"),
            }
        }
    }

    // The account's public signing key for the DID document.
    let signing = match load_signing_key(state, &did).await {
        Ok(k) => k,
        Err(resp) => return resp,
    };
    let key_did = signing.did();
    let public_key_multibase = key_did.strip_prefix("did:key:").unwrap_or(&key_did);

    json_response(
        StatusCode::OK,
        serde_json::json!({
            "handle": handle,
            "did": did,
            "didDoc": {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    "https://w3id.org/security/multikey/v1",
                ],
                "id": did,
                "alsoKnownAs": [format!("at://{handle}")],
                "verificationMethod": [{
                    "id": format!("{did}#atproto"),
                    "type": "Multikey",
                    "controller": did,
                    "publicKeyMultibase": public_key_multibase,
                }],
                "service": [{
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": format!("https://{}", state.config.hostname),
                }],
            },
            "collections": collections.into_iter().collect::<Vec<_>>(),
            "handleIsCorrect": true,
        })
        .to_string(),
    )
}

// ---------------------------------------------------------------------------
// uploadBlob / sync.getBlob / sync.getRepo
// ---------------------------------------------------------------------------

/// POST com.atproto.repo.uploadBlob — store a binary body content-addressed
/// (CIDv1, raw codec, sha2-256) and return the blob ref.
pub(super) async fn upload_blob(
    state: &AppState,
    auth_header: Option<String>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let did = match authed_did(&auth_header, &state.config.jwt_secret, "com.atproto.access") {
        Ok(did) => did,
        Err(resp) => return resp,
    };
    let mime_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_owned();
    let body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return invalid("could not read body"),
    };
    if body.is_empty() {
        return invalid("empty blob");
    }
    if body.len() > MAX_BLOB_BYTES {
        return xrpc_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "InvalidRequest",
            "blob too large",
        );
    }

    let digest = Sha256::digest(&body);
    let mh = match cid::multihash::Multihash::wrap(SHA2_256, digest.as_slice()) {
        Ok(m) => m,
        Err(_) => return internal("multihash wrap failed"),
    };
    let cid = cid::Cid::new_v1(0x55, mh);
    let cid_str = cid.to_string();
    let size = body.len() as i64;

    if state
        .store
        .put_blob(&did, &cid_str, &mime_type, size, body.to_vec())
        .await
        .is_err()
    {
        return internal("store error");
    }

    json_response(
        StatusCode::OK,
        serde_json::json!({
            "blob": {
                "$type": "blob",
                "ref": { "$link": cid_str },
                "mimeType": mime_type,
                "size": size,
            }
        })
        .to_string(),
    )
}

/// GET com.atproto.sync.getBlob — raw blob bytes with the original mime type.
pub(super) async fn get_blob(state: &AppState, query: &str) -> Response<Full<Bytes>> {
    let (Some(did), Some(cid)) = (query_param(query, "did"), query_param(query, "cid")) else {
        return invalid("did and cid are required");
    };
    let (mime_type, bytes) = match state.store.get_blob(&did, &cid).await {
        Ok(Some(v)) => v,
        Ok(None) => return invalid("blob not found"),
        Err(_) => return internal("store error"),
    };
    match Response::builder()
        .status(StatusCode::OK)
        .header("content-type", mime_type)
        .body(Full::new(Bytes::from(bytes)))
    {
        Ok(resp) => resp,
        Err(_) => internal("response build failed"),
    }
}

/// GET com.atproto.sync.getRepo — export the repository as a CARv1 archive.
pub(super) async fn get_repo(state: &AppState, query: &str) -> Response<Full<Bytes>> {
    let Some(did) = query_param(query, "did") else {
        return invalid("missing required query param: did");
    };
    let root_cid = match state.store.load_repo_root(&did).await {
        Ok(Some(c)) => c,
        Ok(None) => return invalid(&format!("repo not found for did: {did}")),
        Err(_) => return internal("store error"),
    };

    let cloned_store = (*state.store).clone();
    let mut diff = DiffBlockStore::wrap(cloned_store);
    let mut repo = match Repository::open(&mut diff, root_cid).await {
        Ok(r) => r,
        Err(_) => return internal("failed to open repo"),
    };
    let cids: Vec<cid::Cid> = match repo.export().await {
        Ok(iter) => iter.collect(),
        Err(_) => return internal("repo export failed"),
    };

    let header = iroh_car::CarHeader::new_v1(vec![root_cid]);
    let mut buf: Vec<u8> = Vec::new();
    let mut car_writer = iroh_car::CarWriter::new(header, &mut buf);
    for cid in cids {
        let bytes = match state.store.read_block_bytes(cid).await {
            Ok(b) => b,
            Err(_) => return internal("read_block_bytes failed"),
        };
        if car_writer.write(cid, &bytes).await.is_err() {
            return internal("CAR write failed");
        }
    }
    if car_writer.finish().await.is_err() {
        return internal("CAR finish failed");
    }

    match Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/vnd.ipld.car")
        .body(Full::new(Bytes::from(buf)))
    {
        Ok(resp) => resp,
        Err(_) => internal("response build failed"),
    }
}
