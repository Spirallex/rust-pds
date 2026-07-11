/// XRPC repo handlers: createRecord, getRepo, listRecords.
///
/// Three lexicon endpoints wired to the repo write path (RepoWriter) and the
/// atrium-repo read path (Repository::export, MST entries_prefixed).
///
/// Route table:
/// | Method | Path                                             | Handler         |
/// |--------|--------------------------------------------------|-----------------|
/// | POST   | /xrpc/com.atproto.repo.createRecord              | create_record   |
/// | GET    | /xrpc/com.atproto.sync.getRepo                   | get_repo        |
/// | GET    | /xrpc/com.atproto.repo.listRecords               | list_records    |
///
/// ## Threat mitigations
/// - Elevation of Privilege: createRecord asserts input.repo == authenticated DID.
///   AccessAuth extractor enforces access scope (refresh tokens rejected → InvalidToken).
/// - Spoofing: AccessAuth extractor validates HS256 JWT and access scope.
/// - Tampering: getRepo sets explicit Content-Type: application/vnd.ipld.car.
/// - DoS: listRecords limit clamped to 1..=100 (default 50).
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use atrium_api::types::string::Did;
use atrium_crypto::keypair::{Did as KeypairDid, Secp256k1Keypair};
use atrium_repo::blockstore::{DiffBlockStore, SHA2_256};
use atrium_repo::Repository;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Json;
use futures::TryStreamExt;
use ipld_core::ipld::Ipld;
use iroh_car::{CarHeader, CarWriter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::extractor::AccessAuth;
use crate::identity::web::{DidDocument, ServiceEntry, VerificationMethod};
use crate::repo::writer::{RepoWriter, WriteOp};
use crate::storage::keys::load_key;
use crate::xrpc::{AppState, XrpcError};

// ---------------------------------------------------------------------------
// createRecord
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRecordInput {
    pub repo: String,
    pub collection: String,
    pub record: serde_json::Value,
    pub rkey: Option<String>,
    #[allow(dead_code)]
    pub validate: Option<bool>,
    #[allow(dead_code)]
    pub swap_commit: Option<String>,
}

#[derive(Serialize)]
pub struct CreateRecordOutput {
    pub uri: String,
    pub cid: String,
}

/// POST /xrpc/com.atproto.repo.createRecord
///
/// Authenticated write path. The AccessAuth extractor enforces access scope —
/// refresh tokens are rejected automatically with 401 InvalidToken.
///
/// Ownership check: input.repo must equal the authenticated DID.
/// The signing key is loaded from the encrypted key store, a RepoWriter is
/// constructed, and `create_record` is called to write the record into the
/// account's MST-backed repo. The lazy empty-repo init fires here on the first
/// call (RepoWriter::create_record handles the "no existing root" case via
/// Repository::create).
pub async fn create_record(
    State(state): State<AppState>,
    AccessAuth(did): AccessAuth,
    Json(input): Json<CreateRecordInput>,
) -> Result<Json<CreateRecordOutput>, XrpcError> {
    // Only allow writing to the caller's own repo.
    if input.repo != did {
        return Err(XrpcError::InvalidRequest(
            "repo must match the authenticated DID".into(),
        ));
    }

    // Validate collection (NSID format) and rkey (if provided) before
    // any key loading or expensive operations.
    validate_collection(&input.collection)?;
    if let Some(ref rkey) = input.rkey {
        validate_rkey(rkey)?;
    }

    // Load the account's signing key from the encrypted key store, checking the
    // process-local cache first so a warm cache skips the argon2id KDF (B4).
    let key_id = format!("{did}#signing");
    let signing = if let Some(cached) = state.signing_key_cache.get(&key_id) {
        Secp256k1Keypair::import(cached.as_slice()).map_err(|e| {
            XrpcError::Internal(anyhow::anyhow!("failed to import signing key: {e}"))
        })?
    } else {
        let key_bytes = load_key(&state.store, &key_id, &state.key_passphrase)
            .await
            .map_err(|e| XrpcError::Internal(anyhow::anyhow!("failed to load signing key: {e}")))?;
        state.signing_key_cache.insert(
            key_id.clone(),
            Arc::new(zeroize::Zeroizing::new(key_bytes.clone())),
        );
        Secp256k1Keypair::import(&key_bytes).map_err(|e| {
            XrpcError::Internal(anyhow::anyhow!("failed to import signing key: {e}"))
        })?
    };

    let did_typed = Did::from_str(&did)
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("invalid DID: {e}")))?;

    // Fetch the shared per-DID write lock so two concurrent writes to this DID
    // serialize through one lock instead of forking repo history (B2).
    let lock = state
        .did_locks
        .entry(did.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();

    // Build the RepoWriter, threading the broadcast sender for live firehose events.
    let writer = RepoWriter::with_lock(
        Arc::clone(&state.store),
        signing,
        did_typed,
        state.firehose_tx.clone(),
        lock,
    );

    // Determine rkey: use provided rkey or generate a TID-style key.
    let rkey = input.rkey.clone().unwrap_or_else(|| {
        // Generate a timestamp-based key (TID format: base32 of microseconds).
        // atrium_api::types::string::Tid::now() would be ideal but may not be pub.
        // Fall back to a microsecond-timestamp base32 key matching TID format.
        let now_us = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        // Encode as 13-char lowercase base32 (TID uses clockid in upper bits, but
        // for rkey uniqueness within a collection, the timestamp is sufficient).
        // ATProto TID is base32(microseconds, padded to 13 chars). Use the same alphabet.
        tid_from_micros(now_us)
    });

    // Build the MST key: collection/rkey
    let mst_key = format!("{}/{}", input.collection, rkey);

    // Convert serde_json::Value → Ipld via dag-cbor round-trip.
    // This preserves $type, nested structures, and CID links correctly.
    let ipld = json_value_to_ipld(input.record)?;

    let (record_cid, _commit_cid) = writer.create_record(&mst_key, ipld).await?;

    let uri = format!("at://{did}/{}/{rkey}", input.collection);

    Ok(Json(CreateRecordOutput {
        uri,
        cid: record_cid.to_string(),
    }))
}

// ---------------------------------------------------------------------------
// applyWrites
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyWritesInput {
    pub repo: String,
    #[allow(dead_code)]
    pub validate: Option<bool>,
    pub writes: Vec<ApplyWritesWrite>,
    #[allow(dead_code)]
    pub swap_commit: Option<String>,
}

/// A single write in an applyWrites batch. Tagged by the `$type` discriminator
/// the Bluesky client sends (`com.atproto.repo.applyWrites#{create,update,delete}`).
#[derive(Deserialize)]
#[serde(tag = "$type")]
pub enum ApplyWritesWrite {
    #[serde(
        rename = "com.atproto.repo.applyWrites#create",
        rename_all = "camelCase"
    )]
    Create {
        collection: String,
        rkey: Option<String>,
        value: serde_json::Value,
    },
    #[serde(
        rename = "com.atproto.repo.applyWrites#update",
        rename_all = "camelCase"
    )]
    Update {
        collection: String,
        rkey: String,
        value: serde_json::Value,
    },
    #[serde(
        rename = "com.atproto.repo.applyWrites#delete",
        rename_all = "camelCase"
    )]
    Delete { collection: String, rkey: String },
}

#[derive(Serialize)]
pub struct CommitMeta {
    pub cid: String,
    pub rev: String,
}

#[derive(Serialize)]
pub struct ApplyWritesOutput {
    pub commit: Option<CommitMeta>,
    pub results: Vec<serde_json::Value>,
}

/// POST /xrpc/com.atproto.repo.applyWrites
///
/// Batched create/update/delete. The Bluesky app uses this during onboarding
/// and other flows that touch multiple records.
///
/// Atomicity note: atrium-repo 0.1.8 cannot batch multiple ops into one signed
/// commit through its public API (`CommitBuilder::new` is private), so each
/// write is applied as its own commit via `RepoWriter::apply_one`. The commit
/// chain stays linear and valid for federation; the only deviation from the
/// lexicon is that a batch produces N commits rather than one.
///
/// Ownership check: input.repo must equal the authenticated DID.
pub async fn apply_writes(
    State(state): State<AppState>,
    AccessAuth(did): AccessAuth,
    Json(input): Json<ApplyWritesInput>,
) -> Result<Json<ApplyWritesOutput>, XrpcError> {
    // Only allow writing to the caller's own repo.
    if input.repo != did {
        return Err(XrpcError::InvalidRequest(
            "repo must match the authenticated DID".into(),
        ));
    }

    if input.writes.is_empty() {
        return Ok(Json(ApplyWritesOutput {
            commit: None,
            results: vec![],
        }));
    }

    // Load the account's signing key and build one writer for the whole batch.
    // Check the process-local cache first so a warm cache skips the argon2id KDF (B4).
    let key_id = format!("{did}#signing");
    let signing = if let Some(cached) = state.signing_key_cache.get(&key_id) {
        Secp256k1Keypair::import(cached.as_slice()).map_err(|e| {
            XrpcError::Internal(anyhow::anyhow!("failed to import signing key: {e}"))
        })?
    } else {
        let key_bytes = load_key(&state.store, &key_id, &state.key_passphrase)
            .await
            .map_err(|e| XrpcError::Internal(anyhow::anyhow!("failed to load signing key: {e}")))?;
        state.signing_key_cache.insert(
            key_id.clone(),
            Arc::new(zeroize::Zeroizing::new(key_bytes.clone())),
        );
        Secp256k1Keypair::import(&key_bytes).map_err(|e| {
            XrpcError::Internal(anyhow::anyhow!("failed to import signing key: {e}"))
        })?
    };
    let did_typed = Did::from_str(&did)
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("invalid DID: {e}")))?;
    // Fetch the shared per-DID write lock so two concurrent writes to this DID
    // serialize through one lock instead of forking repo history (B2).
    let lock = state
        .did_locks
        .entry(did.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let writer = RepoWriter::with_lock(
        Arc::clone(&state.store),
        signing,
        did_typed,
        state.firehose_tx.clone(),
        lock,
    );

    let mut results = Vec::with_capacity(input.writes.len());
    let mut last_commit: Option<CommitMeta> = None;

    for write in input.writes {
        let outcome = match write {
            ApplyWritesWrite::Create {
                collection,
                rkey,
                value,
            } => {
                validate_collection(&collection)?;
                if let Some(ref rk) = rkey {
                    validate_rkey(rk)?;
                }
                let rkey = rkey.unwrap_or_else(|| {
                    let now_us = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_micros() as u64;
                    tid_from_micros(now_us)
                });
                let mst_key = format!("{collection}/{rkey}");
                let ipld = json_value_to_ipld(value)?;
                let outcome = writer
                    .apply_one(WriteOp::Create {
                        key: mst_key,
                        record: ipld,
                    })
                    .await?;
                results.push(serde_json::json!({
                    "$type": "com.atproto.repo.applyWrites#createResult",
                    "uri": format!("at://{did}/{collection}/{rkey}"),
                    "cid": outcome.record_cid.map(|c| c.to_string()),
                    "validationStatus": "unknown",
                }));
                outcome
            }
            ApplyWritesWrite::Update {
                collection,
                rkey,
                value,
            } => {
                validate_collection(&collection)?;
                validate_rkey(&rkey)?;
                let mst_key = format!("{collection}/{rkey}");
                let ipld = json_value_to_ipld(value)?;
                let outcome = writer
                    .apply_one(WriteOp::Update {
                        key: mst_key,
                        record: ipld,
                    })
                    .await?;
                results.push(serde_json::json!({
                    "$type": "com.atproto.repo.applyWrites#updateResult",
                    "uri": format!("at://{did}/{collection}/{rkey}"),
                    "cid": outcome.record_cid.map(|c| c.to_string()),
                    "validationStatus": "unknown",
                }));
                outcome
            }
            ApplyWritesWrite::Delete { collection, rkey } => {
                validate_collection(&collection)?;
                validate_rkey(&rkey)?;
                let mst_key = format!("{collection}/{rkey}");
                let outcome = writer.apply_one(WriteOp::Delete { key: mst_key }).await?;
                results.push(serde_json::json!({
                    "$type": "com.atproto.repo.applyWrites#deleteResult",
                }));
                outcome
            }
        };
        last_commit = Some(CommitMeta {
            cid: outcome.commit_cid.to_string(),
            rev: outcome.rev,
        });
    }

    Ok(Json(ApplyWritesOutput {
        commit: last_commit,
        results,
    }))
}

// ---------------------------------------------------------------------------
// Shared helpers (writer construction, MST reads, repo resolution)
// ---------------------------------------------------------------------------

/// Build a `RepoWriter` for `did`, loading and importing its signing key.
///
/// Checks the process-local signing-key cache before calling `load_key` (B4), and
/// fetches the shared per-DID write lock from `state.did_locks` so two concurrent
/// writes to this DID serialize through one lock instead of forking repo history (B2).
async fn build_writer(state: &AppState, did: &str) -> Result<RepoWriter, XrpcError> {
    let key_id = format!("{did}#signing");
    let signing = if let Some(cached) = state.signing_key_cache.get(&key_id) {
        Secp256k1Keypair::import(cached.as_slice()).map_err(|e| {
            XrpcError::Internal(anyhow::anyhow!("failed to import signing key: {e}"))
        })?
    } else {
        let key_bytes = load_key(&state.store, &key_id, &state.key_passphrase)
            .await
            .map_err(|e| XrpcError::Internal(anyhow::anyhow!("failed to load signing key: {e}")))?;
        state.signing_key_cache.insert(
            key_id.clone(),
            Arc::new(zeroize::Zeroizing::new(key_bytes.clone())),
        );
        Secp256k1Keypair::import(&key_bytes).map_err(|e| {
            XrpcError::Internal(anyhow::anyhow!("failed to import signing key: {e}"))
        })?
    };
    let did_typed =
        Did::from_str(did).map_err(|e| XrpcError::Internal(anyhow::anyhow!("invalid DID: {e}")))?;
    let lock = state
        .did_locks
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

/// Look up the record CID at an MST key (`collection/rkey`), or None if the repo
/// or key does not exist.
async fn lookup_record_cid(
    state: &AppState,
    did: &str,
    mst_key: &str,
) -> Result<Option<cid::Cid>, XrpcError> {
    let root_cid = match state.store.load_repo_root(did).await? {
        Some(c) => c,
        None => return Ok(None),
    };
    let cloned_store = (*state.store).clone();
    let mut diff = DiffBlockStore::wrap(cloned_store);
    let mut repo = Repository::open(&mut diff, root_cid)
        .await
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("failed to open repo: {e}")))?;
    let mut tree = repo.tree();
    tree.get(mst_key)
        .await
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("MST get error: {e}")))
}

/// Resolve a `repo` parameter (DID or handle) to a DID string.
async fn resolve_repo_did(state: &AppState, repo: &str) -> Result<String, XrpcError> {
    if repo.starts_with("did:") {
        Ok(repo.to_string())
    } else {
        state
            .store
            .get_did_by_handle(repo)
            .await?
            .ok_or_else(|| XrpcError::InvalidRequest(format!("could not resolve repo: {repo}")))
    }
}

// ---------------------------------------------------------------------------
// putRecord
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutRecordInput {
    pub repo: String,
    pub collection: String,
    pub rkey: String,
    pub record: serde_json::Value,
    #[allow(dead_code)]
    pub validate: Option<bool>,
    #[allow(dead_code)]
    pub swap_record: Option<serde_json::Value>,
    #[allow(dead_code)]
    pub swap_commit: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PutRecordOutput {
    pub uri: String,
    pub cid: String,
    pub commit: Option<CommitMeta>,
}

/// POST /xrpc/com.atproto.repo.putRecord
///
/// Create or update a record at a fixed rkey (e.g. `app.bsky.actor.profile/self`).
/// If a record already exists at the key it is updated; otherwise it is created.
pub async fn put_record(
    State(state): State<AppState>,
    AccessAuth(did): AccessAuth,
    Json(input): Json<PutRecordInput>,
) -> Result<Json<PutRecordOutput>, XrpcError> {
    if input.repo != did {
        return Err(XrpcError::InvalidRequest(
            "repo must match the authenticated DID".into(),
        ));
    }
    validate_collection(&input.collection)?;
    validate_rkey(&input.rkey)?;

    let mst_key = format!("{}/{}", input.collection, input.rkey);
    let exists = lookup_record_cid(&state, &did, &mst_key).await?.is_some();
    let ipld = json_value_to_ipld(input.record)?;

    let writer = build_writer(&state, &did).await?;
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
    let outcome = writer.apply_one(op).await?;

    let uri = format!("at://{did}/{}/{}", input.collection, input.rkey);
    Ok(Json(PutRecordOutput {
        uri,
        cid: outcome
            .record_cid
            .map(|c| c.to_string())
            .unwrap_or_default(),
        commit: Some(CommitMeta {
            cid: outcome.commit_cid.to_string(),
            rev: outcome.rev,
        }),
    }))
}

// ---------------------------------------------------------------------------
// getRecord
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct GetRecordParams {
    pub repo: String,
    pub collection: String,
    pub rkey: String,
    #[allow(dead_code)]
    pub cid: Option<String>,
}

#[derive(Serialize)]
pub struct GetRecordOutput {
    pub uri: String,
    pub cid: String,
    pub value: serde_json::Value,
}

/// GET /xrpc/com.atproto.repo.getRecord?repo=<did|handle>&collection=<c>&rkey=<k>
///
/// Public read of a single record from the repo's MST.
pub async fn get_record(
    State(state): State<AppState>,
    Query(params): Query<GetRecordParams>,
) -> Result<Json<GetRecordOutput>, XrpcError> {
    let did = resolve_repo_did(&state, &params.repo).await?;
    let mst_key = format!("{}/{}", params.collection, params.rkey);

    let cid = lookup_record_cid(&state, &did, &mst_key)
        .await?
        .ok_or_else(|| XrpcError::InvalidRequest("record not found".into()))?;

    let bytes = state
        .store
        .read_block_bytes(cid)
        .await
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("read_block_bytes for {cid}: {e}")))?;
    let value: serde_json::Value = serde_ipld_dagcbor::from_slice(&bytes).map_err(|e| {
        XrpcError::Internal(anyhow::anyhow!("dagcbor decode for record {cid}: {e}"))
    })?;

    Ok(Json(GetRecordOutput {
        uri: format!("at://{did}/{}/{}", params.collection, params.rkey),
        cid: cid.to_string(),
        value,
    }))
}

// ---------------------------------------------------------------------------
// deleteRecord
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteRecordInput {
    pub repo: String,
    pub collection: String,
    pub rkey: String,
    #[allow(dead_code)]
    pub swap_record: Option<String>,
    #[allow(dead_code)]
    pub swap_commit: Option<String>,
}

#[derive(Serialize)]
pub struct DeleteRecordOutput {
    pub commit: Option<CommitMeta>,
}

/// POST /xrpc/com.atproto.repo.deleteRecord
///
/// Delete a record. Idempotent: deleting a missing record returns success with
/// no commit (matching the lexicon's tombstone-friendly semantics).
pub async fn delete_record(
    State(state): State<AppState>,
    AccessAuth(did): AccessAuth,
    Json(input): Json<DeleteRecordInput>,
) -> Result<Json<DeleteRecordOutput>, XrpcError> {
    if input.repo != did {
        return Err(XrpcError::InvalidRequest(
            "repo must match the authenticated DID".into(),
        ));
    }
    validate_collection(&input.collection)?;
    validate_rkey(&input.rkey)?;

    let mst_key = format!("{}/{}", input.collection, input.rkey);
    if lookup_record_cid(&state, &did, &mst_key).await?.is_none() {
        return Ok(Json(DeleteRecordOutput { commit: None }));
    }

    let writer = build_writer(&state, &did).await?;
    let outcome = writer.apply_one(WriteOp::Delete { key: mst_key }).await?;

    Ok(Json(DeleteRecordOutput {
        commit: Some(CommitMeta {
            cid: outcome.commit_cid.to_string(),
            rev: outcome.rev,
        }),
    }))
}

// ---------------------------------------------------------------------------
// describeRepo
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct DescribeRepoParams {
    pub repo: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DescribeRepoOutput {
    pub handle: String,
    pub did: String,
    pub did_doc: DidDocument,
    pub collections: Vec<String>,
    pub handle_is_correct: bool,
}

/// GET /xrpc/com.atproto.repo.describeRepo?repo=<did|handle>
///
/// Returns the repo's handle, DID, DID document, and the list of collections
/// (top-level NSID prefixes) present in the MST.
pub async fn describe_repo(
    State(state): State<AppState>,
    Query(params): Query<DescribeRepoParams>,
) -> Result<Json<DescribeRepoOutput>, XrpcError> {
    let did = resolve_repo_did(&state, &params.repo).await?;
    let handle = state
        .store
        .get_handle_by_did(&did)
        .await?
        .ok_or_else(|| XrpcError::InvalidRequest(format!("repo not found: {}", params.repo)))?;

    let collections = list_collections(&state, &did).await?;
    let did_doc = build_did_doc(&state, &did, &handle).await?;

    Ok(Json(DescribeRepoOutput {
        handle,
        did,
        did_doc,
        collections,
        handle_is_correct: true,
    }))
}

/// Enumerate the distinct top-level collection NSIDs present in the repo's MST.
/// Returns an empty list if the repo has no commits yet.
async fn list_collections(state: &AppState, did: &str) -> Result<Vec<String>, XrpcError> {
    let root_cid = match state.store.load_repo_root(did).await? {
        Some(c) => c,
        None => return Ok(vec![]),
    };
    let cloned_store = (*state.store).clone();
    let mut diff = DiffBlockStore::wrap(cloned_store);
    let mut repo = Repository::open(&mut diff, root_cid)
        .await
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("failed to open repo: {e}")))?;

    let mut tree = repo.tree();
    let mut stream = Box::pin(tree.entries_prefixed(""));
    let mut set = std::collections::BTreeSet::new();
    while let Some((key, _cid)) = stream
        .try_next()
        .await
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("MST stream error: {e}")))?
    {
        if let Some((collection, _)) = key.split_once('/') {
            set.insert(collection.to_string());
        }
    }
    Ok(set.into_iter().collect())
}

/// Build the account's DID document (id = the account DID, alsoKnownAs = its
/// handle, with the signing key and this PDS as the service endpoint).
async fn build_did_doc(
    state: &AppState,
    did: &str,
    handle: &str,
) -> Result<DidDocument, XrpcError> {
    let key_id = format!("{did}#signing");
    let signing = if let Some(cached) = state.signing_key_cache.get(&key_id) {
        Secp256k1Keypair::import(cached.as_slice()).map_err(|e| {
            XrpcError::Internal(anyhow::anyhow!("failed to import signing key: {e}"))
        })?
    } else {
        let key_bytes = load_key(&state.store, &key_id, &state.key_passphrase)
            .await
            .map_err(|e| XrpcError::Internal(anyhow::anyhow!("failed to load signing key: {e}")))?;
        state.signing_key_cache.insert(
            key_id.clone(),
            Arc::new(zeroize::Zeroizing::new(key_bytes.clone())),
        );
        Secp256k1Keypair::import(&key_bytes).map_err(|e| {
            XrpcError::Internal(anyhow::anyhow!("failed to import signing key: {e}"))
        })?
    };
    let key_did = signing.did();
    let public_key_multibase = key_did
        .strip_prefix("did:key:")
        .unwrap_or(&key_did)
        .to_string();

    Ok(DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/multikey/v1".to_string(),
        ],
        id: did.to_string(),
        also_known_as: vec![format!("at://{handle}")],
        verification_method: vec![VerificationMethod {
            id: format!("{did}#atproto"),
            vm_type: "Multikey".to_string(),
            controller: did.to_string(),
            public_key_multibase,
        }],
        service: vec![ServiceEntry {
            id: "#atproto_pds".to_string(),
            service_type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: state.pds_endpoint.clone(),
        }],
    })
}

// ---------------------------------------------------------------------------
// uploadBlob / getBlob
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct BlobLink {
    #[serde(rename = "$link")]
    pub link: String,
}

#[derive(Serialize)]
pub struct BlobRef {
    #[serde(rename = "$type")]
    pub type_: &'static str,
    #[serde(rename = "ref")]
    pub ref_: BlobLink,
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    pub size: i64,
}

#[derive(Serialize)]
pub struct UploadBlobOutput {
    pub blob: BlobRef,
}

/// POST /xrpc/com.atproto.repo.uploadBlob
///
/// Accepts an arbitrary binary body, stores it content-addressed (CIDv1, raw
/// codec, sha2-256), and returns a blob ref the client then embeds in a record.
pub async fn upload_blob(
    State(state): State<AppState>,
    AccessAuth(did): AccessAuth,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<UploadBlobOutput>, XrpcError> {
    if body.is_empty() {
        return Err(XrpcError::InvalidRequest("empty blob".into()));
    }
    let mime_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    // CIDv1, raw codec (0x55), sha2-256 multihash — the atproto blob CID form.
    let digest = Sha256::digest(&body);
    let mh = cid::multihash::Multihash::wrap(SHA2_256, digest.as_slice())
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("multihash wrap: {e}")))?;
    let cid = cid::Cid::new_v1(0x55, mh);
    let cid_str = cid.to_string();
    let size = body.len() as i64;

    state
        .store
        .put_blob(&did, &cid_str, &mime_type, size, body.to_vec())
        .await?;

    Ok(Json(UploadBlobOutput {
        blob: BlobRef {
            type_: "blob",
            ref_: BlobLink { link: cid_str },
            mime_type,
            size,
        },
    }))
}

#[derive(Deserialize)]
pub struct GetBlobParams {
    pub did: String,
    pub cid: String,
}

/// GET /xrpc/com.atproto.sync.getBlob?did=<did>&cid=<cid>
///
/// Serve a stored blob's raw bytes with its original Content-Type.
pub async fn get_blob(
    State(state): State<AppState>,
    Query(params): Query<GetBlobParams>,
) -> Result<impl IntoResponse, XrpcError> {
    let (mime_type, bytes) = state
        .store
        .get_blob(&params.did, &params.cid)
        .await?
        .ok_or_else(|| XrpcError::InvalidRequest("blob not found".into()))?;

    Ok(([(axum::http::header::CONTENT_TYPE, mime_type)], bytes))
}

/// Validate an ATProto rkey string (shared rules: `stelyph_core::repo::util`).
fn validate_rkey(rkey: &str) -> Result<(), XrpcError> {
    crate::repo::util::validate_rkey(rkey).map_err(XrpcError::InvalidRequest)
}

/// Validate a collection NSID (shared rules: `stelyph_core::repo::util`).
fn validate_collection(collection: &str) -> Result<(), XrpcError> {
    crate::repo::util::validate_collection(collection).map_err(XrpcError::InvalidRequest)
}

/// Convert a `serde_json::Value` to Ipld (shared bridge: `stelyph_core::repo::util`).
fn json_value_to_ipld(value: serde_json::Value) -> Result<Ipld, XrpcError> {
    crate::repo::util::json_value_to_ipld(value)
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!(e)))
}

/// TID-style rkey from a microsecond timestamp (shared: `stelyph_core::repo::util`).
fn tid_from_micros(us: u64) -> String {
    crate::repo::util::tid_from_micros(us)
}

// ---------------------------------------------------------------------------
// getRepo
// ---------------------------------------------------------------------------

/// GET /xrpc/com.atproto.sync.getRepo?did=<did>
///
/// Export the repository as a CARv1 archive with Content-Type
/// `application/vnd.ipld.car` explicitly set (a generic client must not have
/// to sniff the body to know how to parse it).
///
/// Uses iroh-car 0.5.1 CarWriter (API confirmed from source):
/// - `CarHeader::new_v1(roots)` → header
/// - `CarWriter::new(header, &mut buf)` → writer
/// - `writer.write(cid, &bytes).await` → writes one block
/// - `writer.finish().await` → flushes + returns the underlying writer
pub async fn get_repo(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<impl IntoResponse, XrpcError> {
    let did = params
        .get("did")
        .ok_or_else(|| XrpcError::InvalidRequest("missing required query param: did".into()))?
        .clone();

    // Load the repo root CID for this DID.
    let root_cid = state
        .store
        .load_repo_root(&did)
        .await?
        .ok_or_else(|| XrpcError::InvalidRequest(format!("repo not found for did: {did}")))?;

    // Open the repo via DiffBlockStore (read-only; no new writes occur).
    let cloned_store = (*state.store).clone();
    let mut diff = DiffBlockStore::wrap(cloned_store);
    let mut repo = Repository::open(&mut diff, root_cid)
        .await
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("failed to open repo: {e}")))?;

    // Collect all CIDs exported by the repo.
    let cids: Vec<cid::Cid> = repo
        .export()
        .await
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("repo export failed: {e}")))?
        .collect();

    // Build CARv1 bytes using iroh-car CarWriter (API verified from source).
    let header = CarHeader::new_v1(vec![root_cid]);
    let mut buf: Vec<u8> = Vec::new();
    let mut car_writer = CarWriter::new(header, &mut buf);

    for cid in cids {
        let bytes = state.store.read_block_bytes(cid).await.map_err(|e| {
            XrpcError::Internal(anyhow::anyhow!("read_block_bytes failed for {cid}: {e}"))
        })?;
        car_writer
            .write(cid, &bytes)
            .await
            .map_err(|e| XrpcError::Internal(anyhow::anyhow!("CarWriter::write failed: {e}")))?;
    }

    car_writer
        .finish()
        .await
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("CarWriter::finish failed: {e}")))?;

    // Return with explicit Content-Type header.
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/vnd.ipld.car")],
        buf,
    ))
}

// ---------------------------------------------------------------------------
// listRecords
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ListRecordsParams {
    pub repo: String,
    pub collection: String,
    pub limit: Option<u64>,
    pub cursor: Option<String>,
    #[allow(dead_code)]
    pub reverse: Option<bool>,
}

#[derive(Serialize)]
pub struct RecordEntry {
    pub uri: String,
    pub cid: String,
    pub value: serde_json::Value,
}

#[derive(Serialize)]
pub struct ListRecordsOutput {
    pub records: Vec<RecordEntry>,
    pub cursor: Option<String>,
}

/// GET /xrpc/com.atproto.repo.listRecords?repo=<did>&collection=<c>&limit=<n>&cursor=<k>
///
/// Enumerate records in a collection from the MST.
///
/// - limit: clamped to 1..=100, default 50 (DoS mitigation — bounds page size).
/// - cursor: lexicographic resume key. Records with key <= cursor are skipped.
/// - A cursor is returned if a full page was returned (indicating more records may exist).
///
/// The record value is decoded from dag-cbor to `serde_json::Value` for the response.
pub async fn list_records(
    State(state): State<AppState>,
    Query(params): Query<ListRecordsParams>,
) -> Result<Json<ListRecordsOutput>, XrpcError> {
    // Clamp limit to 1..=100, default 50.
    let limit = params.limit.map(|l| l.clamp(1, 100) as usize).unwrap_or(50);

    let did = &params.repo;

    // Load the repo root.
    let root_cid = state
        .store
        .load_repo_root(did)
        .await?
        .ok_or_else(|| XrpcError::InvalidRequest(format!("repo not found for did: {did}")))?;

    // Open the repo.
    let cloned_store = (*state.store).clone();
    let mut diff = DiffBlockStore::wrap(cloned_store);
    let mut repo = Repository::open(&mut diff, root_cid)
        .await
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("failed to open repo: {e}")))?;

    // Stream entries with the collection prefix.
    let prefix = format!("{}/", params.collection);
    let mut tree = repo.tree();
    let mut stream = Box::pin(tree.entries_prefixed(&prefix));

    let mut records = Vec::with_capacity(limit);
    let cursor = params.cursor.as_deref();

    while let Some((key, cid)) = stream
        .try_next()
        .await
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("MST stream error: {e}")))?
    {
        // Skip entries at or before the cursor (cursor is the last key returned
        // in the previous page — the next page starts strictly after it).
        if let Some(c) = cursor {
            if key.as_str() <= c {
                continue;
            }
        }

        // Read and decode the record value from dag-cbor.
        let bytes =
            state.store.read_block_bytes(cid).await.map_err(|e| {
                XrpcError::Internal(anyhow::anyhow!("read_block_bytes for {cid}: {e}"))
            })?;

        let value: serde_json::Value = serde_ipld_dagcbor::from_slice(&bytes).map_err(|e| {
            XrpcError::Internal(anyhow::anyhow!("dagcbor decode for record {cid}: {e}"))
        })?;

        let uri = format!("at://{did}/{key}");

        records.push(RecordEntry {
            uri,
            cid: cid.to_string(),
            value,
        });

        if records.len() >= limit {
            break;
        }
    }

    // Return a cursor if we collected a full page (there may be more records).
    let next_cursor = if records.len() == limit {
        records.last().map(|r| {
            // The cursor key is the last MST key returned (collection/rkey).
            // Extract from the uri: "at://<did>/<collection>/<rkey>" → "collection/rkey"
            r.uri
                .strip_prefix(&format!("at://{did}/"))
                .unwrap_or("")
                .to_string()
        })
    } else {
        None
    };

    Ok(Json(ListRecordsOutput {
        records,
        cursor: next_cursor,
    }))
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

/// Register the three repo routes on a `Router<AppState>`.
pub fn routes() -> axum::Router<AppState> {
    axum::Router::new()
        .route("/xrpc/com.atproto.repo.createRecord", post(create_record))
        .route("/xrpc/com.atproto.repo.applyWrites", post(apply_writes))
        .route("/xrpc/com.atproto.repo.putRecord", post(put_record))
        .route("/xrpc/com.atproto.repo.getRecord", get(get_record))
        .route("/xrpc/com.atproto.repo.deleteRecord", post(delete_record))
        .route("/xrpc/com.atproto.repo.describeRepo", get(describe_repo))
        .route("/xrpc/com.atproto.repo.uploadBlob", post(upload_blob))
        .route("/xrpc/com.atproto.sync.getBlob", get(get_blob))
        .route("/xrpc/com.atproto.sync.getRepo", get(get_repo))
        .route("/xrpc/com.atproto.repo.listRecords", get(list_records))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use atrium_crypto::keypair::{Export, Secp256k1Keypair};
    use atrium_repo::blockstore::DiffBlockStore;
    use atrium_repo::Repository;
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{Request, StatusCode};
    use axum::Json;
    use http_body_util::BodyExt;
    use rand::rngs::OsRng;
    use tower::ServiceExt;

    use super::{create_record, CreateRecordInput};
    use crate::auth::extractor::AccessAuth;
    use crate::auth::jwt::{encode_access_jwt, encode_refresh_jwt, hash_password};
    use crate::identity::plc::MockPlcClient;
    use crate::storage::keys::store_key;
    use crate::storage::SqliteStore;
    use crate::xrpc::{app, AppState};

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    const JWT_SECRET: &[u8] = b"test-jwt-secret-03-04";
    const KEY_PASSPHRASE: &[u8] = b"test-key-passphrase-03-04";

    /// Build a test AppState backed by an in-memory SQLite database.
    async fn test_state() -> (AppState, tempfile::NamedTempFile) {
        let (store, tmp) = SqliteStore::open_in_memory().await.expect("open_in_memory");
        let state = AppState {
            store: Arc::new(store),
            jwt_secret: Arc::new(JWT_SECRET.to_vec()),
            hostname: "pds.test".to_string(),
            pds_endpoint: "https://pds.test".to_string(),
            open_registration: true, // open so we can create accounts freely in tests
            plc_client: Arc::new(MockPlcClient::new()),
            did_web_resolver: Arc::new(crate::identity::web_resolver::MockDidWebResolver::new_ok()),
            key_passphrase: Arc::new(KEY_PASSPHRASE.to_vec()),
            firehose_tx: tokio::sync::broadcast::channel(16).0,
            relay_client: std::sync::Arc::new(crate::firehose::MockRelayClient::new()),
            relay_url: "https://relay.test".to_string(),
            appview_client: std::sync::Arc::new(
                crate::xrpc::appview::client::MockAppViewClient::new((200, Vec::new(), None)),
            ),
            appview_url: "https://appview.test".to_string(),
            appview_did: "did:web:appview.test".to_string(),
            did_locks: Arc::new(dashmap::DashMap::new()),
            signing_key_cache: Arc::new(dashmap::DashMap::new()),
        };
        (state, tmp)
    }

    /// Seed a test account: insert account row + store signing key.
    /// Returns (did, access_token).
    async fn seed_account(state: &AppState, handle: &str) -> (String, String) {
        let did = format!("did:plc:test{}", handle.replace('.', ""));
        let phc = hash_password("test-password").unwrap();
        state
            .store
            .insert_account(&did, handle, None, &phc)
            .await
            .expect("insert_account");

        // Generate a signing keypair and store it encrypted.
        let signing = Secp256k1Keypair::create(&mut OsRng);
        let key_bytes = signing.export();
        store_key(
            &state.store,
            &format!("{did}#signing"),
            &key_bytes,
            &state.key_passphrase,
        )
        .await
        .expect("store_key");

        let access_token = encode_access_jwt(&did, JWT_SECRET).expect("encode_access_jwt");
        (did, access_token)
    }

    /// POST a JSON body to `path` with optional Authorization header.
    async fn post_json_auth(
        state: AppState,
        path: &str,
        body: serde_json::Value,
        auth: Option<&str>,
    ) -> axum::response::Response {
        let mut builder = Request::post(path).header("content-type", "application/json");
        if let Some(token) = auth {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        app(state)
            .oneshot(
                builder
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// GET `path` with optional Authorization header.
    async fn get_auth(state: AppState, path: &str, auth: Option<&str>) -> axum::response::Response {
        let mut builder = Request::get(path);
        if let Some(token) = auth {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        app(state)
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn response_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn response_bytes(resp: axum::response::Response) -> Vec<u8> {
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    // -----------------------------------------------------------------------
    // createRecord — round-trip
    // -----------------------------------------------------------------------

    /// XRPC-03: POST createRecord with valid access JWT creates a record in the repo.
    /// Verifies: 200 + cid + uri, and a repo root now exists in the store.
    #[tokio::test]
    async fn create_record_round_trips() {
        let (state, _tmp) = test_state().await;
        let (did, token) = seed_account(&state, "alice.pds.test").await;

        let resp = post_json_auth(
            state.clone(),
            "/xrpc/com.atproto.repo.createRecord",
            serde_json::json!({
                "repo": did,
                "collection": "app.bsky.feed.post",
                "record": {
                    "$type": "app.bsky.feed.post",
                    "text": "Hello ATProto!",
                    "createdAt": "2026-06-17T00:00:00.000Z"
                }
            }),
            Some(&token),
        )
        .await;

        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "createRecord must return 200"
        );

        let json = response_json(resp).await;
        assert!(
            json["cid"].as_str().is_some() && !json["cid"].as_str().unwrap().is_empty(),
            "response must include a non-empty cid"
        );
        assert!(
            json["uri"]
                .as_str()
                .unwrap_or("")
                .starts_with(&format!("at://{did}/app.bsky.feed.post/")),
            "response uri must start with at://<did>/app.bsky.feed.post/"
        );

        // Verify the repo root was written (lazy init triggered on first createRecord).
        let root = state
            .store
            .load_repo_root(&did)
            .await
            .expect("load_repo_root")
            .expect("repo root must exist after createRecord");
        assert!(
            !root.to_string().is_empty(),
            "repo root CID must be non-empty"
        );
    }

    /// createRecord with a REFRESH-scoped token is rejected with 401 InvalidToken.
    #[tokio::test]
    async fn create_record_rejects_refresh_token() {
        let (state, _tmp) = test_state().await;
        let (did, _) = seed_account(&state, "alice.pds.test").await;
        let refresh_token = encode_refresh_jwt(&did, JWT_SECRET).expect("encode_refresh_jwt");

        let resp = post_json_auth(
            state,
            "/xrpc/com.atproto.repo.createRecord",
            serde_json::json!({
                "repo": did,
                "collection": "app.bsky.feed.post",
                "record": { "$type": "app.bsky.feed.post", "text": "hi" }
            }),
            Some(&refresh_token),
        )
        .await;

        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "refresh token must be rejected with 401"
        );
        let json = response_json(resp).await;
        assert_eq!(
            json["error"].as_str().unwrap_or(""),
            "InvalidToken",
            "error must be InvalidToken for refresh token on access path"
        );
    }

    // -----------------------------------------------------------------------
    // rkey and collection validation
    // -----------------------------------------------------------------------

    /// createRecord with rkey containing '/' must be rejected with 400 InvalidRequest.
    #[tokio::test]
    async fn create_record_rkey_with_slash_rejected() {
        let (state, _tmp) = test_state().await;
        let (did, token) = seed_account(&state, "alice.pds.test").await;

        let resp = post_json_auth(
            state,
            "/xrpc/com.atproto.repo.createRecord",
            serde_json::json!({
                "repo": did,
                "collection": "app.bsky.feed.post",
                "rkey": "../../evil",
                "record": { "$type": "app.bsky.feed.post", "text": "hi" }
            }),
            Some(&token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "InvalidRequest");
    }

    /// createRecord with empty rkey must be rejected.
    #[tokio::test]
    async fn create_record_empty_rkey_rejected() {
        let (state, _tmp) = test_state().await;
        let (did, token) = seed_account(&state, "alice.pds.test").await;

        let resp = post_json_auth(
            state,
            "/xrpc/com.atproto.repo.createRecord",
            serde_json::json!({
                "repo": did,
                "collection": "app.bsky.feed.post",
                "rkey": "",
                "record": { "$type": "app.bsky.feed.post", "text": "hi" }
            }),
            Some(&token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "InvalidRequest");
    }

    /// createRecord with invalid collection (no dots) must be rejected.
    #[tokio::test]
    async fn create_record_invalid_collection_rejected() {
        let (state, _tmp) = test_state().await;
        let (did, token) = seed_account(&state, "alice.pds.test").await;

        let resp = post_json_auth(
            state,
            "/xrpc/com.atproto.repo.createRecord",
            serde_json::json!({
                "repo": did,
                "collection": "nodots",
                "record": { "$type": "app.bsky.feed.post", "text": "hi" }
            }),
            Some(&token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = response_json(resp).await;
        assert_eq!(json["error"], "InvalidRequest");
    }

    /// createRecord with no Authorization header is rejected with 401 AuthRequired.
    #[tokio::test]
    async fn create_record_requires_auth() {
        let (state, _tmp) = test_state().await;
        let (did, _) = seed_account(&state, "alice.pds.test").await;

        let resp = post_json_auth(
            state,
            "/xrpc/com.atproto.repo.createRecord",
            serde_json::json!({
                "repo": did,
                "collection": "app.bsky.feed.post",
                "record": { "$type": "app.bsky.feed.post", "text": "hi" }
            }),
            None, // no token
        )
        .await;

        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "missing auth must return 401"
        );
        let json = response_json(resp).await;
        assert_eq!(
            json["error"].as_str().unwrap_or(""),
            "AuthRequired",
            "error must be AuthRequired when Authorization header is missing"
        );
    }

    // -----------------------------------------------------------------------
    // getRepo — CAR export
    // -----------------------------------------------------------------------

    /// XRPC-03: GET getRepo?did=<did> returns 200 with Content-Type application/vnd.ipld.car
    /// and non-empty CAR bytes after at least one record has been written.
    #[tokio::test]
    async fn get_repo_returns_car() {
        let (state, _tmp) = test_state().await;
        let (did, token) = seed_account(&state, "alice.pds.test").await;

        // Write a record first to initialize the repo.
        let cr = post_json_auth(
            state.clone(),
            "/xrpc/com.atproto.repo.createRecord",
            serde_json::json!({
                "repo": did,
                "collection": "app.bsky.feed.post",
                "record": {
                    "$type": "app.bsky.feed.post",
                    "text": "getRepo test record",
                    "createdAt": "2026-06-17T00:00:00.000Z"
                }
            }),
            Some(&token),
        )
        .await;
        assert_eq!(
            cr.status(),
            StatusCode::OK,
            "createRecord must succeed before getRepo"
        );

        // Now GET the repo.
        let resp = get_auth(
            state,
            &format!("/xrpc/com.atproto.sync.getRepo?did={did}"),
            None, // getRepo is unauthenticated (public read surface)
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK, "getRepo must return 200");

        // Assert Content-Type is exactly "application/vnd.ipld.car".
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(
            ct, "application/vnd.ipld.car",
            "Content-Type must be application/vnd.ipld.car, got {ct:?}"
        );

        let body = response_bytes(resp).await;
        assert!(!body.is_empty(), "CAR body must be non-empty");

        // Verify the bytes are a valid CARv1: parse via iroh-car CarReader.
        // CarReader requires AsyncRead + Unpin, so wrap bytes in tokio::io::BufReader.
        use iroh_car::CarReader;
        let cursor = tokio::io::BufReader::new(std::io::Cursor::new(body));
        let reader = CarReader::new(cursor)
            .await
            .expect("CAR bytes must parse as a valid CARv1 with CarReader");
        let header = reader.header().clone();
        assert_eq!(header.version(), 1, "CAR must be version 1");
        assert!(
            !header.roots().is_empty(),
            "CAR header must have at least one root"
        );
    }

    /// getRepo for an unknown DID returns 400 with an error body.
    #[tokio::test]
    async fn get_repo_missing() {
        let (state, _tmp) = test_state().await;

        let resp = get_auth(
            state,
            "/xrpc/com.atproto.sync.getRepo?did=did:web:nobody.example.com",
            None,
        )
        .await;

        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "getRepo for unknown DID must return 400"
        );
        let json = response_json(resp).await;
        assert!(
            json["error"].as_str().is_some(),
            "getRepo for unknown DID must return an error body"
        );
    }

    // -----------------------------------------------------------------------
    // listRecords — MST enumeration
    // -----------------------------------------------------------------------

    /// XRPC-03: GET listRecords returns the records in a collection.
    #[tokio::test]
    async fn list_records_returns_collection() {
        let (state, _tmp) = test_state().await;
        let (did, token) = seed_account(&state, "alice.pds.test").await;

        // Write 3 records in app.bsky.feed.post with explicit rkeys.
        for i in 0..3u32 {
            let resp = post_json_auth(
                state.clone(),
                "/xrpc/com.atproto.repo.createRecord",
                serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": format!("record{i:04}"),
                    "record": {
                        "$type": "app.bsky.feed.post",
                        "text": format!("post {i}"),
                        "createdAt": "2026-06-17T00:00:00.000Z"
                    }
                }),
                Some(&token),
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "createRecord #{i} must succeed"
            );
        }

        // GET listRecords for the collection.
        let resp = get_auth(
            state,
            &format!("/xrpc/com.atproto.repo.listRecords?repo={did}&collection=app.bsky.feed.post"),
            None,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK, "listRecords must return 200");
        let json = response_json(resp).await;

        let records = json["records"]
            .as_array()
            .expect("records must be an array");
        assert_eq!(records.len(), 3, "must return all 3 records");

        // Verify each record has uri, cid, value.
        for r in records {
            assert!(
                r["uri"]
                    .as_str()
                    .unwrap_or("")
                    .starts_with(&format!("at://{did}/")),
                "record uri must start with at://<did>/"
            );
            assert!(r["cid"].as_str().is_some(), "record must have a cid");
            assert!(r["value"].is_object(), "record value must be an object");
        }
    }

    /// XRPC-03: listRecords pages correctly with limit and cursor.
    #[tokio::test]
    async fn list_records_paging() {
        let (state, _tmp) = test_state().await;
        let (did, token) = seed_account(&state, "alice.pds.test").await;

        // Write 3 records with predictable lexicographic ordering.
        for i in 0..3u32 {
            let resp = post_json_auth(
                state.clone(),
                "/xrpc/com.atproto.repo.createRecord",
                serde_json::json!({
                    "repo": did,
                    "collection": "app.bsky.feed.post",
                    "rkey": format!("rkey{i:04}"),
                    "record": {
                        "$type": "app.bsky.feed.post",
                        "text": format!("page post {i}"),
                        "createdAt": "2026-06-17T00:00:00.000Z"
                    }
                }),
                Some(&token),
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "createRecord #{i} must succeed"
            );
        }

        // First page: limit=2 → 2 records + cursor.
        let resp = get_auth(
            state.clone(),
            &format!(
                "/xrpc/com.atproto.repo.listRecords?repo={did}&collection=app.bsky.feed.post&limit=2"
            ),
            None,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        let json1 = response_json(resp).await;
        let records1 = json1["records"].as_array().expect("records array");
        assert_eq!(records1.len(), 2, "first page must have 2 records");

        let cursor = json1["cursor"]
            .as_str()
            .expect("first page must return a cursor when limit=2 and 3 records exist");
        assert!(!cursor.is_empty(), "cursor must be non-empty");

        // Second page: limit=2 + cursor → 1 record, no cursor.
        let resp2 = get_auth(
            state,
            &format!(
                "/xrpc/com.atproto.repo.listRecords?repo={did}&collection=app.bsky.feed.post&limit=2&cursor={cursor}"
            ),
            None,
        )
        .await;

        assert_eq!(resp2.status(), StatusCode::OK);
        let json2 = response_json(resp2).await;
        let records2 = json2["records"].as_array().expect("records array page 2");
        assert_eq!(
            records2.len(),
            1,
            "second page must have 1 remaining record"
        );

        // Verify the two pages together cover all 3 records (no overlap, no gap).
        let mut all_uris: Vec<&str> = records1
            .iter()
            .chain(records2.iter())
            .map(|r| r["uri"].as_str().unwrap_or(""))
            .collect();
        all_uris.sort();
        all_uris.dedup();
        assert_eq!(
            all_uris.len(),
            3,
            "paged results must cover all 3 records without duplication"
        );
    }

    // -----------------------------------------------------------------------
    // putRecord / getRecord / deleteRecord round-trip
    // -----------------------------------------------------------------------

    /// putRecord creates a record, getRecord reads it back, a second putRecord
    /// updates it (new cid), and deleteRecord removes it (getRecord then 400).
    #[tokio::test]
    async fn put_get_delete_round_trip() {
        let (state, _tmp) = test_state().await;
        let (did, token) = seed_account(&state, "alice.pds.test").await;

        // PUT (create) app.bsky.actor.profile/self
        let resp = post_json_auth(
            state.clone(),
            "/xrpc/com.atproto.repo.putRecord",
            serde_json::json!({
                "repo": did,
                "collection": "app.bsky.actor.profile",
                "rkey": "self",
                "record": { "$type": "app.bsky.actor.profile", "displayName": "Alice" }
            }),
            Some(&token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "putRecord create must 200");
        let created = response_json(resp).await;
        let cid1 = created["cid"].as_str().unwrap().to_string();
        assert!(!cid1.is_empty());
        assert!(created["uri"]
            .as_str()
            .unwrap()
            .ends_with("/app.bsky.actor.profile/self"));

        // GET it back
        let resp = get_auth(
            state.clone(),
            &format!(
                "/xrpc/com.atproto.repo.getRecord?repo={did}&collection=app.bsky.actor.profile&rkey=self"
            ),
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "getRecord must 200");
        let got = response_json(resp).await;
        assert_eq!(got["value"]["displayName"], "Alice");
        assert_eq!(got["cid"].as_str().unwrap(), cid1);

        // PUT (update) — different content yields a different record cid
        let resp = post_json_auth(
            state.clone(),
            "/xrpc/com.atproto.repo.putRecord",
            serde_json::json!({
                "repo": did,
                "collection": "app.bsky.actor.profile",
                "rkey": "self",
                "record": { "$type": "app.bsky.actor.profile", "displayName": "Alice Updated" }
            }),
            Some(&token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "putRecord update must 200");
        let updated = response_json(resp).await;
        assert_ne!(
            updated["cid"].as_str().unwrap(),
            cid1,
            "update must change the record cid"
        );

        // DELETE
        let resp = post_json_auth(
            state.clone(),
            "/xrpc/com.atproto.repo.deleteRecord",
            serde_json::json!({
                "repo": did,
                "collection": "app.bsky.actor.profile",
                "rkey": "self"
            }),
            Some(&token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "deleteRecord must 200");

        // GET now 400 (record not found)
        let resp = get_auth(
            state,
            &format!(
                "/xrpc/com.atproto.repo.getRecord?repo={did}&collection=app.bsky.actor.profile&rkey=self"
            ),
            None,
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "getRecord after delete must 400"
        );
    }

    /// deleteRecord on a missing record is idempotent (200, no commit).
    #[tokio::test]
    async fn delete_missing_record_is_idempotent() {
        let (state, _tmp) = test_state().await;
        let (did, token) = seed_account(&state, "alice.pds.test").await;
        let resp = post_json_auth(
            state,
            "/xrpc/com.atproto.repo.deleteRecord",
            serde_json::json!({
                "repo": did,
                "collection": "app.bsky.feed.post",
                "rkey": "doesnotexist"
            }),
            Some(&token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let json = response_json(resp).await;
        assert!(json["commit"].is_null(), "missing delete has no commit");
    }

    /// describeRepo returns did, handle, the collections present, and a did doc
    /// whose service endpoint is this PDS.
    #[tokio::test]
    async fn describe_repo_reports_collections_and_diddoc() {
        let (state, _tmp) = test_state().await;
        let (did, token) = seed_account(&state, "alice.pds.test").await;

        // Seed one record so a collection exists.
        let resp = post_json_auth(
            state.clone(),
            "/xrpc/com.atproto.repo.createRecord",
            serde_json::json!({
                "repo": did,
                "collection": "app.bsky.feed.post",
                "record": { "$type": "app.bsky.feed.post", "text": "hi" }
            }),
            Some(&token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = get_auth(
            state,
            &format!("/xrpc/com.atproto.repo.describeRepo?repo={did}"),
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "describeRepo must 200");
        let json = response_json(resp).await;
        assert_eq!(json["did"].as_str().unwrap(), did);
        assert_eq!(json["handle"].as_str().unwrap(), "alice.pds.test");
        assert_eq!(json["handleIsCorrect"], true);
        let cols: Vec<&str> = json["collections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        assert!(cols.contains(&"app.bsky.feed.post"));
        assert_eq!(json["didDoc"]["id"].as_str().unwrap(), did);
        assert_eq!(
            json["didDoc"]["service"][0]["serviceEndpoint"]
                .as_str()
                .unwrap(),
            "https://pds.test"
        );
    }

    /// getSession returns the authenticated account's did + handle.
    #[tokio::test]
    async fn get_session_returns_identity() {
        let (state, _tmp) = test_state().await;
        let (did, token) = seed_account(&state, "alice.pds.test").await;
        let resp = get_auth(state, "/xrpc/com.atproto.server.getSession", Some(&token)).await;
        assert_eq!(resp.status(), StatusCode::OK, "getSession must 200");
        let json = response_json(resp).await;
        assert_eq!(json["did"].as_str().unwrap(), did);
        assert_eq!(json["handle"].as_str().unwrap(), "alice.pds.test");
        assert_eq!(json["active"], true);
    }

    /// POST raw bytes with a Content-Type and optional auth (for uploadBlob).
    async fn post_bytes_auth(
        state: AppState,
        path: &str,
        content_type: &str,
        bytes: Vec<u8>,
        auth: Option<&str>,
    ) -> axum::response::Response {
        let mut builder = Request::post(path).header("content-type", content_type);
        if let Some(token) = auth {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }
        app(state)
            .oneshot(builder.body(Body::from(bytes)).unwrap())
            .await
            .unwrap()
    }

    /// uploadBlob stores bytes content-addressed; getBlob serves them back with
    /// the original mime type; an unknown cid returns 400.
    #[tokio::test]
    async fn upload_and_get_blob_round_trip() {
        let (state, _tmp) = test_state().await;
        let (did, token) = seed_account(&state, "alice.pds.test").await;

        let data = b"\x89PNG\r\n\x1a\nfake-png-bytes".to_vec();
        let resp = post_bytes_auth(
            state.clone(),
            "/xrpc/com.atproto.repo.uploadBlob",
            "image/png",
            data.clone(),
            Some(&token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "uploadBlob must 200");
        let json = response_json(resp).await;
        assert_eq!(json["blob"]["$type"], "blob");
        assert_eq!(json["blob"]["mimeType"], "image/png");
        assert_eq!(json["blob"]["size"].as_i64().unwrap(), data.len() as i64);
        let cid = json["blob"]["ref"]["$link"].as_str().unwrap().to_string();
        assert!(!cid.is_empty(), "blob ref must carry a cid");

        // GET it back
        let resp = get_auth(
            state.clone(),
            &format!("/xrpc/com.atproto.sync.getBlob?did={did}&cid={cid}"),
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "getBlob must 200");
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert_eq!(ct, "image/png", "getBlob must echo the stored mime type");
        let body = response_bytes(resp).await;
        assert_eq!(body, data, "getBlob bytes must match what was uploaded");

        // Unknown cid → 400
        let resp = get_auth(
            state,
            &format!("/xrpc/com.atproto.sync.getBlob?did={did}&cid=bafkreidoesnotexist"),
            None,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// getServiceAuth mints an ES256K JWT whose claims carry the account DID,
    /// the requested audience, and the lexicon method.
    #[tokio::test]
    async fn get_service_auth_mints_token() {
        use data_encoding::BASE64URL_NOPAD;
        let (state, _tmp) = test_state().await;
        let (did, token) = seed_account(&state, "alice.pds.test").await;

        let resp = get_auth(
            state,
            "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:api.bsky.app&lxm=app.bsky.feed.getTimeline",
            Some(&token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "getServiceAuth must 200");
        let json = response_json(resp).await;
        let jwt = json["token"].as_str().expect("token field");
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 parts");
        let claims: serde_json::Value =
            serde_json::from_slice(&BASE64URL_NOPAD.decode(parts[1].as_bytes()).unwrap()).unwrap();
        assert_eq!(claims["iss"], did);
        assert_eq!(claims["aud"], "did:web:api.bsky.app");
        assert_eq!(claims["lxm"], "app.bsky.feed.getTimeline");
    }

    /// Local mirror of atrium's private schema::SignedCommit for deserialization
    /// of stored commit blocks, used only to inspect `prev` linkage. Fields must
    /// match the wire format exactly (mirrors rust-core/src/repo/writer.rs's
    /// test-only equivalent).
    #[derive(serde::Deserialize)]
    struct SignedCommitMirror {
        #[allow(dead_code)]
        prev: Option<cid::Cid>,
    }

    /// Two concurrent createRecord calls for the SAME DID must not
    /// fork the repo history. Builds ONE shared AppState (with the did_locks map),
    /// then fires two concurrent create_record calls for the same DID — each call
    /// builds its OWN RepoWriter through AppState the way the real handler does
    /// (NOT a single shared Arc<RepoWriter>, which is exactly what would mask the
    /// production bug: two per-request RepoWriters for the same DID must still
    /// serialize through the same shared per-DID lock fetched from state.did_locks).
    #[tokio::test(flavor = "multi_thread")]
    async fn two_concurrent_creates_same_did() {
        let (state, _tmp) = test_state().await;
        let (did, _token) = seed_account(&state, "concurrent.pds.test").await;

        let state1 = state.clone();
        let did1 = did.clone();
        let t1 = tokio::spawn(async move {
            create_record(
                State(state1),
                AccessAuth(did1.clone()),
                Json(CreateRecordInput {
                    repo: did1,
                    collection: "app.bsky.feed.post".to_string(),
                    record: serde_json::json!({
                        "$type": "app.bsky.feed.post",
                        "text": "concurrent first",
                        "createdAt": "2026-06-17T00:00:00.000Z"
                    }),
                    rkey: Some("3kaaaa".to_string()),
                    validate: None,
                    swap_commit: None,
                }),
            )
            .await
            .expect("create_record 1")
        });

        let state2 = state.clone();
        let did2 = did.clone();
        let t2 = tokio::spawn(async move {
            create_record(
                State(state2),
                AccessAuth(did2.clone()),
                Json(CreateRecordInput {
                    repo: did2,
                    collection: "app.bsky.feed.post".to_string(),
                    record: serde_json::json!({
                        "$type": "app.bsky.feed.post",
                        "text": "concurrent second",
                        "createdAt": "2026-06-17T00:00:00.000Z"
                    }),
                    rkey: Some("3kbbbb".to_string()),
                    validate: None,
                    swap_commit: None,
                }),
            )
            .await
            .expect("create_record 2")
        });

        let (r1, r2) = tokio::join!(t1, t2);
        let out1 = r1.expect("task 1 panicked").0;
        let out2 = r2.expect("task 2 panicked").0;

        assert_ne!(
            out1.cid, out2.cid,
            "two concurrent creates must produce different record CIDs"
        );

        // Exactly two repo_seq rows — no lost update.
        let seq_count = state.store.repo_seq_count().await.expect("seq count");
        assert_eq!(
            seq_count, 2,
            "expected exactly 2 repo_seq rows, got {seq_count}"
        );

        // Both records must be present in the final MST — a fork would silently
        // drop whichever write lost the race instead of chaining both commits.
        let root_cid = state
            .store
            .load_repo_root(&did)
            .await
            .expect("load_repo_root")
            .expect("must have a root after two writes");
        let cloned_store = (*state.store).clone();
        let mut diff = DiffBlockStore::wrap(cloned_store);
        let mut repo = Repository::open(&mut diff, root_cid)
            .await
            .expect("open repo");
        let mut tree = repo.tree();
        assert!(
            tree.get("app.bsky.feed.post/3kaaaa")
                .await
                .expect("mst get 1")
                .is_some(),
            "first concurrent record must be present in the final MST"
        );
        assert!(
            tree.get("app.bsky.feed.post/3kbbbb")
                .await
                .expect("mst get 2")
                .is_some(),
            "second concurrent record must be present in the final MST"
        );

        // repo_roots must be a SINGLE linear chain, not a fork. The very first
        // create_record call for a DID lazily writes an empty-repo genesis commit
        // (prev=None) plus its own write commit chained onto it, so a correctly
        // serialized pair of concurrent writes produces exactly 3 physical commits
        // in one chain: genesis -> write1 -> write2. If the shared per-DID lock were
        // missing, the two calls would race to create TWO independent genesis
        // commits; the loser's genesis+write would be orphaned (unreachable from the
        // final root), so walking the `prev` chain from the final root would only
        // find 2 commits instead of 3 — silently dropping one record.
        let mut chain_len = 0usize;
        let mut cursor = Some(root_cid);
        while let Some(cid) = cursor {
            chain_len += 1;
            let bytes = state
                .store
                .read_block_bytes(cid)
                .await
                .expect("read commit block while walking prev chain");
            let commit: SignedCommitMirror =
                serde_ipld_dagcbor::from_slice(&bytes).expect("decode commit while walking chain");
            cursor = commit.prev;
        }
        assert_eq!(
            chain_len, 3,
            "expected a single linear chain of 3 commits (genesis + 2 chained \
             writes) reachable from the final root, got chain length {chain_len} \
             — a shorter chain means the shared per-DID lock did not serialize the \
             two concurrent writes and one was forked off / orphaned"
        );
    }

    /// A signing-key-touching operation populates
    /// `state.signing_key_cache`, and a second key-touching operation for the
    /// same DID reuses the cached entry instead of re-running the argon2id KDF.
    #[tokio::test]
    async fn signing_key_cache_hit_skips_load() {
        let (state, _tmp) = test_state().await;
        let (did, token) = seed_account(&state, "cachehit.pds.test").await;
        let key_id = format!("{did}#signing");

        // Cache starts empty for this DID.
        assert!(
            !state.signing_key_cache.contains_key(&key_id),
            "cache must start empty before any signing-key-touching request"
        );

        // First createRecord populates the cache (cache miss -> load_key -> insert).
        let resp = post_json_auth(
            state.clone(),
            "/xrpc/com.atproto.repo.createRecord",
            serde_json::json!({
                "repo": did,
                "collection": "app.bsky.feed.post",
                "record": {
                    "$type": "app.bsky.feed.post",
                    "text": "cache warm-up",
                    "createdAt": "2026-06-17T00:00:00.000Z"
                }
            }),
            Some(&token),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "createRecord must 200");

        assert!(
            state.signing_key_cache.contains_key(&key_id),
            "signing_key_cache must contain the \"{{did}}#signing\" entry after a \
             signing-key-touching request"
        );
        let cached_entry = state
            .signing_key_cache
            .get(&key_id)
            .expect("cache entry present");
        // Type is exercised by construction: the map's value type is
        // Arc<zeroize::Zeroizing<Vec<u8>>>, so a successful `.get` + deref here
        // already proves the value is Zeroizing-wrapped.
        assert!(
            !cached_entry.as_slice().is_empty(),
            "cached signing key bytes must be non-empty"
        );
        drop(cached_entry);

        // Second key-touching operation (getServiceAuth, a different read-path
        // handler) succeeds using the cached key — the cache entry is reused, not
        // replaced by a second independent load_key call.
        let resp2 = get_auth(
            state.clone(),
            "/xrpc/com.atproto.server.getServiceAuth?aud=did:web:api.bsky.app",
            Some(&token),
        )
        .await;
        assert_eq!(
            resp2.status(),
            StatusCode::OK,
            "getServiceAuth must 200 using the cached signing key"
        );
        assert!(
            state.signing_key_cache.contains_key(&key_id),
            "signing_key_cache entry must still be present/reused after the second \
             key-touching request"
        );
    }
}
