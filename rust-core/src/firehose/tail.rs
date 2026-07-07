//! firehose::tail — decode + CAR-extract + signature-verify for firehose #commit frames.
//!
//! This module is the shared core consumed by both the demo binary (Plan 02) and the
//! FED-04 E2E integration test. Every primitive it uses already exists and is tested
//! elsewhere in the crate: two-object CBOR streaming (frame.rs), CAR walking
//! (xrpc/repo.rs), and commit signature verification (repo/writer.rs).

use crate::firehose::CommitBody; // reuse — do NOT redefine
use atrium_api::types::string::{Did, Tid};
use atrium_crypto::verify::verify_signature;
use cid::Cid;
use ipld_core::ipld::Ipld;
use iroh_car::CarReader;
use serde::{Deserialize, Serialize};
use std::io::{BufReader, Cursor};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the tail decoder / verifier.
#[derive(Debug)]
pub enum TailError {
    /// op != 1 or t != "#commit" — caller SKIPS, this is not a hard failure.
    NotCommit,
    /// CBOR / header decode error.
    Decode(String),
    /// CAR parse or commit-block-not-found.
    Car(String),
    /// SignedCommit CBOR decode error.
    CommitDecode(String),
    /// Signature verification failure (with reason).
    Sig(String),
}

impl std::fmt::Display for TailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TailError::NotCommit => write!(f, "frame is not a #commit"),
            TailError::Decode(msg) => write!(f, "decode error: {msg}"),
            TailError::Car(msg) => write!(f, "CAR error: {msg}"),
            TailError::CommitDecode(msg) => write!(f, "commit decode error: {msg}"),
            TailError::Sig(msg) => write!(f, "signature error: {msg}"),
        }
    }
}

impl std::error::Error for TailError {}

// ---------------------------------------------------------------------------
// decode_commit_frame
// ---------------------------------------------------------------------------

/// Decode a binary firehose frame into a typed [`CommitBody`].
///
/// The frame is `dag_cbor(header) ++ dag_cbor(body)` with no length prefix.
/// `from_slice` on the full bytes FAILS (TrailingData) — use `from_reader_once`
/// streaming decode instead (mirrors frame.rs:124-153).
///
/// Returns `Err(TailError::NotCommit)` for non-#commit frames (e.g. error frames
/// with op=-1). Returns `Err(TailError::Decode(_))` for malformed CBOR — no panic.
pub fn decode_commit_frame(frame_bytes: &[u8]) -> Result<CommitBody, TailError> {
    let cursor = Cursor::new(frame_bytes);
    let mut reader = BufReader::new(cursor);

    // Decode header as raw Ipld first (op/t inspection).
    let header: Ipld = serde_ipld_dagcbor::de::from_reader_once(&mut reader)
        .map_err(|e| TailError::Decode(format!("header: {e}")))?;

    let (op, t) = match &header {
        Ipld::Map(m) => {
            let op = match m.get("op") {
                Some(Ipld::Integer(n)) => *n,
                _ => return Err(TailError::NotCommit),
            };
            let t = match m.get("t") {
                Some(Ipld::String(s)) => Some(s.clone()),
                _ => None,
            };
            (op, t)
        }
        _ => return Err(TailError::Decode("header not a map".into())),
    };

    // op=1 + t="#commit" is the only accepted combination.
    if op != 1i128 || t.as_deref() != Some("#commit") {
        return Err(TailError::NotCommit);
    }

    // Decode body as the typed CommitBody (body.commit is a real Cid — Pitfall 3).
    let body: CommitBody = serde_ipld_dagcbor::de::from_reader_once(&mut reader)
        .map_err(|e| TailError::Decode(format!("body: {e}")))?;

    Ok(body)
}

// ---------------------------------------------------------------------------
// extract_commit_block (async — CarReader requires AsyncRead)
// ---------------------------------------------------------------------------

/// Walk the CARv1 bytes and return the block whose CID equals `expected`.
///
/// `&[u8]` is NOT AsyncRead, so we wrap in `tokio::io::BufReader<std::io::Cursor<Vec<u8>>>`.
/// Uses `next_block` for a linear find-one walk (mirrors xrpc/repo.rs:828-834).
///
/// IMPORTANT — this CID equality is a *label* check, not a content-integrity check.
/// `iroh-car`'s reader returns the CID as a literal from the CAR framing; it does NOT
/// re-hash the block bytes to confirm they actually hash to that CID. So matching
/// `cid == expected` only proves "a block labeled with the commit CID exists" — not that
/// the block content is what the CID commits to. The real integrity guarantee is provided
/// downstream by `verify_commit_sig`, which reconstructs the unsigned commit bytes and
/// checks the signature against the signer's key: any forged/non-canonical body fails
/// signature verification (absent the signing key). Content integrity is therefore
/// intentionally delegated to signature verification rather than enforced here.
async fn extract_commit_block(car_bytes: &[u8], expected: Cid) -> Result<Vec<u8>, TailError> {
    let cursor = tokio::io::BufReader::new(std::io::Cursor::new(car_bytes.to_vec()));
    let mut reader = CarReader::new(cursor)
        .await
        .map_err(|e| TailError::Car(format!("CarReader::new: {e}")))?;

    if reader.header().roots().first() != Some(&expected) {
        return Err(TailError::Car(format!("CAR root != commit CID {expected}")));
    }

    while let Some((cid, bytes)) = reader
        .next_block()
        .await
        .map_err(|e| TailError::Car(format!("next_block: {e}")))?
    {
        if cid == expected {
            return Ok(bytes);
        }
    }

    Err(TailError::Car("commit block not found in CAR".into()))
}

// ---------------------------------------------------------------------------
// SignedCommit + reconstruct_unsigned_commit_bytes (local — writer.rs originals
// are #[cfg(test)] and cannot be reused outside tests)
// ---------------------------------------------------------------------------

/// Local mirror of the wire-format signed commit block.
///
/// Field order is LOAD-BEARING for CBOR round-trips (Pitfall 2):
/// `did, version, data, rev, prev` then `sig` last.
#[derive(Deserialize)]
struct SignedCommit {
    pub did: Did,
    pub version: i64,
    pub data: Cid,
    pub rev: Tid,
    pub prev: Option<Cid>,
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>,
}

/// Re-serialize the non-sig fields as DAG-CBOR to reconstruct the bytes that
/// were signed. Field order must match exactly what `atrium_repo` produced
/// (mirrors writer.rs:295-312): `did, version, data, rev, prev`.
fn reconstruct_unsigned_commit_bytes(signed: &SignedCommit) -> Vec<u8> {
    #[derive(Serialize)]
    struct Commit {
        did: Did,
        version: i64,
        data: Cid,
        rev: Tid,
        prev: Option<Cid>,
    }
    let c = Commit {
        did: signed.did.clone(),
        version: signed.version,
        data: signed.data,
        rev: signed.rev.clone(),
        prev: signed.prev,
    };
    serde_ipld_dagcbor::to_vec(&c).expect("serialize Commit")
}

// ---------------------------------------------------------------------------
// verify_commit_sig (the load-bearing FED-04 assertion)
// ---------------------------------------------------------------------------

/// Verify the commit signature in a [`CommitBody`] against `signer_did_key`.
///
/// `signer_did_key` must be the signing did:key (e.g. `"did:key:zQ3sh..."`),
/// NOT the account DID in `body.repo` (Pitfall 6 / T-06-04).
///
/// Async because `extract_commit_block` (CAR walk) is async; the
/// `verify_signature` crypto call itself is synchronous.
pub async fn verify_commit_sig(body: &CommitBody, signer_did_key: &str) -> Result<(), TailError> {
    let block = extract_commit_block(&body.blocks, body.commit).await?;
    let signed: SignedCommit = serde_ipld_dagcbor::from_slice(&block)
        .map_err(|e| TailError::CommitDecode(format!("{e}")))?;
    let unsigned = reconstruct_unsigned_commit_bytes(&signed);
    verify_signature(signer_did_key, &unsigned, &signed.sig)
        .map_err(|e| TailError::Sig(format!("{e}")))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firehose::encode_error_frame;
    use crate::repo::RepoWriter;
    use crate::storage::keys::store_key;
    use crate::storage::SqliteStore;
    use atrium_api::types::string::Did as AtDid;
    use atrium_crypto::keypair::{Did as KeypairDid, Secp256k1Keypair};
    use std::str::FromStr;
    use std::sync::Arc;

    const SIGNING_SCALAR: [u8; 32] = [0x11u8; 32];

    fn post(text: &str) -> Ipld {
        let mut m = std::collections::BTreeMap::new();
        m.insert(
            "$type".to_string(),
            Ipld::String("app.bsky.feed.post".into()),
        );
        m.insert("text".to_string(), Ipld::String(text.into()));
        m.insert(
            "createdAt".to_string(),
            Ipld::String("2026-06-16T00:00:00.000Z".into()),
        );
        Ipld::Map(m)
    }

    /// Produce a real signed commit frame and the signer's did:key.
    /// Returns (frame_bytes, did_key_string, fresh_keypair_for_wrong_key_test).
    async fn make_signed_commit_frame() -> (Vec<u8>, String, Secp256k1Keypair) {
        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open");
        let passphrase = b"test-tail-passphrase";
        store_key(&store, "signing", &SIGNING_SCALAR, passphrase)
            .await
            .expect("store_key");
        let key = Secp256k1Keypair::import(&SIGNING_SCALAR).expect("import");
        let did_key = key.did(); // "did:key:zQ3sh..." — the verification key
        let did = AtDid::from_str("did:web:example.com").unwrap();
        let (tx, mut rx) = tokio::sync::broadcast::channel(16);
        let writer = RepoWriter::new(Arc::new(store), key, did, tx);
        writer
            .create_record("app.bsky.feed.post/3kaaaa", post("hi"))
            .await
            .expect("create_record");
        let ev = rx.recv().await.expect("broadcast event"); // FirehoseEvent { seq, frame }
                                                            // keypair is not Clone — re-import for later use (wrong-key test uses a different key)
        let other_key = Secp256k1Keypair::create(&mut rand::rngs::OsRng);
        (ev.frame, did_key, other_key)
    }

    // -----------------------------------------------------------------------
    // decode_commit_sig_roundtrip
    // -----------------------------------------------------------------------

    /// A #commit frame round-trips: encode_message_frame -> decode_commit_frame -> CommitBody.
    /// We use the real broadcast frame from create_record so the body matches a verifiable commit.
    #[tokio::test]
    async fn decode_commit_sig_roundtrip() {
        let (frame, _did_key, _other) = make_signed_commit_frame().await;
        let body = decode_commit_frame(&frame).expect("must decode Ok");
        assert_eq!(body.repo, "did:web:example.com");
        // commit CID must be non-zero (a real CIDv1 dag-cbor hash)
        assert!(!body.commit.to_bytes().is_empty());
    }

    // -----------------------------------------------------------------------
    // decode_error_frame_returns_not_commit
    // -----------------------------------------------------------------------

    /// An error frame (op=-1, no t field) yields TailError::NotCommit — not a hard error.
    #[tokio::test]
    async fn decode_error_frame_returns_not_commit() {
        let frame = encode_error_frame("FutureCursor", None);
        let result = decode_commit_frame(&frame);
        assert!(
            matches!(result, Err(TailError::NotCommit)),
            "expected TailError::NotCommit, got: {:?}",
            result.err()
        );
    }

    // -----------------------------------------------------------------------
    // verify_commit_sig_ok
    // -----------------------------------------------------------------------

    /// A real signed commit verifies Ok against the signer's did:key.
    #[tokio::test]
    async fn verify_commit_sig_ok() {
        let (frame, did_key, _other) = make_signed_commit_frame().await;
        let body = decode_commit_frame(&frame).expect("decode Ok");
        verify_commit_sig(&body, &did_key)
            .await
            .expect("verify must succeed for a freshly signed commit");
    }

    // -----------------------------------------------------------------------
    // verify_commit_sig_tampered  (✗ load-bearing tamper proof for T-06-03)
    // -----------------------------------------------------------------------

    /// Flipping a byte of the sig field in the commit block causes verification to fail.
    /// This is the load-bearing tamper proof for FED-04.
    #[tokio::test]
    async fn verify_commit_sig_tampered() {
        let (frame, did_key, _other) = make_signed_commit_frame().await;
        let mut body = decode_commit_frame(&frame).expect("decode Ok");

        // Extract the commit block, mutate one byte of the sig, re-encode, and
        // splice the mutated block back into body.blocks as a fresh CAR.
        let block_bytes = extract_commit_block(&body.blocks, body.commit)
            .await
            .expect("extract commit block");

        let mut signed: SignedCommit =
            serde_ipld_dagcbor::from_slice(&block_bytes).expect("decode SignedCommit");

        // Flip a byte in the signature — the sig itself is the tamper target so
        // the block still parses but the signature bytes differ.
        let mid = signed.sig.len() / 2;
        signed.sig[mid] ^= 0xFF;

        // Re-encode the tampered SignedCommit back into a fresh block.
        #[derive(Serialize)]
        struct TamperedCommit {
            did: Did,
            version: i64,
            data: Cid,
            rev: Tid,
            prev: Option<Cid>,
            #[serde(with = "serde_bytes")]
            sig: Vec<u8>,
        }
        let tampered_block = serde_ipld_dagcbor::to_vec(&TamperedCommit {
            did: signed.did.clone(),
            version: signed.version,
            data: signed.data,
            rev: signed.rev.clone(),
            prev: signed.prev,
            sig: signed.sig.clone(),
        })
        .expect("re-encode tampered block");

        // Rebuild a CAR containing the tampered block under the same commit CID.
        let mut new_car: Vec<u8> = Vec::new();
        let mut writer =
            iroh_car::CarWriter::new(iroh_car::CarHeader::new_v1(vec![body.commit]), &mut new_car);
        writer
            .write(body.commit, tampered_block)
            .await
            .expect("write tampered block");
        writer.finish().await.expect("finish CAR");

        body.blocks = new_car;

        let result = verify_commit_sig(&body, &did_key).await;
        assert!(
            result.is_err(),
            "tampered commit must fail verification but got Ok"
        );
        assert!(
            matches!(result, Err(TailError::Sig(_))),
            "expected TailError::Sig, got: {:?}",
            result.err()
        );
    }

    // -----------------------------------------------------------------------
    // verify_commit_sig_wrong_key
    // -----------------------------------------------------------------------

    /// Verifying a real signed commit with a DIFFERENT keypair's did:key fails.
    #[tokio::test]
    async fn verify_commit_sig_wrong_key() {
        let (frame, _did_key, other_key) = make_signed_commit_frame().await;
        let body = decode_commit_frame(&frame).expect("decode Ok");
        let result = verify_commit_sig(&body, &other_key.did()).await;
        assert!(
            result.is_err(),
            "wrong key must fail verification but got Ok"
        );
    }
}
