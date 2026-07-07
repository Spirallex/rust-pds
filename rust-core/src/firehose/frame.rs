//! Firehose frame encoding: DAG-CBOR header ++ DAG-CBOR body, no length prefix.

use cid::Cid;
use serde::{Deserialize, Serialize};
use serde_ipld_dagcbor::to_vec;

#[derive(Serialize)]
struct MessageHeader<'a> {
    op: i64,
    t: &'a str,
}

#[derive(Serialize)]
struct ErrorHeader {
    op: i64,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// The #commit message body matching com.atproto.sync.subscribeRepos lexicon.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitBody {
    pub seq: i64,
    pub rebase: bool,
    pub too_big: bool,
    pub repo: String,
    pub commit: Cid,
    pub rev: String,
    pub since: Option<String>,
    #[serde(with = "serde_bytes")]
    pub blocks: Vec<u8>,
    pub ops: Vec<RepoOp>,
    pub blobs: Vec<Cid>,
    pub time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_data: Option<Cid>,
}

/// A single repository operation in the #commit body.
#[derive(Serialize, Deserialize)]
pub struct RepoOp {
    pub action: String,
    pub path: String,
    pub cid: Option<Cid>,
}

/// Encode a message frame: dag_cbor(header{op:1,t}) ++ dag_cbor(body).
/// No length prefix, no delimiter.
pub fn encode_message_frame<B: Serialize>(t: &str, body: &B) -> Vec<u8> {
    let header = to_vec(&MessageHeader { op: 1, t }).expect("header encode");
    let body_bytes = to_vec(body).expect("body encode");
    [header, body_bytes].concat()
}

/// Encode an error frame: dag_cbor({op:-1}) ++ dag_cbor({error, message?}).
/// The error header has NO `t` field.
pub fn encode_error_frame(error: &str, message: Option<&str>) -> Vec<u8> {
    let header = to_vec(&ErrorHeader { op: -1 }).expect("header encode");
    let body = to_vec(&ErrorBody {
        error: error.to_string(),
        message: message.map(|s| s.to_string()),
    })
    .expect("body encode");
    [header, body].concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use atrium_repo::blockstore::SHA2_256;
    use ipld_core::ipld::Ipld;
    use sha2::{Digest, Sha256};
    use std::io::{BufReader, Cursor};

    /// Build a deterministic CIDv1(dag-cbor, sha2-256) from a fixed byte sequence.
    fn fixed_cid() -> Cid {
        let digest = Sha256::digest(b"golden-frame-fixture");
        let mh = cid::multihash::Multihash::wrap(SHA2_256, digest.as_slice())
            .expect("32-byte sha2-256 digest always fits multihash");
        Cid::new_v1(0x71, mh) // 0x71 = dag-cbor codec
    }

    /// Build the standard CommitBody used in deterministic tests.
    fn commit_body() -> CommitBody {
        CommitBody {
            seq: 1,
            rebase: false,
            too_big: false,
            repo: "did:web:example.com".to_string(),
            commit: fixed_cid(),
            rev: "3kaaaa".to_string(),
            since: None,
            blocks: vec![],
            ops: vec![RepoOp {
                action: "create".to_string(),
                path: "app.bsky.feed.post/3kaaaa".to_string(),
                cid: Some(fixed_cid()),
            }],
            blobs: vec![],
            time: "2026-06-17T00:00:00.000Z".to_string(),
            prev_data: None,
        }
    }

    /// A #commit frame is dag_cbor(header) ++ dag_cbor(body) with NO length prefix.
    /// from_slice on the full bytes FAILS (trailing data); streaming decode yields two objects.
    #[test]
    fn frame_is_header_then_body_concatenated() {
        let body = commit_body();
        let frame = encode_message_frame("#commit", &body);

        // Full frame is NOT a single valid CBOR object (trailing data after first object).
        let single: Result<Ipld, _> = serde_ipld_dagcbor::from_slice(&frame);
        assert!(
            single.is_err(),
            "expected from_slice to fail on two concatenated CBOR objects"
        );

        // Streaming decode via from_reader_once: reads exactly one CBOR object and leaves
        // the rest of the BufReader's buffer intact (does NOT call deserializer.end()).
        let cursor = Cursor::new(&frame[..]);
        let mut buf_reader = BufReader::new(cursor);
        let header: Ipld = serde_ipld_dagcbor::de::from_reader_once(&mut buf_reader)
            .expect("header should decode as first CBOR object");

        let body_decoded: Ipld = serde_ipld_dagcbor::de::from_reader_once(&mut buf_reader)
            .expect("body should decode as second CBOR object");

        // Header is a map with op=1 and t="#commit".
        if let Ipld::Map(map) = &header {
            assert_eq!(map.get("op"), Some(&Ipld::Integer(1)), "op must be 1");
            assert_eq!(
                map.get("t"),
                Some(&Ipld::String("#commit".to_string())),
                "t must be #commit"
            );
        } else {
            panic!("header must be an IPLD map, got: {:?}", header);
        }

        // Body is a map (non-empty).
        assert!(
            matches!(body_decoded, Ipld::Map(_)),
            "body must be an IPLD map"
        );

        // BufReader must be exhausted — exactly two objects, no trailing bytes.
        // We verify this by attempting a third decode which must fail.
        let trailing: Result<Ipld, _> = serde_ipld_dagcbor::de::from_reader_once(&mut buf_reader);
        assert!(
            trailing.is_err(),
            "expected no trailing bytes after the two CBOR objects in the frame"
        );
    }

    /// All required lexicon fields are present with the correct camelCase wire names.
    #[test]
    fn commit_body_fields() {
        let body = commit_body();
        let body_bytes = to_vec(&body).expect("encode");
        let decoded: Ipld = serde_ipld_dagcbor::from_slice(&body_bytes).expect("decode");

        if let Ipld::Map(map) = decoded {
            // Required fields present with correct wire names.
            assert!(map.contains_key("seq"), "missing seq");
            assert!(map.contains_key("rebase"), "missing rebase");
            assert!(map.contains_key("tooBig"), "missing tooBig (camelCase)");
            assert!(
                !map.contains_key("too_big"),
                "found too_big (snake_case) — must be tooBig"
            );
            assert!(map.contains_key("repo"), "missing repo");
            assert!(map.contains_key("commit"), "missing commit");
            assert!(map.contains_key("rev"), "missing rev");
            assert!(
                map.contains_key("since"),
                "missing since (required+nullable)"
            );
            assert!(map.contains_key("blocks"), "missing blocks");
            assert!(map.contains_key("ops"), "missing ops");
            assert!(map.contains_key("blobs"), "missing blobs");
            assert!(map.contains_key("time"), "missing time");
            // prevData is optional — not present when None.
            assert!(
                !map.contains_key("prevData"),
                "prevData must be absent when None"
            );
            assert!(
                !map.contains_key("prev_data"),
                "prev_data (snake_case) must not appear"
            );

            // since is null (not absent) because lexicon marks it required+nullable.
            assert_eq!(
                map.get("since"),
                Some(&Ipld::Null),
                "since must be null (not absent) for first commit"
            );
        } else {
            panic!("expected IPLD map");
        }
    }

    /// Error frame: op==-1 header with NO `t` key; body has error + optional message.
    #[test]
    fn error_frame_has_no_t() {
        let frame = encode_error_frame("FutureCursor", Some("Cursor in the future."));

        let mut buf_reader = BufReader::new(Cursor::new(&frame[..]));
        let header: Ipld =
            serde_ipld_dagcbor::de::from_reader_once(&mut buf_reader).expect("header decode");
        let body_decoded: Ipld =
            serde_ipld_dagcbor::de::from_reader_once(&mut buf_reader).expect("body decode");

        if let Ipld::Map(map) = &header {
            assert_eq!(map.get("op"), Some(&Ipld::Integer(-1)), "op must be -1");
            assert!(
                !map.contains_key("t"),
                "error header must NOT have a t field"
            );
        } else {
            panic!("header must be a map");
        }

        if let Ipld::Map(map) = &body_decoded {
            assert_eq!(
                map.get("error"),
                Some(&Ipld::String("FutureCursor".to_string())),
                "error field mismatch"
            );
            assert_eq!(
                map.get("message"),
                Some(&Ipld::String("Cursor in the future.".to_string())),
                "message field mismatch"
            );
        } else {
            panic!("body must be a map");
        }
    }

    /// GOLDEN FRAME: encode a fully-deterministic #commit frame and assert the exact hex bytes.
    /// This test locks the wire encoding so any silent framing drift fails the build.
    #[test]
    fn golden_frame_commit() {
        let body = commit_body();
        let frame = encode_message_frame("#commit", &body);

        // Locked wire bytes — computed once from the fixed inputs above.
        // If this assertion fails, the frame encoding changed and the relay will silently reject it.
        let expected = "a261746723636f6d6d6974626f7001ab636f707381a363636964d82a58250001711220bd18d1b37e87be3c9c62ea97a49c4b31eb0bdc84a5da0d7f032dc0db660c60e9647061746878196170702e62736b792e666565642e706f73742f336b6161616166616374696f6e666372656174656372657666336b616161616373657101647265706f736469643a7765623a6578616d706c652e636f6d6474696d657818323032362d30362d31375430303a30303a30302e3030305a65626c6f6273806573696e6365f666626c6f636b734066636f6d6d6974d82a58250001711220bd18d1b37e87be3c9c62ea97a49c4b31eb0bdc84a5da0d7f032dc0db660c60e966726562617365f466746f6f426967f4";

        assert_eq!(
            data_encoding::HEXLOWER.encode(&frame),
            expected,
            "frame encoding changed — relay will reject this binary"
        );
    }
}
