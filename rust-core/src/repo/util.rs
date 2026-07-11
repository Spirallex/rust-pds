//! Pure helpers shared by every XRPC repo surface (the production axum server
//! in the `stelyph` crate and the feature-gated embedded server here).
//!
//! Validation rules and encodings live in ONE place so the two servers cannot
//! drift: a record accepted on the desktop PDS must be accepted on-device.

use ipld_core::ipld::Ipld;

/// Validate an ATProto rkey string.
///
/// ATProto rkey rules:
/// - 1–512 bytes.
/// - Must not contain '/' (would corrupt the MST key space) or NUL bytes.
/// - Must contain only visible ASCII characters (matching the ATProto spec
///   allowed set: alphanumerics, `-`, `_`, `~`, `.`, `:`).
pub fn validate_rkey(rkey: &str) -> Result<(), String> {
    if rkey.is_empty() || rkey.len() > 512 {
        return Err("rkey must be 1–512 chars".into());
    }
    if rkey.contains('/') || rkey.contains('\0') {
        return Err("rkey must not contain '/' or NUL".into());
    }
    // Reject non-printable ASCII and non-ASCII bytes.
    if !rkey.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err("rkey must contain only printable ASCII characters".into());
    }
    Ok(())
}

/// Validate a collection string (must be a valid NSID-style dotted path).
///
/// Rules: at least two dot-separated segments, each segment non-empty,
/// starts with a letter, and contains only ASCII alphanumeric chars or hyphens.
/// Must not contain NUL bytes or '/'.
pub fn validate_collection(collection: &str) -> Result<(), String> {
    if collection.is_empty() || collection.contains('\0') || collection.contains('/') {
        return Err("collection must be a valid NSID (e.g. app.bsky.feed.post)".into());
    }
    let segments: Vec<&str> = collection.split('.').collect();
    if segments.len() < 2 {
        return Err("collection must have at least two dot-separated segments".into());
    }
    for seg in &segments {
        if seg.is_empty() {
            return Err("collection segment must not be empty".into());
        }
        if !seg
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic())
            .unwrap_or(false)
        {
            return Err("collection segment must start with a letter".into());
        }
        if !seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(
                "collection segment must contain only alphanumeric chars or hyphens".into(),
            );
        }
    }
    Ok(())
}

/// Convert a `serde_json::Value` to `ipld_core::ipld::Ipld`.
///
/// Uses serde_ipld_dagcbor as the conversion bridge: encode to DAG-CBOR bytes
/// then decode back to Ipld. This is the canonical path and preserves all
/// field types correctly including `$type`, nested objects, and arrays.
pub fn json_value_to_ipld(value: serde_json::Value) -> Result<Ipld, String> {
    let cbor_bytes = serde_ipld_dagcbor::to_vec(&value)
        .map_err(|e| format!("json→dagcbor encode failed: {e}"))?;
    let ipld: Ipld = serde_ipld_dagcbor::from_slice(&cbor_bytes)
        .map_err(|e| format!("dagcbor→ipld decode failed: {e}"))?;
    Ok(ipld)
}

/// Generate a TID-style rkey from a microsecond timestamp.
///
/// ATProto TID format: base32-sortable lowercase, 13 characters.
/// The alphabet is `234567abcdefghijklmnopqrstuvwxyz` (base32 without 0, 1).
/// Upper 53 bits = timestamp in microseconds; lower 10 bits = clock ID (0 here).
pub fn tid_from_micros(us: u64) -> String {
    // Pack into 63-bit value with clock id = 0.
    let n = us << 10;
    // Base32 encode: 13 5-bit groups from the 65-bit value.
    let alphabet = b"234567abcdefghijklmnopqrstuvwxyz";
    let mut result = [b'2'; 13];
    let mut val = n;
    for i in (0..13).rev() {
        result[i] = alphabet[(val & 0x1f) as usize];
        val >>= 5;
    }
    String::from_utf8(result.to_vec()).unwrap_or_else(|_| "2222222222222".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rkey_rules() {
        assert!(validate_rkey("3k2akqmqhh52c").is_ok());
        assert!(validate_rkey("self").is_ok());
        assert!(validate_rkey("").is_err());
        assert!(validate_rkey("a/b").is_err());
        assert!(validate_rkey("a\0b").is_err());
        assert!(validate_rkey("空白").is_err());
        assert!(validate_rkey(&"x".repeat(513)).is_err());
    }

    #[test]
    fn collection_rules() {
        assert!(validate_collection("app.bsky.feed.post").is_ok());
        assert!(validate_collection("nodots").is_err());
        assert!(validate_collection("a..b").is_err());
        assert!(validate_collection("1app.bsky").is_err());
        assert!(validate_collection("app.bsky/feed").is_err());
    }

    #[test]
    fn json_round_trips_through_ipld() {
        let v = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "hi",
            "langs": ["en"],
            "n": 3
        });
        let ipld = json_value_to_ipld(v).unwrap();
        match ipld {
            Ipld::Map(m) => assert!(m.contains_key("$type")),
            other => panic!("expected map, got {other:?}"),
        }
    }

    #[test]
    fn tid_is_13_chars_sortable() {
        let a = tid_from_micros(1_000_000);
        let b = tid_from_micros(2_000_000);
        assert_eq!(a.len(), 13);
        assert!(a < b, "TIDs must sort by timestamp: {a} !< {b}");
    }
}
