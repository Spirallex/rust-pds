//! ES256K inter-service auth tokens (atproto "service auth").
//!
//! Signed by the ACCOUNT's repo signing key (not the session HMAC): iss = the
//! account DID, aud = the target service DID, optional lxm = the one method
//! the token is good for. Both the production server's AppView proxy /
//! `getServiceAuth` endpoint and the embedded server mint through here.

use atrium_crypto::keypair::Secp256k1Keypair;
use data_encoding::BASE64URL_NOPAD;

/// Mint a short-lived (60s) service-auth JWT.
/// iss = account DID, aud = target service DID, lxm = full method NSID.
pub fn mint_service_auth_jwt(
    signing_key: &Secp256k1Keypair,
    iss: &str,
    aud: &str,
    lxm: &str,
) -> Result<String, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs();
    mint_service_auth_jwt_with(signing_key, iss, aud, Some(lxm), now + 60)
}

/// Mint a service-auth JWT with an explicit expiry and optional `lxm`.
///
/// This backs both the internal AppView proxy (which always pins `lxm` and a
/// 60s expiry) and the public `com.atproto.server.getServiceAuth` endpoint
/// (where `lxm` is optional and the caller may request a custom `exp`). When
/// `lxm` is `None` the claim is omitted entirely rather than serialized as null.
pub fn mint_service_auth_jwt_with(
    signing_key: &Secp256k1Keypair,
    iss: &str,
    aud: &str,
    lxm: Option<&str>,
    exp_unix: u64,
) -> Result<String, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs();
    let jti = format!("{:032x}", rand::random::<u128>());
    let header_json = r#"{"typ":"JWT","alg":"ES256K"}"#.to_string();
    let mut claims = serde_json::Map::new();
    claims.insert("iss".into(), serde_json::json!(iss));
    claims.insert("aud".into(), serde_json::json!(aud));
    if let Some(l) = lxm {
        claims.insert("lxm".into(), serde_json::json!(l));
    }
    claims.insert("exp".into(), serde_json::json!(exp_unix));
    claims.insert("iat".into(), serde_json::json!(now));
    claims.insert("jti".into(), serde_json::json!(jti));
    let claims_json = serde_json::Value::Object(claims).to_string();
    let h = BASE64URL_NOPAD.encode(header_json.as_bytes());
    let p = BASE64URL_NOPAD.encode(claims_json.as_bytes());
    let signing_input = format!("{h}.{p}");
    let sig_bytes = signing_key
        .sign(signing_input.as_bytes())
        .map_err(|e| format!("ES256K sign: {e}"))?;
    let s = BASE64URL_NOPAD.encode(&sig_bytes);
    Ok(format!("{signing_input}.{s}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_auth_jwt_claims_are_correct() {
        let key = Secp256k1Keypair::import(&[0x11u8; 32]).unwrap();
        let token = mint_service_auth_jwt(
            &key,
            "did:plc:abc123",
            "did:web:api.bsky.app",
            "app.bsky.feed.getTimeline",
        )
        .unwrap();

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 parts");

        let header: serde_json::Value =
            serde_json::from_slice(&BASE64URL_NOPAD.decode(parts[0].as_bytes()).unwrap()).unwrap();
        assert_eq!(header["alg"], "ES256K");
        assert_eq!(header["typ"], "JWT");

        let claims: serde_json::Value =
            serde_json::from_slice(&BASE64URL_NOPAD.decode(parts[1].as_bytes()).unwrap()).unwrap();
        assert_eq!(claims["iss"], "did:plc:abc123");
        assert_eq!(claims["aud"], "did:web:api.bsky.app");
        assert_eq!(claims["lxm"], "app.bsky.feed.getTimeline");
        assert!(claims["exp"].as_u64().unwrap() > claims["iat"].as_u64().unwrap());
        assert!(!claims["jti"].as_str().unwrap().is_empty());

        // The sig must verify against the key's did:key.
        let sig_bytes = BASE64URL_NOPAD.decode(parts[2].as_bytes()).unwrap();
        assert_eq!(sig_bytes.len(), 64, "ES256K compact sig is 64 bytes");
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        use atrium_crypto::keypair::Did;
        use atrium_crypto::verify::verify_signature;
        verify_signature(&key.did(), signing_input.as_bytes(), &sig_bytes)
            .expect("JWT signature must verify against the account's did:key");
    }

    #[test]
    fn lxm_none_is_omitted() {
        let key = Secp256k1Keypair::import(&[0x22u8; 32]).unwrap();
        let token =
            mint_service_auth_jwt_with(&key, "did:plc:a", "did:web:b", None, u64::MAX).unwrap();
        let parts: Vec<&str> = token.split('.').collect();
        let claims: serde_json::Value =
            serde_json::from_slice(&BASE64URL_NOPAD.decode(parts[1].as_bytes()).unwrap()).unwrap();
        assert!(claims.get("lxm").is_none(), "absent lxm must be omitted");
    }
}
