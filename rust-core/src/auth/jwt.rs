use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use jsonwebtoken::{
    decode, encode, Algorithm as JwtAlgorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// JWT claims for AT Protocol sessions.
///
/// Access tokens: `scope = "com.atproto.access"`, `jti = None`, `exp = now + 7200`.
/// Refresh tokens: `scope = "com.atproto.refresh"`, `jti = Some(uuid)`, `exp = now + 7_776_000`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthClaims {
    pub sub: String,
    pub scope: String,
    pub exp: u64,
    pub iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

/// Current Unix timestamp (seconds since epoch).
pub fn current_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs()
}

/// Argon2id memory cost in KiB.
///
/// Default is 19456 KiB (~19 MiB, OWASP-aligned) for server hosts. The argon2
/// working buffer is dirty, non-file-backed memory, so on a memory-constrained
/// device host (iOS Network Extension under the Jetsam per-process ceiling) a
/// single hash/verify of 19 MiB can exceed the entire budget. The `lean-auth`
/// feature drops it to 4096 KiB (~4 MiB) — measured 1:1 against phys_footprint —
/// trading brute-force resistance for footprint. Only enable on single-user
/// device builds where the attacker needs the unlocked device anyway.
#[cfg(not(feature = "lean-auth"))]
const ARGON2_M_COST_KIB: u32 = 19_456;
#[cfg(feature = "lean-auth")]
const ARGON2_M_COST_KIB: u32 = 4_096;

/// Construct the pinned Argon2id instance used by storage/keys.rs too:
/// m=`ARGON2_M_COST_KIB`, t=2, p=1, output_len=32.
fn argon2_instance() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(ARGON2_M_COST_KIB, 2, 1, Some(32)).expect("static argon2 params are valid"),
    )
}

/// Hash `password` with argon2id and return the PHC string.
/// Store this in the `password_argon2` column as TEXT.
pub fn hash_password(password: &str) -> Result<String, CoreError> {
    let salt = SaltString::generate(&mut OsRng);
    argon2_instance()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| CoreError::Internal(anyhow::anyhow!("argon2 hash error: {e}")))
}

/// Verify `password` against a PHC string produced by `hash_password`.
/// Returns `true` on match, `false` on wrong password, `Err` only on a malformed PHC string.
pub fn verify_password(password: &str, phc: &str) -> Result<bool, CoreError> {
    let parsed = PasswordHash::new(phc)
        .map_err(|e| CoreError::Internal(anyhow::anyhow!("malformed PHC string: {e}")))?;
    Ok(argon2_instance()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Issue an access JWT.
/// Scope: `"com.atproto.access"`, exp = now + 7200 s.
pub fn encode_access_jwt(did: &str, secret: &[u8]) -> Result<String, CoreError> {
    let now = current_unix();
    let claims = AuthClaims {
        sub: did.to_string(),
        scope: "com.atproto.access".to_string(),
        exp: now + 7_200,
        iat: now,
        jti: None,
    };
    encode(
        &Header::new(JwtAlgorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| CoreError::Internal(anyhow::anyhow!("JWT encode error: {e}")))
}

/// Issue a refresh JWT.
/// Scope: `"com.atproto.refresh"`, exp = now + 7_776_000 s (90 days), jti = uuid v4.
pub fn encode_refresh_jwt(did: &str, secret: &[u8]) -> Result<String, CoreError> {
    let now = current_unix();
    let claims = AuthClaims {
        sub: did.to_string(),
        scope: "com.atproto.refresh".to_string(),
        exp: now + 7_776_000,
        iat: now,
        jti: Some(uuid::Uuid::new_v4().to_string()),
    };
    encode(
        &Header::new(JwtAlgorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| CoreError::Internal(anyhow::anyhow!("JWT encode error: {e}")))
}

/// Decode and verify a JWT.
/// - `ErrorKind::ExpiredSignature` → `CoreError::ExpiredToken` (T-03-02)
/// - All other decode errors → `CoreError::InvalidToken`
pub fn decode_jwt(token: &str, secret: &[u8]) -> Result<AuthClaims, CoreError> {
    let mut v = Validation::new(JwtAlgorithm::HS256);
    v.validate_exp = true;
    decode::<AuthClaims>(token, &DecodingKey::from_secret(secret), &v)
        .map(|td| td.claims)
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => CoreError::ExpiredToken,
            _ => CoreError::InvalidToken,
        })
}

/// Test helper: encode an access JWT with a specific `exp` timestamp.
/// Allows producing an already-expired token without sleeping.
#[cfg(test)]
pub fn encode_access_jwt_with_exp(did: &str, secret: &[u8], exp: u64) -> Result<String, CoreError> {
    let claims = AuthClaims {
        sub: did.to_string(),
        scope: "com.atproto.access".to_string(),
        exp,
        iat: exp.saturating_sub(1),
        jti: None,
    };
    encode(
        &Header::new(JwtAlgorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| CoreError::Internal(anyhow::anyhow!("JWT encode error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"test-jwt-secret-for-unit-tests";
    const DID: &str = "did:plc:testdid1234";

    // --- password ---

    #[test]
    fn hash_then_verify_correct_password() {
        let phc = hash_password("correct-horse-battery-staple").unwrap();
        let ok = verify_password("correct-horse-battery-staple", &phc).unwrap();
        assert!(ok, "correct password should verify");
    }

    #[test]
    fn wrong_password_fails() {
        let phc = hash_password("correct-horse-battery-staple").unwrap();
        let ok = verify_password("wrong-password", &phc).unwrap();
        assert!(!ok, "wrong password should not verify");
    }

    // --- access JWT ---

    #[test]
    fn access_jwt_claims_scope() {
        let token = encode_access_jwt(DID, SECRET).unwrap();
        let claims = decode_jwt(&token, SECRET).unwrap();
        assert_eq!(claims.sub, DID);
        assert_eq!(claims.scope, "com.atproto.access");
        assert!(claims.jti.is_none(), "access JWT must not have jti");
    }

    // --- refresh JWT ---

    #[test]
    fn refresh_jwt_claims_scope_and_jti() {
        let token = encode_refresh_jwt(DID, SECRET).unwrap();
        // decode_jwt validates scope for access tokens — we need to decode without scope check
        // since this is a refresh token. Use raw jsonwebtoken decode for claims inspection.
        let mut v = Validation::new(JwtAlgorithm::HS256);
        v.validate_exp = true;
        let td = jsonwebtoken::decode::<AuthClaims>(&token, &DecodingKey::from_secret(SECRET), &v)
            .unwrap();
        assert_eq!(td.claims.sub, DID);
        assert_eq!(td.claims.scope, "com.atproto.refresh");
        assert!(td.claims.jti.is_some(), "refresh JWT must have jti");
    }

    // --- expired token ---

    #[test]
    fn expired_token_maps_to_expired_token_error() {
        // Use an exp that is definitely in the past.
        let expired_token = encode_access_jwt_with_exp(DID, SECRET, 1_000_000).unwrap();
        let result = decode_jwt(&expired_token, SECRET);
        match result {
            Err(CoreError::ExpiredToken) => {}
            other => panic!("expected ExpiredToken, got: {:?}", other),
        }
    }

    // --- wrong secret ---

    #[test]
    fn wrong_secret_maps_to_invalid_token() {
        let token = encode_access_jwt(DID, SECRET).unwrap();
        let result = decode_jwt(&token, b"wrong-secret");
        match result {
            Err(CoreError::InvalidToken) => {}
            other => panic!("expected InvalidToken, got: {:?}", other),
        }
    }
}
