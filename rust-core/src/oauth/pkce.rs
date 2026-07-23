//! PKCE (RFC 7636), `S256` only.
//!
//! The atproto profile requires PKCE on every authorization request and permits
//! only the `S256` challenge method. `plain` is not implemented — not merely
//! defaulted away — so a client cannot downgrade to it.

use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest, Sha256};

use crate::oauth::{constant_time_eq, OAuthError};

/// A `code_challenge` captured at authorization time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeChallenge {
    /// The base64url-encoded SHA-256 of the client's `code_verifier`.
    pub challenge: String,
}

impl CodeChallenge {
    /// Validate an incoming `code_challenge` / `code_challenge_method` pair.
    pub fn parse(challenge: &str, method: Option<&str>) -> Result<Self, OAuthError> {
        // Absent method would default to `plain` under RFC 7636. The atproto
        // profile forbids `plain`, so require S256 explicitly rather than
        // silently accepting the weaker default.
        match method {
            Some("S256") => {}
            Some(other) => {
                return Err(OAuthError::InvalidRequest(format!(
                    "unsupported code_challenge_method: {other} (only S256 is allowed)"
                )))
            }
            None => {
                return Err(OAuthError::InvalidRequest(
                    "code_challenge_method is required and must be S256".into(),
                ))
            }
        }

        // A base64url-encoded SHA-256 digest is exactly 43 unpadded characters.
        // Anything else cannot be a valid S256 challenge.
        if challenge.len() != 43 {
            return Err(OAuthError::InvalidRequest(
                "code_challenge must be a base64url-encoded SHA-256 digest".into(),
            ));
        }
        if BASE64URL_NOPAD.decode(challenge.as_bytes()).is_err() {
            return Err(OAuthError::InvalidRequest(
                "code_challenge is not valid base64url".into(),
            ));
        }

        Ok(Self {
            challenge: challenge.to_string(),
        })
    }

    /// Check a `code_verifier` presented at the token endpoint.
    ///
    /// The comparison is constant-time. The verifier is a secret held by the
    /// legitimate client, and a timing oracle on the challenge would let an
    /// attacker holding a stolen authorization code recover it byte by byte.
    pub fn verify(&self, code_verifier: &str) -> Result<(), OAuthError> {
        // RFC 7636 §4.1 fixes the verifier length range; enforcing it rejects
        // trivially low-entropy verifiers.
        if !(43..=128).contains(&code_verifier.len()) {
            return Err(OAuthError::InvalidGrant(
                "code_verifier must be 43-128 characters".into(),
            ));
        }
        if !code_verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
        {
            return Err(OAuthError::InvalidGrant(
                "code_verifier contains characters outside the unreserved set".into(),
            ));
        }

        let computed = BASE64URL_NOPAD.encode(&Sha256::digest(code_verifier.as_bytes()));
        if constant_time_eq(&computed, &self.challenge) {
            Ok(())
        } else {
            Err(OAuthError::InvalidGrant(
                "code_verifier does not match code_challenge".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the challenge for a verifier the way a correct client would.
    fn challenge_for(verifier: &str) -> String {
        BASE64URL_NOPAD.encode(&Sha256::digest(verifier.as_bytes()))
    }

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    #[test]
    fn rfc7636_appendix_b_vector() {
        // RFC 7636 Appendix B: this verifier yields this exact challenge.
        assert_eq!(
            challenge_for(VERIFIER),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let c = CodeChallenge::parse("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Some("S256"))
            .unwrap();
        c.verify(VERIFIER).expect("the RFC vector must verify");
    }

    #[test]
    fn round_trip() {
        let c = CodeChallenge::parse(&challenge_for(VERIFIER), Some("S256")).unwrap();
        assert!(c.verify(VERIFIER).is_ok());
    }

    #[test]
    fn wrong_verifier_is_rejected() {
        let c = CodeChallenge::parse(&challenge_for(VERIFIER), Some("S256")).unwrap();
        let other = "a".repeat(43);
        assert!(c.verify(&other).is_err());
    }

    #[test]
    fn plain_method_is_rejected() {
        assert!(
            CodeChallenge::parse(&challenge_for(VERIFIER), Some("plain")).is_err(),
            "the atproto profile forbids the plain method"
        );
    }

    #[test]
    fn missing_method_is_rejected_rather_than_defaulting_to_plain() {
        assert!(
            CodeChallenge::parse(&challenge_for(VERIFIER), None).is_err(),
            "an absent method must not fall back to plain"
        );
    }

    #[test]
    fn malformed_challenge_is_rejected() {
        assert!(CodeChallenge::parse("short", Some("S256")).is_err());
        assert!(CodeChallenge::parse(&"!".repeat(43), Some("S256")).is_err());
        assert!(CodeChallenge::parse("", Some("S256")).is_err());
    }

    #[test]
    fn verifier_length_bounds_are_enforced() {
        let c = CodeChallenge::parse(&challenge_for(VERIFIER), Some("S256")).unwrap();
        assert!(c.verify(&"a".repeat(42)).is_err(), "42 chars is too short");
        assert!(c.verify(&"a".repeat(129)).is_err(), "129 chars is too long");
    }

    #[test]
    fn verifier_charset_is_enforced() {
        let bad = format!("{}!", "a".repeat(42));
        assert_eq!(bad.len(), 43);
        let c = CodeChallenge::parse(&challenge_for(&bad), Some("S256")).unwrap();
        assert!(
            c.verify(&bad).is_err(),
            "characters outside the unreserved set must be rejected even if the digest matches"
        );
    }
}
