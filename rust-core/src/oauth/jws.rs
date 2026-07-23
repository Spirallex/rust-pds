//! Compact JWS (`header.payload.signature`) encoding and decoding.
//!
//! Deliberately small and separate from the `jsonwebtoken` crate used by the
//! legacy session path. That crate hides the header behind its own types, but
//! DPoP verification needs the raw header *before* verification — the key to
//! verify with is embedded in it — and needs to reject an unexpected `typ` or
//! `alg` rather than negotiate one. Doing that through a general-purpose library
//! invites exactly the algorithm-confusion mistakes the atproto profile exists
//! to rule out.

use data_encoding::BASE64URL_NOPAD;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::oauth::jwk::{Alg, PublicJwk, SigningKey};
use crate::oauth::OAuthError;

/// A parsed but **not yet verified** compact JWS.
///
/// The name is deliberate: nothing in this struct has been authenticated. Read
/// `header` to find the key, then call [`Unverified::verify_with`] before
/// trusting `payload_bytes`.
pub struct Unverified {
    /// Raw header JSON, already decoded from base64url.
    pub header: serde_json::Value,
    /// Raw payload JSON, already decoded from base64url.
    pub payload_bytes: Vec<u8>,
    /// The `header.payload` substring the signature covers.
    signing_input: String,
    signature: Vec<u8>,
}

impl Unverified {
    /// Split and base64url-decode a compact JWS. Performs no cryptography.
    pub fn parse(token: &str) -> Result<Self, OAuthError> {
        let malformed = |what: &str| OAuthError::InvalidDpopProof(format!("malformed JWS: {what}"));

        let mut parts = token.split('.');
        let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            // A fourth segment means this is JWE or a malformed JWS; either way
            // it is not something we will verify.
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => return Err(malformed("expected exactly three segments")),
        };

        let header_bytes = BASE64URL_NOPAD
            .decode(h.as_bytes())
            .map_err(|_| malformed("header is not base64url"))?;
        let payload_bytes = BASE64URL_NOPAD
            .decode(p.as_bytes())
            .map_err(|_| malformed("payload is not base64url"))?;
        let signature = BASE64URL_NOPAD
            .decode(s.as_bytes())
            .map_err(|_| malformed("signature is not base64url"))?;
        let header: serde_json::Value =
            serde_json::from_slice(&header_bytes).map_err(|_| malformed("header is not JSON"))?;

        Ok(Self {
            header,
            payload_bytes,
            signing_input: format!("{h}.{p}"),
            signature,
        })
    }

    /// A string member of the header, or `None` if absent or not a string.
    pub fn header_str(&self, key: &str) -> Option<&str> {
        self.header.get(key).and_then(|v| v.as_str())
    }

    /// The declared `alg`, rejecting anything outside the atproto profile.
    ///
    /// In particular `none` fails here, closing the classic unsigned-token hole.
    pub fn alg(&self) -> Result<Alg, OAuthError> {
        let alg = self
            .header_str("alg")
            .ok_or_else(|| OAuthError::InvalidDpopProof("JWS header has no alg".into()))?;
        Alg::parse(alg)
    }

    /// Verify the signature with `jwk` and deserialize the payload.
    ///
    /// The algorithm is taken from the **key**, not from the token header, and
    /// the header's declared `alg` must agree with it. Trusting the header alone
    /// is the algorithm-confusion attack; requiring agreement means a token
    /// cannot select a weaker primitive than its key implies.
    pub fn verify_with<T: DeserializeOwned>(&self, jwk: &PublicJwk) -> Result<T, OAuthError> {
        let key_alg = jwk.alg()?;
        if self.alg()? != key_alg {
            return Err(OAuthError::InvalidDpopProof(
                "JWS alg does not match the key's curve".into(),
            ));
        }
        jwk.verify(self.signing_input.as_bytes(), &self.signature)?;
        serde_json::from_slice(&self.payload_bytes)
            .map_err(|e| OAuthError::InvalidDpopProof(format!("payload is not valid JSON: {e}")))
    }

    /// Deserialize the payload **without** verifying the signature.
    ///
    /// Only for inspecting a token whose signature cannot be checked yet — for
    /// example reading `iss` to decide which key to fetch. Never use the result
    /// for an authorization decision.
    pub fn payload_unverified<T: DeserializeOwned>(&self) -> Result<T, OAuthError> {
        serde_json::from_slice(&self.payload_bytes)
            .map_err(|e| OAuthError::InvalidDpopProof(format!("payload is not valid JSON: {e}")))
    }
}

/// Sign `claims` as a compact JWS with `typ` and the server's ES256 key.
pub fn sign<T: Serialize>(key: &SigningKey, typ: &str, claims: &T) -> Result<String, OAuthError> {
    let header = serde_json::json!({
        "typ": typ,
        "alg": "ES256",
        "kid": key.kid(),
    });
    let header_b64 = BASE64URL_NOPAD.encode(
        serde_json::to_vec(&header)
            .map_err(|e| OAuthError::Internal(format!("encode JWS header: {e}")))?
            .as_slice(),
    );
    let payload_b64 = BASE64URL_NOPAD.encode(
        serde_json::to_vec(claims)
            .map_err(|e| OAuthError::Internal(format!("encode JWS payload: {e}")))?
            .as_slice(),
    );
    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = key.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", BASE64URL_NOPAD.encode(&sig)))
}

/// Verify a compact JWS produced by [`sign`] and return its claims.
pub fn verify<T: DeserializeOwned>(
    key: &SigningKey,
    expected_typ: &str,
    token: &str,
) -> Result<T, OAuthError> {
    let unverified =
        Unverified::parse(token).map_err(|_| OAuthError::InvalidToken("malformed token".into()))?;

    // Check `typ` before verifying so a token minted for one purpose can never
    // be replayed as another (an access token presented as a DPoP proof, say),
    // even if both are signed by the same key.
    match unverified.header_str("typ") {
        Some(t) if t == expected_typ => {}
        _ => {
            return Err(OAuthError::InvalidToken(format!(
                "expected typ {expected_typ}"
            )))
        }
    }

    unverified
        .verify_with(&key.public_jwk())
        .map_err(|_| OAuthError::InvalidToken("signature verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Claims {
        sub: String,
        exp: u64,
    }

    fn claims() -> Claims {
        Claims {
            sub: "did:plc:abc".into(),
            exp: 1_800_000_000,
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = SigningKey::generate();
        let token = sign(&key, "at+jwt", &claims()).unwrap();
        let got: Claims = verify(&key, "at+jwt", &token).unwrap();
        assert_eq!(got, claims());
    }

    #[test]
    fn wrong_typ_is_rejected() {
        let key = SigningKey::generate();
        let token = sign(&key, "at+jwt", &claims()).unwrap();
        assert!(
            verify::<Claims>(&key, "dpop+jwt", &token).is_err(),
            "a token minted as at+jwt must not verify as dpop+jwt"
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let key = SigningKey::generate();
        let other = SigningKey::generate();
        let token = sign(&key, "at+jwt", &claims()).unwrap();
        assert!(verify::<Claims>(&other, "at+jwt", &token).is_err());
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let key = SigningKey::generate();
        let token = sign(&key, "at+jwt", &claims()).unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = BASE64URL_NOPAD.encode(
            serde_json::to_vec(&Claims {
                sub: "did:plc:attacker".into(),
                exp: 1_800_000_000,
            })
            .unwrap()
            .as_slice(),
        );
        parts[1] = &forged;
        assert!(verify::<Claims>(&key, "at+jwt", &parts.join(".")).is_err());
    }

    #[test]
    fn alg_none_is_rejected() {
        // The classic unsigned-token attack: alg "none" with an empty signature.
        let header = BASE64URL_NOPAD.encode(br#"{"typ":"at+jwt","alg":"none"}"#);
        let payload = BASE64URL_NOPAD.encode(&serde_json::to_vec(&claims()).unwrap());
        let token = format!("{header}.{payload}.");

        let key = SigningKey::generate();
        assert!(
            verify::<Claims>(&key, "at+jwt", &token).is_err(),
            "alg=none must never verify"
        );
        assert!(Unverified::parse(&token).unwrap().alg().is_err());
    }

    #[test]
    fn malformed_tokens_error_rather_than_panic() {
        for bad in [
            "",
            "onlyonepart",
            "two.parts",
            "four.parts.are.invalid",
            "!!!.###.$$$",
            "....",
        ] {
            assert!(
                Unverified::parse(bad).is_err(),
                "{bad:?} must fail to parse, not panic"
            );
        }
    }

    #[test]
    fn header_alg_must_match_key_curve() {
        // Sign with P-256 but claim ES256K in the header: the signature is
        // valid over the bytes, yet the declared alg disagrees with the key.
        let key = SigningKey::generate();
        let header = BASE64URL_NOPAD.encode(br#"{"typ":"at+jwt","alg":"ES256K"}"#);
        let payload = BASE64URL_NOPAD.encode(&serde_json::to_vec(&claims()).unwrap());
        let signing_input = format!("{header}.{payload}");
        let sig = key.sign(signing_input.as_bytes());
        let token = format!("{signing_input}.{}", BASE64URL_NOPAD.encode(&sig));

        let parsed = Unverified::parse(&token).unwrap();
        assert!(
            parsed.verify_with::<Claims>(&key.public_jwk()).is_err(),
            "a header alg that disagrees with the key must be rejected"
        );
    }

    #[test]
    fn payload_unverified_does_not_check_signature() {
        let key = SigningKey::generate();
        let token = sign(&key, "at+jwt", &claims()).unwrap();
        // Corrupt the signature; the unverified read must still work.
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        parts[2] = BASE64URL_NOPAD.encode(&[0u8; 64]);
        let parsed = Unverified::parse(&parts.join(".")).unwrap();
        let got: Claims = parsed.payload_unverified().unwrap();
        assert_eq!(got, claims());
        // ...but verification must still fail.
        assert!(parsed.verify_with::<Claims>(&key.public_jwk()).is_err());
    }
}
