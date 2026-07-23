//! JSON Web Keys: the subset the AT Protocol OAuth profile actually uses.
//!
//! Only EC keys on P-256 (`ES256`) and secp256k1 (`ES256K`) appear here.
//! atproto's OAuth profile forbids RSA and forbids symmetric algorithms, so
//! there is deliberately no code path that could accept one — an unsupported
//! `crv` or `alg` is a parse error, not a fallback.

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::oauth::OAuthError;

/// Signature algorithms permitted by the atproto OAuth profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Alg {
    /// ECDSA on P-256 with SHA-256. The default for atproto clients.
    ES256,
    /// ECDSA on secp256k1 with SHA-256. Permitted, and what an atproto signing
    /// key already uses, so a client may reuse one.
    ES256K,
}

impl Alg {
    pub fn as_str(self) -> &'static str {
        match self {
            Alg::ES256 => "ES256",
            Alg::ES256K => "ES256K",
        }
    }

    pub fn parse(s: &str) -> Result<Self, OAuthError> {
        match s {
            "ES256" => Ok(Alg::ES256),
            "ES256K" => Ok(Alg::ES256K),
            other => Err(OAuthError::UnsupportedAlgorithm(other.to_string())),
        }
    }

    /// The JWK `crv` value this algorithm's keys must carry.
    pub fn curve(self) -> &'static str {
        match self {
            Alg::ES256 => "P-256",
            Alg::ES256K => "secp256k1",
        }
    }
}

/// A public EC JWK.
///
/// Field order in the struct is irrelevant to the wire format, but *is* relevant
/// to [`PublicJwk::thumbprint`], which builds its own canonical ordering rather
/// than relying on serialization order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicJwk {
    pub kty: String,
    pub crv: String,
    /// base64url (unpadded) big-endian X coordinate.
    pub x: String,
    /// base64url (unpadded) big-endian Y coordinate.
    pub y: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
}

impl PublicJwk {
    /// Reject a JWK that carries private key material.
    ///
    /// A DPoP proof embeds the client's public key in its header. If a client
    /// mistakenly embeds the private key, accepting it would mean logging and
    /// storing that secret. RFC 9449 §4.3 requires this check.
    pub fn reject_if_private(value: &serde_json::Value) -> Result<(), OAuthError> {
        // `d` is the EC private scalar; the RSA private members are listed too so
        // an RSA key with private parts is rejected as private rather than
        // falling through to the "unsupported kty" error.
        const PRIVATE_MEMBERS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "oth"];
        if let Some(obj) = value.as_object() {
            for m in PRIVATE_MEMBERS {
                if obj.contains_key(m) {
                    return Err(OAuthError::InvalidDpopProof(
                        "embedded JWK contains private key material".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Which algorithm this key can verify, derived from `crv`.
    pub fn alg(&self) -> Result<Alg, OAuthError> {
        if self.kty != "EC" {
            return Err(OAuthError::UnsupportedAlgorithm(format!(
                "unsupported kty: {}",
                self.kty
            )));
        }
        let from_curve = match self.crv.as_str() {
            "P-256" => Alg::ES256,
            "secp256k1" => Alg::ES256K,
            other => {
                return Err(OAuthError::UnsupportedAlgorithm(format!(
                    "unsupported crv: {other}"
                )))
            }
        };

        // If the JWK also names an `alg`, it must agree with the curve. A key
        // that claims ES256 while carrying a secp256k1 point is either
        // misconfigured or an attempt to steer verification toward the wrong
        // primitive; either way the curve is authoritative and disagreement is
        // an error rather than something to silently resolve.
        if let Some(declared) = self.alg.as_deref() {
            let declared = Alg::parse(declared)?;
            if declared != from_curve {
                return Err(OAuthError::UnsupportedAlgorithm(format!(
                    "JWK declares alg {} but crv {} implies {}",
                    declared.as_str(),
                    self.crv,
                    from_curve.as_str()
                )));
            }
        }
        Ok(from_curve)
    }

    /// Decode `x` and `y` into a 65-byte uncompressed SEC1 point (`0x04 || X || Y`).
    fn sec1_uncompressed(&self) -> Result<Vec<u8>, OAuthError> {
        let x = BASE64URL_NOPAD
            .decode(self.x.as_bytes())
            .map_err(|_| OAuthError::InvalidDpopProof("JWK x is not base64url".into()))?;
        let y = BASE64URL_NOPAD
            .decode(self.y.as_bytes())
            .map_err(|_| OAuthError::InvalidDpopProof("JWK y is not base64url".into()))?;
        if x.len() != 32 || y.len() != 32 {
            return Err(OAuthError::InvalidDpopProof(
                "JWK coordinates must be 32 bytes".into(),
            ));
        }
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        Ok(point)
    }

    /// Verify a raw (r‖s, 64-byte) ECDSA signature over `message`.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), OAuthError> {
        let point = self.sec1_uncompressed()?;
        let bad_sig = || OAuthError::InvalidDpopProof("signature verification failed".into());

        match self.alg()? {
            Alg::ES256 => {
                use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
                let vk = VerifyingKey::from_sec1_bytes(&point)
                    .map_err(|_| OAuthError::InvalidDpopProof("invalid P-256 point".into()))?;
                let sig = Signature::from_slice(signature).map_err(|_| bad_sig())?;
                vk.verify(message, &sig).map_err(|_| bad_sig())
            }
            Alg::ES256K => {
                use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
                let vk = VerifyingKey::from_sec1_bytes(&point)
                    .map_err(|_| OAuthError::InvalidDpopProof("invalid secp256k1 point".into()))?;
                let sig = Signature::from_slice(signature).map_err(|_| bad_sig())?;
                vk.verify(message, &sig).map_err(|_| bad_sig())
            }
        }
    }

    /// RFC 7638 JWK thumbprint, base64url-encoded — the `jkt` that binds an
    /// access token to a client key.
    ///
    /// The canonical form is a JSON object containing **only** the required
    /// members for the key type, with keys in lexicographic order and no
    /// whitespace. For EC keys that is exactly `crv`, `kty`, `x`, `y`. This is
    /// built by hand rather than via `serde_json::to_string` on a struct because
    /// the thumbprint must not depend on struct field order, on which optional
    /// fields happen to be populated, or on serde's escaping choices — any of
    /// which would silently change the `jkt` and unbind every live token.
    pub fn thumbprint(&self) -> String {
        let canonical = format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
            self.crv, self.kty, self.x, self.y
        );
        BASE64URL_NOPAD.encode(&Sha256::digest(canonical.as_bytes()))
    }
}

/// A JWK Set, as served from the authorization server's `jwks_uri`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    pub keys: Vec<PublicJwk>,
}

/// The authorization server's ES256 signing key.
///
/// Used to sign access tokens and to publish the corresponding public JWK. The
/// private scalar never leaves this struct; it is persisted encrypted through
/// the ordinary [`crate::storage::KeyStore`] path like any other key.
pub struct SigningKey {
    inner: p256::ecdsa::SigningKey,
    kid: String,
}

impl SigningKey {
    /// Generate a fresh P-256 signing key.
    pub fn generate() -> Self {
        let inner = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        Self::with_derived_kid(inner)
    }

    /// Import from a 32-byte private scalar (as returned by [`Self::export`]).
    pub fn import(scalar: &[u8]) -> Result<Self, OAuthError> {
        let inner = p256::ecdsa::SigningKey::from_slice(scalar)
            .map_err(|_| OAuthError::Internal("invalid P-256 signing key scalar".into()))?;
        Ok(Self::with_derived_kid(inner))
    }

    /// Derive the `kid` from the key's own thumbprint so that it is stable
    /// across restarts and cannot drift from the key it names.
    fn with_derived_kid(inner: p256::ecdsa::SigningKey) -> Self {
        let mut this = Self {
            inner,
            kid: String::new(),
        };
        this.kid = this.public_jwk_without_kid().thumbprint();
        this
    }

    /// The raw 32-byte private scalar, for encrypted storage.
    pub fn export(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The bare public JWK — `kty`/`crv`/`x`/`y` only.
    ///
    /// This is the form a DPoP proof embeds in its header: the thumbprint
    /// ignores `kid`/`alg`/`use` anyway, and omitting them keeps the proof
    /// header small and unambiguous.
    pub fn bare_public_jwk(&self) -> PublicJwk {
        self.public_jwk_without_kid()
    }

    fn public_jwk_without_kid(&self) -> PublicJwk {
        let point = self.inner.verifying_key().to_encoded_point(false);
        // `false` requests the uncompressed encoding, so both coordinates are
        // present; the unwraps cannot fire for a valid verifying key.
        PublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: BASE64URL_NOPAD.encode(point.x().expect("uncompressed point has x")),
            y: BASE64URL_NOPAD.encode(point.y().expect("uncompressed point has y")),
            kid: None,
            alg: None,
            use_: None,
        }
    }

    /// The public JWK to publish at `jwks_uri`, complete with `kid`/`alg`/`use`.
    pub fn public_jwk(&self) -> PublicJwk {
        PublicJwk {
            kid: Some(self.kid.clone()),
            alg: Some("ES256".into()),
            use_: Some("sig".into()),
            ..self.public_jwk_without_kid()
        }
    }

    /// Sign `message`, returning a raw 64-byte `r‖s` signature.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        use p256::ecdsa::{signature::Signer, Signature};
        let sig: Signature = self.inner.sign(message);
        sig.to_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumbprint_matches_rfc7638_vector() {
        // RFC 7638 §3.1 uses an RSA key; for EC the canonical members are
        // crv/kty/x/y. This vector is the P-256 key from RFC 7515 Appendix A.3,
        // whose thumbprint is stable and independently checkable.
        let jwk = PublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".into(),
            y: "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".into(),
            kid: Some("some-kid".into()),
            alg: Some("ES256".into()),
            use_: Some("sig".into()),
        };

        // The thumbprint must ignore kid/alg/use entirely.
        let bare = PublicJwk {
            kid: None,
            alg: None,
            use_: None,
            ..jwk.clone()
        };
        assert_eq!(
            jwk.thumbprint(),
            bare.thumbprint(),
            "thumbprint must depend only on crv/kty/x/y"
        );

        // Recompute the expected digest independently of the implementation.
        let canonical = r#"{"crv":"P-256","kty":"EC","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
        let expected = BASE64URL_NOPAD.encode(&Sha256::digest(canonical.as_bytes()));
        assert_eq!(jwk.thumbprint(), expected);
    }

    #[test]
    fn thumbprint_changes_with_key() {
        let a = SigningKey::generate().public_jwk();
        let b = SigningKey::generate().public_jwk();
        assert_ne!(a.thumbprint(), b.thumbprint());
    }

    #[test]
    fn signing_key_round_trips_through_export() {
        let key = SigningKey::generate();
        let imported = SigningKey::import(&key.export()).expect("import");
        assert_eq!(
            key.kid(),
            imported.kid(),
            "kid must be stable across import"
        );
        assert_eq!(key.public_jwk(), imported.public_jwk());
    }

    #[test]
    fn kid_is_the_thumbprint() {
        let key = SigningKey::generate();
        assert_eq!(key.kid(), key.public_jwk().thumbprint());
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let key = SigningKey::generate();
        let msg = b"the quick brown fox";
        let sig = key.sign(msg);
        key.public_jwk().verify(msg, &sig).expect("must verify");

        // A tampered message must not verify.
        assert!(key
            .public_jwk()
            .verify(b"a different message", &sig)
            .is_err());
        // Nor a signature from a different key.
        let other = SigningKey::generate();
        assert!(key.public_jwk().verify(msg, &other.sign(msg)).is_err());
    }

    #[test]
    fn private_key_material_is_rejected() {
        let with_d = serde_json::json!({
            "kty": "EC", "crv": "P-256", "x": "aaa", "y": "bbb", "d": "secret"
        });
        assert!(
            PublicJwk::reject_if_private(&with_d).is_err(),
            "a JWK carrying `d` must be rejected"
        );

        let public_only = serde_json::json!({"kty": "EC", "crv": "P-256", "x": "aaa", "y": "bbb"});
        assert!(PublicJwk::reject_if_private(&public_only).is_ok());
    }

    #[test]
    fn unsupported_curves_and_algs_are_rejected() {
        assert!(Alg::parse("RS256").is_err(), "RSA must not be accepted");
        assert!(
            Alg::parse("HS256").is_err(),
            "symmetric must not be accepted"
        );
        assert_eq!(Alg::parse("ES256").unwrap(), Alg::ES256);
        assert_eq!(Alg::parse("ES256K").unwrap(), Alg::ES256K);

        let p384 = PublicJwk {
            kty: "EC".into(),
            crv: "P-384".into(),
            x: "aaa".into(),
            y: "bbb".into(),
            kid: None,
            alg: None,
            use_: None,
        };
        assert!(p384.alg().is_err(), "P-384 is not in the atproto profile");

        let rsa = PublicJwk {
            kty: "RSA".into(),
            crv: "P-256".into(),
            x: "aaa".into(),
            y: "bbb".into(),
            kid: None,
            alg: None,
            use_: None,
        };
        assert!(rsa.alg().is_err(), "RSA kty must be rejected");
    }

    #[test]
    fn malformed_coordinates_error_rather_than_panic() {
        let bad = PublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "not!base64".into(),
            y: "bbb".into(),
            kid: None,
            alg: None,
            use_: None,
        };
        assert!(bad.verify(b"msg", &[0u8; 64]).is_err());

        // Correctly-encoded but wrong-length coordinates.
        let short = PublicJwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: BASE64URL_NOPAD.encode(&[0u8; 16]),
            y: BASE64URL_NOPAD.encode(&[0u8; 16]),
            kid: None,
            alg: None,
            use_: None,
        };
        assert!(short.verify(b"msg", &[0u8; 64]).is_err());
    }

    #[test]
    fn alg_curve_mapping_is_consistent() {
        assert_eq!(Alg::ES256.curve(), "P-256");
        assert_eq!(Alg::ES256K.curve(), "secp256k1");
    }
}
