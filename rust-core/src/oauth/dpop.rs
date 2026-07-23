//! DPoP — Demonstrating Proof of Possession (RFC 9449).
//!
//! Every token request and every authenticated XRPC request in the atproto
//! OAuth profile carries a `DPoP` header holding a single-use JWT signed by the
//! client's own key. That binds the token to the key: a stolen access token is
//! useless without the private key that minted its proofs.
//!
//! # Nonces are derived, not stored
//!
//! The server requires a nonce in each proof and supplies it via the
//! `DPoP-Nonce` response header. Rather than persisting issued nonces, each is
//! derived from a server secret and the current time window:
//!
//! ```text
//! nonce(w) = base64url(SHA-256(secret || w))    where w = now / window_secs
//! ```
//!
//! This is unforgeable without the secret, rotates automatically, needs no
//! storage, and costs one hash to check. The previous window is also accepted so
//! a proof built moments before a rollover still validates.
//!
//! Nonces bound *freshness*. Uniqueness is a separate job, handled by the `jti`
//! replay cache — the two are often conflated, and dropping either one reopens
//! replay.

use data_encoding::BASE64URL_NOPAD;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::oauth::jwk::PublicJwk;
use crate::oauth::jws::Unverified;
use crate::oauth::store::OAuthStore;
use crate::oauth::{constant_time_eq, now_unix, OAuthError};

/// How long a nonce stays valid. The previous window is accepted too, so the
/// effective acceptance range is between one and two of these.
const NONCE_WINDOW_SECS: u64 = 300;

/// How far a proof's `iat` may be from server time, in either direction.
///
/// Bounds both clock skew and how long the replay cache must remember a `jti`.
const MAX_PROOF_AGE_SECS: u64 = 300;

/// The claims carried by a DPoP proof JWT.
#[derive(Debug, Deserialize)]
struct DpopClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: u64,
    #[serde(default)]
    nonce: Option<String>,
    /// base64url SHA-256 of the associated access token. Required whenever the
    /// proof accompanies one.
    #[serde(default)]
    ath: Option<String>,
}

/// A verified DPoP proof.
///
/// Only constructed by [`DpopVerifier::verify`], so holding one is evidence
/// every check in RFC 9449 §4.3 passed.
#[derive(Debug, Clone)]
pub struct DpopProof {
    /// RFC 7638 thumbprint of the proof's key — the `cnf.jkt` an issued token
    /// gets bound to.
    pub jkt: String,
    pub jti: String,
    pub htm: String,
    pub htu: String,
    pub iat: u64,
    pub ath: Option<String>,
}

/// Verifies DPoP proofs and issues nonces.
pub struct DpopVerifier {
    nonce_secret: Vec<u8>,
}

impl DpopVerifier {
    /// `nonce_secret` must be stable across restarts within a deployment (or
    /// clients simply retry once) and secret — anyone holding it can mint
    /// nonces, which removes the freshness guarantee.
    pub fn new(nonce_secret: Vec<u8>) -> Self {
        Self { nonce_secret }
    }

    fn nonce_for_window(&self, window: u64) -> String {
        let mut h = Sha256::new();
        h.update(&self.nonce_secret);
        h.update(window.to_be_bytes());
        BASE64URL_NOPAD.encode(&h.finalize())
    }

    /// The nonce to advertise in the `DPoP-Nonce` response header.
    pub fn current_nonce(&self) -> String {
        self.nonce_for_window(now_unix() / NONCE_WINDOW_SECS)
    }

    /// Whether `nonce` is one this server issued recently.
    fn nonce_is_valid(&self, nonce: &str) -> bool {
        let window = now_unix() / NONCE_WINDOW_SECS;
        // Constant-time compare: a timing oracle here would let an attacker
        // recover a valid nonce without the secret.
        constant_time_eq(nonce, &self.nonce_for_window(window))
            || constant_time_eq(nonce, &self.nonce_for_window(window.saturating_sub(1)))
    }

    /// Verify a DPoP proof against the request it accompanies.
    ///
    /// `access_token` must be supplied whenever the request also carries one, so
    /// the `ath` binding can be checked. Passing `None` on a request that *does*
    /// carry a token would let a proof minted for one token authorize another.
    ///
    /// `require_nonce` is true for the token endpoint and for resource requests;
    /// it is only false where the profile permits a nonce-less first attempt.
    #[allow(clippy::too_many_arguments)]
    pub async fn verify(
        &self,
        store: &dyn OAuthStore,
        proof: &str,
        method: &str,
        uri: &str,
        access_token: Option<&str>,
        require_nonce: bool,
    ) -> Result<DpopProof, OAuthError> {
        let bad = |m: &str| OAuthError::InvalidDpopProof(m.to_string());

        // (2) well-formed JWT
        let unverified = Unverified::parse(proof)?;

        // (4) typ must be dpop+jwt — stops an access token or any other JWT the
        // server itself minted from being replayed as a proof.
        match unverified.header_str("typ") {
            Some("dpop+jwt") => {}
            _ => return Err(bad("DPoP proof must have typ=dpop+jwt")),
        }

        // (6) the public key lives in the header
        let jwk_value = unverified
            .header
            .get("jwk")
            .ok_or_else(|| bad("DPoP proof header has no jwk"))?;
        PublicJwk::reject_if_private(jwk_value)?;
        let jwk: PublicJwk = serde_json::from_value(jwk_value.clone())
            .map_err(|e| bad(&format!("DPoP proof jwk is not a supported EC key: {e}")))?;

        // (5) + (7) signature verification. `verify_with` also rejects `alg:
        // none` and any header alg that disagrees with the key's curve.
        let claims: DpopClaims = unverified.verify_with(&jwk)?;

        // (8) HTTP method binding.
        if !claims.htm.eq_ignore_ascii_case(method) {
            return Err(bad("DPoP htm does not match the request method"));
        }

        // (9) URI binding, compared on the normalized form (query and fragment
        // removed, per RFC 9449).
        if normalize_htu(&claims.htu) != normalize_htu(uri) {
            return Err(bad("DPoP htu does not match the request URI"));
        }

        // (12) freshness. Checked in both directions: a far-future `iat` would
        // otherwise let a proof be minted now and replayed long after its `jti`
        // has aged out of the replay cache.
        let now = now_unix();
        let age = now.abs_diff(claims.iat);
        if age > MAX_PROOF_AGE_SECS {
            return Err(bad("DPoP proof iat is outside the acceptable window"));
        }

        // (10) nonce.
        if require_nonce {
            match claims.nonce.as_deref() {
                None => return Err(OAuthError::UseDpopNonce("a DPoP nonce is required".into())),
                Some(n) if !self.nonce_is_valid(n) => {
                    return Err(OAuthError::UseDpopNonce(
                        "the supplied DPoP nonce is stale or unrecognised".into(),
                    ))
                }
                Some(_) => {}
            }
        }

        // (11) access-token binding.
        match (access_token, claims.ath.as_deref()) {
            (Some(token), Some(ath)) => {
                let expected = BASE64URL_NOPAD.encode(&Sha256::digest(token.as_bytes()));
                if !constant_time_eq(ath, &expected) {
                    return Err(bad("DPoP ath does not match the presented access token"));
                }
            }
            (Some(_), None) => {
                return Err(bad(
                    "DPoP proof must carry ath when an access token is presented",
                ))
            }
            // A proof with `ath` but no token presented is a client bug, not an
            // attack — there is nothing it could authorize. Accept it.
            (None, _) => {}
        }

        // (13) replay. Last, so a replayed proof that would have failed an
        // earlier check does not consume a cache slot.
        let jti_expires = now + MAX_PROOF_AGE_SECS;
        if !store.record_dpop_jti(&claims.jti, jti_expires).await? {
            return Err(bad("DPoP proof jti has already been used"));
        }

        Ok(DpopProof {
            jkt: jwk.thumbprint(),
            jti: claims.jti,
            htm: claims.htm,
            htu: claims.htu,
            iat: claims.iat,
            ath: claims.ath,
        })
    }
}

/// Normalize a URI for `htu` comparison.
///
/// RFC 9449 compares the request URI without query or fragment. Scheme and
/// authority are lowercased and a default port is dropped, so that
/// `HTTPS://Pds.Example.com:443/x` and `https://pds.example.com/x` — which
/// address the same resource — compare equal. The path keeps its case, since
/// paths are case-sensitive.
fn normalize_htu(uri: &str) -> String {
    let without_fragment = uri.split('#').next().unwrap_or("");
    let base = without_fragment.split('?').next().unwrap_or("");

    let Some(scheme_end) = base.find("://") else {
        return base.to_string();
    };
    let (scheme, rest) = base.split_at(scheme_end);
    let rest = &rest[3..]; // skip "://"

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };

    let scheme = scheme.to_ascii_lowercase();
    let authority = authority.to_ascii_lowercase();
    let authority = match scheme.as_str() {
        "https" => authority.strip_suffix(":443").unwrap_or(&authority),
        "http" => authority.strip_suffix(":80").unwrap_or(&authority),
        _ => &authority,
    };

    // A bare origin and one with a trailing slash denote the same resource.
    let path = if path == "/" { "" } else { path };
    format!("{scheme}://{authority}{path}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::jwk::SigningKey;
    use crate::storage::MemoryStore;

    /// Mint a DPoP proof the way a correct client would.
    #[allow(clippy::too_many_arguments)]
    fn make_proof(
        key: &SigningKey,
        htm: &str,
        htu: &str,
        iat: u64,
        jti: &str,
        nonce: Option<&str>,
        ath: Option<&str>,
        typ: &str,
    ) -> String {
        let header = serde_json::json!({
            "typ": typ,
            "alg": "ES256",
            "jwk": key.bare_public_jwk(),
        });
        let mut payload = serde_json::json!({
            "jti": jti, "htm": htm, "htu": htu, "iat": iat,
        });
        if let Some(n) = nonce {
            payload["nonce"] = serde_json::Value::String(n.into());
        }
        if let Some(a) = ath {
            payload["ath"] = serde_json::Value::String(a.into());
        }

        let h = BASE64URL_NOPAD.encode(&serde_json::to_vec(&header).unwrap());
        let p = BASE64URL_NOPAD.encode(&serde_json::to_vec(&payload).unwrap());
        let signing_input = format!("{h}.{p}");
        let sig = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", BASE64URL_NOPAD.encode(&sig))
    }

    fn verifier() -> DpopVerifier {
        DpopVerifier::new(b"test-nonce-secret".to_vec())
    }

    const URI: &str = "https://pds.example.com/oauth/token";

    #[tokio::test]
    async fn valid_proof_verifies() {
        let store = MemoryStore::new();
        let v = verifier();
        let key = SigningKey::generate();
        let proof = make_proof(
            &key,
            "POST",
            URI,
            now_unix(),
            "jti-1",
            Some(&v.current_nonce()),
            None,
            "dpop+jwt",
        );

        let ok = v
            .verify(&store, &proof, "POST", URI, None, true)
            .await
            .expect("a well-formed proof must verify");
        assert_eq!(ok.jkt, key.public_jwk().thumbprint());
        assert_eq!(ok.jti, "jti-1");
    }

    #[tokio::test]
    async fn replayed_jti_is_rejected() {
        let store = MemoryStore::new();
        let v = verifier();
        let key = SigningKey::generate();
        let nonce = v.current_nonce();
        let proof = make_proof(
            &key,
            "POST",
            URI,
            now_unix(),
            "jti-replay",
            Some(&nonce),
            None,
            "dpop+jwt",
        );

        v.verify(&store, &proof, "POST", URI, None, true)
            .await
            .expect("first use succeeds");
        assert!(
            v.verify(&store, &proof, "POST", URI, None, true)
                .await
                .is_err(),
            "the same jti must not be accepted twice"
        );
    }

    #[tokio::test]
    async fn method_and_uri_are_bound() {
        let store = MemoryStore::new();
        let v = verifier();
        let key = SigningKey::generate();
        let nonce = v.current_nonce();

        let proof = make_proof(
            &key,
            "POST",
            URI,
            now_unix(),
            "jti-m",
            Some(&nonce),
            None,
            "dpop+jwt",
        );
        assert!(
            v.verify(&store, &proof, "GET", URI, None, true)
                .await
                .is_err(),
            "a proof for POST must not authorize GET"
        );

        let proof2 = make_proof(
            &key,
            "POST",
            URI,
            now_unix(),
            "jti-u",
            Some(&nonce),
            None,
            "dpop+jwt",
        );
        assert!(
            v.verify(
                &store,
                &proof2,
                "POST",
                "https://pds.example.com/oauth/revoke",
                None,
                true
            )
            .await
            .is_err(),
            "a proof for one endpoint must not authorize another"
        );
    }

    #[tokio::test]
    async fn stale_and_future_iat_are_rejected() {
        let store = MemoryStore::new();
        let v = verifier();
        let key = SigningKey::generate();
        let nonce = v.current_nonce();

        let old = make_proof(
            &key,
            "POST",
            URI,
            now_unix() - MAX_PROOF_AGE_SECS - 60,
            "jti-old",
            Some(&nonce),
            None,
            "dpop+jwt",
        );
        assert!(v
            .verify(&store, &old, "POST", URI, None, true)
            .await
            .is_err());

        let future = make_proof(
            &key,
            "POST",
            URI,
            now_unix() + MAX_PROOF_AGE_SECS + 60,
            "jti-future",
            Some(&nonce),
            None,
            "dpop+jwt",
        );
        assert!(
            v.verify(&store, &future, "POST", URI, None, true)
                .await
                .is_err(),
            "a far-future iat must be rejected, not just a stale one"
        );
    }

    #[tokio::test]
    async fn missing_or_bad_nonce_asks_for_one() {
        let store = MemoryStore::new();
        let v = verifier();
        let key = SigningKey::generate();

        let no_nonce = make_proof(
            &key,
            "POST",
            URI,
            now_unix(),
            "jti-n1",
            None,
            None,
            "dpop+jwt",
        );
        assert!(matches!(
            v.verify(&store, &no_nonce, "POST", URI, None, true).await,
            Err(OAuthError::UseDpopNonce(_))
        ));

        let bad_nonce = make_proof(
            &key,
            "POST",
            URI,
            now_unix(),
            "jti-n2",
            Some("not-a-real-nonce"),
            None,
            "dpop+jwt",
        );
        assert!(matches!(
            v.verify(&store, &bad_nonce, "POST", URI, None, true).await,
            Err(OAuthError::UseDpopNonce(_))
        ));

        // With nonce not required, the same nonce-less proof passes.
        let no_nonce2 = make_proof(
            &key,
            "POST",
            URI,
            now_unix(),
            "jti-n3",
            None,
            None,
            "dpop+jwt",
        );
        assert!(v
            .verify(&store, &no_nonce2, "POST", URI, None, false)
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn ath_binds_the_access_token() {
        let store = MemoryStore::new();
        let v = verifier();
        let key = SigningKey::generate();
        let nonce = v.current_nonce();
        let token = "the-access-token";
        let ath = BASE64URL_NOPAD.encode(&Sha256::digest(token.as_bytes()));

        let good = make_proof(
            &key,
            "POST",
            URI,
            now_unix(),
            "jti-a1",
            Some(&nonce),
            Some(&ath),
            "dpop+jwt",
        );
        assert!(v
            .verify(&store, &good, "POST", URI, Some(token), true)
            .await
            .is_ok());

        // A proof bound to one token must not authorize a different one.
        let other = make_proof(
            &key,
            "POST",
            URI,
            now_unix(),
            "jti-a2",
            Some(&nonce),
            Some(&ath),
            "dpop+jwt",
        );
        assert!(v
            .verify(&store, &other, "POST", URI, Some("a-different-token"), true)
            .await
            .is_err());

        // Presenting a token with no ath in the proof must fail.
        let missing = make_proof(
            &key,
            "POST",
            URI,
            now_unix(),
            "jti-a3",
            Some(&nonce),
            None,
            "dpop+jwt",
        );
        assert!(v
            .verify(&store, &missing, "POST", URI, Some(token), true)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn wrong_typ_is_rejected() {
        let store = MemoryStore::new();
        let v = verifier();
        let key = SigningKey::generate();
        let proof = make_proof(
            &key,
            "POST",
            URI,
            now_unix(),
            "jti-t",
            Some(&v.current_nonce()),
            None,
            "at+jwt",
        );
        assert!(
            v.verify(&store, &proof, "POST", URI, None, true)
                .await
                .is_err(),
            "only typ=dpop+jwt may be accepted as a proof"
        );
    }

    #[tokio::test]
    async fn tampered_signature_is_rejected() {
        let store = MemoryStore::new();
        let v = verifier();
        let key = SigningKey::generate();
        let proof = make_proof(
            &key,
            "POST",
            URI,
            now_unix(),
            "jti-s",
            Some(&v.current_nonce()),
            None,
            "dpop+jwt",
        );
        let mut parts: Vec<String> = proof.split('.').map(String::from).collect();
        parts[2] = BASE64URL_NOPAD.encode(&[0u8; 64]);
        assert!(v
            .verify(&store, &parts.join("."), "POST", URI, None, true)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn private_key_in_header_is_rejected() {
        let store = MemoryStore::new();
        let v = verifier();
        let key = SigningKey::generate();
        let mut jwk = serde_json::to_value(key.bare_public_jwk()).unwrap();
        jwk["d"] = serde_json::Value::String("private-scalar".into());

        let header = serde_json::json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk});
        let payload = serde_json::json!({
            "jti": "jti-priv", "htm": "POST", "htu": URI, "iat": now_unix(),
            "nonce": v.current_nonce(),
        });
        let h = BASE64URL_NOPAD.encode(&serde_json::to_vec(&header).unwrap());
        let p = BASE64URL_NOPAD.encode(&serde_json::to_vec(&payload).unwrap());
        let si = format!("{h}.{p}");
        let proof = format!("{si}.{}", BASE64URL_NOPAD.encode(&key.sign(si.as_bytes())));

        assert!(v
            .verify(&store, &proof, "POST", URI, None, true)
            .await
            .is_err());
    }

    #[test]
    fn nonce_rotates_and_accepts_previous_window() {
        let v = verifier();
        let now = now_unix();
        let w = now / NONCE_WINDOW_SECS;

        assert!(v.nonce_is_valid(&v.nonce_for_window(w)));
        assert!(
            v.nonce_is_valid(&v.nonce_for_window(w - 1)),
            "the previous window must still be accepted across a rollover"
        );
        assert!(
            !v.nonce_is_valid(&v.nonce_for_window(w - 2)),
            "a nonce two windows old must be rejected"
        );
        assert!(!v.nonce_is_valid("garbage"));

        // A different secret yields different nonces.
        let other = DpopVerifier::new(b"a-different-secret".to_vec());
        assert!(!v.nonce_is_valid(&other.current_nonce()));
    }

    #[test]
    fn htu_normalization() {
        // Query and fragment are stripped.
        assert_eq!(
            normalize_htu("https://a.test/path?x=1#frag"),
            "https://a.test/path"
        );
        // Scheme and host are case-insensitive; the path is not.
        assert_eq!(normalize_htu("HTTPS://A.TEST/Path"), "https://a.test/Path");
        // Default ports are equivalent to no port.
        assert_eq!(normalize_htu("https://a.test:443/p"), "https://a.test/p");
        assert_eq!(normalize_htu("http://a.test:80/p"), "http://a.test/p");
        // A non-default port is significant.
        assert_eq!(
            normalize_htu("https://a.test:8443/p"),
            "https://a.test:8443/p"
        );
        // Bare origin, with and without a trailing slash.
        assert_eq!(normalize_htu("https://a.test"), "https://a.test");
        assert_eq!(normalize_htu("https://a.test/"), "https://a.test");
        // Garbage in, no panic out.
        assert_eq!(normalize_htu(""), "");
        assert_eq!(normalize_htu("not-a-uri"), "not-a-uri");
    }
}
