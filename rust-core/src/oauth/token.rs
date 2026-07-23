//! Access-token minting and verification.
//!
//! Access tokens are ES256-signed JWTs with `typ: at+jwt`, so a resource request
//! is authorized with one signature check and no storage round trip. The
//! trade-off is that they cannot be revoked before they expire, which is why the
//! lifetime is short and revocation acts on the refresh chain — killing a
//! session stops new access tokens within one access-token lifetime.
//!
//! Every token carries `cnf.jkt`, binding it to the client's DPoP key. A token
//! without a matching DPoP proof is worthless, which is what makes the short
//! non-revocable window acceptable.

use serde::{Deserialize, Serialize};

use crate::oauth::jwk::SigningKey;
use crate::oauth::{jws, now_unix, random_token, OAuthError, Scope};

/// How long an access token is valid. Short, because access tokens cannot be
/// revoked individually — see the module docs.
pub const ACCESS_TOKEN_TTL_SECS: u64 = 3_600;

/// How long a refresh token is valid if unused.
pub const REFRESH_TOKEN_TTL_SECS: u64 = 90 * 24 * 3_600;

/// How long an authorization code is valid. Deliberately tiny: a code is
/// redeemed within seconds by a correct client.
pub const AUTH_CODE_TTL_SECS: u64 = 60;

/// How long a pushed authorization request is valid — long enough for a user to
/// read a consent screen and type a password, not longer.
pub const PAR_TTL_SECS: u64 = 300;

/// RFC 7800 confirmation claim: the key the token is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cnf {
    /// RFC 7638 thumbprint of the client's DPoP public key.
    pub jkt: String,
}

/// Claims carried by an access token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// The authorization server's issuer URL.
    pub iss: String,
    /// The authenticated account's DID.
    pub sub: String,
    /// The resource server this token is for — this PDS's own DID.
    pub aud: String,
    /// The client this token was issued to.
    pub client_id: String,
    /// Space-delimited granted scopes.
    pub scope: String,
    pub jti: String,
    pub iat: u64,
    pub exp: u64,
    pub cnf: Cnf,
}

impl AccessTokenClaims {
    /// Parse the `scope` claim.
    pub fn scope(&self) -> Result<Scope, OAuthError> {
        Scope::parse(&self.scope)
    }
}

/// Mints and verifies this server's access tokens.
pub struct TokenIssuer {
    key: SigningKey,
    /// Issuer URL, e.g. `https://pds.example.com`.
    issuer: String,
    /// This PDS's service DID, e.g. `did:web:pds.example.com`.
    audience: String,
}

impl TokenIssuer {
    pub fn new(key: SigningKey, issuer: String, audience: String) -> Self {
        Self {
            key,
            issuer,
            audience,
        }
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Mint an access token bound to `jkt`. Returns the token and its lifetime.
    pub fn issue_access_token(
        &self,
        did: &str,
        client_id: &str,
        scope: &Scope,
        jkt: &str,
    ) -> Result<(String, u64), OAuthError> {
        let now = now_unix();
        let claims = AccessTokenClaims {
            iss: self.issuer.clone(),
            sub: did.to_string(),
            aud: self.audience.clone(),
            client_id: client_id.to_string(),
            scope: scope.to_string(),
            jti: random_token(16),
            iat: now,
            exp: now + ACCESS_TOKEN_TTL_SECS,
            cnf: Cnf {
                jkt: jkt.to_string(),
            },
        };
        let token = jws::sign(&self.key, "at+jwt", &claims)?;
        Ok((token, ACCESS_TOKEN_TTL_SECS))
    }

    /// Verify an access token and return its claims.
    ///
    /// Checks the signature, `typ`, expiry, issuer, and audience. It does **not**
    /// check the DPoP binding — the caller must additionally verify a DPoP proof
    /// and compare its `jkt` against `claims.cnf.jkt`. That is deliberately the
    /// caller's job because only the caller knows the request method and URI the
    /// proof has to match.
    pub fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, OAuthError> {
        let claims: AccessTokenClaims = jws::verify(&self.key, "at+jwt", token)?;

        let now = now_unix();
        if claims.exp <= now {
            return Err(OAuthError::InvalidToken("access token has expired".into()));
        }
        // A token minted by a different issuer, or intended for a different
        // resource server, must not be accepted here even though it may carry a
        // valid signature in its own domain.
        if claims.iss != self.issuer {
            return Err(OAuthError::InvalidToken(
                "access token issuer does not match".into(),
            ));
        }
        if claims.aud != self.audience {
            return Err(OAuthError::InvalidToken(
                "access token audience does not match".into(),
            ));
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://pds.example.com";
    const AUDIENCE: &str = "did:web:pds.example.com";
    const DID: &str = "did:plc:abc123";
    const JKT: &str = "test-thumbprint";

    fn issuer() -> TokenIssuer {
        TokenIssuer::new(
            SigningKey::generate(),
            ISSUER.to_string(),
            AUDIENCE.to_string(),
        )
    }

    fn scope() -> Scope {
        Scope::parse("atproto transition:generic").unwrap()
    }

    #[test]
    fn issue_then_verify_round_trip() {
        let iss = issuer();
        let (token, ttl) = iss
            .issue_access_token(DID, "https://app.test/client-metadata.json", &scope(), JKT)
            .unwrap();
        assert_eq!(ttl, ACCESS_TOKEN_TTL_SECS);

        let claims = iss.verify_access_token(&token).unwrap();
        assert_eq!(claims.sub, DID);
        assert_eq!(claims.iss, ISSUER);
        assert_eq!(claims.aud, AUDIENCE);
        assert_eq!(claims.cnf.jkt, JKT);
        assert_eq!(claims.scope().unwrap(), scope());
    }

    #[test]
    fn tokens_from_another_issuer_are_rejected() {
        let a = issuer();
        let b = issuer();
        let (token, _) = a.issue_access_token(DID, "client", &scope(), JKT).unwrap();
        assert!(
            b.verify_access_token(&token).is_err(),
            "a token signed by a different key must not verify"
        );
    }

    #[test]
    fn issuer_and_audience_mismatch_are_rejected() {
        let key = SigningKey::generate();
        let minting = TokenIssuer::new(key, ISSUER.into(), AUDIENCE.into());
        let (token, _) = minting.issue_access_token(DID, "c", &scope(), JKT).unwrap();

        // Same signing key, different expected issuer.
        let wrong_iss = TokenIssuer::new(
            SigningKey::import(&minting.signing_key().export()).unwrap(),
            "https://evil.example.com".into(),
            AUDIENCE.into(),
        );
        assert!(wrong_iss.verify_access_token(&token).is_err());

        // Same signing key, different expected audience.
        let wrong_aud = TokenIssuer::new(
            SigningKey::import(&minting.signing_key().export()).unwrap(),
            ISSUER.into(),
            "did:web:other.example.com".into(),
        );
        assert!(
            wrong_aud.verify_access_token(&token).is_err(),
            "a token for another resource server must not be accepted"
        );
    }

    #[test]
    fn expired_tokens_are_rejected() {
        let iss = issuer();
        let now = now_unix();
        let claims = AccessTokenClaims {
            iss: ISSUER.into(),
            sub: DID.into(),
            aud: AUDIENCE.into(),
            client_id: "c".into(),
            scope: scope().to_string(),
            jti: random_token(16),
            iat: now - 7_200,
            exp: now - 3_600,
            cnf: Cnf { jkt: JKT.into() },
        };
        let token = jws::sign(iss.signing_key(), "at+jwt", &claims).unwrap();
        assert!(iss.verify_access_token(&token).is_err());
    }

    #[test]
    fn a_dpop_proof_cannot_be_presented_as_an_access_token() {
        let iss = issuer();
        let claims = serde_json::json!({"jti": "x", "htm": "POST", "htu": "https://a.test"});
        let proof = jws::sign(iss.signing_key(), "dpop+jwt", &claims).unwrap();
        assert!(
            iss.verify_access_token(&proof).is_err(),
            "typ must keep the two token kinds apart even under one key"
        );
    }

    #[test]
    fn each_token_gets_a_distinct_jti() {
        let iss = issuer();
        let (a, _) = iss.issue_access_token(DID, "c", &scope(), JKT).unwrap();
        let (b, _) = iss.issue_access_token(DID, "c", &scope(), JKT).unwrap();
        let ca = iss.verify_access_token(&a).unwrap();
        let cb = iss.verify_access_token(&b).unwrap();
        assert_ne!(ca.jti, cb.jti);
    }
}
