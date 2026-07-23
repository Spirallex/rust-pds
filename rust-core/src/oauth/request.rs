//! Authorization request validation — the PAR entry point.
//!
//! Because PAR is mandatory in the atproto profile, this is the *only* place
//! authorization parameters enter the system. Everything downstream reads a
//! [`StoredPushedRequest`] that was validated here, so the authorization
//! endpoint never has to re-derive trust from query parameters.

use crate::oauth::client::{ClientId, ClientMetadata};
use crate::oauth::pkce::CodeChallenge;
use crate::oauth::store::StoredPushedRequest;
use crate::oauth::{now_unix, random_token, store, token, OAuthError, Scope};

/// Raw parameters as submitted to the PAR endpoint.
///
/// Every field is untrusted. `Option` here means "the client may omit it",
/// not "optional to check".
#[derive(Debug, Clone, Default)]
pub struct PushedRequest {
    pub client_id: String,
    pub response_type: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub login_hint: Option<String>,
}

/// A validated authorization request, ready to be stored and shown to the user.
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// The one-time handle returned to the client as `request_uri`.
    pub request_uri: String,
    pub stored: StoredPushedRequest,
    /// Resolved client metadata, for rendering the consent screen.
    pub client: ClientMetadata,
}

/// The `request_uri` scheme the profile uses for PAR handles.
const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

impl PushedRequest {
    /// Validate against resolved client metadata and produce a storable request.
    ///
    /// `dpop_jkt` is the thumbprint from the DPoP proof on the PAR request
    /// itself, when the client sent one. Carrying it forward lets the token
    /// endpoint insist that the same key completes the flow.
    pub fn validate(
        self,
        client_id: &ClientId,
        client: ClientMetadata,
        dpop_jkt: Option<String>,
    ) -> Result<AuthorizationRequest, OAuthError> {
        let bad = |m: &str| OAuthError::InvalidRequest(m.to_string());

        // Only the authorization-code flow exists in this profile; the implicit
        // and hybrid flows are gone, so anything else is a downgrade attempt or
        // a badly configured client.
        if self.response_type != "code" {
            return Err(bad("response_type must be `code`"));
        }

        // `state` is the client's CSRF defence. It is optional in bare OAuth
        // when PKCE is present, but requiring it costs the client nothing and
        // removes a class of cross-session mix-up.
        let state = match self.state {
            Some(s) if !s.is_empty() => s,
            _ => return Err(bad("state is required")),
        };

        // A redirect_uri must be present *and* registered. Falling back to "the
        // client's only registered URI" when omitted would mean a request whose
        // delivery address was never explicitly stated by the client.
        let redirect_uri = self
            .redirect_uri
            .ok_or_else(|| bad("redirect_uri is required"))?;
        if !client.allows_redirect_uri(&redirect_uri) {
            return Err(OAuthError::InvalidRequest(
                "redirect_uri is not registered for this client".into(),
            ));
        }

        // Scope: valid on its own terms, and within what the client registered.
        let requested = Scope::parse(self.scope.as_deref().unwrap_or(""))?;
        if !client.scope.is_empty() {
            let declared = Scope::parse(&client.scope)?;
            if !requested.is_subset_of(&declared) {
                return Err(OAuthError::InvalidScope(
                    "requested scope exceeds the client's registered scope".into(),
                ));
            }
        }

        let challenge = CodeChallenge::parse(
            self.code_challenge
                .as_deref()
                .ok_or_else(|| bad("code_challenge is required"))?,
            self.code_challenge_method.as_deref(),
        )?;

        // The handle is a fresh 256-bit random value; it is a bearer credential
        // for this pending request, so it is stored hashed like any other.
        let handle = random_token(32);
        let request_uri = format!("{REQUEST_URI_PREFIX}{handle}");

        Ok(AuthorizationRequest {
            stored: StoredPushedRequest {
                request_uri_hash: store::hash_secret(&request_uri),
                client_id: client_id.as_str().to_string(),
                redirect_uri,
                scope: requested.to_string(),
                state,
                code_challenge: challenge.challenge,
                dpop_jkt,
                login_hint: self.login_hint,
                expires_at: now_unix() + token::PAR_TTL_SECS,
            },
            request_uri,
            client,
        })
    }
}

/// Reject a `request_uri` that is not one of ours before hashing and lookup.
///
/// Cheap, and it keeps obviously-foreign values out of the store lookup path.
pub fn validate_request_uri(request_uri: &str) -> Result<(), OAuthError> {
    if !request_uri.starts_with(REQUEST_URI_PREFIX) {
        return Err(OAuthError::InvalidRequest(
            "request_uri is not a recognised pushed-request handle".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: &str = "https://app.example.com/client-metadata.json";
    const REDIRECT: &str = "https://app.example.com/callback";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    fn client_id() -> ClientId {
        ClientId::parse(CLIENT).unwrap()
    }

    fn metadata() -> ClientMetadata {
        ClientMetadata {
            client_id: CLIENT.into(),
            client_name: Some("App".into()),
            redirect_uris: vec![REDIRECT.into()],
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            scope: "atproto transition:generic".into(),
            token_endpoint_auth_method: "none".into(),
            dpop_bound_access_tokens: true,
            application_type: Some("web".into()),
            jwks_uri: None,
            jwks: None,
            client_uri: None,
            logo_uri: None,
            policy_uri: None,
            tos_uri: None,
        }
    }

    fn request() -> PushedRequest {
        PushedRequest {
            client_id: CLIENT.into(),
            response_type: "code".into(),
            redirect_uri: Some(REDIRECT.into()),
            scope: Some("atproto transition:generic".into()),
            state: Some("client-state-123".into()),
            code_challenge: Some(CHALLENGE.into()),
            code_challenge_method: Some("S256".into()),
            login_hint: None,
        }
    }

    #[test]
    fn a_well_formed_request_validates() {
        let out = request().validate(&client_id(), metadata(), None).unwrap();
        assert!(out.request_uri.starts_with(REQUEST_URI_PREFIX));
        assert_eq!(out.stored.redirect_uri, REDIRECT);
        assert_eq!(out.stored.state, "client-state-123");
        assert_eq!(out.stored.scope, "atproto transition:generic");
        assert_eq!(
            out.stored.request_uri_hash,
            store::hash_secret(&out.request_uri),
            "the stored handle must be the hash of the returned request_uri"
        );
        assert!(
            !out.stored.request_uri_hash.contains(&out.request_uri),
            "the raw handle must not be stored"
        );
    }

    #[test]
    fn each_request_gets_a_distinct_handle() {
        let a = request().validate(&client_id(), metadata(), None).unwrap();
        let b = request().validate(&client_id(), metadata(), None).unwrap();
        assert_ne!(a.request_uri, b.request_uri);
    }

    #[test]
    fn dpop_jkt_is_carried_through() {
        let out = request()
            .validate(&client_id(), metadata(), Some("thumb-1".into()))
            .unwrap();
        assert_eq!(out.stored.dpop_jkt.as_deref(), Some("thumb-1"));
    }

    #[test]
    fn non_code_response_types_are_rejected() {
        for rt in ["token", "id_token", "code token", ""] {
            let mut r = request();
            r.response_type = rt.into();
            assert!(
                r.validate(&client_id(), metadata(), None).is_err(),
                "response_type {rt:?} must be rejected"
            );
        }
    }

    #[test]
    fn state_is_required() {
        for state in [None, Some(String::new())] {
            let mut r = request();
            r.state = state;
            assert!(r.validate(&client_id(), metadata(), None).is_err());
        }
    }

    #[test]
    fn unregistered_redirect_uri_is_rejected() {
        let mut r = request();
        r.redirect_uri = Some("https://evil.example.com/callback".into());
        assert!(r.validate(&client_id(), metadata(), None).is_err());

        let mut r = request();
        r.redirect_uri = None;
        assert!(
            r.validate(&client_id(), metadata(), None).is_err(),
            "an omitted redirect_uri must not fall back to a registered one"
        );
    }

    #[test]
    fn scope_must_be_within_the_registered_scope() {
        let mut r = request();
        r.scope = Some("atproto transition:chat.bsky".into());
        assert!(
            r.validate(&client_id(), metadata(), None).is_err(),
            "a client must not request more than it registered"
        );

        // Narrowing is fine.
        let mut r = request();
        r.scope = Some("atproto".into());
        assert!(r.validate(&client_id(), metadata(), None).is_ok());
    }

    #[test]
    fn pkce_is_required_and_must_be_s256() {
        let mut r = request();
        r.code_challenge = None;
        assert!(r.validate(&client_id(), metadata(), None).is_err());

        let mut r = request();
        r.code_challenge_method = Some("plain".into());
        assert!(r.validate(&client_id(), metadata(), None).is_err());

        let mut r = request();
        r.code_challenge_method = None;
        assert!(
            r.validate(&client_id(), metadata(), None).is_err(),
            "an absent method must not default to plain"
        );
    }

    #[test]
    fn request_uri_prefix_is_checked() {
        assert!(validate_request_uri("urn:ietf:params:oauth:request_uri:abc").is_ok());
        for bad in ["abc", "https://evil.test/x", "", "urn:ietf:params:oauth:x"] {
            assert!(
                validate_request_uri(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn expiry_is_set_from_the_par_ttl() {
        let before = now_unix();
        let out = request().validate(&client_id(), metadata(), None).unwrap();
        assert!(out.stored.expires_at >= before + token::PAR_TTL_SECS);
        assert!(out.stored.expires_at <= now_unix() + token::PAR_TTL_SECS);
    }
}
