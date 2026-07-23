//! Client identity and client-metadata documents.
//!
//! atproto has no dynamic client registration. A `client_id` *is* an HTTPS URL,
//! and the document it serves is the client's registration. Two consequences
//! shape this module:
//!
//! - Fetching the document is a server-side HTTP request to a client-controlled
//!   URL, so the URL must be validated hard before anything dereferences it.
//!   That validation lives in [`ClientId::parse`] and the fetching lives in the
//!   server crate, which cannot construct a `ClientId` any other way.
//! - The document must claim the same `client_id` that was used to find it,
//!   or one client could serve another's registration.
//!
//! Development clients are the documented exception: `http://localhost` with
//! `redirect_uri` and `scope` as query parameters, and no document at all.

use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::oauth::{OAuthError, Scope};

/// A validated client identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientId {
    /// A normal client: an HTTPS URL serving a metadata document.
    Web(Url),
    /// A development client running on the developer's own machine. Carries its
    /// registration inline as query parameters instead of serving a document.
    Loopback {
        redirect_uris: Vec<String>,
        scope: Option<String>,
        raw: String,
    },
}

impl ClientId {
    /// Parse and validate a `client_id`.
    pub fn parse(raw: &str) -> Result<Self, OAuthError> {
        let bad = |m: &str| OAuthError::InvalidClient(m.to_string());

        let url = Url::parse(raw).map_err(|e| bad(&format!("client_id is not a URL: {e}")))?;

        // Credentials in a client_id have no meaning and would be sent onward
        // when the document is fetched.
        if !url.username().is_empty() || url.password().is_some() {
            return Err(bad("client_id must not contain credentials"));
        }
        // A fragment is never transmitted to the server that would serve the
        // document, so two client_ids differing only by fragment would collide.
        if url.fragment().is_some() {
            return Err(bad("client_id must not contain a fragment"));
        }

        match url.scheme() {
            "http" => Self::parse_loopback(raw, &url),
            "https" => Self::parse_web(url),
            other => Err(bad(&format!(
                "client_id scheme must be https (or http for localhost), got {other}"
            ))),
        }
    }

    fn parse_web(url: Url) -> Result<Self, OAuthError> {
        let bad = |m: &str| OAuthError::InvalidClient(m.to_string());

        match url.host() {
            // An IP-literal client_id cannot be tied to a domain the operator
            // can reason about, and lets a client point the server's fetch at
            // an arbitrary address.
            Some(Host::Domain(d)) => {
                if d == "localhost" || d.ends_with(".localhost") {
                    return Err(bad("localhost clients must use the http:// loopback form"));
                }
            }
            Some(_) => {
                return Err(bad(
                    "client_id host must be a domain name, not an IP address",
                ))
            }
            None => return Err(bad("client_id must have a host")),
        }

        // An explicit non-default port would let two client_ids share a
        // hostname; the profile requires the default.
        if url.port().is_some() {
            return Err(bad("client_id must not specify a port"));
        }

        // The document has to live somewhere specific. A bare origin is not a
        // document URL.
        if url.path().is_empty() || url.path() == "/" {
            return Err(bad(
                "client_id must include a path to the metadata document",
            ));
        }

        if url.query().is_some() {
            return Err(bad("client_id must not contain a query string"));
        }

        Ok(ClientId::Web(url))
    }

    /// `http://localhost` development clients (`http://127.0.0.1` and `[::1]`
    /// are *not* accepted as client_ids — the spec names `localhost`).
    fn parse_loopback(raw: &str, url: &Url) -> Result<Self, OAuthError> {
        let bad = |m: &str| OAuthError::InvalidClient(m.to_string());

        match url.host() {
            Some(Host::Domain("localhost")) => {}
            _ => return Err(bad("http client_id is only permitted for localhost")),
        }
        if url.port().is_some() {
            return Err(bad("localhost client_id must not specify a port"));
        }
        if !(url.path().is_empty() || url.path() == "/") {
            return Err(bad("localhost client_id must not have a path"));
        }

        let mut redirect_uris = Vec::new();
        let mut scope = None;
        for (k, v) in url.query_pairs() {
            match k.as_ref() {
                "redirect_uri" => redirect_uris.push(v.to_string()),
                "scope" => scope = Some(v.to_string()),
                other => {
                    return Err(bad(&format!(
                        "unsupported localhost client_id parameter: {other}"
                    )))
                }
            }
        }

        // With no explicit redirect_uri, the spec's defaults apply.
        if redirect_uris.is_empty() {
            redirect_uris = vec!["http://127.0.0.1/".to_string(), "http://[::1]/".to_string()];
        }

        Ok(ClientId::Loopback {
            redirect_uris,
            scope,
            raw: raw.to_string(),
        })
    }

    /// The canonical string form, as it appears in tokens and stored records.
    pub fn as_str(&self) -> &str {
        match self {
            ClientId::Web(u) => u.as_str(),
            ClientId::Loopback { raw, .. } => raw,
        }
    }

    /// Whether this client's registration must be fetched over the network.
    pub fn is_loopback(&self) -> bool {
        matches!(self, ClientId::Loopback { .. })
    }

    /// The metadata document for a loopback client, synthesized from its
    /// `client_id` query parameters. Web clients must fetch theirs instead.
    pub fn loopback_metadata(&self) -> Option<ClientMetadata> {
        match self {
            ClientId::Web(_) => None,
            ClientId::Loopback {
                redirect_uris,
                scope,
                raw,
            } => Some(ClientMetadata {
                client_id: raw.clone(),
                client_name: Some("Local development client".into()),
                redirect_uris: redirect_uris.clone(),
                grant_types: vec!["authorization_code".into(), "refresh_token".into()],
                response_types: vec!["code".into()],
                scope: scope.clone().unwrap_or_else(|| "atproto".into()),
                token_endpoint_auth_method: "none".into(),
                dpop_bound_access_tokens: true,
                application_type: Some("native".into()),
                jwks_uri: None,
                jwks: None,
                client_uri: None,
                logo_uri: None,
                policy_uri: None,
                tos_uri: None,
            }),
        }
    }
}

/// A client-metadata document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientMetadata {
    pub client_id: String,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub response_types: Vec<String>,
    #[serde(default)]
    pub scope: String,
    #[serde(default = "default_auth_method")]
    pub token_endpoint_auth_method: String,
    #[serde(default)]
    pub dpop_bound_access_tokens: bool,
    #[serde(default)]
    pub application_type: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    #[serde(default)]
    pub client_uri: Option<String>,
    #[serde(default)]
    pub logo_uri: Option<String>,
    #[serde(default)]
    pub policy_uri: Option<String>,
    #[serde(default)]
    pub tos_uri: Option<String>,
}

fn default_auth_method() -> String {
    "none".to_string()
}

impl ClientMetadata {
    /// Validate a fetched document against the `client_id` it was fetched for.
    pub fn validate(&self, client_id: &ClientId) -> Result<(), OAuthError> {
        let bad = |m: String| OAuthError::InvalidClient(m);

        // The document must claim the identity it was found under, or one client
        // could serve a document impersonating another.
        if self.client_id != client_id.as_str() {
            return Err(bad(format!(
                "client metadata declares client_id {} but was fetched as {}",
                self.client_id,
                client_id.as_str()
            )));
        }

        // The atproto profile mandates DPoP. A client that has not opted in
        // would receive tokens it cannot use, and accepting `false` here would
        // silently permit bearer-style tokens.
        if !self.dpop_bound_access_tokens {
            return Err(bad(
                "client metadata must set dpop_bound_access_tokens to true".into(),
            ));
        }

        if !self.grant_types.iter().any(|g| g == "authorization_code") {
            return Err(bad(
                "client metadata must include the authorization_code grant type".into(),
            ));
        }
        if !self.response_types.iter().any(|r| r == "code") {
            return Err(bad(
                "client metadata must include the `code` response type".into()
            ));
        }
        if self.redirect_uris.is_empty() {
            return Err(bad(
                "client metadata must declare at least one redirect_uri".into(),
            ));
        }

        match self.token_endpoint_auth_method.as_str() {
            "none" => {}
            "private_key_jwt" => {
                // A confidential client authenticates by signing an assertion,
                // which is unverifiable without its public keys.
                if self.jwks_uri.is_none() && self.jwks.is_none() {
                    return Err(bad(
                        "a private_key_jwt client must publish jwks or jwks_uri".into(),
                    ));
                }
            }
            other => {
                return Err(bad(format!(
                    "unsupported token_endpoint_auth_method: {other}"
                )))
            }
        }

        // The declared scope has to be one this server can actually grant, or
        // every authorization request from this client would fail later with a
        // more confusing error.
        if !self.scope.is_empty() {
            Scope::parse(&self.scope)?;
        }

        Ok(())
    }

    /// Whether `uri` is one of this client's registered redirect URIs.
    ///
    /// Exact string comparison, as OAuth 2.1 requires. No prefix or wildcard
    /// matching: a redirect URI is where an authorization code is delivered, and
    /// any loosening here is a code-interception vulnerability.
    pub fn allows_redirect_uri(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|u| u == uri)
    }

    /// A human-readable name for the consent screen, falling back to the
    /// `client_id` so the screen always identifies *something* concrete.
    pub fn display_name(&self) -> &str {
        self.client_name
            .as_deref()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or(&self.client_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEB_ID: &str = "https://app.example.com/client-metadata.json";

    fn valid_metadata() -> ClientMetadata {
        ClientMetadata {
            client_id: WEB_ID.into(),
            client_name: Some("Test App".into()),
            redirect_uris: vec!["https://app.example.com/callback".into()],
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

    // --- client_id parsing ---

    #[test]
    fn accepts_a_normal_https_client_id() {
        let id = ClientId::parse(WEB_ID).unwrap();
        assert_eq!(id.as_str(), WEB_ID);
        assert!(!id.is_loopback());
    }

    #[test]
    fn rejects_structurally_invalid_client_ids() {
        for (raw, why) in [
            (
                "http://app.example.com/meta.json",
                "plain http for a non-localhost host",
            ),
            ("ftp://app.example.com/meta.json", "non-http scheme"),
            (
                "https://app.example.com",
                "bare origin with no document path",
            ),
            ("https://app.example.com/", "root path is not a document"),
            ("https://app.example.com:8443/meta.json", "explicit port"),
            ("https://user:pw@app.example.com/meta.json", "credentials"),
            ("https://app.example.com/meta.json#frag", "fragment"),
            ("https://app.example.com/meta.json?x=1", "query string"),
            ("https://192.0.2.1/meta.json", "IP-literal host"),
            ("https://[2001:db8::1]/meta.json", "IPv6-literal host"),
            ("not-a-url", "not a URL at all"),
            ("", "empty"),
        ] {
            assert!(
                ClientId::parse(raw).is_err(),
                "{raw:?} must be rejected ({why})"
            );
        }
    }

    #[test]
    fn https_localhost_is_pushed_to_the_loopback_form() {
        assert!(
            ClientId::parse("https://localhost/meta.json").is_err(),
            "localhost must use the documented http:// loopback form"
        );
    }

    // --- loopback clients ---

    #[test]
    fn loopback_client_gets_default_redirect_uris() {
        let id = ClientId::parse("http://localhost").unwrap();
        assert!(id.is_loopback());
        let md = id.loopback_metadata().unwrap();
        assert!(md.allows_redirect_uri("http://127.0.0.1/"));
        assert!(md.allows_redirect_uri("http://[::1]/"));
        assert!(md.dpop_bound_access_tokens);
        md.validate(&id)
            .expect("synthesized metadata must be valid");
    }

    #[test]
    fn loopback_client_honours_explicit_parameters() {
        let raw = "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&scope=atproto";
        let id = ClientId::parse(raw).unwrap();
        let md = id.loopback_metadata().unwrap();
        assert_eq!(md.redirect_uris, vec!["http://127.0.0.1:9999/cb"]);
        assert_eq!(md.scope, "atproto");
        md.validate(&id).unwrap();
    }

    #[test]
    fn loopback_rejects_unknown_parameters_and_paths() {
        assert!(ClientId::parse("http://localhost?evil=1").is_err());
        assert!(ClientId::parse("http://localhost/some/path").is_err());
        assert!(ClientId::parse("http://localhost:3000").is_err());
        assert!(
            ClientId::parse("http://127.0.0.1").is_err(),
            "the spec names `localhost`, not a raw loopback IP"
        );
    }

    #[test]
    fn web_client_has_no_synthesized_metadata() {
        assert!(ClientId::parse(WEB_ID)
            .unwrap()
            .loopback_metadata()
            .is_none());
    }

    // --- metadata validation ---

    #[test]
    fn valid_metadata_passes() {
        let id = ClientId::parse(WEB_ID).unwrap();
        valid_metadata().validate(&id).unwrap();
    }

    #[test]
    fn metadata_must_claim_its_own_client_id() {
        let id = ClientId::parse(WEB_ID).unwrap();
        let mut md = valid_metadata();
        md.client_id = "https://evil.example.com/client-metadata.json".into();
        assert!(
            md.validate(&id).is_err(),
            "a document claiming another client_id must be rejected"
        );
    }

    #[test]
    fn dpop_is_mandatory() {
        let id = ClientId::parse(WEB_ID).unwrap();
        let mut md = valid_metadata();
        md.dpop_bound_access_tokens = false;
        assert!(md.validate(&id).is_err());
    }

    #[test]
    fn required_grant_and_response_types_are_enforced() {
        let id = ClientId::parse(WEB_ID).unwrap();

        let mut md = valid_metadata();
        md.grant_types = vec!["refresh_token".into()];
        assert!(md.validate(&id).is_err(), "authorization_code is required");

        let mut md = valid_metadata();
        md.response_types = vec!["token".into()];
        assert!(
            md.validate(&id).is_err(),
            "the code response type is required"
        );

        let mut md = valid_metadata();
        md.redirect_uris = vec![];
        assert!(
            md.validate(&id).is_err(),
            "at least one redirect_uri is required"
        );
    }

    #[test]
    fn private_key_jwt_requires_published_keys() {
        let id = ClientId::parse(WEB_ID).unwrap();

        let mut md = valid_metadata();
        md.token_endpoint_auth_method = "private_key_jwt".into();
        assert!(
            md.validate(&id).is_err(),
            "a confidential client with no keys cannot be authenticated"
        );

        md.jwks_uri = Some("https://app.example.com/jwks.json".into());
        md.validate(&id)
            .expect("jwks_uri satisfies the requirement");
    }

    #[test]
    fn unsupported_auth_methods_are_rejected() {
        let id = ClientId::parse(WEB_ID).unwrap();
        let mut md = valid_metadata();
        md.token_endpoint_auth_method = "client_secret_basic".into();
        assert!(
            md.validate(&id).is_err(),
            "shared-secret auth is not in the atproto profile"
        );
    }

    #[test]
    fn declared_scope_must_be_grantable() {
        let id = ClientId::parse(WEB_ID).unwrap();
        let mut md = valid_metadata();
        md.scope = "atproto admin:everything".into();
        assert!(md.validate(&id).is_err());
    }

    // --- redirect URI matching ---

    #[test]
    fn redirect_uri_matching_is_exact() {
        let md = valid_metadata();
        assert!(md.allows_redirect_uri("https://app.example.com/callback"));
        // Every one of these is a real-world bypass shape.
        for near_miss in [
            "https://app.example.com/callback/",
            "https://app.example.com/callback?x=1",
            "https://app.example.com/callback/../evil",
            "https://app.example.com/callbackevil",
            "https://evil.example.com/callback",
            "HTTPS://APP.EXAMPLE.COM/callback",
        ] {
            assert!(
                !md.allows_redirect_uri(near_miss),
                "{near_miss:?} must not match — redirect matching is exact"
            );
        }
    }

    #[test]
    fn display_name_falls_back_to_client_id() {
        let mut md = valid_metadata();
        assert_eq!(md.display_name(), "Test App");
        md.client_name = None;
        assert_eq!(md.display_name(), WEB_ID);
        md.client_name = Some("   ".into());
        assert_eq!(md.display_name(), WEB_ID, "a blank name must not be shown");
    }

    #[test]
    fn metadata_deserializes_with_defaults() {
        let json = serde_json::json!({
            "client_id": WEB_ID,
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "scope": "atproto",
            "dpop_bound_access_tokens": true
        });
        let md: ClientMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(
            md.token_endpoint_auth_method, "none",
            "the default auth method is `none`"
        );
        md.validate(&ClientId::parse(WEB_ID).unwrap()).unwrap();
    }
}
