//! Discovery documents.
//!
//! Two documents let a client bootstrap a session knowing only a handle:
//!
//! 1. Resolve handle → DID → PDS URL.
//! 2. `GET {pds}/.well-known/oauth-protected-resource` → the authorization
//!    server's URL.
//! 3. `GET {as}/.well-known/oauth-authorization-server` → endpoints and
//!    capabilities.
//!
//! For a self-hosted PDS the resource server and authorization server are the
//! same origin, but the indirection is kept because the protocol requires it and
//! because it is what would allow the two to be split later.

use serde::{Deserialize, Serialize};

use crate::oauth::Scope;

/// RFC 8414 authorization-server metadata, with the atproto profile's
/// additions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub pushed_authorization_request_endpoint: String,
    pub revocation_endpoint: String,
    pub jwks_uri: String,

    pub scopes_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,

    /// Must be `true`: the profile does not allow parameters on the
    /// authorization endpoint.
    pub require_pushed_authorization_requests: bool,
    /// Must be `true`: every issued token is DPoP-bound.
    pub dpop_signing_alg_values_supported: Vec<String>,
    pub require_request_uri_registration: bool,
    pub client_id_metadata_document_supported: bool,
    pub authorization_response_iss_parameter_supported: bool,
}

impl AuthorizationServerMetadata {
    /// Build the document for a PDS serving OAuth at `issuer`.
    ///
    /// `issuer` must be the origin with no trailing slash — clients compare it
    /// byte-for-byte against the `iss` in tokens and authorization responses, so
    /// a stray slash breaks every client.
    pub fn new(issuer: &str) -> Self {
        let issuer = issuer.trim_end_matches('/').to_string();
        Self {
            authorization_endpoint: format!("{issuer}/oauth/authorize"),
            token_endpoint: format!("{issuer}/oauth/token"),
            pushed_authorization_request_endpoint: format!("{issuer}/oauth/par"),
            revocation_endpoint: format!("{issuer}/oauth/revoke"),
            jwks_uri: format!("{issuer}/oauth/jwks"),
            issuer,

            scopes_supported: Scope::supported().iter().map(|s| s.to_string()).collect(),
            response_types_supported: vec!["code".into()],
            grant_types_supported: vec!["authorization_code".into(), "refresh_token".into()],
            // S256 only — `plain` is not implemented.
            code_challenge_methods_supported: vec!["S256".into()],
            token_endpoint_auth_methods_supported: vec!["none".into(), "private_key_jwt".into()],
            token_endpoint_auth_signing_alg_values_supported: vec!["ES256".into()],

            require_pushed_authorization_requests: true,
            dpop_signing_alg_values_supported: vec!["ES256".into(), "ES256K".into()],
            // There is no request_uri pre-registration in this profile; handles
            // come from PAR.
            require_request_uri_registration: false,
            client_id_metadata_document_supported: true,
            // The `iss` parameter on the authorization response is what lets a
            // client detect a mix-up attack between two authorization servers.
            authorization_response_iss_parameter_supported: true,
        }
    }
}

/// RFC 9728 protected-resource metadata: which authorization server guards this
/// resource server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub bearer_methods_supported: Vec<String>,
    pub resource_documentation: String,
}

impl ProtectedResourceMetadata {
    pub fn new(resource: &str) -> Self {
        let resource = resource.trim_end_matches('/').to_string();
        Self {
            authorization_servers: vec![resource.clone()],
            resource,
            scopes_supported: Scope::supported().iter().map(|s| s.to_string()).collect(),
            // DPoP only. Advertising `header` (plain bearer) would invite
            // clients to send unbound tokens the resource server then rejects.
            bearer_methods_supported: vec!["DPoP".into()],
            resource_documentation: "https://atproto.com".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://pds.example.com";

    #[test]
    fn endpoints_are_derived_from_the_issuer() {
        let m = AuthorizationServerMetadata::new(ISSUER);
        assert_eq!(m.issuer, ISSUER);
        assert_eq!(
            m.authorization_endpoint,
            "https://pds.example.com/oauth/authorize"
        );
        assert_eq!(m.token_endpoint, "https://pds.example.com/oauth/token");
        assert_eq!(
            m.pushed_authorization_request_endpoint,
            "https://pds.example.com/oauth/par"
        );
        assert_eq!(
            m.revocation_endpoint,
            "https://pds.example.com/oauth/revoke"
        );
        assert_eq!(m.jwks_uri, "https://pds.example.com/oauth/jwks");
    }

    #[test]
    fn a_trailing_slash_is_normalized_away() {
        let a = AuthorizationServerMetadata::new("https://pds.example.com/");
        let b = AuthorizationServerMetadata::new("https://pds.example.com");
        assert_eq!(a, b, "clients compare `iss` byte-for-byte");
        assert!(!a.token_endpoint.contains("//oauth"));
    }

    #[test]
    fn profile_requirements_are_advertised() {
        let m = AuthorizationServerMetadata::new(ISSUER);
        assert!(m.require_pushed_authorization_requests, "PAR is mandatory");
        assert_eq!(
            m.code_challenge_methods_supported,
            vec!["S256"],
            "plain must not be advertised"
        );
        assert!(m.client_id_metadata_document_supported);
        assert!(m.authorization_response_iss_parameter_supported);
        assert_eq!(m.response_types_supported, vec!["code"]);
        assert!(
            !m.dpop_signing_alg_values_supported.is_empty(),
            "DPoP algorithms must be advertised"
        );
        assert!(
            !m.token_endpoint_auth_signing_alg_values_supported
                .iter()
                .any(|a| a.starts_with("RS") || a.starts_with("HS")),
            "only asymmetric EC algorithms belong in this profile"
        );
    }

    #[test]
    fn advertised_scopes_match_the_scope_module() {
        let m = AuthorizationServerMetadata::new(ISSUER);
        assert!(m.scopes_supported.contains(&"atproto".to_string()));
        assert_eq!(m.scopes_supported.len(), Scope::supported().len());
    }

    #[test]
    fn protected_resource_points_at_itself() {
        let m = ProtectedResourceMetadata::new("https://pds.example.com/");
        assert_eq!(m.resource, ISSUER);
        assert_eq!(m.authorization_servers, vec![ISSUER]);
        assert_eq!(
            m.bearer_methods_supported,
            vec!["DPoP"],
            "plain bearer must not be advertised"
        );
    }

    #[test]
    fn documents_serialize_with_the_expected_field_names() {
        let json = serde_json::to_value(AuthorizationServerMetadata::new(ISSUER)).unwrap();
        for field in [
            "issuer",
            "authorization_endpoint",
            "token_endpoint",
            "pushed_authorization_request_endpoint",
            "jwks_uri",
            "require_pushed_authorization_requests",
            "dpop_signing_alg_values_supported",
            "client_id_metadata_document_supported",
        ] {
            assert!(json.get(field).is_some(), "missing required field {field}");
        }
    }
}
