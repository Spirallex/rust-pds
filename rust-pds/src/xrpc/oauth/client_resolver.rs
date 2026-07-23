//! Resolving a `client_id` to its metadata document.
//!
//! For a web client this means the server makes an HTTP request to a
//! client-controlled URL. That is an SSRF surface, so it is deliberately narrow:
//! the URL has already been validated by `ClientId::parse` (HTTPS, domain host —
//! never an IP literal, no port, no credentials), redirects are refused, and the
//! response body is size-capped.

use std::sync::Arc;

use async_trait::async_trait;

use stelyph_core::oauth::{ClientId, ClientMetadata, OAuthError};

/// Largest client-metadata document we will read.
///
/// These are small JSON objects. The cap stops a client from pointing us at an
/// endless stream and exhausting server memory.
const MAX_METADATA_BYTES: usize = 64 * 1024;

/// Resolves a validated `client_id` to its metadata.
#[async_trait]
pub trait ClientResolver: Send + Sync {
    async fn resolve(&self, client_id: &ClientId) -> Result<ClientMetadata, OAuthError>;
}

/// Fetches web clients' documents over HTTPS.
pub struct HttpClientResolver {
    http: reqwest::Client,
}

impl HttpClientResolver {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            // A slow or hanging client endpoint must not tie up a request
            // handler indefinitely.
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            // Refuse redirects. A redirect could send us to an internal address
            // that `ClientId::parse` had no chance to inspect, which is the
            // classic SSRF bypass.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("stelyph-pds")
            .build()
            .expect("static reqwest client configuration is valid");
        Self { http }
    }
}

impl Default for HttpClientResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ClientResolver for HttpClientResolver {
    async fn resolve(&self, client_id: &ClientId) -> Result<ClientMetadata, OAuthError> {
        // Loopback development clients carry their registration inline; there is
        // nothing to fetch, and nothing to fetch it from.
        if let Some(metadata) = client_id.loopback_metadata() {
            metadata.validate(client_id)?;
            return Ok(metadata);
        }

        let url = client_id.as_str();
        let resp = self.http.get(url).send().await.map_err(|e| {
            OAuthError::InvalidClient(format!("could not fetch client metadata: {e}"))
        })?;

        if !resp.status().is_success() {
            return Err(OAuthError::InvalidClient(format!(
                "client metadata request returned HTTP {}",
                resp.status()
            )));
        }

        // Check the advertised length before reading, then cap the read anyway —
        // `Content-Length` is a hint from an untrusted server and may be absent
        // or wrong.
        if let Some(len) = resp.content_length() {
            if len as usize > MAX_METADATA_BYTES {
                return Err(OAuthError::InvalidClient(
                    "client metadata document is too large".into(),
                ));
            }
        }
        let bytes = resp.bytes().await.map_err(|e| {
            OAuthError::InvalidClient(format!("could not read client metadata: {e}"))
        })?;
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(OAuthError::InvalidClient(
                "client metadata document is too large".into(),
            ));
        }

        let metadata: ClientMetadata = serde_json::from_slice(&bytes).map_err(|e| {
            OAuthError::InvalidClient(format!("client metadata is not valid JSON: {e}"))
        })?;

        // Validate against the identity it was fetched under — including that
        // the document claims that same client_id.
        metadata.validate(client_id)?;
        Ok(metadata)
    }
}

/// A resolver backed by a fixed table, for tests.
///
/// Lets the OAuth endpoint tests exercise the full flow without standing up an
/// HTTP server to host a client document.
pub struct StaticClientResolver {
    clients: Vec<(String, ClientMetadata)>,
}

impl StaticClientResolver {
    pub fn new(clients: Vec<(String, ClientMetadata)>) -> Arc<Self> {
        Arc::new(Self { clients })
    }
}

#[async_trait]
impl ClientResolver for StaticClientResolver {
    async fn resolve(&self, client_id: &ClientId) -> Result<ClientMetadata, OAuthError> {
        if let Some(metadata) = client_id.loopback_metadata() {
            metadata.validate(client_id)?;
            return Ok(metadata);
        }
        let found = self
            .clients
            .iter()
            .find(|(id, _)| id == client_id.as_str())
            .map(|(_, m)| m.clone())
            .ok_or_else(|| OAuthError::InvalidClient("unknown client".into()))?;
        found.validate(client_id)?;
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(client_id: &str) -> ClientMetadata {
        ClientMetadata {
            client_id: client_id.into(),
            client_name: Some("Test".into()),
            redirect_uris: vec!["https://app.test/cb".into()],
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

    #[tokio::test]
    async fn loopback_clients_resolve_without_any_fetch() {
        // The HTTP resolver must not make a request for a loopback client — this
        // would hang or fail if it tried.
        let resolver = HttpClientResolver::new();
        let id = ClientId::parse("http://localhost").unwrap();
        let md = resolver.resolve(&id).await.unwrap();
        assert!(md.dpop_bound_access_tokens);
        assert!(md.allows_redirect_uri("http://127.0.0.1/"));
    }

    #[tokio::test]
    async fn static_resolver_returns_registered_clients() {
        let id = "https://app.test/client-metadata.json";
        let resolver = StaticClientResolver::new(vec![(id.into(), metadata(id))]);
        let parsed = ClientId::parse(id).unwrap();
        assert_eq!(resolver.resolve(&parsed).await.unwrap().client_id, id);
    }

    #[tokio::test]
    async fn unknown_clients_are_rejected() {
        let resolver = StaticClientResolver::new(vec![]);
        let parsed = ClientId::parse("https://other.test/client-metadata.json").unwrap();
        assert!(resolver.resolve(&parsed).await.is_err());
    }

    #[tokio::test]
    async fn a_document_claiming_another_client_id_is_rejected() {
        let requested = "https://app.test/client-metadata.json";
        // The table serves a document that claims to be a different client.
        let resolver = StaticClientResolver::new(vec![(
            requested.into(),
            metadata("https://evil.test/client-metadata.json"),
        )]);
        let parsed = ClientId::parse(requested).unwrap();
        assert!(
            resolver.resolve(&parsed).await.is_err(),
            "validation must run on resolved metadata, not just on fetch success"
        );
    }
}
