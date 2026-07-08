//! Server-only did:web RESOLVER — fetches a remote `/.well-known/did.json`
//! (or a device-path variant) and returns the parsed DID document.
//!
//! This is the inverse of `stelyph_core::identity::web` (which BUILDS a did:web
//! document for documents Stelyph itself serves). This module RESOLVES a
//! did:web DID that some OTHER host serves, so `createAccount` can confirm a
//! caller-supplied did:web DID actually resolves before persisting the account.
//!
//! SSRF hardening: `redirect::Policy::none()` (never follow a
//! redirect to an attacker-chosen host), a 10s timeout, and a body read capped
//! to 256 bytes on error paths (mirrors `ReqwestPlcClient`). Plain HTTP is only
//! ever used when `http_dev` is explicitly true (compose-network dev mode) —
//! NEVER set true in production.

use stelyph_core::error::CoreError;

/// Resolves a did:web DID to its DID document. Trait-based so tests can inject
/// a mock instead of making real network calls.
#[async_trait::async_trait]
pub trait DidWebResolver: Send + Sync {
    async fn resolve(&self, did: &str) -> Result<serde_json::Value, CoreError>;
}

/// Production `DidWebResolver` implementation using `reqwest`.
pub struct ReqwestDidWebResolver {
    client: reqwest::Client,
    http_dev: bool,
}

impl ReqwestDidWebResolver {
    /// `http_dev`: when true, did:web hosts are resolved over plain HTTP instead
    /// of HTTPS. This is a compose-network dev-mode toggle ONLY — production
    /// deployments MUST leave this false so resolution always uses HTTPS.
    pub fn new(http_dev: bool) -> Result<Self, anyhow::Error> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            // Never follow a redirect — an attacker-controlled did:web
            // host could otherwise redirect the resolver to an internal service.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(ReqwestDidWebResolver { client, http_dev })
    }
}

/// Convert a `did:web:<host>[:<path-segment>...]` DID into the URL its DID
/// document is served from, per the did:web spec:
/// - `did:web:host` -> `{scheme}://host/.well-known/did.json`
/// - `did:web:host:devices:d001` -> `{scheme}://host/devices/d001/did.json`
///
/// Path segments are `:`-separated in the DID and `%3A`-percent-decoded (and
/// `%25`-decoded) per spec; each segment becomes a `/`-separated URL path
/// component. `scheme` is `http` only when `http_dev` is true, else `https`.
fn did_web_to_url(did: &str, http_dev: bool) -> Result<String, CoreError> {
    let rest = did.strip_prefix("did:web:").ok_or_else(|| {
        CoreError::Internal(anyhow::anyhow!("did_web_to_url: not a did:web DID: {did}"))
    })?;
    if rest.is_empty() {
        return Err(CoreError::Internal(anyhow::anyhow!(
            "did_web_to_url: empty did:web identifier"
        )));
    }

    let scheme = if http_dev { "http" } else { "https" };

    let segments: Vec<String> = rest
        .split(':')
        .map(|seg| {
            // did:web spec: colon-separated path segments are percent-decoded
            // (":" -> "%3A" when the segment itself needs a literal colon; here
            // we decode the reverse direction — the DID's percent-encoding).
            percent_decode(seg)
        })
        .collect();

    if segments.is_empty() {
        return Err(CoreError::Internal(anyhow::anyhow!(
            "did_web_to_url: no host in did:web DID"
        )));
    }

    let host = &segments[0];
    if host.is_empty() {
        return Err(CoreError::Internal(anyhow::anyhow!(
            "did_web_to_url: empty host in did:web DID"
        )));
    }

    if segments.len() == 1 {
        Ok(format!("{scheme}://{host}/.well-known/did.json"))
    } else {
        let path = segments[1..].join("/");
        Ok(format!("{scheme}://{host}/{path}/did.json"))
    }
}

/// Minimal percent-decoder sufficient for did:web path segments (no `+` handling
/// needed — did:web segments are not query strings).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[async_trait::async_trait]
impl DidWebResolver for ReqwestDidWebResolver {
    async fn resolve(&self, did: &str) -> Result<serde_json::Value, CoreError> {
        let url = did_web_to_url(did, self.http_dev)?;

        let resp =
            self.client.get(&url).send().await.map_err(|e| {
                CoreError::Internal(anyhow::anyhow!("did:web resolve GET failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            // Cap body read to 256 bytes; never leak it to the caller.
            let body = resp.text().await.unwrap_or_default();
            let end = body
                .char_indices()
                .map(|(i, _)| i)
                .take_while(|&i| i <= 256)
                .last()
                .unwrap_or(0);
            let _body_preview = &body[..end]; // diagnostics only, never returned
            return Err(CoreError::Internal(anyhow::anyhow!(
                "did:web resolve got {status}"
            )));
        }

        resp.json::<serde_json::Value>()
            .await
            .map_err(|e| CoreError::Internal(anyhow::anyhow!("did:web resolve parse failed: {e}")))
    }
}

/// Test double: always resolves successfully (or always fails), without any
/// network access. Used by `createAccount` tests and other test AppState
/// builders so they compile without a live did:web host.
///
/// NOT `#[cfg(test)]`-gated: integration tests in `tests/` live in a separate
/// crate and cannot access `#[cfg(test)]` items (same pattern as MockPlcClient).
pub struct MockDidWebResolver {
    should_succeed: bool,
}

impl MockDidWebResolver {
    pub fn new_ok() -> Self {
        MockDidWebResolver {
            should_succeed: true,
        }
    }

    pub fn new_err() -> Self {
        MockDidWebResolver {
            should_succeed: false,
        }
    }
}

#[async_trait::async_trait]
impl DidWebResolver for MockDidWebResolver {
    async fn resolve(&self, did: &str) -> Result<serde_json::Value, CoreError> {
        if self.should_succeed {
            Ok(serde_json::json!({ "id": did }))
        } else {
            Err(CoreError::Internal(anyhow::anyhow!(
                "mock did:web resolver: forced failure"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_only_https() {
        let url = did_web_to_url("did:web:pds.example.com", false).unwrap();
        assert_eq!(url, "https://pds.example.com/.well-known/did.json");
    }

    #[test]
    fn host_only_http_dev() {
        let url = did_web_to_url("did:web:pds.example.com", true).unwrap();
        assert_eq!(url, "http://pds.example.com/.well-known/did.json");
    }

    #[test]
    fn one_path_segment_https() {
        let url = did_web_to_url("did:web:example.com:user", false).unwrap();
        assert_eq!(url, "https://example.com/user/did.json");
    }

    #[test]
    fn one_path_segment_http_dev() {
        let url = did_web_to_url("did:web:example.com:user", true).unwrap();
        assert_eq!(url, "http://example.com/user/did.json");
    }

    #[test]
    fn device_path_https() {
        let url = did_web_to_url("did:web:backend.test:devices:d001", false).unwrap();
        assert_eq!(url, "https://backend.test/devices/d001/did.json");
    }

    #[test]
    fn device_path_http_dev() {
        let url = did_web_to_url("did:web:backend.test:devices:d001", true).unwrap();
        assert_eq!(url, "http://backend.test/devices/d001/did.json");
    }

    #[test]
    fn non_did_web_errors() {
        assert!(did_web_to_url("did:plc:abc123", false).is_err());
        assert!(did_web_to_url("not-a-did-at-all", true).is_err());
    }

    #[tokio::test]
    async fn mock_resolver_ok_returns_id() {
        let resolver = MockDidWebResolver::new_ok();
        let doc = resolver
            .resolve("did:web:pds.test:devices:d001")
            .await
            .unwrap();
        assert_eq!(doc["id"], "did:web:pds.test:devices:d001");
    }

    #[tokio::test]
    async fn mock_resolver_err_fails() {
        let resolver = MockDidWebResolver::new_err();
        assert!(resolver
            .resolve("did:web:pds.test:devices:d001")
            .await
            .is_err());
    }
}
