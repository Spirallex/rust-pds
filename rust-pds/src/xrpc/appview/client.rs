//! AppViewClient: injectable trait for forwarding GET requests to an AppView service.
//!
//! Production impl: `ReqwestAppViewClient` — GETs `<appview_url>/xrpc/<method>?<query>`
//! with an `Authorization: Bearer <jwt>` header and passes through status + body verbatim.
//!
//! SSRF guard: `appview_url` MUST be an `https://` URL whose host is NOT a
//! loopback/link-local/private/internal address — both scheme and host are validated
//! before any network I/O.
//!
//! Timeout: reqwest client is built with a 10-second timeout.
//!
//! `MockAppViewClient` is NOT `#[cfg(test)]`-gated: the integration test in `tests/`
//! (plan 04-05) is a separate crate and cannot see `#[cfg(test)]` items.

use std::time::Duration;

use crate::xrpc::XrpcError;

/// Injectable trait for proxying AppView GET requests.
///
/// Returns `(status_code, body_bytes, content_type)`.
/// A non-2xx status is NOT an error — it is passed through verbatim.
/// Only transport/connection/body-read failures map to `XrpcError::UpstreamFailure`.
#[async_trait::async_trait]
pub trait AppViewClient: Send + Sync {
    async fn proxy_get(
        &self,
        appview_url: &str,
        method: &str,
        query_string: &str,
        jwt: &str,
    ) -> Result<(u16, bytes::Bytes, Option<String>), XrpcError>;
}

/// Production `AppViewClient` implementation using `reqwest`.
///
/// Sends `GET <appview_url>/xrpc/<method>[?<query>]` with a Bearer JWT.
pub struct ReqwestAppViewClient {
    client: reqwest::Client,
}

impl ReqwestAppViewClient {
    /// Build a client with a 10-second timeout (DoS mitigation).
    pub fn new() -> Result<Self, anyhow::Error> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?,
        })
    }
}

impl Default for ReqwestAppViewClient {
    fn default() -> Self {
        Self::new().expect("failed to build reqwest client")
    }
}

/// SSRF guard: validate the AppView URL before any network I/O.
///
/// Enforces `https://` scheme AND rejects internal/loopback/link-local/private hosts
/// (cloud metadata `169.254.169.254`, `127.0.0.1`, `localhost`, RFC1918 ranges, `.local`,
/// `.internal`). Returns `XrpcError::UpstreamFailure` on rejection (maps to HTTP 502).
pub fn validate_appview_url(url: &str) -> Result<(), XrpcError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| XrpcError::UpstreamFailure(format!("invalid appview_url: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(XrpcError::UpstreamFailure(format!(
            "appview_url must be an https:// URL, got: {url}"
        )));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| XrpcError::UpstreamFailure("appview_url missing host".to_string()))?;
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let blocked = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    // cloud metadata 169.254.169.254 is covered by link_local, but be explicit.
                    || (v4.octets()[0] == 169 && v4.octets()[1] == 254)
            }
            std::net::IpAddr::V6(v6) => {
                // Re-check IPv4-mapped addresses (e.g. ::ffff:169.254.169.254)
                // against the v4 rules so they can't bypass the v4 branch.
                if let Some(v4) = v6.to_ipv4_mapped() {
                    v4.is_loopback()
                        || v4.is_private()
                        || v4.is_link_local()
                        || (v4.octets()[0] == 169 && v4.octets()[1] == 254)
                } else {
                    v6.is_loopback()
                        || v6.is_unspecified()
                        // unique-local fc00::/7 (RFC4193, the IPv6 analog of RFC1918)
                        || (v6.segments()[0] & 0xfe00) == 0xfc00
                        // link-local fe80::/10
                        || (v6.segments()[0] & 0xffc0) == 0xfe80
                }
            }
        };
        if blocked {
            return Err(XrpcError::UpstreamFailure(
                "appview_url host not allowed".to_string(),
            ));
        }
    } else if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
        return Err(XrpcError::UpstreamFailure(
            "appview_url host not allowed".to_string(),
        ));
    }
    Ok(())
}

#[async_trait::async_trait]
impl AppViewClient for ReqwestAppViewClient {
    async fn proxy_get(
        &self,
        appview_url: &str,
        method: &str,
        query_string: &str,
        jwt: &str,
    ) -> Result<(u16, bytes::Bytes, Option<String>), XrpcError> {
        // SSRF guard: enforce https scheme AND block internal/private hosts.
        validate_appview_url(appview_url)?;
        let mut url = format!("{appview_url}/xrpc/{method}");
        if !query_string.is_empty() {
            url.push('?');
            url.push_str(query_string);
        }
        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {jwt}"))
            .send()
            .await
            .map_err(|e| XrpcError::UpstreamFailure(format!("appview GET failed: {e}")))?;
        let status = resp.status().as_u16();
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let body = resp
            .bytes()
            .await
            .map_err(|e| XrpcError::UpstreamFailure(format!("appview body read: {e}")))?;
        // Do NOT branch on is_success() — pass non-2xx through verbatim.
        Ok((status, body, content_type))
    }
}

/// Test double for `AppViewClient`. Records every `(method, query_string, jwt)` call.
///
/// NOT `#[cfg(test)]`-gated: the integration test in `tests/` lives in a separate
/// crate and cannot access `#[cfg(test)]` items.
pub struct MockAppViewClient {
    calls: std::sync::Mutex<Vec<(String, String, String)>>,
    response: (u16, Vec<u8>, Option<String>),
}

impl MockAppViewClient {
    pub fn new(response: (u16, Vec<u8>, Option<String>)) -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
            response,
        }
    }

    /// Returns all recorded `(method, query_string, jwt)` triples in call order.
    pub fn calls(&self) -> Vec<(String, String, String)> {
        self.calls.lock().unwrap().clone()
    }
}

impl Default for MockAppViewClient {
    fn default() -> Self {
        Self::new((200, Vec::new(), None))
    }
}

#[async_trait::async_trait]
impl AppViewClient for MockAppViewClient {
    async fn proxy_get(
        &self,
        _appview_url: &str,
        method: &str,
        query_string: &str,
        jwt: &str,
    ) -> Result<(u16, bytes::Bytes, Option<String>), XrpcError> {
        self.calls.lock().unwrap().push((
            method.to_string(),
            query_string.to_string(),
            jwt.to_string(),
        ));
        Ok((
            self.response.0,
            bytes::Bytes::from(self.response.1.clone()),
            self.response.2.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SSRF guard: non-https and internal/loopback/private/metadata hosts are rejected.
    #[test]
    fn rejects_non_https_and_internal_appview_urls() {
        let blocked = [
            "http://api.bsky.app",
            "http://evil.example",
            "https://127.0.0.1",
            "https://localhost",
            "https://169.254.169.254/latest/meta-data",
            "https://10.0.0.1",
            "https://192.168.1.1",
            "https://172.16.0.1",
            "https://foo.internal",
            "https://bar.local",
        ];
        for url in blocked {
            assert!(
                validate_appview_url(url).is_err(),
                "{url} must be rejected by SSRF guard"
            );
        }
        assert!(
            validate_appview_url("https://api.bsky.app").is_ok(),
            "valid public https URL must be accepted"
        );
    }

    /// Mock records the call tuple and returns the canned response.
    #[tokio::test]
    async fn mock_records_call_and_returns_canned() {
        let mock = MockAppViewClient::new((
            200,
            b"{\"ok\":true}".to_vec(),
            Some("application/json".into()),
        ));
        let (status, body, ct) = mock
            .proxy_get("https://x", "app.bsky.feed.getTimeline", "limit=5", "tok")
            .await
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, bytes::Bytes::from(b"{\"ok\":true}".as_ref()));
        assert_eq!(ct, Some("application/json".to_string()));

        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0],
            (
                "app.bsky.feed.getTimeline".to_string(),
                "limit=5".to_string(),
                "tok".to_string()
            )
        );
    }
}
