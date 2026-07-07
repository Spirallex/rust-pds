//! RelayClient: injectable trait for posting com.atproto.sync.requestCrawl to a relay.
//!
//! Production impl: `ReqwestRelayClient` — POSTs `{"hostname": <pds_hostname>}` to
//! `<relay_url>/xrpc/com.atproto.sync.requestCrawl`.
//!
//! SSRF guard (T-04-06): relay_url MUST be an `https://` URL whose host is NOT a
//! loopback/link-local/private/internal address — both scheme and host are validated
//! before any network I/O. Residual risk: DNS rebinding is not mitigated here.
//!
//! Timeout (T-04-08): reqwest client is built with a 10-second timeout.
//!
//! `MockRelayClient` is NOT `#[cfg(test)]`-gated: the integration test in `tests/`
//! (plan 04-05) is a separate crate and cannot see `#[cfg(test)]` items
//! (PATTERNS.md line 110).

use std::time::Duration;

use crate::xrpc::XrpcError;

/// Injectable trait for notifying a relay to begin crawling this PDS.
///
/// The production implementation POSTs to `<relay_url>/xrpc/com.atproto.sync.requestCrawl`.
/// Tests use `MockRelayClient` to avoid any network calls.
#[async_trait::async_trait]
pub trait RelayClient: Send + Sync {
    /// POST com.atproto.sync.requestCrawl to the relay so it begins crawling this PDS.
    async fn request_crawl(&self, relay_url: &str, pds_hostname: &str) -> Result<(), XrpcError>;
}

/// Production `RelayClient` implementation using `reqwest`.
///
/// Sends `POST <relay_url>/xrpc/com.atproto.sync.requestCrawl` with body
/// `{"hostname": "<pds_hostname>"}`.
pub struct ReqwestRelayClient {
    client: reqwest::Client,
}

impl ReqwestRelayClient {
    /// Build a client with a 10-second timeout (T-04-08 DoS mitigation).
    pub fn new() -> Result<Self, anyhow::Error> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?,
        })
    }
}

impl Default for ReqwestRelayClient {
    fn default() -> Self {
        Self::new().expect("failed to build reqwest client")
    }
}

/// Build the full requestCrawl endpoint URL from a relay base URL.
fn crawl_url(relay_url: &str) -> String {
    format!("{relay_url}/xrpc/com.atproto.sync.requestCrawl")
}

/// SSRF guard (T-04-06): validate the relay URL before any network I/O.
///
/// Enforces `https://` scheme AND rejects internal/loopback/link-local/private hosts
/// (cloud metadata `169.254.169.254`, `127.0.0.1`, `localhost`, RFC1918 ranges, `.local`,
/// `.internal`). `relay_url` is operator-controlled today, but this guard defends the SSRF
/// boundary the module doc advertises so a future client-influenced relay target cannot
/// reach the deployment's private network.
///
/// Residual risk: DNS rebinding (a public name resolving to a private IP) is NOT mitigated
/// here — full defense requires resolving + re-checking the IP at connect time.
fn validate_relay_url(relay_url: &str) -> Result<(), XrpcError> {
    let url = reqwest::Url::parse(relay_url)
        .map_err(|e| XrpcError::Internal(anyhow::anyhow!("invalid relay_url: {e}")))?;
    if url.scheme() != "https" {
        return Err(XrpcError::Internal(anyhow::anyhow!(
            "relay_url must be an https:// URL, got: {relay_url}"
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| XrpcError::Internal(anyhow::anyhow!("relay_url missing host")))?;
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let blocked = match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()
                    || v4.is_link_local()
                    // cloud metadata 169.254.169.254 is covered by link_local, but be explicit.
                    || (v4.octets()[0] == 169 && v4.octets()[1] == 254)
            }
            std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
        };
        if blocked {
            return Err(XrpcError::Internal(anyhow::anyhow!(
                "relay_url host not allowed"
            )));
        }
    } else if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
        return Err(XrpcError::Internal(anyhow::anyhow!(
            "relay_url host not allowed"
        )));
    }
    Ok(())
}

#[async_trait::async_trait]
impl RelayClient for ReqwestRelayClient {
    async fn request_crawl(&self, relay_url: &str, pds_hostname: &str) -> Result<(), XrpcError> {
        // SSRF guard (T-04-06): enforce https scheme AND block internal/private hosts.
        validate_relay_url(relay_url)?;
        let url = crawl_url(relay_url);
        let body = serde_json::json!({ "hostname": pds_hostname });
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| XrpcError::Internal(anyhow::anyhow!("requestCrawl POST failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(XrpcError::Internal(anyhow::anyhow!(
                "relay returned status {}",
                resp.status()
            )));
        }
        Ok(())
    }
}

/// Test double for `RelayClient`. Records every `(relay_url, pds_hostname)` pair received.
///
/// NOT `#[cfg(test)]`-gated: the integration test in `tests/` (plan 04-05) lives in a
/// separate crate and cannot access `#[cfg(test)]` items.
pub struct MockRelayClient {
    calls: std::sync::Mutex<Vec<(String, String)>>,
}

impl MockRelayClient {
    pub fn new() -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Returns all recorded `(relay_url, pds_hostname)` pairs in call order.
    pub fn calls(&self) -> Vec<(String, String)> {
        self.calls.lock().unwrap().clone()
    }
}

impl Default for MockRelayClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl RelayClient for MockRelayClient {
    async fn request_crawl(&self, relay_url: &str, pds_hostname: &str) -> Result<(), XrpcError> {
        self.calls
            .lock()
            .unwrap()
            .push((relay_url.to_string(), pds_hostname.to_string()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock records the exact (relay_url, hostname) pair passed.
    #[tokio::test]
    async fn request_crawl_sends_hostname() {
        let mock = MockRelayClient::new();
        mock.request_crawl("https://bsky.network", "pds.example.com")
            .await
            .unwrap();

        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        let (relay, hostname) = &calls[0];
        assert_eq!(relay, "https://bsky.network");
        assert_eq!(hostname, "pds.example.com");
    }

    /// The URL helper appends the correct XRPC path.
    #[test]
    fn reqwest_builds_correct_url() {
        let url = crawl_url("https://bsky.network");
        assert_eq!(
            url,
            "https://bsky.network/xrpc/com.atproto.sync.requestCrawl"
        );
    }

    /// Non-https relay URLs are rejected before any I/O (SSRF guard T-04-06).
    #[tokio::test]
    async fn rejects_non_https_relay_url() {
        let client = ReqwestRelayClient::new().unwrap();
        let result = client.request_crawl("http://evil.example", "h").await;
        assert!(result.is_err(), "non-https relay_url must be rejected");
        match result.unwrap_err() {
            XrpcError::Internal(_) => {}
            other => panic!("expected XrpcError::Internal, got {:?}", other),
        }
    }

    /// SSRF host guard: internal/loopback/link-local/private/metadata hosts are rejected.
    #[tokio::test]
    async fn rejects_internal_relay_hosts() {
        let client = ReqwestRelayClient::new().unwrap();
        let blocked = [
            "https://127.0.0.1/x",
            "https://localhost/x",
            "https://169.254.169.254/latest/meta-data",
            "https://10.0.0.5/x",
            "https://192.168.1.1/x",
            "https://172.16.0.1/x",
            "https://foo.internal/x",
            "https://bar.local/x",
        ];
        for url in blocked {
            let result = client.request_crawl(url, "h").await;
            assert!(result.is_err(), "{url} must be rejected by SSRF host guard");
        }
    }

    /// validate_relay_url accepts a normal public https host.
    #[test]
    fn validate_relay_url_accepts_public_https() {
        assert!(validate_relay_url("https://bsky.network").is_ok());
    }

    /// Multiple calls are all recorded.
    #[tokio::test]
    async fn mock_records_multiple_calls() {
        let mock = MockRelayClient::new();
        mock.request_crawl("https://relay1.example.com", "pds1.example.com")
            .await
            .unwrap();
        mock.request_crawl("https://relay2.example.com", "pds2.example.com")
            .await
            .unwrap();

        let calls = mock.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].1, "pds1.example.com");
        assert_eq!(calls[1].1, "pds2.example.com");
    }
}
