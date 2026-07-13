//! AppViewClient: injectable trait for forwarding XRPC requests upstream.
//!
//! Production impl: `ReqwestAppViewClient` — sends
//! `GET|POST <base_url>/xrpc/<nsid>?<query>` with an
//! `Authorization: Bearer <jwt>` header (plus the request body and
//! `atproto-accept-labelers` when present) and passes status + body +
//! moderation headers through verbatim. This backs the generalized
//! `atproto-proxy` routing (AppView, chat, moderation, video, feed
//! generators, …), not just the AppView.
//!
//! SSRF guard: the upstream base URL MUST be an `https://` URL whose host is
//! NOT a loopback/link-local/private/internal address — both scheme and host
//! are validated before any network I/O.
//!
//! Timeout: reqwest client is built with a 10-second timeout.
//!
//! `MockAppViewClient` is NOT `#[cfg(test)]`-gated: the integration test in
//! `tests/` is a separate crate and cannot see `#[cfg(test)]` items.

use std::time::Duration;

use crate::xrpc::XrpcError;

/// HTTP verb for a proxied XRPC call. Lexicon queries are GET, procedures POST.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProxyMethod {
    Get,
    Post,
}

/// One proxied XRPC request, fully resolved (the routing layer has already
/// turned the `atproto-proxy` DID into `base_url` and minted `jwt`).
#[derive(Clone)]
pub struct UpstreamRequest {
    pub method: ProxyMethod,
    /// e.g. `https://api.bsky.app` — SSRF-validated by the client impl.
    pub base_url: String,
    /// Full method NSID, e.g. `chat.bsky.convo.listConvos`.
    pub nsid: String,
    /// Raw query string ("" when none).
    pub query: String,
    /// Request body for POST (empty for GET).
    pub body: bytes::Bytes,
    /// Request Content-Type, forwarded verbatim when present.
    pub content_type: Option<String>,
    /// Service-auth JWT minted for the target service.
    pub jwt: String,
    /// Caller's `atproto-accept-labelers` header, forwarded verbatim.
    pub accept_labelers: Option<String>,
}

/// Upstream response relayed to the caller. Non-2xx statuses are NOT errors —
/// they pass through verbatim; only transport failures surface as
/// `XrpcError::UpstreamFailure`.
pub struct UpstreamResponse {
    pub status: u16,
    pub body: bytes::Bytes,
    pub content_type: Option<String>,
    /// Upstream `atproto-content-labelers` header (moderation attribution).
    pub content_labelers: Option<String>,
}

/// Injectable trait for proxying XRPC requests upstream.
#[async_trait::async_trait]
pub trait AppViewClient: Send + Sync {
    async fn proxy_request(&self, req: UpstreamRequest) -> Result<UpstreamResponse, XrpcError>;
}

/// Production `AppViewClient` implementation using `reqwest`.
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

/// SSRF guard: validate an upstream base URL before any network I/O.
///
/// Enforces `https://` scheme AND rejects internal/loopback/link-local/private
/// hosts (cloud metadata `169.254.169.254`, `127.0.0.1`, `localhost`, RFC1918
/// ranges, `.local`, `.internal`). Returns `XrpcError::UpstreamFailure` on
/// rejection (maps to HTTP 502).
pub fn validate_appview_url(url: &str) -> Result<(), XrpcError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| XrpcError::UpstreamFailure(format!("invalid upstream url: {e}")))?;
    if parsed.scheme() != "https" {
        return Err(XrpcError::UpstreamFailure(format!(
            "upstream url must be an https:// URL, got: {url}"
        )));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| XrpcError::UpstreamFailure("upstream url missing host".to_string()))?;
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
                "upstream host not allowed".to_string(),
            ));
        }
    } else if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
        return Err(XrpcError::UpstreamFailure(
            "upstream host not allowed".to_string(),
        ));
    }
    Ok(())
}

#[async_trait::async_trait]
impl AppViewClient for ReqwestAppViewClient {
    async fn proxy_request(&self, req: UpstreamRequest) -> Result<UpstreamResponse, XrpcError> {
        // SSRF guard: enforce https scheme AND block internal/private hosts.
        validate_appview_url(&req.base_url)?;
        let mut url = format!("{}/xrpc/{}", req.base_url, req.nsid);
        if !req.query.is_empty() {
            url.push('?');
            url.push_str(&req.query);
        }
        let mut builder = match req.method {
            ProxyMethod::Get => self.client.get(&url),
            ProxyMethod::Post => self.client.post(&url).body(req.body.clone()),
        };
        builder = builder.header("Authorization", format!("Bearer {}", req.jwt));
        if let Some(ct) = &req.content_type {
            builder = builder.header("Content-Type", ct);
        }
        if let Some(labelers) = &req.accept_labelers {
            builder = builder.header("atproto-accept-labelers", labelers);
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| XrpcError::UpstreamFailure(format!("upstream request failed: {e}")))?;
        let status = resp.status().as_u16();
        let header = |name: &str| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let content_type = header("content-type");
        let content_labelers = header("atproto-content-labelers");
        let body = resp
            .bytes()
            .await
            .map_err(|e| XrpcError::UpstreamFailure(format!("upstream body read: {e}")))?;
        // Do NOT branch on is_success() — pass non-2xx through verbatim.
        Ok(UpstreamResponse {
            status,
            body,
            content_type,
            content_labelers,
        })
    }
}

/// Test double for `AppViewClient`. Records every request.
///
/// NOT `#[cfg(test)]`-gated: the integration test in `tests/` lives in a
/// separate crate and cannot access `#[cfg(test)]` items.
pub struct MockAppViewClient {
    calls: std::sync::Mutex<Vec<UpstreamRequest>>,
    response: (u16, Vec<u8>, Option<String>),
}

impl MockAppViewClient {
    pub fn new(response: (u16, Vec<u8>, Option<String>)) -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
            response,
        }
    }

    /// All recorded requests, in call order.
    pub fn requests(&self) -> Vec<UpstreamRequest> {
        self.calls.lock().unwrap().clone()
    }

    /// Back-compat view of recorded calls as `(nsid, query, jwt)` triples.
    pub fn calls(&self) -> Vec<(String, String, String)> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|r| (r.nsid.clone(), r.query.clone(), r.jwt.clone()))
            .collect()
    }
}

impl Default for MockAppViewClient {
    fn default() -> Self {
        Self::new((200, Vec::new(), None))
    }
}

#[async_trait::async_trait]
impl AppViewClient for MockAppViewClient {
    async fn proxy_request(&self, req: UpstreamRequest) -> Result<UpstreamResponse, XrpcError> {
        self.calls.lock().unwrap().push(req);
        Ok(UpstreamResponse {
            status: self.response.0,
            body: bytes::Bytes::from(self.response.1.clone()),
            content_type: self.response.2.clone(),
            content_labelers: None,
        })
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

    /// Mock records the request and returns the canned response.
    #[tokio::test]
    async fn mock_records_call_and_returns_canned() {
        let mock = MockAppViewClient::new((
            200,
            b"{\"ok\":true}".to_vec(),
            Some("application/json".into()),
        ));
        let resp = mock
            .proxy_request(UpstreamRequest {
                method: ProxyMethod::Get,
                base_url: "https://x".into(),
                nsid: "app.bsky.feed.getTimeline".into(),
                query: "limit=5".into(),
                body: bytes::Bytes::new(),
                content_type: None,
                jwt: "tok".into(),
                accept_labelers: None,
            })
            .await
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, bytes::Bytes::from(b"{\"ok\":true}".as_ref()));
        assert_eq!(resp.content_type, Some("application/json".to_string()));

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
