//! Mode detection for the adaptive front-door wizard.
//!
//! Provides an `ExternalIpClient` trait seam (mirrors `RelayClient` in `firehose/crawl.rs`),
//! a synchronous `can_bind_443()` bind-test, and an advisory `detect_mode()` that recommends
//! `Standalone`, `Proxy`, or `Tunnel` — never asserts. `--mode` always overrides upstream.
//!
//! `MockExternalIpClient` is NOT `#[cfg(test)]`-gated: the wizard integration test in
//! `tests/` is a separate crate and cannot see `#[cfg(test)]` items.
//!
//! Security: the echo endpoint (`api.ipify.org`) is HARDCODED — not operator/user-configurable
//! — so there is no SSRF surface. The returned IP is treated as ADVISORY only: it gates
//! no auth/access and never selects a bind target.

use std::net::IpAddr;
use std::time::Duration;

/// Injectable trait for fetching the machine's public IP address via an echo endpoint.
///
/// The production implementation calls `https://api.ipify.org` (hardcoded, no SSRF).
/// Tests use `MockExternalIpClient` to avoid any network calls.
#[async_trait::async_trait]
pub trait ExternalIpClient: Send + Sync {
    /// Fetch this machine's public IP via a fixed echo endpoint (no SSRF surface — endpoint
    /// is hardcoded at `https://api.ipify.org`; not operator/user-configurable).
    async fn fetch_ip(&self) -> Result<IpAddr, anyhow::Error>;
}

/// Production `ExternalIpClient` implementation using `reqwest`.
///
/// Calls `GET https://api.ipify.org` (hardcoded — no SSRF surface) and parses the plaintext
/// response as an IP address. Built with a 10-second timeout matching the `RelayClient` seam.
pub struct ReqwestExternalIpClient {
    client: reqwest::Client,
}

impl ReqwestExternalIpClient {
    /// Build a client with a 10-second timeout.
    pub fn new() -> Result<Self, anyhow::Error> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?,
        })
    }
}

impl Default for ReqwestExternalIpClient {
    fn default() -> Self {
        Self::new().expect("build reqwest client")
    }
}

#[async_trait::async_trait]
impl ExternalIpClient for ReqwestExternalIpClient {
    async fn fetch_ip(&self) -> Result<IpAddr, anyhow::Error> {
        // HARDCODED endpoint — not operator/user-configurable → no SSRF surface.
        let txt = self
            .client
            .get("https://api.ipify.org")
            .send()
            .await?
            .text()
            .await?;
        Ok(txt.trim().parse()?)
    }
}

/// Test double for `ExternalIpClient`. Returns a canned `Ok(IpAddr)` or `Err`, and records
/// whether it was called.
///
/// NOT `#[cfg(test)]`-gated: the integration test in `tests/` (plan 04-05) lives in a
/// separate crate and cannot access `#[cfg(test)]` items.
pub struct MockExternalIpClient {
    result: std::sync::Mutex<Option<Result<IpAddr, String>>>,
    called: std::sync::Mutex<bool>,
}

impl MockExternalIpClient {
    /// Construct a mock that returns the given IP address.
    pub fn with_ip(ip: IpAddr) -> Self {
        Self {
            result: std::sync::Mutex::new(Some(Ok(ip))),
            called: std::sync::Mutex::new(false),
        }
    }

    /// Construct a mock that returns the given error message.
    pub fn with_error(msg: &str) -> Self {
        Self {
            result: std::sync::Mutex::new(Some(Err(msg.to_string()))),
            called: std::sync::Mutex::new(false),
        }
    }

    /// Returns `true` if `fetch_ip` was called at least once.
    pub fn was_called(&self) -> bool {
        *self.called.lock().unwrap()
    }
}

impl Default for MockExternalIpClient {
    fn default() -> Self {
        Self::with_error("no mock result set")
    }
}

#[async_trait::async_trait]
impl ExternalIpClient for MockExternalIpClient {
    async fn fetch_ip(&self) -> Result<IpAddr, anyhow::Error> {
        *self.called.lock().unwrap() = true;
        match self.result.lock().unwrap().clone() {
            Some(Ok(ip)) => Ok(ip),
            Some(Err(e)) => Err(anyhow::anyhow!(e)),
            None => Err(anyhow::anyhow!("no mock result set")),
        }
    }
}

/// Synchronous bind-test for port 443 (no allocation). Returns `false` on `PermissionDenied`
/// (non-root process on Linux) or address-in-use. Advisory only — never grants capability.
pub fn can_bind_443() -> bool {
    std::net::TcpListener::bind("0.0.0.0:443").is_ok()
}

/// Advisory mode recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recommendation {
    /// Port 443 bindable AND public IP reachable — recommend standalone TLS mode.
    Standalone,
    /// Port 443 not bindable — recommend a reverse proxy.
    Proxy,
    /// Port 443 bindable but public IP unreachable — recommend a tunnel.
    Tunnel,
}

/// ADVISORY mode detection.
///
/// `bindable` is injected so tests do not need root (pass `can_bind_443()` in production).
/// The echoed IP is treated as advisory only: it gates no auth/access and never
/// selects a bind target. `--mode` always overrides this recommendation upstream.
///
/// Decision logic (fail-safe toward proxy/tunnel):
/// - `!bindable`                    → `Recommendation::Proxy`   (cannot bind :443)
/// - `bindable && fetch_ip` errors  → `Recommendation::Tunnel`  (no inbound reachability)
/// - `bindable && fetch_ip` ok      → `Recommendation::Standalone`
pub async fn detect_mode(
    bindable: bool,
    ip_client: &dyn ExternalIpClient,
) -> (Recommendation, String) {
    if !bindable {
        return (
            Recommendation::Proxy,
            "cannot bind :443 (non-root or in use) — recommend proxy mode".into(),
        );
    }
    match ip_client.fetch_ip().await {
        Ok(ip) => (
            Recommendation::Standalone,
            format!("public IP {ip} reachable, :443 bindable — recommend standalone"),
        ),
        Err(e) => (
            Recommendation::Tunnel,
            format!(
                "no inbound reachability ({e}) — recommend a tunnel (Cloudflare Tunnel / Tailscale Funnel)"
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Behavior 1: mock returns a canned IP and records the call.
    #[tokio::test]
    async fn mock_returns_canned_ip_and_records_call() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let mock = MockExternalIpClient::with_ip(ip);
        let result = mock.fetch_ip().await.unwrap();
        assert_eq!(result, ip);
        assert!(mock.was_called(), "fetch_ip must record call");
    }

    /// Behavior 2: mock returns a canned error and records the call.
    #[tokio::test]
    async fn mock_returns_canned_error_and_records_call() {
        let mock = MockExternalIpClient::with_error("network unreachable");
        let result = mock.fetch_ip().await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("network unreachable"),
            "error message must be propagated"
        );
        assert!(mock.was_called(), "fetch_ip must record call on error");
    }

    /// Behavior 3: detect_mode → Proxy when bind-test fails (bind false, IP irrelevant).
    #[tokio::test]
    async fn detect_mode_proxy_when_bind_fails() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let mock = MockExternalIpClient::with_ip(ip);
        let (rec, reason) = detect_mode(false, &mock).await;
        assert_eq!(rec, Recommendation::Proxy);
        assert!(
            reason.contains("cannot bind"),
            "reason must mention bind failure: {reason}"
        );
        // IP client must NOT be called when bind fails (fail-safe: no network when unnecessary).
        assert!(
            !mock.was_called(),
            "ip client must not be called when bind fails"
        );
    }

    /// Behavior 4: detect_mode → Tunnel when bind ok but IP fetch errors.
    #[tokio::test]
    async fn detect_mode_tunnel_when_ip_fetch_errors() {
        let mock = MockExternalIpClient::with_error("connection refused");
        let (rec, reason) = detect_mode(true, &mock).await;
        assert_eq!(rec, Recommendation::Tunnel);
        assert!(
            reason.contains("no inbound reachability"),
            "reason must mention no reachability: {reason}"
        );
        assert!(mock.was_called());
    }

    /// Behavior 5: detect_mode → Standalone when bind ok AND IP fetched successfully.
    #[tokio::test]
    async fn detect_mode_standalone_when_bind_ok_and_ip_fetched() {
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let mock = MockExternalIpClient::with_ip(ip);
        let (rec, reason) = detect_mode(true, &mock).await;
        assert_eq!(rec, Recommendation::Standalone);
        assert!(
            reason.contains("203.0.113.1"),
            "reason must mention the public IP: {reason}"
        );
        assert!(mock.was_called());
    }

    /// Behavior guard: detect_mode NEVER returns Standalone when bind fails.
    #[tokio::test]
    async fn detect_mode_never_standalone_when_bind_fails() {
        // Even if the IP client would succeed, bind failure must dominate.
        let ip: IpAddr = "203.0.113.1".parse().unwrap();
        let mock = MockExternalIpClient::with_ip(ip);
        let (rec, _) = detect_mode(false, &mock).await;
        assert_ne!(
            rec,
            Recommendation::Standalone,
            "must not recommend Standalone when bind fails"
        );
    }
}
