//! DNS A-record check seam for the wizard.
//!
//! Mirrors the `RelayClient` seam in `firehose/crawl.rs`: a trait, a production
//! Hickory-backed implementation, and a test-double `MockDnsResolver`.
//!
//! Security: DNS results are advisory only — `check_a_record` returns a
//! typed enum (`DnsCheck`) so the caller WARNS but NEVER hard-fails on mismatch or
//! lookup failure. DNS propagation lag is a normal operational condition.
//!
//! `MockDnsResolver` is NOT `#[cfg(test)]`-gated: wizard tests in any context (including
//! integration tests in a separate crate) can import it directly.

use std::net::IpAddr;

/// Injectable trait for DNS A-record lookups.
///
/// Production: `HickoryResolver` (hickory-resolver 0.26, tokio-native).
/// Tests: `MockDnsResolver` (canned records or error, no network).
#[async_trait::async_trait]
pub trait DnsResolver: Send + Sync {
    /// Resolve the A/AAAA records for `hostname`. Returns `Ok(Vec<IpAddr>)` on success
    /// (empty vec is valid — name exists but has no A records). Returns `Err` on a
    /// hard DNS failure (NXDOMAIN, timeout, resolver error).
    async fn resolve_a(&self, hostname: &str) -> Result<Vec<IpAddr>, anyhow::Error>;
}

/// Production `DnsResolver` backed by `hickory-resolver`.
///
/// Uses the system / default DNS configuration (from `/etc/resolv.conf` on Unix).
/// `builder_tokio()` requires the `tokio` feature on the `hickory-resolver` crate.
pub struct HickoryResolver {
    resolver: hickory_resolver::TokioResolver,
}

impl HickoryResolver {
    /// Build a resolver from the system / tokio-compatible configuration.
    pub fn new() -> anyhow::Result<Self> {
        let resolver = hickory_resolver::Resolver::builder_tokio()?.build()?;
        Ok(Self { resolver })
    }
}

#[async_trait::async_trait]
impl DnsResolver for HickoryResolver {
    async fn resolve_a(&self, hostname: &str) -> Result<Vec<IpAddr>, anyhow::Error> {
        let resp = self.resolver.lookup_ip(hostname).await?;
        Ok(resp.iter().collect())
    }
}

/// Test double for `DnsResolver`. Returns canned A records or a canned error.
///
/// NOT `#[cfg(test)]`-gated: wizard tests outside this module (e.g. `cmd::init` tests,
/// or future integration crates) can import it without `#[cfg(test)]` gating.
pub struct MockDnsResolver {
    result: std::sync::Mutex<Option<Result<Vec<IpAddr>, String>>>,
}

impl MockDnsResolver {
    /// Construct a mock that returns the given set of IP addresses.
    pub fn with_records(ips: Vec<IpAddr>) -> Self {
        Self {
            result: std::sync::Mutex::new(Some(Ok(ips))),
        }
    }

    /// Construct a mock that returns a lookup failure with the given message.
    pub fn with_error(msg: &str) -> Self {
        Self {
            result: std::sync::Mutex::new(Some(Err(msg.to_string()))),
        }
    }
}

impl Default for MockDnsResolver {
    fn default() -> Self {
        Self::with_error("no mock result set")
    }
}

#[async_trait::async_trait]
impl DnsResolver for MockDnsResolver {
    async fn resolve_a(&self, _hostname: &str) -> Result<Vec<IpAddr>, anyhow::Error> {
        match self.result.lock().unwrap().clone() {
            Some(Ok(v)) => Ok(v),
            Some(Err(e)) => Err(anyhow::anyhow!(e)),
            None => Ok(vec![]),
        }
    }
}

/// The outcome of `check_a_record`. All variants are non-error — the caller always
/// continues (warn-but-allow). Hard-failing on DNS mismatch is explicitly rejected
/// because DNS propagation can lag.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsCheck {
    /// The expected IP was found in the resolved A records. All good.
    Match,
    /// The resolved A records exist but do not contain the expected IP.
    Mismatch {
        /// All IPs that were resolved.
        resolved: Vec<IpAddr>,
        /// The IP the wizard expected to see.
        expected: IpAddr,
    },
    /// The DNS lookup itself failed (NXDOMAIN, timeout, network error).
    LookupFailed(String),
}

/// Advisory A-record check — WARN-BUT-ALLOW on any deviation.
///
/// Returns `DnsCheck::Match` when `expected` appears in the resolved set.
/// Returns `DnsCheck::Mismatch` when the lookup succeeds but does not contain `expected`.
/// Returns `DnsCheck::LookupFailed` when the resolver returns an error.
///
/// NEVER returns `Err` — mismatch and lookup failures are non-fatal variants
/// (DNS propagation lag is a normal operational condition).
pub async fn check_a_record(
    resolver: &dyn DnsResolver,
    hostname: &str,
    expected: IpAddr,
) -> DnsCheck {
    match resolver.resolve_a(hostname).await {
        Ok(ips) if ips.contains(&expected) => DnsCheck::Match,
        Ok(ips) => DnsCheck::Mismatch {
            resolved: ips,
            expected,
        },
        Err(e) => DnsCheck::LookupFailed(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Match: expected IP is in the resolved set → DnsCheck::Match.
    #[tokio::test]
    async fn check_a_record_match_when_ip_in_set() {
        let expected: IpAddr = "1.2.3.4".parse().unwrap();
        let mock = MockDnsResolver::with_records(vec![
            "1.2.3.4".parse().unwrap(),
            "5.6.7.8".parse().unwrap(),
        ]);
        let result = check_a_record(&mock, "example.com", expected).await;
        assert_eq!(
            result,
            DnsCheck::Match,
            "expected Match when IP in resolved set"
        );
    }

    /// Mismatch: resolved set exists but expected IP absent → DnsCheck::Mismatch (NOT Err).
    #[tokio::test]
    async fn check_a_record_mismatch_when_ip_absent() {
        let expected: IpAddr = "9.9.9.9".parse().unwrap();
        let resolved_ips: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
        let mock = MockDnsResolver::with_records(resolved_ips.clone());
        let result = check_a_record(&mock, "example.com", expected).await;
        match result {
            DnsCheck::Mismatch {
                resolved,
                expected: exp,
            } => {
                assert_eq!(exp, expected, "expected IP must be preserved in Mismatch");
                assert_eq!(
                    resolved, resolved_ips,
                    "resolved IPs must be preserved in Mismatch"
                );
            }
            other => panic!("expected DnsCheck::Mismatch, got {:?}", other),
        }
    }

    /// LookupFailed: resolver errors → DnsCheck::LookupFailed (NOT Err, NOT hard-fail).
    #[tokio::test]
    async fn check_a_record_lookup_failed_on_resolver_error() {
        let expected: IpAddr = "1.2.3.4".parse().unwrap();
        let mock = MockDnsResolver::with_error("NXDOMAIN: no such host");
        let result = check_a_record(&mock, "nonexistent.invalid", expected).await;
        match result {
            DnsCheck::LookupFailed(msg) => {
                assert!(
                    msg.contains("NXDOMAIN"),
                    "LookupFailed must preserve error message: {msg}"
                );
            }
            other => panic!("expected DnsCheck::LookupFailed, got {:?}", other),
        }
    }

    /// Mismatch with empty resolved set (valid DNS response — no A records for name).
    #[tokio::test]
    async fn check_a_record_mismatch_when_resolved_is_empty() {
        let expected: IpAddr = "1.2.3.4".parse().unwrap();
        let mock = MockDnsResolver::with_records(vec![]);
        let result = check_a_record(&mock, "example.com", expected).await;
        match result {
            DnsCheck::Mismatch { resolved, .. } => {
                assert!(resolved.is_empty(), "resolved must be empty");
            }
            other => panic!("expected DnsCheck::Mismatch for empty set, got {:?}", other),
        }
    }

    /// Mock with a single IPv6 record + expected IPv4 → Mismatch (not Match).
    #[tokio::test]
    async fn check_a_record_mismatch_for_ipv4_vs_ipv6() {
        let expected: IpAddr = "1.2.3.4".parse().unwrap();
        let mock = MockDnsResolver::with_records(vec!["::1".parse().unwrap()]);
        let result = check_a_record(&mock, "example.com", expected).await;
        assert!(
            matches!(result, DnsCheck::Mismatch { .. }),
            "IPv4 expected vs IPv6 resolved must be Mismatch"
        );
    }
}
