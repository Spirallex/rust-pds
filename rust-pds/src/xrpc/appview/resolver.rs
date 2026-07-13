//! Resolve an `atproto-proxy` target (`<did>#<fragment>`) to a service base URL.
//!
//! - `did:web:<host>` → `https://<host>` directly. Every Bluesky service DID
//!   (api.bsky.app, api.bsky.chat, video.bsky.app, mod service) follows this
//!   convention, so no DID-document fetch is needed for the common path.
//! - `did:plc:<id>` → fetch the DID document from the PLC directory and pick
//!   the service entry whose id matches `#<fragment>`; used by feed
//!   generators and labelers. Results are cached per (did, fragment) for the
//!   process lifetime (service endpoints effectively never change).
//!
//! The resolved URL is SSRF-validated by the proxy client before any request.

use crate::xrpc::XrpcError;

/// Injectable resolver: `(did, fragment)` → service base URL.
#[async_trait::async_trait]
pub trait ServiceDidResolver: Send + Sync {
    async fn resolve(&self, did: &str, fragment: &str) -> Result<String, XrpcError>;
}

/// Production resolver: did:web by convention, did:plc via the PLC directory.
pub struct ReqwestServiceDidResolver {
    plc_url: String,
    client: reqwest::Client,
    cache: dashmap::DashMap<String, String>,
}

impl ReqwestServiceDidResolver {
    pub fn new(plc_url: String) -> Result<Self, anyhow::Error> {
        Ok(Self {
            plc_url,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()?,
            cache: dashmap::DashMap::new(),
        })
    }
}

/// Shared pure helpers (`stelyph_core::identity::service`) with XrpcError mapping.
pub fn service_endpoint_from_doc(
    doc: &serde_json::Value,
    did: &str,
    fragment: &str,
) -> Option<String> {
    stelyph_core::identity::service::service_endpoint_from_doc(doc, did, fragment)
}

pub fn did_web_endpoint(did: &str) -> Result<String, XrpcError> {
    stelyph_core::identity::service::did_web_endpoint(did).map_err(XrpcError::InvalidRequest)
}

#[async_trait::async_trait]
impl ServiceDidResolver for ReqwestServiceDidResolver {
    async fn resolve(&self, did: &str, fragment: &str) -> Result<String, XrpcError> {
        if did.starts_with("did:web:") {
            return did_web_endpoint(did);
        }
        if !did.starts_with("did:plc:") {
            return Err(XrpcError::InvalidRequest(format!(
                "unsupported proxy DID method: {did}"
            )));
        }
        let cache_key = format!("{did}#{fragment}");
        if let Some(hit) = self.cache.get(&cache_key) {
            return Ok(hit.clone());
        }
        let url = format!("{}/{did}", self.plc_url);
        let doc: serde_json::Value = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| XrpcError::UpstreamFailure(format!("plc fetch failed: {e}")))?
            .json()
            .await
            .map_err(|e| XrpcError::UpstreamFailure(format!("plc doc decode failed: {e}")))?;
        let endpoint = service_endpoint_from_doc(&doc, did, fragment)
            .ok_or_else(|| XrpcError::InvalidRequest(format!("no #{fragment} service on {did}")))?;
        self.cache.insert(cache_key, endpoint.clone());
        Ok(endpoint)
    }
}

/// Test double: fixed endpoint for every (did, fragment), recording calls.
pub struct MockServiceDidResolver {
    endpoint: String,
    calls: std::sync::Mutex<Vec<(String, String)>>,
}

impl MockServiceDidResolver {
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn calls(&self) -> Vec<(String, String)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl ServiceDidResolver for MockServiceDidResolver {
    async fn resolve(&self, did: &str, fragment: &str) -> Result<String, XrpcError> {
        self.calls
            .lock()
            .unwrap()
            .push((did.to_string(), fragment.to_string()));
        if did.starts_with("did:web:") {
            return did_web_endpoint(did);
        }
        Ok(self.endpoint.clone())
    }
}
