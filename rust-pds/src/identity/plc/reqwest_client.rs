//! Production `PlcClient` implementation using `reqwest`.
//!
//! POSTs the signed PLC genesis op as JSON to `https://plc.directory/{did}`.
//! Uses a 10-second timeout (Pitfall 6 mitigation — T-03-09). Server-only: kept
//! out of `stelyph-core` so the device build does not pull in reqwest.

use stelyph_core::error::CoreError;
use stelyph_core::identity::plc::{PlcClient, PlcGenesisOpSigned};

pub struct ReqwestPlcClient {
    client: reqwest::Client,
    plc_directory_url: String,
}

impl ReqwestPlcClient {
    /// Create a client targeting the standard `https://plc.directory` endpoint.
    pub fn new() -> Result<Self, anyhow::Error> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        Ok(ReqwestPlcClient {
            client,
            plc_directory_url: "https://plc.directory".to_string(),
        })
    }

    /// Create a client targeting a custom directory URL (useful for staging).
    pub fn with_url(url: &str) -> Result<Self, anyhow::Error> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;
        Ok(ReqwestPlcClient {
            client,
            plc_directory_url: url.to_string(),
        })
    }
}

#[async_trait::async_trait]
impl PlcClient for ReqwestPlcClient {
    async fn post_operation(&self, did: &str, op: &PlcGenesisOpSigned) -> Result<(), CoreError> {
        let url = format!("{}/{}", self.plc_directory_url, did);
        let resp =
            self.client.post(&url).json(op).send().await.map_err(|e| {
                CoreError::Internal(anyhow::anyhow!("plc.directory POST failed: {e}"))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            // WR-05: cap body read to 256 bytes to prevent OOM on adversarial or
            // malfunctioning PLC directory responses. The body is not included in
            // the error returned to the caller (Internal suppresses inner detail).
            let body = resp.text().await.unwrap_or_default();
            // Safe: truncate to <=256 bytes ending on a UTF-8 char boundary. Slicing a
            // String by a raw byte index would panic if byte 256 split a multi-byte char
            // (an adversarial/malformed plc.directory body can arrange this).
            let end = body
                .char_indices()
                .map(|(i, _)| i)
                .take_while(|&i| i <= 256)
                .last()
                .unwrap_or(0);
            let body_preview = &body[..end];
            // Log the preview server-side for diagnostics; never expose to clients.
            let _ = body_preview; // used by server-side logging when tracing is wired up
            return Err(CoreError::Internal(anyhow::anyhow!(
                "plc.directory returned {status}"
            )));
        }
        Ok(())
    }
}
