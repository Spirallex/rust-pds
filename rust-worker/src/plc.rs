//! `PlcClient` over the Workers `fetch` API.
//!
//! The counterpart to `ReqwestPlcClient` in the server crate, which cannot reach
//! wasm32. Nothing about the PLC operation itself is duplicated: building,
//! signing, and hashing the genesis op all live in `stelyph_core::identity::plc`
//! behind the injected trait, so this file is only transport.

use worker::send::SendFuture;
use worker::{Fetch, Headers, Method, Request, RequestInit};

use stelyph_core::error::CoreError;
use stelyph_core::identity::plc::{PlcClient, PlcGenesisOpSigned};

/// Where genesis operations are submitted.
pub const DEFAULT_PLC_DIRECTORY: &str = "https://plc.directory";

pub struct FetchPlcClient {
    directory_url: String,
}

impl FetchPlcClient {
    pub fn new(directory_url: impl Into<String>) -> Self {
        Self {
            directory_url: directory_url.into(),
        }
    }
}

#[async_trait::async_trait]
impl PlcClient for FetchPlcClient {
    async fn post_operation(&self, did: &str, op: &PlcGenesisOpSigned) -> Result<(), CoreError> {
        let url = format!("{}/{}", self.directory_url, did);
        let body = serde_json::to_string(op)
            .map_err(|e| CoreError::Internal(anyhow::anyhow!("serialize plc op: {e}")))?;

        // The whole request is built and awaited inside `SendFuture`: every
        // `worker` handle here is JS-backed and therefore not `Send`, while the
        // `PlcClient` trait is `async_trait` and demands a `Send` future. The
        // bridge is sound for the same reason it is in `store.rs` — a Workers
        // isolate is single-threaded, so there is no thread for the handle to
        // escape to.
        SendFuture::new(async move {
            let headers = Headers::new();
            headers.set("content-type", "application/json")?;

            let mut init = RequestInit::new();
            init.with_method(Method::Post)
                .with_headers(headers)
                .with_body(Some(body.into()));

            let req = Request::new_with_init(&url, &init)?;
            let resp = Fetch::Request(req).send().await?;
            Ok::<_, worker::Error>(resp.status_code())
        })
        .await
        .map_err(|e| CoreError::Internal(anyhow::anyhow!("plc.directory POST failed: {e}")))
        .and_then(|status| {
            if (200..300).contains(&status) {
                Ok(())
            } else {
                // The directory's body is deliberately not surfaced. It is a
                // third-party response on a path that runs during registration,
                // and `Internal` suppressing the detail is what keeps it out of
                // an error rendered back to whoever is signing up.
                Err(CoreError::Internal(anyhow::anyhow!(
                    "plc.directory returned {status}"
                )))
            }
        })
    }
}
