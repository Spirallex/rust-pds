//! Pure helpers for resolving an `atproto-proxy` target (`<did>#<fragment>`)
//! to a service base URL. Shared by the production server's resolver and the
//! embedded server so the two cannot drift.

/// `did:web:<host>` → `https://<host>`, rejecting path-form did:web (encoded
/// `:` separators) and hostnames with characters that could smuggle a path.
/// Every Bluesky service DID (api.bsky.app, api.bsky.chat, video.bsky.app)
/// follows the host-only convention, so no DID-document fetch is needed.
pub fn did_web_endpoint(did: &str) -> Result<String, String> {
    let host = did
        .strip_prefix("did:web:")
        .ok_or_else(|| "not a did:web".to_string())?;
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(format!("unsupported did:web host: {host}"));
    }
    Ok(format!("https://{host}"))
}

/// Extract the service endpoint for `#<fragment>` from a DID document,
/// accepting both short (`#frag`) and fully-qualified (`did…#frag`) ids.
pub fn service_endpoint_from_doc(
    doc: &serde_json::Value,
    did: &str,
    fragment: &str,
) -> Option<String> {
    let wanted_short = format!("#{fragment}");
    let wanted_full = format!("{did}#{fragment}");
    doc["service"].as_array()?.iter().find_map(|svc| {
        let id = svc["id"].as_str()?;
        (id == wanted_short || id == wanted_full)
            .then(|| svc["serviceEndpoint"].as_str().map(str::to_string))
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_web_maps_to_https_host() {
        assert_eq!(
            did_web_endpoint("did:web:api.bsky.chat").unwrap(),
            "https://api.bsky.chat"
        );
        assert!(did_web_endpoint("did:web:").is_err());
        assert!(did_web_endpoint("did:web:evil.com%3A8443").is_err());
        assert!(did_web_endpoint("did:web:host/path").is_err());
        assert!(did_web_endpoint("did:plc:xyz").is_err());
    }

    #[test]
    fn service_endpoint_matches_short_and_full_ids() {
        let doc = serde_json::json!({
            "id": "did:plc:feedgen",
            "service": [
                { "id": "#bsky_fg", "type": "BskyFeedGenerator",
                  "serviceEndpoint": "https://feeds.example.com" },
                { "id": "did:plc:feedgen#other", "type": "X",
                  "serviceEndpoint": "https://other.example.com" }
            ]
        });
        assert_eq!(
            service_endpoint_from_doc(&doc, "did:plc:feedgen", "bsky_fg").as_deref(),
            Some("https://feeds.example.com")
        );
        assert_eq!(
            service_endpoint_from_doc(&doc, "did:plc:feedgen", "other").as_deref(),
            Some("https://other.example.com")
        );
        assert!(service_endpoint_from_doc(&doc, "did:plc:feedgen", "missing").is_none());
    }
}
