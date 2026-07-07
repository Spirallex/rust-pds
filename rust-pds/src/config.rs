//! PdsConfig: TOML-backed configuration for rust-pds.
//!
//! Secrets (jwt_secret, key_passphrase) are intentionally absent from this struct —
//! they are never written to disk (T-7-01-02).

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default, PartialEq)]
pub struct PdsConfig {
    pub hostname: Option<String>,
    pub mode: Option<String>,       // "standalone" | "proxy"
    pub did_method: Option<String>, // "plc" | "web"
    pub db_path: Option<String>,
    pub port: Option<u16>,
    pub acme_env: Option<String>, // "production" | "staging"
    pub acme_cache_dir: Option<String>,
    pub plc_url: Option<String>,
    pub relay_url: Option<String>,
    pub appview_url: Option<String>,
    pub appview_did: Option<String>,
    /// Compose-network plain-HTTP dev mode for the did:web resolver.
    /// NEVER set true in production — resolution must use HTTPS in prod.
    pub did_web_http_dev: Option<bool>,
    // NO jwt_secret / key_passphrase — secrets never written to disk (T-7-01-02)
}

impl PdsConfig {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        Ok(toml::from_str(&std::fs::read_to_string(path)?)?)
    }

    pub fn load_or_default(path: Option<&std::path::Path>) -> anyhow::Result<Self> {
        match path {
            Some(p) if p.exists() => Self::load(p),
            _ => Ok(Self::default()),
        }
    }

    pub fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        std::fs::write(path, toml::to_string(self)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_through_toml() {
        let cfg = PdsConfig {
            hostname: Some("pds.example.com".to_string()),
            mode: Some("proxy".to_string()),
            did_method: Some("plc".to_string()),
            db_path: Some("pds.db".to_string()),
            port: Some(3000),
            acme_env: Some("staging".to_string()),
            acme_cache_dir: Some("/var/lib/pds/acme".to_string()),
            plc_url: Some("https://plc.directory".to_string()),
            relay_url: Some("https://bsky.network".to_string()),
            appview_url: Some("https://api.bsky.app".to_string()),
            appview_did: Some("did:web:api.bsky.app".to_string()),
            did_web_http_dev: Some(true),
        };

        let tmp = tempfile::NamedTempFile::new().unwrap();
        cfg.save(tmp.path()).unwrap();
        let loaded = PdsConfig::load(tmp.path()).unwrap();
        assert_eq!(cfg, loaded, "round-trip must produce equal struct");
    }

    #[test]
    fn serialized_toml_does_not_contain_secrets() {
        let cfg = PdsConfig {
            hostname: Some("pds.example.com".to_string()),
            ..Default::default()
        };
        let toml_str = toml::to_string(&cfg).unwrap();
        assert!(
            !toml_str.contains("jwt_secret"),
            "TOML must not contain jwt_secret"
        );
        assert!(
            !toml_str.contains("key_passphrase"),
            "TOML must not contain key_passphrase"
        );
    }

    #[test]
    fn load_or_default_with_none_returns_default() {
        let cfg = PdsConfig::load_or_default(None).unwrap();
        assert_eq!(cfg, PdsConfig::default(), "None path must return default");
    }

    #[test]
    fn load_or_default_with_absent_path_returns_default() {
        let cfg = PdsConfig::load_or_default(Some(std::path::Path::new(
            "/nonexistent/path/rust-pds.toml",
        )))
        .unwrap();
        assert_eq!(cfg, PdsConfig::default(), "absent file must return default");
    }
}
