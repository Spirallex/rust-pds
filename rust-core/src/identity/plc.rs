//! did:plc genesis operation: build, sign, submit, and derive the DID.
//!
//! References:
//!   - https://web.plc.directory/spec/v0.1/did-plc
//!   - atrium-crypto Secp256k1Keypair::sign() for low-S ECDSA
//!
//! CRITICAL (Pitfall 2): The DID derives from sha256(dag-cbor(SIGNED op)).
//! Never derive from the unsigned op bytes or from the JSON representation.
//! The POST body sent to plc.directory is JSON; dag-cbor is only used for
//! signing and DID derivation.

use std::collections::BTreeMap;

use atrium_crypto::keypair::{Did as KeypairDid, Secp256k1Keypair};
use data_encoding::BASE32_NOPAD;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::CoreError;

/// Unsigned genesis PLC operation (no `sig` field).
///
/// BTreeMap is used for `verificationMethods` and `services` so field ordering
/// is deterministic across platforms (required for reproducible dag-cbor encoding).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlcGenesisOpUnsigned {
    #[serde(rename = "type")]
    op_type: &'static str,
    rotation_keys: Vec<String>,
    verification_methods: BTreeMap<String, String>,
    also_known_as: Vec<String>,
    services: BTreeMap<String, PlcService>,
    prev: Option<String>,
}

/// Signed genesis PLC operation (includes `sig` field).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlcGenesisOpSigned {
    #[serde(rename = "type")]
    pub op_type: &'static str,
    pub rotation_keys: Vec<String>,
    pub verification_methods: BTreeMap<String, String>,
    pub also_known_as: Vec<String>,
    pub services: BTreeMap<String, PlcService>,
    pub prev: Option<String>,
    /// base64url-nopad encoded signature over dag-cbor(unsigned op).
    pub sig: String,
}

/// A PLC service entry.
#[derive(Debug, Clone, Serialize)]
pub struct PlcService {
    #[serde(rename = "type")]
    pub service_type: String,
    pub endpoint: String,
}

/// Injectable trait for submitting PLC operations.
///
/// The production implementation POSTs to https://plc.directory/{did}.
/// Tests use `MockPlcClient` to avoid any network calls.
#[async_trait::async_trait]
pub trait PlcClient: Send + Sync {
    async fn post_operation(&self, did: &str, op: &PlcGenesisOpSigned) -> Result<(), CoreError>;
}

/// Build, sign, and submit a genesis PLC operation. Returns the `did:plc:...` string.
///
/// Steps:
/// 1. Build the unsigned op (BTreeMaps for deterministic dag-cbor).
/// 2. dag-cbor encode the unsigned op; sign with `rotation_key`.
/// 3. base64url-nopad encode the signature bytes.
/// 4. Build the signed op (same fields + `sig`).
/// 5. dag-cbor encode the SIGNED op; sha256 hash; base32lower first 24 chars.
/// 6. Submit to plc.directory via the injected `plc_client`.
pub async fn register_did_plc(
    handle: &str,
    pds_endpoint: &str,
    signing_key: &Secp256k1Keypair,
    rotation_key: &Secp256k1Keypair,
    plc_client: &dyn PlcClient,
) -> Result<String, CoreError> {
    let signing_did = signing_key.did();
    let rotation_did = rotation_key.did();

    // 1. Build unsigned op
    let mut verification_methods = BTreeMap::new();
    verification_methods.insert("atproto".to_string(), signing_did.clone());

    let mut services = BTreeMap::new();
    services.insert(
        "atproto_pds".to_string(),
        PlcService {
            service_type: "AtprotoPersonalDataServer".to_string(),
            endpoint: pds_endpoint.to_string(),
        },
    );

    let unsigned = PlcGenesisOpUnsigned {
        op_type: "plc_operation",
        rotation_keys: vec![rotation_did.clone()],
        verification_methods: verification_methods.clone(),
        also_known_as: vec![format!("at://{handle}")],
        services: services.clone(),
        prev: None,
    };

    // 2. dag-cbor encode unsigned op; sign with rotation key
    let unsigned_cbor = serde_ipld_dagcbor::to_vec(&unsigned)
        .map_err(|e| CoreError::Internal(anyhow::anyhow!("dag-cbor encode unsigned: {e}")))?;
    let sig_bytes = rotation_key
        .sign(&unsigned_cbor)
        .map_err(|e| CoreError::Internal(anyhow::anyhow!("secp256k1 sign error: {e}")))?;

    // 3. base64url-nopad encode signature
    let sig_b64url = data_encoding::BASE64URL_NOPAD.encode(&sig_bytes);

    // 4. Build signed op (same fields + sig)
    let signed = PlcGenesisOpSigned {
        op_type: "plc_operation",
        rotation_keys: vec![rotation_did],
        verification_methods,
        also_known_as: vec![format!("at://{handle}")],
        services,
        prev: None,
        sig: sig_b64url,
    };

    // 5. DID derivation: sha256(dag-cbor(SIGNED op)) — NOT from the unsigned op or JSON.
    //    CRITICAL: The DID must be derived from the dag-cbor of the signed op.
    let signed_cbor = serde_ipld_dagcbor::to_vec(&signed)
        .map_err(|e| CoreError::Internal(anyhow::anyhow!("dag-cbor encode signed: {e}")))?;
    let hash = Sha256::digest(&signed_cbor);
    let b32 = BASE32_NOPAD.encode(&hash).to_ascii_lowercase();
    let did_suffix = &b32[..24];
    let did = format!("did:plc:{did_suffix}");

    // 6. Submit to plc.directory (injectable for testing — no live network in tests)
    plc_client.post_operation(&did, &signed).await?;

    Ok(did)
}

/// Test double for `PlcClient`: records the last call, never makes a network request.
///
/// NOT `#[cfg(test)]`-gated: the integration test in `tests/` (plan 04-05) lives in a
/// separate crate and cannot access `#[cfg(test)]` items (same pattern as MockRelayClient).
pub struct MockPlcClient {
    last_call: std::sync::Mutex<Option<(String, PlcGenesisOpSigned)>>,
}

impl MockPlcClient {
    pub fn new() -> Self {
        MockPlcClient {
            last_call: std::sync::Mutex::new(None),
        }
    }

    pub fn last_did(&self) -> Option<String> {
        self.last_call
            .lock()
            .unwrap()
            .as_ref()
            .map(|(d, _)| d.clone())
    }

    pub fn last_op(&self) -> Option<PlcGenesisOpSigned> {
        self.last_call
            .lock()
            .unwrap()
            .as_ref()
            .map(|(_, op)| op.clone())
    }
}

impl Default for MockPlcClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl PlcClient for MockPlcClient {
    async fn post_operation(&self, did: &str, op: &PlcGenesisOpSigned) -> Result<(), CoreError> {
        let mut guard = self.last_call.lock().unwrap();
        *guard = Some((did.to_string(), op.clone()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic keypairs from fixed scalars for reproducible tests
    fn signing_key() -> Secp256k1Keypair {
        Secp256k1Keypair::import(&[0x11u8; 32]).expect("valid scalar")
    }
    fn rotation_key() -> Secp256k1Keypair {
        Secp256k1Keypair::import(&[0x22u8; 32]).expect("valid scalar")
    }

    #[tokio::test]
    async fn plc_op_shape_and_did_format() {
        let signing = signing_key();
        let rotation = rotation_key();
        let mock = MockPlcClient::new();

        let did = register_did_plc(
            "alice.test",
            "https://pds.example.com",
            &signing,
            &rotation,
            &mock,
        )
        .await
        .unwrap();

        // DID format check
        assert!(did.starts_with("did:plc:"), "DID must start with did:plc:");
        let suffix = &did["did:plc:".len()..];
        assert_eq!(suffix.len(), 24, "DID suffix must be 24 chars");
        assert!(
            suffix
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "DID suffix must be lowercase base32"
        );

        // Op shape check
        let op = mock.last_op().expect("mock should have recorded an op");
        assert_eq!(op.op_type, "plc_operation");
        assert!(op.prev.is_none(), "genesis op must have prev=null");
        assert_eq!(op.rotation_keys, vec![rotation.did()]);
        assert_eq!(
            op.verification_methods.get("atproto").unwrap(),
            &signing.did()
        );
        assert_eq!(op.also_known_as, vec!["at://alice.test"]);
        let svc = op
            .services
            .get("atproto_pds")
            .expect("must have atproto_pds service");
        assert_eq!(svc.service_type, "AtprotoPersonalDataServer");
        assert_eq!(svc.endpoint, "https://pds.example.com");
        assert!(!op.sig.is_empty(), "sig must be non-empty base64url");
    }

    #[tokio::test]
    async fn did_derivation_deterministic() {
        let signing = signing_key();
        let rotation = rotation_key();

        let mock1 = MockPlcClient::new();
        let did1 = register_did_plc(
            "alice.test",
            "https://pds.example.com",
            &signing,
            &rotation,
            &mock1,
        )
        .await
        .unwrap();

        let mock2 = MockPlcClient::new();
        let did2 = register_did_plc(
            "alice.test",
            "https://pds.example.com",
            &signing,
            &rotation,
            &mock2,
        )
        .await
        .unwrap();

        assert_eq!(
            did1, did2,
            "DID derivation must be deterministic for same inputs"
        );
        assert!(did1.starts_with("did:plc:"));
        let suffix = &did1["did:plc:".len()..];
        assert_eq!(suffix.len(), 24);
    }

    #[tokio::test]
    async fn mock_client_receives_correct_did() {
        let signing = signing_key();
        let rotation = rotation_key();
        let mock = MockPlcClient::new();

        let did = register_did_plc(
            "bob.example.com",
            "https://pds.example.com",
            &signing,
            &rotation,
            &mock,
        )
        .await
        .unwrap();

        assert_eq!(mock.last_did().unwrap(), did);
    }
}
