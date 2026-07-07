//! did:web DID document builder.
//!
//! Reference: https://atproto.com/specs/did
//!
//! The did:web DID is `did:web:<hostname>`. The DID document includes:
//! - A `Multikey` verification method with `publicKeyMultibase` derived from
//!   `Secp256k1Keypair::did()` by stripping the `did:key:` prefix.
//! - An `AtprotoPersonalDataServer` service entry.

use atrium_crypto::keypair::{Did as KeypairDid, Secp256k1Keypair};
use serde::Serialize;

/// A DID document as served at `/.well-known/did.json` for did:web accounts.
#[derive(Debug, Clone, Serialize)]
pub struct DidDocument {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "alsoKnownAs")]
    pub also_known_as: Vec<String>,
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    pub service: Vec<ServiceEntry>,
}

/// A verification method in the DID document.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationMethod {
    pub id: String,
    #[serde(rename = "type")]
    pub vm_type: String,
    pub controller: String,
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// A service entry in the DID document.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceEntry {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

/// Derive the did:web DID for a given hostname.
///
/// Result: `"did:web:<hostname>"`.
pub fn did_web(hostname: &str) -> String {
    format!("did:web:{hostname}")
}

/// Build the DID document for a did:web account.
///
/// `publicKeyMultibase` is extracted from `Secp256k1Keypair::did()` by
/// stripping the `"did:key:"` prefix — the remaining `z...` string IS the
/// multibase-encoded compressed public key in multikey format.
///
/// Note: (Assumption A4) This derivation is consistent with atproto.com/specs/did.
pub fn did_web_document(
    hostname: &str,
    signing_key: &Secp256k1Keypair,
    pds_endpoint: &str,
) -> DidDocument {
    let did = did_web(hostname);
    let key_did = signing_key.did();
    let public_key_multibase = key_did
        .strip_prefix("did:key:")
        .unwrap_or(&key_did)
        .to_string();

    DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".to_string(),
            "https://w3id.org/security/multikey/v1".to_string(),
        ],
        id: did.clone(),
        also_known_as: vec![],
        verification_method: vec![VerificationMethod {
            id: format!("{did}#atproto"),
            vm_type: "Multikey".to_string(),
            controller: did.clone(),
            public_key_multibase,
        }],
        service: vec![ServiceEntry {
            id: "#atproto_pds".to_string(),
            service_type: "AtprotoPersonalDataServer".to_string(),
            service_endpoint: pds_endpoint.to_string(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key() -> Secp256k1Keypair {
        Secp256k1Keypair::import(&[0x11u8; 32]).expect("valid scalar")
    }

    #[test]
    fn did_web_format() {
        assert_eq!(did_web("example.com"), "did:web:example.com");
        assert_eq!(did_web("pds.alice.com"), "did:web:pds.alice.com");
    }

    #[test]
    fn did_web_document_id() {
        let key = signing_key();
        let doc = did_web_document("example.com", &key, "https://pds.example.com");
        assert_eq!(doc.id, "did:web:example.com");
    }

    #[test]
    fn did_web_document_verification_method() {
        let key = signing_key();
        let doc = did_web_document("example.com", &key, "https://pds.example.com");
        assert_eq!(doc.verification_method.len(), 1);
        let vm = &doc.verification_method[0];
        assert_eq!(vm.vm_type, "Multikey");
        assert_eq!(vm.id, "did:web:example.com#atproto");
        assert_eq!(vm.controller, "did:web:example.com");
        // publicKeyMultibase must start with 'z' (base58btc multibase prefix)
        assert!(
            vm.public_key_multibase.starts_with('z'),
            "publicKeyMultibase must start with 'z' (multibase base58btc)"
        );
        // Must match Secp256k1Keypair::did() minus the did:key: prefix
        let expected = key.did().strip_prefix("did:key:").unwrap().to_string();
        assert_eq!(vm.public_key_multibase, expected);
    }

    #[test]
    fn did_web_document_service() {
        let key = signing_key();
        let doc = did_web_document("example.com", &key, "https://pds.example.com");
        assert_eq!(doc.service.len(), 1);
        let svc = &doc.service[0];
        assert_eq!(svc.service_type, "AtprotoPersonalDataServer");
        assert_eq!(svc.service_endpoint, "https://pds.example.com");
    }
}
