//! Link probe: measures a realistic bundle by touching the subsystems the real
//! Worker will use, so dead-code elimination cannot flatter the number.
use worker::*;

#[event(fetch)]
async fn fetch(_req: HttpRequest, _env: Env, _ctx: Context) -> Result<HttpResponse> {
    use stelyph_core::oauth::{
        AuthorizationServerMetadata, ClientId, DpopVerifier, Scope, SigningKey, TokenIssuer,
    };
    use stelyph_core::storage::{MemoryStore, StorageBackend};

    let store = MemoryStore::new();
    let _: &dyn StorageBackend = &store;

    // OAuth: signing, token issuance, DPoP, client + scope validation, metadata.
    let key = SigningKey::generate();
    let issuer = TokenIssuer::new(key, "https://x.test".into(), "did:web:x.test".into());
    let scope = Scope::parse("atproto transition:generic").unwrap();
    let _ = issuer.issue_access_token("did:plc:x", "c", &scope, "jkt");
    let _ = DpopVerifier::new(vec![0u8; 32]).current_nonce();
    let _ = ClientId::parse("https://app.test/client-metadata.json");
    let _ = serde_json::to_string(&AuthorizationServerMetadata::new("https://x.test"));

    // Repo engine: MST + signed commits + CAR, the heaviest part of the core.
    let signing = atrium_crypto::keypair::Secp256k1Keypair::create(&mut rand::rngs::OsRng);
    let did = atrium_api::types::string::Did::new("did:web:x.test".into()).unwrap();
    let (tx, _rx) = tokio::sync::broadcast::channel(1);
    let writer = stelyph_core::repo::RepoWriter::new(std::sync::Arc::new(store), signing, did, tx);
    let _ = writer.current_mst_root().await;

    Ok(http::Response::builder()
        .status(200)
        .body(worker::Body::empty())
        .unwrap())
}
