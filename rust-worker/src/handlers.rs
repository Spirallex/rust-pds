//! HTTP surface served by the Durable Object.
//!
//! Handlers are written against `stelyph-core` directly rather than reusing the
//! axum handlers in the `stelyph` server crate: that crate cannot compile to
//! wasm32 (tokio-full, reqwest + rustls, axum-server, rustls-acme, keyring), so
//! sharing them would mean extracting them into a fourth crate first. The
//! protocol logic — which is the part worth sharing — already lives in
//! `stelyph-core` and is used as-is here.

use worker::*;

use stelyph_core::oauth::{AuthorizationServerMetadata, JwkSet, ProtectedResourceMetadata};
use stelyph_core::storage::AccountStore;

use crate::store::DoStore;

/// Key id for this PDS's OAuth authorization-server signing key.
const AS_SIGNING_KEY_ID: &str = "oauth#as-signing";

/// Everything a handler needs to know about which PDS it is serving.
///
/// A single Worker and Durable Object class serve every hostname, so identity is
/// per-request, not per-deployment.
pub struct Ctx {
    /// e.g. `https://joey.pds.spirallex.net` — the OAuth issuer. No trailing
    /// slash, because clients compare `iss` byte-for-byte.
    pub issuer: String,
    /// The **service** DID of this PDS instance — not the DID of the account it
    /// hosts. e.g. `did:web:joey.pds.spirallex.net`.
    ///
    /// The two are easy to confuse here, because one hostname is both the
    /// person's handle and the PDS serving it, so both DIDs answer at the same
    /// name. They are different identities with different jobs:
    ///
    /// | | value | served at | answers |
    /// |---|---|---|---|
    /// | service | `did:web:<host>` | `/.well-known/did.json` | "what software is this?" |
    /// | account | `did:plc:…` | `/.well-known/atproto-did` | "who lives here?" |
    ///
    /// Accounts are `did:plc` so they stay portable — a `did:web` identity is
    /// welded to its hostname and cannot survive a move to another server, which
    /// is the whole point of the protocol. The service DID has no such
    /// requirement: it describes a deployment, which does not migrate.
    ///
    /// This is why `did.json` deliberately carries no `verificationMethod`. A
    /// client that mistook it for the account's identity finds nothing to verify
    /// against and fails, rather than proceeding with the wrong DID.
    pub service_did: String,
}

impl Ctx {
    pub fn from_host(hostname: &str) -> Self {
        Self {
            issuer: format!("https://{hostname}"),
            service_did: format!("did:web:{hostname}"),
        }
    }
}

/// `GET /.well-known/oauth-authorization-server` (RFC 8414).
pub fn oauth_as_metadata(ctx: &Ctx) -> Result<Response> {
    Response::from_json(&AuthorizationServerMetadata::new(&ctx.issuer))
}

/// `GET /.well-known/oauth-protected-resource` (RFC 9728).
pub fn oauth_protected_resource(ctx: &Ctx) -> Result<Response> {
    Response::from_json(&ProtectedResourceMetadata::new(&ctx.issuer))
}

/// `GET /xrpc/com.atproto.server.describeServer`.
///
/// The first call most atproto clients make. `availableUserDomains` is the
/// zone suffix rather than this hostname: it advertises where *new* handles can
/// be created, and every account on this deployment is a label under the zone.
///
/// `did` here is the service DID, which is what the lexicon field means — the
/// same way `bsky.social` answers `did:web:bsky.social`. It is not the DID of
/// whoever's account lives at this hostname; that one is `did:plc` and is
/// resolved through `/.well-known/atproto-did`.
pub fn describe_server(ctx: &Ctx, zone_suffix: &str) -> Result<Response> {
    Response::from_json(&serde_json::json!({
        "did": ctx.service_did,
        "availableUserDomains": [format!(".{zone_suffix}")],
        // No open registration: an account needs a `pulumi`-free but
        // operator-driven creation step, so advertise the invite requirement
        // rather than letting clients attempt a signup that will fail.
        "inviteCodeRequired": true,
        "links": {},
    }))
}

/// `GET /oauth/jwks` — the authorization server's public keys.
///
/// The private half never leaves the Durable Object: `public_jwk()` cannot
/// produce private material, so there is no path by which the scalar could be
/// serialized here.
pub async fn jwks(store: &DoStore, passphrase: &[u8]) -> Result<Response> {
    let key = load_or_create_signing_key(store, passphrase).await?;
    Response::from_json(&JwkSet {
        keys: vec![key.public_jwk()],
    })
}

/// Load this PDS's AS signing key, generating and persisting one on first use.
///
/// Stored through the ordinary encrypted `KeyStore` path, so it sits at rest
/// under the same argon2id + AES-GCM envelope as account signing keys. Note the
/// KDF runs inline on wasm32 (no thread pool), which is why the crate builds
/// with `lean-auth`.
pub async fn load_or_create_signing_key(
    store: &DoStore,
    passphrase: &[u8],
) -> Result<stelyph_core::oauth::SigningKey> {
    use stelyph_core::oauth::SigningKey;
    use stelyph_core::storage::crypto;

    if let Ok(scalar) = crypto::load_key(store, AS_SIGNING_KEY_ID, passphrase).await {
        if let Ok(key) = SigningKey::import(&scalar) {
            return Ok(key);
        }
    }

    let key = SigningKey::generate();
    crypto::store_key(store, AS_SIGNING_KEY_ID, &key.export(), passphrase)
        .await
        .map_err(|e| Error::RustError(format!("persist OAuth signing key: {e}")))?;
    Ok(key)
}

/// `GET /.well-known/atproto-did` — handle resolution.
///
/// How a handle becomes a DID: a resolver fetches this over HTTPS at the handle
/// itself and gets back the DID as bare text. `did.json` does not substitute for
/// it — that document only answers for `did:web`, and accounts here are
/// `did:plc`, so without this endpoint every handle on the deployment is
/// unresolvable and no appview ever finds the account.
pub async fn atproto_did(store: &DoStore, hostname: &str) -> Result<Response> {
    let did = store
        .get_did_by_handle(hostname)
        .await
        .map_err(|e| Error::RustError(format!("handle lookup: {e}")))?;
    match did {
        Some(did) => {
            let mut resp = Response::ok(did)?;
            resp.headers_mut().set("content-type", "text/plain")?;
            Ok(resp)
        }
        // Deliberately 404 rather than an empty 200: a resolver must be able to
        // tell "no account here" from "an account with an empty DID".
        None => Response::error("no account for this handle", 404),
    }
}

/// Create the single account this Durable Object exists to serve.
///
/// Called only by the front Worker, and only after the registry has reserved the
/// label — the invite gate is not re-checked here because it cannot be: this
/// object sees one hostname and can never tell a first registration from a
/// thousandth. What it *can* enforce is that it holds at most one account, which
/// is the invariant that makes "one DO per hostname" mean "one PDS per person".
#[allow(clippy::too_many_arguments)]
pub async fn provision_account(
    store: &DoStore,
    ctx: &Ctx,
    handle: &str,
    email: Option<&str>,
    password: &str,
    passphrase: &[u8],
    jwt_secret: &[u8],
    plc_directory: &str,
) -> Result<ProvisionOutcome> {
    use atrium_crypto::keypair::{Export, Secp256k1Keypair};
    use stelyph_core::auth::jwt::{encode_access_jwt, encode_refresh_jwt, hash_password};
    use stelyph_core::identity::plc::register_did_plc;
    use stelyph_core::storage::crypto;

    if password.len() < 8 {
        return Ok(ProvisionOutcome::Rejected {
            error: "InvalidRequest",
            message: "Password must be at least 8 characters.".into(),
        });
    }

    // One account per object. A second call means either a retry after a
    // response was lost, or a registry that handed out the same label twice;
    // either way, creating a second identity in the same repo is wrong.
    let existing = store
        .count_accounts()
        .await
        .map_err(|e| Error::RustError(format!("count accounts: {e}")))?;
    if existing > 0 {
        return Ok(ProvisionOutcome::Rejected {
            error: "HandleNotAvailable",
            message: "That handle already has an account.".into(),
        });
    }

    let signing = Secp256k1Keypair::create(&mut rand::rngs::OsRng);
    let rotation = Secp256k1Keypair::create(&mut rand::rngs::OsRng);

    // The point of no return. Everything above is local to this object and can
    // be abandoned; this writes a signed genesis operation to a public ledger.
    // It runs before the account row is inserted so that a PLC failure leaves no
    // local trace, which is the recoverable direction to fail in — the opposite
    // order would leave an account whose DID does not exist.
    let plc = crate::plc::FetchPlcClient::new(plc_directory);
    let did = match register_did_plc(handle, &ctx.issuer, &signing, &rotation, &plc).await {
        Ok(did) => did,
        Err(e) => {
            return Ok(ProvisionOutcome::Rejected {
                error: "UpstreamFailure",
                message: format!("Could not register your identity: {e}"),
            })
        }
    };

    // argon2id runs inline — a Workers isolate has no thread pool to move it to,
    // which is why this crate builds with `lean-auth`.
    let phc =
        hash_password(password).map_err(|e| Error::RustError(format!("hash password: {e}")))?;

    store
        .count_and_insert_account(&did, handle, email, &phc)
        .await
        .map_err(|e| Error::RustError(format!("insert account: {e}")))?;

    for (suffix, scalar) in [
        ("signing", signing.export()),
        ("rotation", rotation.export()),
    ] {
        crypto::store_key(store, &format!("{did}#{suffix}"), &scalar, passphrase)
            .await
            .map_err(|e| Error::RustError(format!("store {suffix} key: {e}")))?;
    }

    let access_jwt = encode_access_jwt(&did, jwt_secret)
        .map_err(|e| Error::RustError(format!("access jwt: {e}")))?;
    let refresh_jwt = encode_refresh_jwt(&did, jwt_secret)
        .map_err(|e| Error::RustError(format!("refresh jwt: {e}")))?;

    Ok(ProvisionOutcome::Created {
        did,
        access_jwt,
        refresh_jwt,
    })
}

/// Result of a provisioning attempt.
///
/// A rejection is a value rather than an `Err` because the front Worker has to
/// act on it — releasing the reservation and returning the invite — and an
/// opaque transport error would not tell it whether that is safe.
pub enum ProvisionOutcome {
    Created {
        did: String,
        access_jwt: String,
        refresh_jwt: String,
    },
    Rejected {
        error: &'static str,
        message: String,
    },
}

/// `GET /.well-known/did.json` — the did:web document for this PDS *service*.
///
/// Describes the deployment, not the person. Accounts are `did:plc` and resolve
/// through `/.well-known/atproto-did`; see the note on [`Ctx::service_did`] for
/// why the two answer at the same hostname without being the same identity.
///
/// The verification method is deliberately absent. Nothing should be
/// authenticating against the service DID — a client that mistook this for the
/// account's identity finds no key and fails, which is the outcome to want.
pub fn did_web_document(ctx: &Ctx) -> Result<Response> {
    Response::from_json(&serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        ],
        "id": ctx.service_did,
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": ctx.issuer,
        }],
    }))
}
