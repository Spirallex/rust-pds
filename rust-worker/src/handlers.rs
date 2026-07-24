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
///
/// `inviteCodeRequired` mirrors the deployment's gate, so a client learns
/// whether to prompt for a code before it tries — advertising `true` while
/// registration is open would make well-behaved clients demand a code that is
/// not needed.
pub fn describe_server(ctx: &Ctx, zone_suffix: &str, open_registration: bool) -> Result<Response> {
    Response::from_json(&serde_json::json!({
        "did": ctx.service_did,
        "availableUserDomains": [format!(".{zone_suffix}")],
        "inviteCodeRequired": !open_registration,
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
    use stelyph_core::auth::jwt::{encode_access_jwt_at, encode_refresh_jwt_at, hash_password};
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

    let access_jwt = encode_access_jwt_at(&did, jwt_secret, now_unix())
        .map_err(|e| Error::RustError(format!("access jwt: {e}")))?;
    let refresh_jwt = encode_refresh_jwt_at(&did, jwt_secret, now_unix())
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

// ---------------------------------------------------------------------------
// Sign in with Stelyph — device-approval sign-in
// ---------------------------------------------------------------------------
// See rust-worker/SIGN-IN-WITH-STELYPH.md. These endpoints are per-account: the
// Durable Object *is* the account, so a request reaching this host is already
// scoped to it, and no account id travels in the body.

/// How long a pending sign-in stays approvable.
const SIGNIN_TTL_SECS: u64 = 300;

fn now_unix() -> u64 {
    worker::Date::now().as_millis() / 1000
}

/// A short opaque token: 24 random bytes, base32-nopad. Used for request ids and
/// device ids. Randomness is the isolate's CSPRNG, the same source account keys
/// come from.
fn random_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase()
}

/// A human-facing confirmation code, e.g. `WXYZ-1234`: four letters, four
/// digits, grouped. Enough entropy to make guessing a specific pending request
/// impractical, short enough to read off one screen and match on another.
fn user_code() -> String {
    use rand::Rng;
    const LETTERS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ"; // no I/O — reads cleaner
    const DIGITS: &[u8] = b"0123456789";
    let mut rng = rand::rngs::OsRng;
    let l: String = (0..4)
        .map(|_| LETTERS[rng.gen_range(0..LETTERS.len())] as char)
        .collect();
    let d: String = (0..4)
        .map(|_| DIGITS[rng.gen_range(0..DIGITS.len())] as char)
        .collect();
    format!("{l}-{d}")
}

/// `POST /oauth/device/register` — enrol a device key, gated by the password.
///
/// Proving account control once, with the password, is what lets every later
/// sign-in be passwordless. The body carries only the device's public
/// `did:key`; the private half stays on the device.
pub async fn device_register(
    store: &DoStore,
    handle: &str,
    password: &str,
    device_did_key: &str,
    label: &str,
) -> Result<Response> {
    use stelyph_core::auth::jwt::verify_password;
    use stelyph_core::storage::AccountStore;

    // A key that is not a did:key can never verify an approval; reject it at
    // enrolment rather than store a device that can do nothing. (The signature
    // check at approval time is the real gate; this is an early, friendly no.)
    if !device_did_key.starts_with("did:key:z") {
        return json_err(400, "InvalidRequest", "deviceDidKey must be a did:key.");
    }

    let account = store
        .get_account_by_handle(handle)
        .await
        .map_err(|e| Error::RustError(format!("account lookup: {e}")))?;
    let Some((_did, phc)) = account else {
        // Identical response for unknown account and wrong password — no oracle.
        return json_err(401, "Unauthorized", "Handle or password is incorrect.");
    };
    let ok = verify_password(password, &phc).unwrap_or(false);
    if !ok {
        return json_err(401, "Unauthorized", "Handle or password is incorrect.");
    }

    let device_id = random_token();
    store
        .register_device(&device_id, device_did_key, label)
        .map_err(|e| Error::RustError(format!("register device: {e}")))?;
    Response::from_json(&serde_json::json!({ "deviceId": device_id }))
}

/// `POST /oauth/signin/start` — begin a passwordless sign-in.
pub async fn signin_start(store: &DoStore, client_name: &str) -> Result<Response> {
    let request_id = random_token();
    let code = user_code();
    store
        .create_signin(
            &request_id,
            &code,
            client_name,
            now_unix() + SIGNIN_TTL_SECS,
        )
        .map_err(|e| Error::RustError(format!("create signin: {e}")))?;

    let challenge = stelyph_core::oauth::approval_challenge(&request_id, &code);
    Response::from_json(&serde_json::json!({
        "requestId": request_id,
        "userCode": code,
        // The exact bytes the device signs, so a client relaying to the phone
        // does not have to reconstruct the domain-separated challenge itself.
        "challenge": data_encoding::BASE64.encode(&challenge),
        "expiresAt": now_unix() + SIGNIN_TTL_SECS,
    }))
}

/// `POST /xrpc/com.atproto.server.createSession` — password login.
///
/// The legacy session path Bluesky uses: `identifier` (handle or DID) +
/// `password` → access + refresh JWTs. Served from the account's own DO (the
/// front Worker routes it by `identifier`), so this DO checks the one account it
/// holds. The identifier is accepted whether it is the handle or the DID.
pub async fn create_session(
    store: &DoStore,
    identifier: &str,
    password: &str,
    jwt_secret: &[u8],
) -> Result<Response> {
    use stelyph_core::auth::jwt::{encode_access_jwt_at, encode_refresh_jwt_at, verify_password};
    use stelyph_core::storage::AccountStore;

    let Some(account) = store
        .list_accounts()
        .await
        .map_err(|e| Error::RustError(format!("list accounts: {e}")))?
        .into_iter()
        .next()
    else {
        return xrpc_err(
            401,
            "AuthenticationRequired",
            "Invalid identifier or password.",
        );
    };
    let did = account.did;
    let handle = account.handle.clone().unwrap_or_default();

    // The identifier must name this account (its handle or DID). Mismatch reads
    // the same as a bad password — no oracle for which accounts exist.
    let id = identifier.to_ascii_lowercase();
    if id != handle.to_ascii_lowercase() && id != did.to_ascii_lowercase() {
        return xrpc_err(
            401,
            "AuthenticationRequired",
            "Invalid identifier or password.",
        );
    }

    let phc = store
        .account_password_phc(&did)
        .await
        .map_err(|e| Error::RustError(format!("load phc: {e}")))?;
    let ok = phc
        .as_deref()
        .map(|p| verify_password(password, p).unwrap_or(false))
        .unwrap_or(false);
    if !ok {
        return xrpc_err(
            401,
            "AuthenticationRequired",
            "Invalid identifier or password.",
        );
    }

    let now = worker::Date::now().as_millis() / 1000;
    let access = encode_access_jwt_at(&did, jwt_secret, now)
        .map_err(|e| Error::RustError(format!("access jwt: {e}")))?;
    let refresh = encode_refresh_jwt_at(&did, jwt_secret, now)
        .map_err(|e| Error::RustError(format!("refresh jwt: {e}")))?;

    Response::from_json(&serde_json::json!({
        "did": did,
        "handle": handle,
        "accessJwt": access,
        "refreshJwt": refresh,
        "active": true,
    }))
}

/// `GET /xrpc/app.bsky.actor.getPreferences` — the account's stored prefs.
///
/// Bearer-authenticated; the prefs are a private per-account JSON array (Bluesky
/// stores birth date, content labels, feeds here). Returns `{preferences: []}`
/// when none are set — a new account has none, which is correct, not an error.
pub async fn get_preferences(
    store: &DoStore,
    bearer: Option<&str>,
    jwt_secret: &[u8],
) -> Result<Response> {
    use stelyph_core::auth::jwt::decode_jwt;
    let Some(did) = bearer
        .and_then(|t| decode_jwt(t, jwt_secret).ok())
        .map(|c| c.sub)
    else {
        return xrpc_err(401, "AuthenticationRequired", "Invalid token.");
    };
    let prefs = store
        .get_preferences(&did)
        .await
        .map_err(|e| Error::RustError(format!("get prefs: {e}")))?;
    // Stored value is the JSON array; wrap it as {preferences: [...]}.
    let arr: serde_json::Value = prefs
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!([]));
    Response::from_json(&serde_json::json!({ "preferences": arr }))
}

/// `POST /xrpc/app.bsky.actor.putPreferences` — replace the account's prefs.
///
/// This is the endpoint Bluesky's onboarding calls to save the birth date. The
/// body is `{preferences: [...]}`; the array is stored verbatim.
pub async fn put_preferences(
    store: &DoStore,
    bearer: Option<&str>,
    jwt_secret: &[u8],
    body: &str,
) -> Result<Response> {
    use stelyph_core::auth::jwt::decode_jwt;
    let Some(did) = bearer
        .and_then(|t| decode_jwt(t, jwt_secret).ok())
        .map(|c| c.sub)
    else {
        return xrpc_err(401, "AuthenticationRequired", "Invalid token.");
    };
    let prefs = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("preferences").cloned())
        .unwrap_or_else(|| serde_json::json!([]));
    store
        .upsert_preferences(&did, &prefs.to_string())
        .await
        .map_err(|e| Error::RustError(format!("put prefs: {e}")))?;
    // putPreferences returns an empty 200 body.
    Response::from_json(&serde_json::json!({}))
}

/// `GET /xrpc/com.atproto.server.getSession` — who am I, from the bearer token.
pub async fn get_session(
    store: &DoStore,
    bearer: Option<&str>,
    jwt_secret: &[u8],
) -> Result<Response> {
    use stelyph_core::auth::jwt::decode_jwt;
    use stelyph_core::storage::AccountStore;

    let Some(token) = bearer else {
        return xrpc_err(401, "AuthenticationRequired", "Missing bearer token.");
    };
    let Ok(claims) = decode_jwt(token, jwt_secret) else {
        return xrpc_err(401, "AuthenticationRequired", "Invalid token.");
    };
    let handle = store
        .get_handle_by_did(&claims.sub)
        .await
        .map_err(|e| Error::RustError(format!("handle lookup: {e}")))?
        .unwrap_or_default();
    Response::from_json(&serde_json::json!({
        "did": claims.sub, "handle": handle, "active": true,
    }))
}

/// Proxy an `app.bsky.*` / `chat.bsky.*` request to the Bluesky AppView.
///
/// These are AppView methods, not PDS methods — the PDS's job is to forward them
/// with an inter-service auth token so the AppView knows, and trusts, which
/// account is asking. The token is a short-lived ES256K JWT signed by the
/// account's own signing key (iss = account DID, aud = AppView DID, lxm = the
/// method), which the AppView verifies against the account's DID document. This
/// is what lets a self-hosted PDS use the shared Bluesky AppView.
pub async fn proxy_appview(
    store: &DoStore,
    bearer: Option<&str>,
    jwt_secret: &[u8],
    passphrase: &[u8],
    nsid: &str,
    query: &str,
) -> Result<Response> {
    use atrium_crypto::keypair::Secp256k1Keypair;
    use stelyph_core::auth::jwt::decode_jwt;
    use stelyph_core::auth::service_auth::mint_service_auth_jwt_at;
    use stelyph_core::storage::crypto;
    use worker::send::SendFuture;

    const APPVIEW_DID: &str = "did:web:api.bsky.app";
    const APPVIEW_URL: &str = "https://api.bsky.app";

    // Resolve the caller from the access token, and load their signing key.
    let Some(did) = bearer
        .and_then(|t| decode_jwt(t, jwt_secret).ok())
        .map(|c| c.sub)
    else {
        return xrpc_err(401, "AuthenticationRequired", "Invalid token.");
    };
    let scalar = crypto::load_key(store, &format!("{did}#signing"), passphrase)
        .await
        .map_err(|e| Error::RustError(format!("load signing key: {e}")))?;
    let key = Secp256k1Keypair::import(&scalar)
        .map_err(|e| Error::RustError(format!("import key: {e}")))?;

    let now = worker::Date::now().as_millis() / 1000;
    let token = mint_service_auth_jwt_at(&key, &did, APPVIEW_DID, Some(nsid), now + 60, now)
        .map_err(|e| Error::RustError(format!("mint service auth: {e}")))?;

    let url = if query.is_empty() {
        format!("{APPVIEW_URL}/xrpc/{nsid}")
    } else {
        format!("{APPVIEW_URL}/xrpc/{nsid}?{query}")
    };

    // Fetch the AppView with the minted token and relay the body back.
    let (status, body, ctype) = SendFuture::new(async move {
        let headers = worker::Headers::new();
        headers.set("authorization", &format!("Bearer {token}"))?;
        let mut init = worker::RequestInit::new();
        init.with_method(worker::Method::Get).with_headers(headers);
        let req = worker::Request::new_with_init(&url, &init)?;
        let mut resp = worker::Fetch::Request(req).send().await?;
        let ct = resp
            .headers()
            .get("content-type")?
            .unwrap_or_else(|| "application/json".into());
        let bytes = resp.bytes().await?;
        Ok::<_, worker::Error>((resp.status_code(), bytes, ct))
    })
    .await?;

    let mut resp = Response::from_bytes(body)?.with_status(status);
    resp.headers_mut().set("content-type", &ctype)?;
    Ok(resp)
}

/// XRPC-shaped error with a status code (createSession/getSession use it).
fn xrpc_err(status: u16, error: &str, message: &str) -> Result<Response> {
    Ok(
        Response::from_json(&serde_json::json!({ "error": error, "message": message }))?
            .with_status(status),
    )
}

/// `GET /xrpc/com.atproto.repo.describeRepo` — public identity of the account
/// this Durable Object holds.
///
/// Served after the front Worker has routed the request to the right account's
/// DO (by `repo` = handle or DID). Because each DO holds exactly one account,
/// the `repo` parameter is only a routing key — here we simply describe the one
/// account present. `collections` is genuinely empty until records exist; the
/// write path that would populate it is not on this Worker yet.
pub async fn describe_repo(store: &DoStore, ctx: &Ctx, hostname: &str) -> Result<Response> {
    use stelyph_core::storage::AccountStore;

    let account = store
        .list_accounts()
        .await
        .map_err(|e| Error::RustError(format!("list accounts: {e}")))?
        .into_iter()
        .next();
    let Some(account) = account else {
        return json_err(404, "RepoNotFound", "No account on this host.");
    };
    let did = account.did;
    let handle = account.handle.unwrap_or_else(|| hostname.to_string());

    // The DID document a resolver would fetch — the account did:plc pointing at
    // the shared PDS service (ctx.issuer), and the handle it also-known-as.
    let did_doc = serde_json::json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "alsoKnownAs": [format!("at://{handle}")],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": ctx.issuer,
        }],
    });

    Response::from_json(&serde_json::json!({
        "handle": handle,
        "did": did,
        "didDoc": did_doc,
        "collections": [],
        "handleIsCorrect": true,
    }))
}

/// `GET /oauth/signin/pending` — the approving phone lists requests to approve.
///
/// Served from the account's own DO, so it is already scoped to that account.
/// Returns only what the approver needs to decide; the issued session is never
/// here — that goes only to the client that polls `signin/poll`.
pub async fn signin_pending(store: &DoStore) -> Result<Response> {
    let pending = store
        .list_pending_signins(now_unix())
        .map_err(|e| Error::RustError(format!("list pending: {e}")))?;
    Response::from_json(&serde_json::json!({ "pending": pending }))
}

/// `GET /oauth/signin/poll?requestId=…` — the client waits here.
pub async fn signin_poll(store: &DoStore, request_id: &str) -> Result<Response> {
    let Some(row) = store
        .get_signin(request_id)
        .map_err(|e| Error::RustError(format!("get signin: {e}")))?
    else {
        return json_err(404, "NotFound", "No such sign-in request.");
    };

    // Expiry is computed on read rather than swept: a pending request past its
    // deadline reads as expired without a background job.
    let status = if row.status == "pending" && (row.expires_at as u64) < now_unix() {
        "expired".to_string()
    } else {
        row.status.clone()
    };

    let mut body = serde_json::json!({ "status": status });
    if status == "approved" {
        body["did"] = serde_json::json!(row.did);
        body["handle"] = serde_json::json!(row.handle);
        body["accessJwt"] = serde_json::json!(row.access_jwt);
        body["refreshJwt"] = serde_json::json!(row.refresh_jwt);
    }
    Response::from_json(&body)
}

/// `POST /oauth/device/approve` — the phone approves, with a signature.
#[allow(clippy::too_many_arguments)]
pub async fn device_approve(
    store: &DoStore,
    ctx: &Ctx,
    request_id: &str,
    device_id: &str,
    signature: &[u8],
    jwt_secret: &[u8],
) -> Result<Response> {
    use stelyph_core::auth::jwt::{encode_access_jwt_at, encode_refresh_jwt_at};
    use stelyph_core::storage::AccountStore;

    let Some(row) = store
        .get_signin(request_id)
        .map_err(|e| Error::RustError(format!("get signin: {e}")))?
    else {
        return json_err(404, "NotFound", "No such sign-in request.");
    };
    if row.status != "pending" {
        return json_err(409, "AlreadyDecided", "This sign-in is no longer pending.");
    }
    if (row.expires_at as u64) < now_unix() {
        return json_err(410, "Expired", "This sign-in has expired.");
    }

    let Some(did_key) = store
        .device_did_key(device_id)
        .map_err(|e| Error::RustError(format!("device lookup: {e}")))?
    else {
        return json_err(401, "Unauthorized", "Unknown device.");
    };

    // The heart of it: a valid signature over this request's challenge, by the
    // enrolled device key. Fails closed on any parse/verify error.
    if !stelyph_core::oauth::verify_approval(&did_key, request_id, &row.user_code, signature) {
        return json_err(401, "Unauthorized", "Approval signature did not verify.");
    }

    // Resolve the account this host serves, and mint its session.
    let (did, handle) = match store
        .list_accounts()
        .await
        .map_err(|e| Error::RustError(format!("list accounts: {e}")))?
        .into_iter()
        .next()
    {
        Some(a) => (a.did, a.handle.unwrap_or_default()),
        None => return json_err(409, "NoAccount", "This host has no account to sign in to."),
    };
    // The issuer is this host; keep it in the tokens for parity with createAccount.
    let _ = &ctx.issuer;

    let access = encode_access_jwt_at(&did, jwt_secret, now_unix())
        .map_err(|e| Error::RustError(format!("access jwt: {e}")))?;
    let refresh = encode_refresh_jwt_at(&did, jwt_secret, now_unix())
        .map_err(|e| Error::RustError(format!("refresh jwt: {e}")))?;

    store
        .approve_signin(request_id, &did, &handle, &access, &refresh)
        .map_err(|e| Error::RustError(format!("approve signin: {e}")))?;

    Response::from_json(&serde_json::json!({ "ok": true }))
}

/// `POST /oauth/device/deny` — the phone refuses, with a signature.
pub async fn device_deny(
    store: &DoStore,
    request_id: &str,
    device_id: &str,
    signature: &[u8],
) -> Result<Response> {
    let Some(row) = store
        .get_signin(request_id)
        .map_err(|e| Error::RustError(format!("get signin: {e}")))?
    else {
        return json_err(404, "NotFound", "No such sign-in request.");
    };
    if row.status != "pending" {
        return json_err(409, "AlreadyDecided", "This sign-in is no longer pending.");
    }
    let Some(did_key) = store
        .device_did_key(device_id)
        .map_err(|e| Error::RustError(format!("device lookup: {e}")))?
    else {
        return json_err(401, "Unauthorized", "Unknown device.");
    };
    if !stelyph_core::oauth::verify_approval(&did_key, request_id, &row.user_code, signature) {
        return json_err(401, "Unauthorized", "Signature did not verify.");
    }
    store
        .deny_signin(request_id)
        .map_err(|e| Error::RustError(format!("deny signin: {e}")))?;
    Response::from_json(&serde_json::json!({ "ok": true }))
}

/// Erase the single account this Durable Object holds, returning its DID and
/// handle so the front Worker can free the registry label.
///
/// Internal: reachable only from the front Worker's admin path, never routed
/// from a client request.
pub async fn delete_account(store: &DoStore) -> Result<Response> {
    use stelyph_core::storage::AccountStore;

    let account = store
        .list_accounts()
        .await
        .map_err(|e| Error::RustError(format!("list accounts: {e}")))?
        .into_iter()
        .next();
    let Some(account) = account else {
        return Response::from_json(&serde_json::json!({ "ok": false, "error": "NoAccount" }));
    };
    let handle = account.handle.clone().unwrap_or_default();
    store
        .delete_account_data(&account.did)
        .map_err(|e| Error::RustError(format!("delete account data: {e}")))?;
    Response::from_json(&serde_json::json!({
        "ok": true, "did": account.did, "handle": handle,
    }))
}

/// A JSON error body with an HTTP status, matching the app-facing error shape.
fn json_err(status: u16, error: &str, message: &str) -> Result<Response> {
    Ok(Response::from_json(&serde_json::json!({
        "error": error,
        "message": message,
    }))?
    .with_status(status))
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
