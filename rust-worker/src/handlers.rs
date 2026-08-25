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

/// `GET /xrpc/com.atproto.identity.resolveHandle?handle=<h>` — handle → DID.
///
/// The XRPC twin of [`atproto_did`]: same question, same answer, different
/// callers. A resolver following the identity spec fetches `atproto-did` at the
/// handle's own host, but a client that already has a PDS configured — the iOS
/// app, and every atproto SDK's login path — calls this method on that PDS and
/// never looks at the well-known. Serving only the former means login fails at
/// its first step against a handle that is otherwise perfectly resolvable.
///
/// This object holds exactly one account, so an unknown `handle` — including a
/// real handle belonging to a *different* account, whose request landed here
/// because it named a host this deployment does not serve — simply misses the
/// store and gets `HandleNotFound`. Routing a shared-host request to the right
/// object is the front Worker's job (`resolve_handle_target`), not this one's.
pub async fn resolve_handle(store: &DoStore, handle: &str) -> Result<Response> {
    let did = store
        .get_did_by_handle(&handle.to_ascii_lowercase())
        .await
        .map_err(|e| Error::RustError(format!("handle lookup: {e}")))?;
    match did {
        Some(did) => Response::from_json(&serde_json::json!({ "did": did })),
        None => xrpc_err(404, "HandleNotFound", "Unable to resolve handle"),
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

/// Proxy an `app.bsky.*` or `chat.bsky.*` request to the service that serves it.
///
/// These are AppView methods, not PDS methods — the PDS's job is to forward them
/// with an inter-service auth token so the AppView knows, and trusts, which
/// account is asking. The token is a short-lived ES256K JWT signed by the
/// account's own signing key (iss = account DID, aud = the target's DID, lxm =
/// the method), which the target verifies against the account's DID document.
/// This is what lets a self-hosted PDS use the shared Bluesky services.
///
/// **`chat.bsky.*` does not live on the AppView.** Direct messages are served by
/// a separate service with its own DID, so sending them to the AppView returns
/// `501 MethodNotImplemented` for every call — which is what made DMs fail.
/// The audience matters as much as the URL: a token minted for the AppView's DID
/// would be rejected by the chat service even if it reached the right host.
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
    const CHAT_DID: &str = "did:web:api.bsky.chat";
    const CHAT_URL: &str = "https://api.bsky.chat";

    // Chat is its own service; everything else is the AppView.
    let (target_did, target_url) = if nsid.starts_with("chat.bsky.") {
        (CHAT_DID, CHAT_URL)
    } else {
        (APPVIEW_DID, APPVIEW_URL)
    };

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
    let token = mint_service_auth_jwt_at(&key, &did, target_did, Some(nsid), now + 60, now)
        .map_err(|e| Error::RustError(format!("mint service auth: {e}")))?;

    let url = if query.is_empty() {
        format!("{target_url}/xrpc/{nsid}")
    } else {
        format!("{target_url}/xrpc/{nsid}?{query}")
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
/// account present. `collections` is computed by walking the repo, so it is
/// empty only when the account really has written nothing.
pub async fn describe_repo(
    store: std::sync::Arc<DoStore>,
    ctx: &Ctx,
    hostname: &str,
) -> Result<Response> {
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

    let collections = stelyph_core::repo::list_collections(store, &did)
        .await
        .map_err(|e| Error::RustError(format!("list_collections: {e}")))?;

    Response::from_json(&serde_json::json!({
        "handle": handle,
        "did": did,
        "didDoc": did_doc,
        "collections": collections,
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

// ---------------------------------------------------------------------------
// createRecord
// ---------------------------------------------------------------------------

/// What a successful write needs handed to the sequencer.
///
/// The commit is already durable when this exists — the sequencer only decides
/// what the *firehose* says about it, and it owns the PDS-wide `seq` that a
/// repo-local writer cannot know (see `sequencer.rs`).
pub struct Sequenced {
    pub uri: String,
    pub cid: String,
    pub body: stelyph_core::firehose::CommitBody,
    /// The record as JSON, in the same order as `body.ops`, `None` for a delete.
    ///
    /// Carried so the internal indexer receives what was written rather than
    /// having to decode the CAR to find out. The CAR is the wire format for the
    /// network; an indexer on the other side of a queue wants the record.
    pub records: Vec<Option<serde_json::Value>>,
}

/// `POST /xrpc/com.atproto.repo.createRecord` — a signed write into the caller's
/// repo.
///
/// Returns `Ok(Err(response))` for every client-visible rejection so the caller
/// can send it unchanged, and `Ok(Ok(Sequenced))` once the commit is durable.
/// Splitting it this way keeps the sequencer call in the Durable Object, which
/// is the only place with the `env` needed to reach the sequencer binding.
pub async fn create_record(
    store: std::sync::Arc<DoStore>,
    bearer: Option<&str>,
    jwt_secret: &[u8],
    passphrase: &[u8],
    body: &str,
) -> Result<std::result::Result<Sequenced, Response>> {
    use atrium_api::types::string::Did;
    use atrium_crypto::keypair::Secp256k1Keypair;
    use stelyph_core::auth::jwt::decode_jwt;
    use stelyph_core::repo::util::{
        json_value_to_ipld, tid_from_micros, validate_collection, validate_rkey,
    };
    use stelyph_core::repo::writer::WriteOp;
    use stelyph_core::repo::RepoWriter;
    use stelyph_core::storage::crypto;

    // The DID comes from the access token, never the body: `repo` is checked
    // against it below so a valid token cannot write into someone else's repo.
    let Some(did) = bearer
        .and_then(|t| decode_jwt(t, jwt_secret).ok())
        .map(|c| c.sub)
    else {
        return Ok(Err(xrpc_err(
            401,
            "AuthenticationRequired",
            "Invalid token.",
        )?));
    };

    let Ok(input) = serde_json::from_str::<serde_json::Value>(body) else {
        return Ok(Err(xrpc_err(400, "InvalidRequest", "Malformed body.")?));
    };

    if input["repo"].as_str() != Some(did.as_str()) {
        return Ok(Err(xrpc_err(
            400,
            "InvalidRequest",
            "repo must match the authenticated DID.",
        )?));
    }

    let Some(collection) = input["collection"].as_str().map(str::to_owned) else {
        return Ok(Err(xrpc_err(
            400,
            "InvalidRequest",
            "collection is required.",
        )?));
    };
    if let Err(msg) = validate_collection(&collection) {
        return Ok(Err(xrpc_err(400, "InvalidRequest", &msg)?));
    }

    // An absent rkey is normal: most records are keyed by creation time. A
    // supplied one is validated, since it becomes part of the AT-URI.
    let rkey = match input["rkey"].as_str() {
        Some(rk) => {
            if let Err(msg) = validate_rkey(rk) {
                return Ok(Err(xrpc_err(400, "InvalidRequest", &msg)?));
            }
            rk.to_owned()
        }
        None => tid_from_micros(Date::now().as_millis() * 1_000),
    };

    let record = input["record"].clone();
    if record.is_null() {
        return Ok(Err(xrpc_err(400, "InvalidRequest", "record is required.")?));
    }
    let Ok(ipld) = json_value_to_ipld(record) else {
        return Ok(Err(xrpc_err(
            400,
            "InvalidRequest",
            "record is not encodable as IPLD.",
        )?));
    };

    // Unwrap the account's signing key. Every commit is signed with it, so a
    // failure here is a server fault, not a bad request.
    let scalar = crypto::load_key(store.as_ref(), &format!("{did}#signing"), passphrase)
        .await
        .map_err(|e| Error::RustError(format!("load signing key: {e}")))?;
    let key = Secp256k1Keypair::import(&scalar)
        .map_err(|e| Error::RustError(format!("import signing key: {e}")))?;

    let did_typed =
        Did::new(did.clone()).map_err(|e| Error::RustError(format!("bad account DID: {e}")))?;

    // The broadcast sender is required by the constructor but never fires:
    // `apply_one_parts` deliberately does not publish, because this deployment's
    // firehose is the sequencer Durable Object, not an in-process channel.
    let (tx, _rx) = tokio::sync::broadcast::channel(1);
    let writer = RepoWriter::new(store.clone(), key, did_typed, tx);

    let mst_key = format!("{collection}/{rkey}");
    let (_outcome, commit) = writer
        .apply_one_parts(WriteOp::Create {
            key: mst_key,
            record: ipld,
        })
        .await
        .map_err(|e| Error::RustError(format!("repo write failed: {e}")))?;

    let record_cid = commit
        .ops
        .first()
        .and_then(|op| op.cid)
        .ok_or_else(|| Error::RustError("create op yielded no record cid".into()))?;

    Ok(Ok(Sequenced {
        uri: format!("at://{did}/{collection}/{rkey}"),
        cid: record_cid.to_string(),
        body: commit,
        records: vec![Some(input["record"].clone())],
    }))
}

// ---------------------------------------------------------------------------
// repo reads
// ---------------------------------------------------------------------------

/// The DID of the one account this Durable Object holds.
///
/// The `repo` query parameter is only a routing key — the front Worker already
/// used it to pick this DO — so reads answer for the account present here
/// rather than trusting the parameter a second time.
async fn sole_account_did(store: &DoStore) -> Result<Option<String>> {
    Ok(store
        .list_accounts()
        .await
        .map_err(|e| Error::RustError(format!("list accounts: {e}")))?
        .into_iter()
        .next()
        .map(|a| a.did))
}

/// `GET /xrpc/com.atproto.repo.getRecord`
pub async fn get_record(
    store: std::sync::Arc<DoStore>,
    collection: &str,
    rkey: &str,
) -> Result<Response> {
    let Some(did) = sole_account_did(store.as_ref()).await? else {
        return xrpc_err(404, "RepoNotFound", "No account on this host.");
    };
    let mst_key = format!("{collection}/{rkey}");
    let found = stelyph_core::repo::get_record(store, &did, &mst_key)
        .await
        .map_err(|e| Error::RustError(format!("get_record: {e}")))?;
    let Some(entry) = found else {
        return xrpc_err(404, "RecordNotFound", "Record not found.");
    };
    Response::from_json(&serde_json::json!({
        "uri": format!("at://{did}/{}", entry.key),
        "cid": entry.cid.to_string(),
        "value": entry.value,
    }))
}

/// `GET /xrpc/com.atproto.repo.listRecords`
pub async fn list_records(
    store: std::sync::Arc<DoStore>,
    collection: &str,
    limit: Option<usize>,
    cursor: Option<&str>,
) -> Result<Response> {
    let Some(did) = sole_account_did(store.as_ref()).await? else {
        return xrpc_err(404, "RepoNotFound", "No account on this host.");
    };
    let page =
        stelyph_core::repo::list_records(store, &did, collection, limit.unwrap_or(50), cursor)
            .await
            .map_err(|e| Error::RustError(format!("list_records: {e}")))?;
    let records: Vec<serde_json::Value> = page
        .records
        .iter()
        .map(|r| {
            serde_json::json!({
                "uri": format!("at://{did}/{}", r.key),
                "cid": r.cid.to_string(),
                "value": r.value,
            })
        })
        .collect();
    Response::from_json(&serde_json::json!({
        "records": records,
        "cursor": page.cursor,
    }))
}

// ---------------------------------------------------------------------------
// sync: repo backfill
// ---------------------------------------------------------------------------

/// `GET /xrpc/com.atproto.sync.getLatestCommit` — the repo's head.
///
/// The cheap half of backfill: a consumer calls this to decide whether its copy
/// is stale before paying for a full [`get_repo`].
pub async fn get_latest_commit(store: std::sync::Arc<DoStore>) -> Result<Response> {
    let Some(did) = sole_account_did(store.as_ref()).await? else {
        return xrpc_err(404, "RepoNotFound", "No account on this host.");
    };
    let found = stelyph_core::repo::latest_commit(store, &did)
        .await
        .map_err(|e| Error::RustError(format!("latest_commit: {e}")))?;
    let Some((cid, rev)) = found else {
        return xrpc_err(400, "RepoNotFound", "Repo has no commits.");
    };
    Response::from_json(&serde_json::json!({ "cid": cid.to_string(), "rev": rev }))
}

/// `GET /xrpc/com.atproto.sync.getRepo` — the whole repo as CARv1.
///
/// This is how a relay obtains a repo it has never seen, or has fallen behind
/// on. Without it the firehose is the only source, and a firehose only carries
/// what happens next — so a consumer that disconnects can never catch up.
///
/// The `since` parameter is accepted and ignored: this always returns the full
/// repo. A full CAR is a superset of any incremental one, so the answer stays
/// correct, it is merely larger than a caller with a partial copy needs.
/// Honouring `since` requires walking commit history, which this repo layout
/// does not retain.
pub async fn get_repo(store: std::sync::Arc<DoStore>) -> Result<Response> {
    let Some(did) = sole_account_did(store.as_ref()).await? else {
        return xrpc_err(404, "RepoNotFound", "No account on this host.");
    };
    let found = stelyph_core::repo::export_car(store, &did)
        .await
        .map_err(|e| Error::RustError(format!("export_car: {e}")))?;
    let Some(export) = found else {
        return xrpc_err(400, "RepoNotFound", "Repo has no commits.");
    };
    let mut resp = Response::from_bytes(export.car)?;
    let headers = resp.headers_mut();
    // The CAR media type atproto clients and relays expect.
    headers.set("content-type", "application/vnd.ipld.car")?;
    // Lets a caller check the head it just fetched without a second request.
    headers.set("atproto-repo-rev", &export.rev)?;
    Ok(resp)
}
// blobs
// ---------------------------------------------------------------------------

/// `POST /xrpc/com.atproto.repo.uploadBlob` — store bytes, return a blob ref.
///
/// The bytes are opaque: a blob is only *referenced* by a record, and that
/// reference is made later by whatever `createRecord` call embeds the returned
/// ref. So nothing is written to the repo here, and no commit or firehose event
/// results.
pub async fn upload_blob(
    store: std::sync::Arc<DoStore>,
    bearer: Option<&str>,
    jwt_secret: &[u8],
    mime_type: &str,
    bytes: Vec<u8>,
) -> Result<Response> {
    use stelyph_core::auth::jwt::decode_jwt;
    use stelyph_core::blob::{store_blob, BlobError};

    // The owning DID comes from the token: an upload has no body field naming
    // the account, and accepting one would let a caller fill someone else's
    // blob quota.
    let Some(did) = bearer
        .and_then(|t| decode_jwt(t, jwt_secret).ok())
        .map(|c| c.sub)
    else {
        return xrpc_err(401, "AuthenticationRequired", "Invalid token.");
    };

    match store_blob(store.as_ref(), &did, mime_type, bytes).await {
        Ok(blob) => Response::from_json(&serde_json::json!({ "blob": blob.to_lex_json() })),
        Err(BlobError::Empty) => xrpc_err(400, "InvalidRequest", "Blob is empty."),
        Err(e @ BlobError::TooLarge(_)) => xrpc_err(413, "InvalidRequest", &e.to_string()),
        Err(BlobError::Storage(e)) => Err(Error::RustError(format!("store blob: {e}"))),
    }
}

/// `GET /xrpc/com.atproto.sync.getBlob` — raw bytes with the original type.
///
/// Unauthenticated by design: blobs are public once referenced, and a relay
/// mirroring an account has no session. Ownership still scopes the lookup, so
/// one account cannot serve another's blob by guessing a CID.
pub async fn get_blob(store: std::sync::Arc<DoStore>, cid: &str) -> Result<Response> {
    use stelyph_core::storage::BlobStore;

    let Some(did) = sole_account_did(store.as_ref()).await? else {
        return xrpc_err(404, "RepoNotFound", "No account on this host.");
    };
    let found = store
        .get_blob(&did, cid)
        .await
        .map_err(|e| Error::RustError(format!("get_blob: {e}")))?;
    let Some((mime_type, bytes)) = found else {
        return xrpc_err(404, "BlobNotFound", "Blob not found.");
    };
    let mut resp = Response::from_bytes(bytes)?;
    resp.headers_mut().set("content-type", &mime_type)?;
    Ok(resp)
}

/// `GET /xrpc/com.atproto.sync.listBlobs` — the account's blob CIDs.
///
/// How a relay discovers which blobs it must fetch to mirror an account, since
/// `getRepo` carries records but not the bytes they point at.
pub async fn list_blobs(
    store: std::sync::Arc<DoStore>,
    limit: Option<usize>,
    cursor: Option<&str>,
) -> Result<Response> {
    use stelyph_core::storage::BlobStore;

    let Some(did) = sole_account_did(store.as_ref()).await? else {
        return xrpc_err(404, "RepoNotFound", "No account on this host.");
    };
    // Clamped like listRecords: the caller does not get to choose how much work
    // one request is.
    let limit = limit.unwrap_or(500).clamp(1, 1000);
    let cids = store
        .list_blobs(&did, limit, cursor)
        .await
        .map_err(|e| Error::RustError(format!("list_blobs: {e}")))?;
    // Only hand back a cursor on a full page; a short page is the end.
    let next = if cids.len() == limit {
        cids.last().cloned()
    } else {
        None
    };
    Response::from_json(&serde_json::json!({ "cids": cids, "cursor": next }))
}

// ---------------------------------------------------------------------------
// putRecord / deleteRecord
// ---------------------------------------------------------------------------

/// Shared front half of a repo write: authenticate, validate, and reach the
/// signing key.
///
/// Returns `Err(response)` for every client-visible rejection so each handler
/// can pass it straight back.
async fn write_preamble(
    store: &std::sync::Arc<DoStore>,
    bearer: Option<&str>,
    jwt_secret: &[u8],
    passphrase: &[u8],
    input: &serde_json::Value,
) -> Result<
    std::result::Result<
        (
            String,
            atrium_crypto::keypair::Secp256k1Keypair,
            String,
            String,
        ),
        Response,
    >,
> {
    use atrium_crypto::keypair::Secp256k1Keypair;
    use stelyph_core::auth::jwt::decode_jwt;
    use stelyph_core::repo::util::{validate_collection, validate_rkey};
    use stelyph_core::storage::crypto;

    let Some(did) = bearer
        .and_then(|t| decode_jwt(t, jwt_secret).ok())
        .map(|c| c.sub)
    else {
        return Ok(Err(xrpc_err(
            401,
            "AuthenticationRequired",
            "Invalid token.",
        )?));
    };
    if input["repo"].as_str() != Some(did.as_str()) {
        return Ok(Err(xrpc_err(
            400,
            "InvalidRequest",
            "repo must match the authenticated DID.",
        )?));
    }
    let Some(collection) = input["collection"].as_str().map(str::to_owned) else {
        return Ok(Err(xrpc_err(
            400,
            "InvalidRequest",
            "collection is required.",
        )?));
    };
    if let Err(msg) = validate_collection(&collection) {
        return Ok(Err(xrpc_err(400, "InvalidRequest", &msg)?));
    }
    // Unlike createRecord, rkey is required here: both methods address an
    // existing record, and inventing one would silently create a second.
    let Some(rkey) = input["rkey"].as_str().map(str::to_owned) else {
        return Ok(Err(xrpc_err(400, "InvalidRequest", "rkey is required.")?));
    };
    if let Err(msg) = validate_rkey(&rkey) {
        return Ok(Err(xrpc_err(400, "InvalidRequest", &msg)?));
    }

    let scalar = crypto::load_key(store.as_ref(), &format!("{did}#signing"), passphrase)
        .await
        .map_err(|e| Error::RustError(format!("load signing key: {e}")))?;
    let key = Secp256k1Keypair::import(&scalar)
        .map_err(|e| Error::RustError(format!("import signing key: {e}")))?;
    Ok(Ok((did, key, collection, rkey)))
}

fn writer_for(
    store: std::sync::Arc<DoStore>,
    key: atrium_crypto::keypair::Secp256k1Keypair,
    did: &str,
) -> Result<stelyph_core::repo::RepoWriter> {
    use atrium_api::types::string::Did;
    use stelyph_core::repo::RepoWriter;

    let did_typed =
        Did::new(did.to_string()).map_err(|e| Error::RustError(format!("bad account DID: {e}")))?;
    // Never fires: apply_one_parts does not publish, because the firehose here
    // is the sequencer Durable Object rather than an in-process channel.
    let (tx, _rx) = tokio::sync::broadcast::channel(1);
    Ok(RepoWriter::new(store, key, did_typed, tx))
}

/// `POST /xrpc/com.atproto.repo.putRecord` — create or replace at a fixed rkey.
///
/// This is how a profile is written: `app.bsky.actor.profile/self` is a single
/// record a client rewrites, so without it an account can never set a display
/// name or avatar.
///
/// Existence decides create-vs-update rather than always updating: the MST's
/// `update` requires the key to be present, so a blind update on a first write
/// fails.
pub async fn put_record(
    store: std::sync::Arc<DoStore>,
    bearer: Option<&str>,
    jwt_secret: &[u8],
    passphrase: &[u8],
    body: &str,
) -> Result<std::result::Result<Sequenced, Response>> {
    use stelyph_core::repo::util::json_value_to_ipld;
    use stelyph_core::repo::writer::WriteOp;

    let Ok(input) = serde_json::from_str::<serde_json::Value>(body) else {
        return Ok(Err(xrpc_err(400, "InvalidRequest", "Malformed body.")?));
    };
    let (did, key, collection, rkey) =
        match write_preamble(&store, bearer, jwt_secret, passphrase, &input).await? {
            Err(resp) => return Ok(Err(resp)),
            Ok(v) => v,
        };

    let record = input["record"].clone();
    if record.is_null() {
        return Ok(Err(xrpc_err(400, "InvalidRequest", "record is required.")?));
    }
    let Ok(ipld) = json_value_to_ipld(record) else {
        return Ok(Err(xrpc_err(
            400,
            "InvalidRequest",
            "record is not encodable as IPLD.",
        )?));
    };

    let mst_key = format!("{collection}/{rkey}");
    let exists = stelyph_core::repo::get_record(store.clone(), &did, &mst_key)
        .await
        .map_err(|e| Error::RustError(format!("lookup existing: {e}")))?
        .is_some();

    let writer = writer_for(store, key, &did)?;
    let op = if exists {
        WriteOp::Update {
            key: mst_key,
            record: ipld,
        }
    } else {
        WriteOp::Create {
            key: mst_key,
            record: ipld,
        }
    };
    let (_outcome, commit) = writer
        .apply_one_parts(op)
        .await
        .map_err(|e| Error::RustError(format!("repo write failed: {e}")))?;

    let record_cid = commit
        .ops
        .first()
        .and_then(|o| o.cid)
        .ok_or_else(|| Error::RustError("write yielded no record cid".into()))?;

    Ok(Ok(Sequenced {
        uri: format!("at://{did}/{collection}/{rkey}"),
        cid: record_cid.to_string(),
        body: commit,
        records: vec![Some(input["record"].clone())],
    }))
}

/// `POST /xrpc/com.atproto.repo.deleteRecord` — remove a record.
///
/// Deleting something already absent returns success with nothing sequenced.
/// atproto treats delete as idempotent, and committing an empty change would
/// put a no-op event on the firehose that every consumer must then ignore.
pub async fn delete_record(
    store: std::sync::Arc<DoStore>,
    bearer: Option<&str>,
    jwt_secret: &[u8],
    passphrase: &[u8],
    body: &str,
) -> Result<std::result::Result<Option<Sequenced>, Response>> {
    use stelyph_core::repo::writer::WriteOp;

    let Ok(input) = serde_json::from_str::<serde_json::Value>(body) else {
        return Ok(Err(xrpc_err(400, "InvalidRequest", "Malformed body.")?));
    };
    let (did, key, collection, rkey) =
        match write_preamble(&store, bearer, jwt_secret, passphrase, &input).await? {
            Err(resp) => return Ok(Err(resp)),
            Ok(v) => v,
        };

    let mst_key = format!("{collection}/{rkey}");
    if stelyph_core::repo::get_record(store.clone(), &did, &mst_key)
        .await
        .map_err(|e| Error::RustError(format!("lookup existing: {e}")))?
        .is_none()
    {
        return Ok(Ok(None));
    }

    let writer = writer_for(store, key, &did)?;
    let (_outcome, commit) = writer
        .apply_one_parts(WriteOp::Delete { key: mst_key })
        .await
        .map_err(|e| Error::RustError(format!("repo delete failed: {e}")))?;

    Ok(Ok(Some(Sequenced {
        uri: format!("at://{did}/{collection}/{rkey}"),
        cid: String::new(),
        body: commit,
        records: vec![None],
    })))
}

// ---------------------------------------------------------------------------
// applyWrites
// ---------------------------------------------------------------------------

/// A batch write's outcome: one result per write, and the single commit that
/// carried all of them.
///
/// Separate from [`Sequenced`] because that type describes one record; folding a
/// batch into it would mean encoding a list inside a field named `uri`.
pub struct BatchSequenced {
    pub results: Vec<serde_json::Value>,
    pub body: stelyph_core::firehose::CommitBody,
    /// See [`Sequenced::records`].
    pub records: Vec<Option<serde_json::Value>>,
}

/// `POST /xrpc/com.atproto.repo.applyWrites` — several writes, one commit.
///
/// The batch is what the caller asked for and what the network must see: one
/// signed commit carrying every op, so a partial failure cannot leave some
/// writes federated and others not.
pub async fn apply_writes(
    store: std::sync::Arc<DoStore>,
    bearer: Option<&str>,
    jwt_secret: &[u8],
    passphrase: &[u8],
    body: &str,
) -> Result<std::result::Result<BatchSequenced, Response>> {
    use atrium_api::types::string::Did;
    use atrium_crypto::keypair::Secp256k1Keypair;
    use stelyph_core::auth::jwt::decode_jwt;
    use stelyph_core::repo::util::{
        json_value_to_ipld, tid_from_micros, validate_collection, validate_rkey,
    };
    use stelyph_core::repo::writer::WriteOp;
    use stelyph_core::repo::RepoWriter;
    use stelyph_core::storage::crypto;

    let Some(did) = bearer
        .and_then(|t| decode_jwt(t, jwt_secret).ok())
        .map(|c| c.sub)
    else {
        return Ok(Err(xrpc_err(
            401,
            "AuthenticationRequired",
            "Invalid token.",
        )?));
    };
    let Ok(input) = serde_json::from_str::<serde_json::Value>(body) else {
        return Ok(Err(xrpc_err(400, "InvalidRequest", "Malformed body.")?));
    };
    if input["repo"].as_str() != Some(did.as_str()) {
        return Ok(Err(xrpc_err(
            400,
            "InvalidRequest",
            "repo must match the authenticated DID.",
        )?));
    }
    let Some(writes) = input["writes"].as_array() else {
        return Ok(Err(xrpc_err(
            400,
            "InvalidRequest",
            "writes must be an array.",
        )?));
    };
    if writes.is_empty() {
        return Ok(Err(xrpc_err(
            400,
            "InvalidRequest",
            "writes must not be empty.",
        )?));
    }

    // Every write is validated before any is applied. The whole point of the
    // batch is that it is atomic, so a bad entry at position 5 must not find
    // entries 1-4 already committed.
    let mut ops: Vec<WriteOp> = Vec::with_capacity(writes.len());
    let mut uris: Vec<String> = Vec::with_capacity(writes.len());
    let mut records: Vec<Option<serde_json::Value>> = Vec::with_capacity(writes.len());
    for w in writes {
        let kind = w["$type"].as_str().unwrap_or_default();
        let Some(collection) = w["collection"].as_str() else {
            return Ok(Err(xrpc_err(
                400,
                "InvalidRequest",
                "each write needs a collection.",
            )?));
        };
        if let Err(msg) = validate_collection(collection) {
            return Ok(Err(xrpc_err(400, "InvalidRequest", &msg)?));
        }
        // Only a create may omit rkey; the others address an existing record.
        let rkey = match w["rkey"].as_str() {
            Some(rk) => {
                if let Err(msg) = validate_rkey(rk) {
                    return Ok(Err(xrpc_err(400, "InvalidRequest", &msg)?));
                }
                rk.to_owned()
            }
            None if kind.ends_with("#create") => tid_from_micros(Date::now().as_millis() * 1_000),
            None => {
                return Ok(Err(xrpc_err(
                    400,
                    "InvalidRequest",
                    "rkey is required for update and delete.",
                )?))
            }
        };
        let key = format!("{collection}/{rkey}");
        uris.push(format!("at://{did}/{key}"));

        if kind.ends_with("#delete") {
            ops.push(WriteOp::Delete { key });
            records.push(None);
            continue;
        }
        let value = w["value"].clone();
        if value.is_null() {
            return Ok(Err(xrpc_err(
                400,
                "InvalidRequest",
                "create and update need a value.",
            )?));
        }
        let Ok(ipld) = json_value_to_ipld(value) else {
            return Ok(Err(xrpc_err(
                400,
                "InvalidRequest",
                "value is not encodable as IPLD.",
            )?));
        };
        if kind.ends_with("#update") {
            ops.push(WriteOp::Update { key, record: ipld });
            records.push(Some(w["value"].clone()));
        } else if kind.ends_with("#create") {
            ops.push(WriteOp::Create { key, record: ipld });
            records.push(Some(w["value"].clone()));
        } else {
            return Ok(Err(xrpc_err(
                400,
                "InvalidRequest",
                "each write must be a create, update or delete.",
            )?));
        }
    }

    let scalar = crypto::load_key(store.as_ref(), &format!("{did}#signing"), passphrase)
        .await
        .map_err(|e| Error::RustError(format!("load signing key: {e}")))?;
    let key = Secp256k1Keypair::import(&scalar)
        .map_err(|e| Error::RustError(format!("import signing key: {e}")))?;
    let did_typed =
        Did::new(did.clone()).map_err(|e| Error::RustError(format!("bad account DID: {e}")))?;
    let (tx, _rx) = tokio::sync::broadcast::channel(1);
    let writer = RepoWriter::new(store, key, did_typed, tx);

    let (outcomes, commit) = writer
        .apply_many_parts(ops)
        .await
        .map_err(|e| Error::RustError(format!("batch write failed: {e}")))?;

    // One commit means one thing to sequence, however many ops it carried.
    // Each result carries a `$type` discriminator. The lexicon types `results`
    // as a union, so a client validating the response rejects a bare
    // `{uri, cid}` outright -- which reads to a user as "the post failed", even
    // though the commit is already written and federated.
    //
    // A delete result has no uri or cid: there is no record left to point at.
    let results: Vec<serde_json::Value> = outcomes
        .iter()
        .zip(uris.iter())
        .map(|(o, uri)| match o.action {
            "delete" => serde_json::json!({
                "$type": "com.atproto.repo.applyWrites#deleteResult",
            }),
            action => serde_json::json!({
                "$type": format!("com.atproto.repo.applyWrites#{action}Result"),
                "uri": uri,
                "cid": o.record_cid.map(|c| c.to_string()),
                // Records are stored as sent; nothing here checks them against
                // their lexicon, and saying "valid" would be a claim we cannot
                // make. `unknown` is the value for exactly that case.
                "validationStatus": "unknown",
            }),
        })
        .collect();

    Ok(Ok(BatchSequenced {
        results,
        records,
        body: commit,
    }))
}

// ---------------------------------------------------------------------------
// zh-TW feed
// ---------------------------------------------------------------------------

/// The feed URI this PDS serves itself instead of forwarding.
///
/// Not a real feed generator record: there is no separate service to run, and
/// nothing else needs to resolve it. It is a name the client can pin, which
/// this PDS recognises and answers.
pub const ZH_TW_FEED_URI: &str = "at://did:web:taiwansky.social/app.bsky.feed.generator/zh-tw";

/// Characters written differently in Simplified and Traditional Chinese.
///
/// The language tag cannot do this job: Bluesky's `lang=zh-TW` returns the whole
/// `zh` family — measured, only 5 posts in 100 carry a `zh-TW` tag at all, and
/// `lang=zh` returns byte-identical results. Most writers in Taiwan and in China
/// alike tag plain `zh`, so telling the two apart means reading the characters.
///
/// Pairs are (simplified, traditional) and deliberately common: these appear in
/// ordinary prose rather than in specialist vocabulary, so a short post still
/// lands on one side or the other.
const SCRIPT_PAIRS: &[(char, char)] = &[
    // Only pairs whose simplified form is *never* written in Traditional text.
    //
    // That exclusion matters more than the list's length. `台` was in an earlier
    // version paired against `臺`, and it was wrong: Taiwanese writers use `台灣`
    // in ordinary prose and reserve `臺灣` for formal registers, so counting it
    // as Simplified penalised exactly the posts this filter exists to keep.
    //
    // Deliberately absent for the same reason — each is valid Traditional with
    // its own meaning, so its presence says nothing about script:
    //   里 (公里, 里長)   干 (干涉)     面 (面對)    只 (只有)
    //   云 (子曰詩云)     制 (制度)     表 (表面)    系 (系統)   谷 (山谷)
    ('国', '國'),
    ('学', '學'),
    ('会', '會'),
    ('时', '時'),
    ('这', '這'),
    ('过', '過'),
    ('来', '來'),
    ('后', '後'),
    ('发', '發'),
    ('样', '樣'),
    ('还', '還'),
    ('说', '說'),
    ('对', '對'),
    ('开', '開'),
    ('买', '買'),
    ('车', '車'),
    ('见', '見'),
    ('长', '長'),
    ('门', '門'),
    ('问', '問'),
    ('间', '間'),
    ('东', '東'),
    ('马', '馬'),
    ('鸟', '鳥'),
    ('鱼', '魚'),
    ('几', '幾'),
    ('点', '點'),
    ('电', '電'),
    ('话', '話'),
    ('语', '語'),
    ('读', '讀'),
    ('写', '寫'),
    ('谢', '謝'),
    ('欢', '歡'),
    ('爱', '愛'),
    ('体', '體'),
    ('号', '號'),
    ('钱', '錢'),
    ('医', '醫'),
    ('艺', '藝'),
    ('丽', '麗'),
    ('边', '邊'),
    ('远', '遠'),
    ('实', '實'),
    ('无', '無'),
    ('讨', '討'),
    ('论', '論'),
    ('应', '應'),
    ('现', '現'),
    ('协', '協'),
    ('给', '給'),
    ('经', '經'),
    ('种', '種'),
    ('员', '員'),
    ('亚', '亞'),
    ('丰', '豐'),
    ('节', '節'),
    ('让', '讓'),
    ('热', '熱'),
    ('际', '際'),
    ('济', '濟'),
    ('视', '視'),
    ('军', '軍'),
    ('级', '級'),
    ('关', '關'),
    ('闭', '閉'),
    ('题', '題'),
    ('产', '產'),
    ('业', '業'),
    ('务', '務'),
    ('农', '農'),
    ('图', '圖'),
    ('书', '書'),
    ('馆', '館'),
    ('当', '當'),
    ('虽', '雖'),
    ('从', '從'),
    ('们', '們'),
    ('儿', '兒'),
    ('妇', '婦'),
    ('双', '雙'),
    ('亲', '親'),
    ('办', '辦'),
    ('检', '檢'),
    ('历', '歷'),
    ('压', '壓'),
    ('厂', '廠'),
    ('广', '廣'),
    ('场', '場'),
    ('复', '復'),
    ('习', '習'),
    ('乡', '鄉'),
    ('汉', '漢'),
    ('认', '認'),
    ('识', '識'),
    ('设', '設'),
    ('计', '計'),
    ('记', '記'),
    ('访', '訪'),
    ('许', '許'),
    ('证', '證'),
    ('评', '評'),
    ('该', '該'),
    ('诉', '訴'),
    ('课', '課'),
    ('调', '調'),
    ('请', '請'),
    ('谁', '誰'),
    ('课', '課'),
    ('赛', '賽'),
    ('贵', '貴'),
    ('费', '費'),
    ('资', '資'),
    ('购', '購'),
    ('贴', '貼'),
    ('账', '賬'),
    ('质', '質'),
    ('赶', '趕'),
    ('起', '起'),
    ('运', '運'),
    ('进', '進'),
    ('连', '連'),
    ('选', '選'),
    ('适', '適'),
    ('迟', '遲'),
    ('达', '達'),
    ('过', '過'),
    ('还', '還'),
    ('这', '這'),
    ('边', '邊'),
    ('阳', '陽'),
    ('阴', '陰'),
    ('陆', '陸'),
    ('随', '隨'),
    ('险', '險'),
    ('难', '難'),
    ('鸡', '雞'),
    ('鲜', '鮮'),
    ('龙', '龍'),
    ('龟', '龜'),
    ('齐', '齊'),
    ('齿', '齒'),
    ('声', '聲'),
    ('壮', '壯'),
    ('妆', '妝'),
    ('举', '舉'),
    ('义', '義'),
    ('乐', '樂'),
    ('习', '習'),
    ('书', '書'),
    ('买', '買'),
    ('乱', '亂'),
    ('争', '爭'),
    ('亏', '虧'),
];

/// Whether a character is Han (CJK ideographs).
fn is_han(ch: char) -> bool {
    matches!(ch as u32, 0x4E00..=0x9FFF | 0x3400..=0x4DBF | 0xF900..=0xFAFF)
}

/// Whether a character is Japanese kana.
///
/// Kana is the reliable tell for Japanese: a post tagged `zh` that contains
/// hiragana or katakana is Japanese whose author also tagged Chinese, and kanji
/// alone cannot distinguish the two.
fn is_kana(ch: char) -> bool {
    // Hiragana and katakana are contiguous, so one range covers both.
    matches!(ch as u32, 0x3040..=0x30FF)
}

/// Whether text reads as Traditional Chinese rather than Simplified.
///
/// Three checks, each earning its place against what actually came back from a
/// live `lang=zh-TW` search:
///
/// 1. **Some Han is required.** Posts tagged `zh` that are just a URL, `Truth`
///    or `tem` are not Chinese content in any useful sense.
/// 2. **Kana disqualifies.** Japanese posts routinely carry `zh` among their
///    tags, and their kanji pass every Simplified/Traditional test.
/// 3. **Then count script pairs.** A count rather than a rule, because real
///    posts quote each other and spell names either way, so one stray
///    Simplified character should not disqualify an otherwise Traditional post.
///
/// Han text with no distinguishing pair is kept: the tag already said `zh`, and
/// excluding it would drop short Taiwanese posts whose script cannot be told.
pub fn looks_traditional(text: &str) -> bool {
    let mut simplified = 0usize;
    let mut traditional = 0usize;
    let mut han = false;

    for ch in text.chars() {
        if is_kana(ch) {
            return false;
        }
        if is_han(ch) {
            han = true;
        }
        for (s, t) in SCRIPT_PAIRS {
            if ch == *s {
                simplified += 1;
            } else if ch == *t {
                traditional += 1;
            }
        }
    }

    han && traditional >= simplified
}

/// `app.bsky.feed.getFeed` for [`ZH_TW_FEED_URI`].
///
/// Backed by the AppView's own search rather than an index of our own: search
/// accepts `q=*` as a wildcard, so it can be read as a stream rather than
/// queried for a term. It needs authentication — the public AppView refuses it —
/// which is why this lives in the PDS, the only component holding a signing key
/// to mint the service token.
///
/// Results are then filtered by script, because the language tag alone returns
/// Simplified and Traditional alike.
pub async fn zh_tw_feed(
    store: &DoStore,
    bearer: Option<&str>,
    jwt_secret: &[u8],
    passphrase: &[u8],
    query: &str,
) -> Result<Response> {
    // Ask upstream for more than the caller wants: roughly half of `zh` posts
    // are Simplified, so filtering a page of 30 would return a short page and
    // the client would read it as the end of the feed.
    let limit: usize = query_value(query, "limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(30)
        .clamp(1, 100);
    let cursor = query_value(query, "cursor");
    let mut upstream = format!("q=*&lang=zh-TW&sort=latest&limit={}", (limit * 3).min(100));
    if let Some(c) = &cursor {
        upstream.push_str(&format!("&cursor={c}"));
    }

    let resp = proxy_appview(
        store,
        bearer,
        jwt_secret,
        passphrase,
        "app.bsky.feed.searchPosts",
        &upstream,
    )
    .await?;

    let mut resp = resp;
    let body = resp.text().await?;
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) else {
        // Upstream said something we cannot read: hand it back rather than
        // inventing an empty feed, so the failure stays visible.
        return Response::from_bytes(body.into_bytes());
    };
    let Some(posts) = parsed.get("posts").and_then(|p| p.as_array()) else {
        return Response::from_bytes(body.into_bytes());
    };

    let feed: Vec<serde_json::Value> = posts
        .iter()
        .filter(|p| {
            p.pointer("/record/text")
                .and_then(|t| t.as_str())
                .map(looks_traditional)
                .unwrap_or(true)
        })
        .take(limit)
        .map(|p| serde_json::json!({ "post": p }))
        .collect();

    // Upstream's cursor is passed through untouched. It refers to search's own
    // position, not ours, so rewriting it would break the next page — a short
    // page here means we filtered, not that the stream ended.
    let mut out = serde_json::json!({ "feed": feed });
    if let Some(c) = parsed.get("cursor") {
        out["cursor"] = c.clone();
    }
    Response::from_json(&out)
}

/// One value out of a raw query string.
fn query_value(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| v.to_string())
    })
}

#[cfg(test)]
mod zh_tw_tests {
    use super::looks_traditional;

    #[test]
    fn traditional_text_is_kept() {
        assert!(looks_traditional("這個國家的學生會說國語"));
        assert!(looks_traditional("臺灣的天氣很好，發財了"));
    }

    #[test]
    fn simplified_text_is_rejected() {
        assert!(!looks_traditional("这个国家的学生会说国语"));
        assert!(!looks_traditional("台湾的天气很好，发财了"));
    }

    /// Real posts quote each other and spell names either way, so one stray
    /// character must not decide the whole post.
    #[test]
    fn a_mixed_post_goes_with_the_majority() {
        assert!(looks_traditional("這個國家的學生說國語，偶爾写错字"));
        assert!(!looks_traditional("这个国家的学生说国语，偶爾寫對"));
    }

    /// Short Han posts carry no distinguishing characters. Keeping them is
    /// deliberate: the language tag already said zh, and dropping them would
    /// lose a lot of genuinely Taiwanese content.
    #[test]
    fn undecidable_han_text_is_kept() {
        assert!(looks_traditional("早安 ☀️"));
        assert!(looks_traditional("今天 #minecraft"));
    }

    /// Seen live: posts tagged `zh` that contain no Chinese at all.
    #[test]
    fn text_without_han_is_rejected() {
        assert!(!looks_traditional("Truth"));
        assert!(!looks_traditional("tem"));
        assert!(!looks_traditional("youtube.com/shorts/5u0pK"));
        assert!(!looks_traditional(""));
    }

    /// `台灣` is how Taiwanese writers normally spell it; `臺灣` is the formal
    /// register. Treating `台` as Simplified penalised the very posts this
    /// filter exists to keep, so the pair was removed.
    #[test]
    fn taiwanese_spelling_of_taiwan_is_not_penalised() {
        assert!(looks_traditional("台灣的天氣"));
        assert!(looks_traditional("臺灣的天氣"));
        assert!(looks_traditional("我在台北"));
    }

    /// Characters that are valid Traditional in their own right must not count
    /// as Simplified: 里 (公里), 干 (干涉), 面 (面對), 只 (只有), 制 (制度).
    #[test]
    fn shared_characters_do_not_count_as_simplified() {
        assert!(looks_traditional("走了三公里，只有他一個人面對制度"));
    }

    /// The gap the audit found: high-frequency Simplified characters that were
    /// simply missing from the table.
    #[test]
    fn newly_covered_simplified_characters_are_caught() {
        assert!(!looks_traditional("世界的实然无需讨论，应然无力讨论"));
        assert!(!looks_traditional("现在有中文配音了，开大声音"));
        assert!(!looks_traditional("过去 30 分钟的话题"));
    }

    /// Also seen live: Japanese posts tagged `ja,zh,en`. Their kanji pass every
    /// Simplified/Traditional test, so kana is what tells them apart.
    #[test]
    fn japanese_is_rejected_even_when_tagged_zh() {
        assert!(!looks_traditional("これオススメだよって言われて"));
        assert!(!looks_traditional("またブルスカを病気の記録にしている"));
        // Kanji-only Japanese is genuinely ambiguous and not claimed here.
    }
}
