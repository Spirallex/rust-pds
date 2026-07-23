//! SQL schema for the Durable Object's SQLite storage.
//!
//! Deliberately close to `stelyph_core::storage::sqlite::schema`, because the
//! two backends must agree on semantics and a diff between them should be easy
//! to read. Three differences are intentional:
//!
//! 1. **No `STRICT`.** The DO SQLite dialect does not accept it. Column types
//!    are therefore advisory, which is one more reason the conformance suite
//!    matters here.
//! 2. **No `blobs` table.** User uploads live in R2, which is what it is for;
//!    keeping multi-megabyte blobs in a Durable Object's storage would be both
//!    expensive and pointless.
//! 3. **`seq` is an explicit counter row, not `AUTOINCREMENT`.** See below.
//!
//! # Why `seq` is not AUTOINCREMENT here
//!
//! The SQLite backend reads `last_insert_rowid()` after the insert. That is
//! correct on a connection only one task can hold. A Durable Object is
//! single-threaded too, so it would also work — but the counter is made
//! explicit so the invariant is visible in the schema rather than resting on a
//! connection-scoped side effect that a future refactor could quietly break.

/// Schema version, tracked in `schema_version`. Mirrors the SQLite backend's
/// numbering so the two cannot drift apart unnoticed.
pub const SCHEMA_VERSION: i64 = 5;

pub const SCHEMA: &str = r#"
-- Content-addressed blocks. Hot blocks live here; cold ones spill to R2.
CREATE TABLE IF NOT EXISTS blocks (
    cid   TEXT PRIMARY KEY NOT NULL,
    bytes BLOB NOT NULL
);

-- Firehose event log.
CREATE TABLE IF NOT EXISTS repo_seq (
    seq           INTEGER PRIMARY KEY,
    did           TEXT    NOT NULL,
    event_type    TEXT    NOT NULL,
    event         BLOB    NOT NULL,
    invalidated   INTEGER NOT NULL DEFAULT 0,
    sequenced_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS repo_seq_did_idx ON repo_seq (did);

-- The monotonic sequence counter. Exactly one row, id = 0.
CREATE TABLE IF NOT EXISTS seq_counter (
    id   INTEGER PRIMARY KEY,
    next INTEGER NOT NULL
);
INSERT OR IGNORE INTO seq_counter (id, next) VALUES (0, 0);

CREATE TABLE IF NOT EXISTS accounts (
    did              TEXT PRIMARY KEY NOT NULL,
    handle           TEXT UNIQUE,
    email            TEXT,
    password_argon2  TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    deactivated_at   TEXT,
    takedown_ref     TEXT
);

CREATE TABLE IF NOT EXISTS keys (
    id          TEXT PRIMARY KEY NOT NULL,
    ciphertext  BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS invites (
    code            TEXT PRIMARY KEY NOT NULL,
    available_uses  INTEGER NOT NULL DEFAULT 1,
    disabled        INTEGER NOT NULL DEFAULT 0,
    for_account     TEXT NOT NULL,
    created_by      TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS invite_uses (
    code      TEXT NOT NULL,
    used_by   TEXT NOT NULL,
    used_at   TEXT NOT NULL,
    PRIMARY KEY (code, used_by)
);

CREATE TABLE IF NOT EXISTS repo_roots (
    did        TEXT PRIMARY KEY NOT NULL,
    root_cid   TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS account_preferences (
    did   TEXT PRIMARY KEY NOT NULL,
    prefs TEXT NOT NULL DEFAULT '[]'
);

-- Blob metadata only. The bytes live in R2 under `{did}/{cid}`; this table
-- exists so `getBlob` can answer "does this account own that blob?" without an
-- R2 round trip, and so a listing does not require an R2 prefix scan.
CREATE TABLE IF NOT EXISTS blob_refs (
    did         TEXT NOT NULL,
    cid         TEXT NOT NULL,
    mime_type   TEXT NOT NULL,
    size        INTEGER NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (did, cid)
);

-- --- OAuth authorization server state -------------------------------------

CREATE TABLE IF NOT EXISTS oauth_par (
    request_uri_hash TEXT PRIMARY KEY NOT NULL,
    client_id        TEXT NOT NULL,
    redirect_uri     TEXT NOT NULL,
    scope            TEXT NOT NULL,
    state            TEXT NOT NULL,
    code_challenge   TEXT NOT NULL,
    dpop_jkt         TEXT,
    login_hint       TEXT,
    expires_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_auth_codes (
    code_hash      TEXT PRIMARY KEY NOT NULL,
    did            TEXT NOT NULL,
    client_id      TEXT NOT NULL,
    redirect_uri   TEXT NOT NULL,
    scope          TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    dpop_jkt       TEXT,
    expires_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL,
    did        TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    scope      TEXT NOT NULL,
    dpop_jkt   TEXT NOT NULL,
    issued_at  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS oauth_refresh_session_idx ON oauth_refresh_tokens (session_id);
CREATE INDEX IF NOT EXISTS oauth_refresh_did_idx     ON oauth_refresh_tokens (did);

CREATE TABLE IF NOT EXISTS oauth_dpop_jti (
    jti        TEXT PRIMARY KEY NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY NOT NULL
);
INSERT OR REPLACE INTO schema_version (version) VALUES (5);
"#;
