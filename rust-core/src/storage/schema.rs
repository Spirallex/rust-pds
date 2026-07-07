/// Schema version tracked in schema_version table.
pub const SCHEMA_VERSION: i64 = 4;

/// Full SQLite DDL for all Phase 1 tables and indexes.
/// Defined here, frozen for Phases 2-4 — no migrations needed downstream.
pub const SCHEMA: &str = r#"
-- Core block store (STOR-01)
CREATE TABLE IF NOT EXISTS blocks (
    cid   TEXT PRIMARY KEY NOT NULL,
    bytes BLOB NOT NULL
) STRICT;

-- Firehose event log (schema fixed Phase 1, populated Phase 4)
-- Mirrors official Bluesky PDS sequencer schema (verified from atproto source)
CREATE TABLE IF NOT EXISTS repo_seq (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    did           TEXT    NOT NULL,
    event_type    TEXT    NOT NULL,
    event         BLOB    NOT NULL,
    invalidated   INTEGER NOT NULL DEFAULT 0,
    sequenced_at  TEXT    NOT NULL
) STRICT;

-- Indexes for subscribeRepos cursor semantics (Phase 4 uses these)
CREATE INDEX IF NOT EXISTS repo_seq_did_idx         ON repo_seq (did);
CREATE INDEX IF NOT EXISTS repo_seq_event_type_idx  ON repo_seq (event_type);
CREATE INDEX IF NOT EXISTS repo_seq_sequenced_at_idx ON repo_seq (sequenced_at);

-- Accounts (Phase 3 populates, schema fixed here)
CREATE TABLE IF NOT EXISTS accounts (
    did              TEXT PRIMARY KEY NOT NULL,
    handle           TEXT UNIQUE,
    email            TEXT,
    password_argon2  TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    deactivated_at   TEXT,
    takedown_ref     TEXT
) STRICT;

-- Encrypted key blobs (ACCT-05)
CREATE TABLE IF NOT EXISTS keys (
    id          TEXT PRIMARY KEY NOT NULL,
    ciphertext  BLOB NOT NULL
) STRICT;

-- Invite codes (Phase 3 populates)
CREATE TABLE IF NOT EXISTS invites (
    code            TEXT PRIMARY KEY NOT NULL,
    available_uses  INTEGER NOT NULL DEFAULT 1,
    disabled        INTEGER NOT NULL DEFAULT 0,
    for_account     TEXT NOT NULL,
    created_by      TEXT NOT NULL,
    created_at      TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS invite_uses (
    code      TEXT NOT NULL REFERENCES invites(code),
    used_by   TEXT NOT NULL,
    used_at   TEXT NOT NULL,
    PRIMARY KEY (code, used_by)
) STRICT;

-- Repo root tracking (Phase 2): latest signed-commit CID per DID.
CREATE TABLE IF NOT EXISTS repo_roots (
    did        TEXT PRIMARY KEY NOT NULL,
    root_cid   TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

-- AppView preferences (Phase 5, XRPC-05): opaque JSON array per account.
CREATE TABLE IF NOT EXISTS account_preferences (
    did   TEXT PRIMARY KEY NOT NULL,
    prefs TEXT NOT NULL DEFAULT '[]'
) STRICT;

-- Blob store (uploadBlob / sync.getBlob): content-addressed user uploads
-- (avatars, images, video). Keyed by (did, cid) so two accounts can hold the
-- same content-addressed blob independently.
CREATE TABLE IF NOT EXISTS blobs (
    did         TEXT NOT NULL,
    cid         TEXT NOT NULL,
    mime_type   TEXT NOT NULL,
    size        INTEGER NOT NULL,
    bytes       BLOB NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (did, cid)
) STRICT;

-- Schema version for future migrations.
-- PRIMARY KEY ensures at most one row; INSERT OR REPLACE handles v1→v2 upgrades
-- by replacing the old row rather than appending a duplicate.
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY NOT NULL
) STRICT;
INSERT OR REPLACE INTO schema_version (version) VALUES (4);
"#;
