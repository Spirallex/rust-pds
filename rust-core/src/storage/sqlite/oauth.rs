//! SQLite implementation of [`OAuthStore`].
//!
//! The single-use operations (`consume_auth_code`, `consume_refresh_token`,
//! `record_dpop_jti`) each run in one `BEGIN IMMEDIATE` transaction on the
//! singleton writer connection. That is what makes them genuinely atomic rather
//! than a racy read-then-write.

use async_trait::async_trait;
use rusqlite::OptionalExtension;

use crate::oauth::store::{
    AuthCode, ConsumeResult, OAuthStore, RefreshTokenRecord, StoredPushedRequest,
};
use crate::storage::sqlite::SqliteStore;
use crate::storage::StorageError;

#[async_trait]
impl OAuthStore for SqliteStore {
    async fn put_pushed_request(&self, req: StoredPushedRequest) -> Result<(), StorageError> {
        let writer = self.writer.lock().await;
        writer
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO oauth_par \
                     (request_uri_hash, client_id, redirect_uri, scope, state, \
                      code_challenge, dpop_jkt, login_hint, expires_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    rusqlite::params![
                        req.request_uri_hash,
                        req.client_id,
                        req.redirect_uri,
                        req.scope,
                        req.state,
                        req.code_challenge,
                        req.dpop_jkt,
                        req.login_hint,
                        req.expires_at as i64,
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    async fn get_pushed_request(
        &self,
        request_uri_hash: &str,
        now: u64,
    ) -> Result<Option<StoredPushedRequest>, StorageError> {
        let hash = request_uri_hash.to_string();
        let conn = self.reader().await?;
        let row = conn
            .interact(move |c| {
                c.query_row(
                    "SELECT request_uri_hash, client_id, redirect_uri, scope, state, \
                            code_challenge, dpop_jkt, login_hint, expires_at \
                     FROM oauth_par WHERE request_uri_hash = ?1 AND expires_at > ?2",
                    rusqlite::params![hash, now as i64],
                    |r| {
                        Ok(StoredPushedRequest {
                            request_uri_hash: r.get(0)?,
                            client_id: r.get(1)?,
                            redirect_uri: r.get(2)?,
                            scope: r.get(3)?,
                            state: r.get(4)?,
                            code_challenge: r.get(5)?,
                            dpop_jkt: r.get(6)?,
                            login_hint: r.get(7)?,
                            expires_at: r.get::<_, i64>(8)? as u64,
                        })
                    },
                )
                .optional()
            })
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?;
        Ok(row)
    }

    async fn delete_pushed_request(&self, request_uri_hash: &str) -> Result<(), StorageError> {
        let hash = request_uri_hash.to_string();
        let writer = self.writer.lock().await;
        writer
            .call(move |conn| {
                conn.execute(
                    "DELETE FROM oauth_par WHERE request_uri_hash = ?1",
                    rusqlite::params![hash],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    async fn put_auth_code(&self, code: AuthCode) -> Result<(), StorageError> {
        let writer = self.writer.lock().await;
        writer
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO oauth_auth_codes \
                     (code_hash, did, client_id, redirect_uri, scope, code_challenge, \
                      dpop_jkt, expires_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    rusqlite::params![
                        code.code_hash,
                        code.did,
                        code.client_id,
                        code.redirect_uri,
                        code.scope,
                        code.code_challenge,
                        code.dpop_jkt,
                        code.expires_at as i64,
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// SELECT then DELETE inside one `Immediate` transaction. Two concurrent
    /// redemptions of one code therefore serialize, and exactly one sees a row.
    async fn consume_auth_code(
        &self,
        code_hash: &str,
        now: u64,
    ) -> Result<Option<AuthCode>, StorageError> {
        let hash = code_hash.to_string();
        let writer = self.writer.lock().await;
        let out = writer
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let row: Option<AuthCode> = tx
                    .query_row(
                        "SELECT code_hash, did, client_id, redirect_uri, scope, \
                                code_challenge, dpop_jkt, expires_at \
                         FROM oauth_auth_codes WHERE code_hash = ?1 AND expires_at > ?2",
                        rusqlite::params![hash, now as i64],
                        |r| {
                            Ok(AuthCode {
                                code_hash: r.get(0)?,
                                did: r.get(1)?,
                                client_id: r.get(2)?,
                                redirect_uri: r.get(3)?,
                                scope: r.get(4)?,
                                code_challenge: r.get(5)?,
                                dpop_jkt: r.get(6)?,
                                expires_at: r.get::<_, i64>(7)? as u64,
                            })
                        },
                    )
                    .optional()?;

                // Delete unconditionally: an expired code that was not returned
                // is still worth clearing out here.
                tx.execute(
                    "DELETE FROM oauth_auth_codes WHERE code_hash = ?1",
                    rusqlite::params![hash],
                )?;
                tx.commit()?;
                Ok(row)
            })
            .await?;
        Ok(out)
    }

    async fn put_refresh_token(&self, token: RefreshTokenRecord) -> Result<(), StorageError> {
        let writer = self.writer.lock().await;
        writer
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO oauth_refresh_tokens \
                     (token_hash, session_id, did, client_id, scope, dpop_jkt, \
                      issued_at, expires_at, used) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)",
                    rusqlite::params![
                        token.token_hash,
                        token.session_id,
                        token.did,
                        token.client_id,
                        token.scope,
                        token.dpop_jkt,
                        token.issued_at as i64,
                        token.expires_at as i64,
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Marks the row used inside one transaction, so two concurrent refreshes
    /// cannot both be `Consumed` — the loser sees `Reused` and revokes the chain.
    async fn consume_refresh_token(
        &self,
        token_hash: &str,
        now: u64,
    ) -> Result<ConsumeResult, StorageError> {
        let hash = token_hash.to_string();
        let writer = self.writer.lock().await;
        let out = writer
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

                let row: Option<(RefreshTokenRecord, bool)> = tx
                    .query_row(
                        "SELECT token_hash, session_id, did, client_id, scope, dpop_jkt, \
                                issued_at, expires_at, used \
                         FROM oauth_refresh_tokens WHERE token_hash = ?1 AND expires_at > ?2",
                        rusqlite::params![hash, now as i64],
                        |r| {
                            Ok((
                                RefreshTokenRecord {
                                    token_hash: r.get(0)?,
                                    session_id: r.get(1)?,
                                    did: r.get(2)?,
                                    client_id: r.get(3)?,
                                    scope: r.get(4)?,
                                    dpop_jkt: r.get(5)?,
                                    issued_at: r.get::<_, i64>(6)? as u64,
                                    expires_at: r.get::<_, i64>(7)? as u64,
                                },
                                r.get::<_, i64>(8)? != 0,
                            ))
                        },
                    )
                    .optional()?;

                let result = match row {
                    None => ConsumeResult::NotFound,
                    Some((rec, true)) => ConsumeResult::Reused {
                        session_id: rec.session_id,
                    },
                    Some((rec, false)) => {
                        tx.execute(
                            "UPDATE oauth_refresh_tokens SET used = 1 WHERE token_hash = ?1",
                            rusqlite::params![hash],
                        )?;
                        ConsumeResult::Consumed(Box::new(rec))
                    }
                };
                tx.commit()?;
                Ok(result)
            })
            .await?;
        Ok(out)
    }

    async fn revoke_session(&self, session_id: &str) -> Result<u64, StorageError> {
        let sid = session_id.to_string();
        let writer = self.writer.lock().await;
        let n = writer
            .call(move |conn| {
                let n = conn.execute(
                    "DELETE FROM oauth_refresh_tokens WHERE session_id = ?1",
                    rusqlite::params![sid],
                )?;
                Ok(n)
            })
            .await?;
        Ok(n as u64)
    }

    /// Revokes the whole chain, not just the one token: the caller is asking to
    /// end a session, and leaving its siblings alive would not do that.
    async fn revoke_refresh_token(&self, token_hash: &str) -> Result<bool, StorageError> {
        let hash = token_hash.to_string();
        let writer = self.writer.lock().await;
        let found = writer
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let session: Option<String> = tx
                    .query_row(
                        "SELECT session_id FROM oauth_refresh_tokens WHERE token_hash = ?1",
                        rusqlite::params![hash],
                        |r| r.get(0),
                    )
                    .optional()?;
                let found = match session {
                    None => false,
                    Some(sid) => {
                        tx.execute(
                            "DELETE FROM oauth_refresh_tokens WHERE session_id = ?1",
                            rusqlite::params![sid],
                        )?;
                        true
                    }
                };
                tx.commit()?;
                Ok(found)
            })
            .await?;
        Ok(found)
    }

    async fn list_sessions_for_did(
        &self,
        did: &str,
        now: u64,
    ) -> Result<Vec<RefreshTokenRecord>, StorageError> {
        let did = did.to_string();
        let conn = self.reader().await?;
        let rows = conn
            .interact(move |c| {
                let mut stmt = c.prepare(
                    "SELECT token_hash, session_id, did, client_id, scope, dpop_jkt, \
                            issued_at, expires_at \
                     FROM oauth_refresh_tokens \
                     WHERE did = ?1 AND expires_at > ?2 AND used = 0 \
                     ORDER BY issued_at DESC",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![did, now as i64], |r| {
                        Ok(RefreshTokenRecord {
                            token_hash: r.get(0)?,
                            session_id: r.get(1)?,
                            did: r.get(2)?,
                            client_id: r.get(3)?,
                            scope: r.get(4)?,
                            dpop_jkt: r.get(5)?,
                            issued_at: r.get::<_, i64>(6)? as u64,
                            expires_at: r.get::<_, i64>(7)? as u64,
                        })
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;
                Ok(rows)
            })
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?;
        Ok(rows)
    }

    /// `INSERT ... ON CONFLICT DO NOTHING` is itself atomic, so the affected-row
    /// count is a reliable "was this new?" without an explicit transaction.
    async fn record_dpop_jti(&self, jti: &str, expires_at: u64) -> Result<bool, StorageError> {
        let jti = jti.to_string();
        let writer = self.writer.lock().await;
        let inserted = writer
            .call(move |conn| {
                let n = conn.execute(
                    "INSERT INTO oauth_dpop_jti (jti, expires_at) VALUES (?1, ?2) \
                     ON CONFLICT(jti) DO NOTHING",
                    rusqlite::params![jti, expires_at as i64],
                )?;
                Ok(n)
            })
            .await?;
        Ok(inserted > 0)
    }

    async fn purge_expired(&self, now: u64) -> Result<u64, StorageError> {
        let writer = self.writer.lock().await;
        let n = writer
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let mut total = 0usize;
                for table in [
                    "oauth_par",
                    "oauth_auth_codes",
                    "oauth_refresh_tokens",
                    "oauth_dpop_jti",
                ] {
                    total += tx.execute(
                        &format!("DELETE FROM {table} WHERE expires_at <= ?1"),
                        rusqlite::params![now as i64],
                    )?;
                }
                tx.commit()?;
                Ok(total)
            })
            .await?;
        Ok(n as u64)
    }
}
