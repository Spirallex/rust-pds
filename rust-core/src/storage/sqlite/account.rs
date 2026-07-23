//! SQLite implementation of [`AccountStore`] — accounts, invites, preferences.

use async_trait::async_trait;
use rusqlite::OptionalExtension;

use crate::storage::sqlite::SqliteStore;
use crate::storage::{AccountStore, AccountSummary, StorageError};

#[async_trait]
impl AccountStore for SqliteStore {
    async fn count_accounts(&self) -> Result<i64, StorageError> {
        let conn = self.reader().await?;
        let n: i64 = conn
            .interact(|c| c.query_row("SELECT count(*) FROM accounts", [], |r| r.get(0)))
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?;
        Ok(n)
    }

    async fn insert_account(
        &self,
        did: &str,
        handle: &str,
        email: Option<&str>,
        password_phc: &str,
    ) -> Result<(), StorageError> {
        let did = did.to_string();
        let handle = handle.to_string();
        let email = email.map(|e| e.to_string());
        let phc = password_phc.to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let writer = self.writer.lock().await;
        writer
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO accounts (did, handle, email, password_argon2, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![did, handle, email, phc, now],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// The count and the insert share one `Immediate` transaction (rollback on
    /// drop), so two concurrent first-registrations cannot both observe 0.
    async fn count_and_insert_account(
        &self,
        did: &str,
        handle: &str,
        email: Option<&str>,
        password_phc: &str,
    ) -> Result<i64, StorageError> {
        let did = did.to_string();
        let handle = handle.to_string();
        let email = email.map(|e| e.to_string());
        let phc = password_phc.to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let writer = self.writer.lock().await;
        let count_before = writer
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let n: i64 = tx.query_row("SELECT count(*) FROM accounts", [], |r| r.get(0))?;
                tx.execute(
                    "INSERT INTO accounts (did, handle, email, password_argon2, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![did, handle, email, phc, now],
                )?;
                tx.commit()?;
                Ok(n)
            })
            .await?;
        Ok(count_before)
    }

    async fn get_account_by_handle(
        &self,
        handle: &str,
    ) -> Result<Option<(String, String)>, StorageError> {
        let handle = handle.to_string();
        let conn = self.reader().await?;
        let row: Option<(String, String)> = conn.interact(move |c| {
            c.query_row(
                "SELECT did, password_argon2 FROM accounts WHERE handle = ?1 AND deactivated_at IS NULL AND takedown_ref IS NULL",
                rusqlite::params![handle],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            ).optional()
        })
        .await.map_err(|e| StorageError::Pool(e.to_string()))?
        .map_err(StorageError::Sqlite)?;
        Ok(row)
    }

    async fn get_did_by_handle(&self, handle: &str) -> Result<Option<String>, StorageError> {
        let handle = handle.to_string();
        let conn = self.reader().await?;
        let did: Option<String> = conn.interact(move |c| {
            c.query_row(
                "SELECT did FROM accounts WHERE handle = ?1 AND deactivated_at IS NULL AND takedown_ref IS NULL",
                rusqlite::params![handle],
                |row| row.get::<_, String>(0),
            ).optional()
        })
        .await.map_err(|e| StorageError::Pool(e.to_string()))?
        .map_err(StorageError::Sqlite)?;
        Ok(did)
    }

    async fn get_handle_by_did(&self, did: &str) -> Result<Option<String>, StorageError> {
        let did = did.to_string();
        let conn = self.reader().await?;
        let handle: Option<String> = conn
            .interact(move |c| {
                c.query_row(
                    "SELECT handle FROM accounts WHERE did = ?1 \
                 AND deactivated_at IS NULL AND takedown_ref IS NULL",
                    rusqlite::params![did],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
            })
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?
            .flatten();
        Ok(handle)
    }

    async fn list_accounts(&self) -> Result<Vec<AccountSummary>, StorageError> {
        let conn = self.reader().await?;
        let rows = conn
            .interact(|c| {
                let mut stmt = c.prepare(
                    "SELECT did, handle, deactivated_at, takedown_ref, created_at \
                     FROM accounts ORDER BY created_at",
                )?;
                let mapped = stmt
                    .query_map([], |r| {
                        Ok(AccountSummary {
                            did: r.get(0)?,
                            handle: r.get(1)?,
                            deactivated_at: r.get(2)?,
                            takedown_ref: r.get(3)?,
                            created_at: r.get(4)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;
                Ok(mapped)
            })
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?;
        Ok(rows)
    }

    async fn update_password(&self, did: &str, password_phc: &str) -> Result<u64, StorageError> {
        let did = did.to_string();
        let phc = password_phc.to_string();
        let writer = self.writer.lock().await;
        let n = writer
            .call(move |conn| {
                let n = conn.execute(
                    "UPDATE accounts SET password_argon2 = ?1 WHERE did = ?2",
                    rusqlite::params![phc, did],
                )?;
                Ok(n)
            })
            .await?;
        Ok(n as u64)
    }

    /// `reference` is an operator-supplied marker (reason / ticket id); when
    /// empty a timestamp is stored so the column is still non-null — the column
    /// being non-null is what hides the account from the auth-path lookups.
    async fn set_takedown(&self, did: &str, reference: &str) -> Result<u64, StorageError> {
        let did = did.to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let reference = if reference.is_empty() {
            now
        } else {
            reference.to_string()
        };
        let writer = self.writer.lock().await;
        let n = writer
            .call(move |conn| {
                let n = conn.execute(
                    "UPDATE accounts SET takedown_ref = ?1 WHERE did = ?2",
                    rusqlite::params![reference, did],
                )?;
                Ok(n)
            })
            .await?;
        Ok(n as u64)
    }

    async fn clear_takedown(&self, did: &str) -> Result<u64, StorageError> {
        let did = did.to_string();
        let writer = self.writer.lock().await;
        let n = writer
            .call(move |conn| {
                let n = conn.execute(
                    "UPDATE accounts SET takedown_ref = NULL WHERE did = ?1",
                    rusqlite::params![did],
                )?;
                Ok(n)
            })
            .await?;
        Ok(n as u64)
    }

    async fn insert_invite(
        &self,
        code: &str,
        available_uses: i64,
        for_account: &str,
    ) -> Result<(), StorageError> {
        let code = code.to_string();
        let for_account = for_account.to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let writer = self.writer.lock().await;
        writer.call(move |conn| {
            conn.execute(
                "INSERT INTO invites (code, available_uses, disabled, for_account, created_by, created_at)
                 VALUES (?1, ?2, 0, ?3, 'admin', ?4)",
                rusqlite::params![code, available_uses, for_account, now],
            )?;
            Ok(())
        }).await?;
        Ok(())
    }

    /// Runs inside the writer mutex AND an explicit `Immediate` transaction so the
    /// SELECT → INSERT → UPDATE sequence is crash-safe: if the process dies between
    /// the INSERT and the UPDATE, SQLite rolls back both on restart. The guard also
    /// rolls back on `Drop` if an early `?` returns before `commit()`, so the
    /// singleton writer connection is never left with a stuck-open transaction.
    async fn consume_invite(&self, code: &str, used_by: &str) -> Result<bool, StorageError> {
        let code = code.to_string();
        let used_by = used_by.to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let writer = self.writer.lock().await;
        let consumed = writer
            .call(move |conn| {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

                // Check invite is valid and has remaining uses.
                let row: Option<(i64, i64)> = tx
                    .query_row(
                        "SELECT available_uses, disabled FROM invites WHERE code = ?1",
                        rusqlite::params![code],
                        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .optional()?;

                let (available_uses, _disabled) = match row {
                    None => return Ok(false),         // code not found
                    Some((_, 1)) => return Ok(false), // disabled
                    Some((0, _)) => return Ok(false), // no uses left
                    Some(v) => v,
                };

                if available_uses <= 0 {
                    return Ok(false);
                }

                // Check if already used by this DID
                let already_used: i64 = tx.query_row(
                    "SELECT count(*) FROM invite_uses WHERE code = ?1 AND used_by = ?2",
                    rusqlite::params![code, used_by],
                    |row| row.get(0),
                )?;
                if already_used > 0 {
                    return Ok(false);
                }

                // INSERT invite_uses — the PK constraint prevents double-use
                let inserted = tx.execute(
                "INSERT OR IGNORE INTO invite_uses (code, used_by, used_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![code, used_by, now],
            )?;
                if inserted == 0 {
                    return Ok(false); // PK conflict — already used
                }

                tx.execute(
                    "UPDATE invites SET available_uses = available_uses - 1 WHERE code = ?1",
                    rusqlite::params![code],
                )?;

                tx.commit()?;
                Ok(true)
            })
            .await?;
        Ok(consumed)
    }

    async fn upsert_preferences(&self, did: &str, prefs_json: &str) -> Result<(), StorageError> {
        let did = did.to_string();
        let prefs = prefs_json.to_string();
        let writer = self.writer.lock().await;
        writer
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO account_preferences (did, prefs) VALUES (?1, ?2)",
                    rusqlite::params![did, prefs],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    async fn get_preferences(&self, did: &str) -> Result<Option<String>, StorageError> {
        let did = did.to_string();
        let conn = self.reader().await?;
        let prefs: Option<String> = conn
            .interact(move |c| {
                c.query_row(
                    "SELECT prefs FROM account_preferences WHERE did = ?1",
                    rusqlite::params![did],
                    |row| row.get::<_, String>(0),
                )
                .optional()
            })
            .await
            .map_err(|e| StorageError::Pool(e.to_string()))?
            .map_err(StorageError::Sqlite)?;
        Ok(prefs)
    }
}

/// SQLite-specific tests only — the account behavioural contract is asserted for
/// every backend in [`crate::storage::conformance`].
#[cfg(test)]
mod tests {
    use super::*;

    /// B1: a forced mid-transaction failure inside `count_and_insert_account`
    /// (duplicate `did` violates the PRIMARY KEY constraint) must NOT leave the
    /// singleton writer connection stuck with an open transaction. A subsequent,
    /// independent write on the same store must still succeed.
    #[tokio::test]
    async fn txn_leak_writer_stays_usable() {
        let (store, _tmp) = SqliteStore::open_in_memory().await.expect("open failed");

        store
            .count_and_insert_account("did:plc:dup", "first.test", None, "phc-1")
            .await
            .expect("first insert must succeed");

        let result = store
            .count_and_insert_account("did:plc:dup", "second.test", None, "phc-2")
            .await;
        assert!(
            result.is_err(),
            "duplicate did must violate the PRIMARY KEY constraint and return Err"
        );

        // An independent write on the same store must still succeed — proving the
        // writer connection was NOT left stuck with an open transaction.
        let count_before = store
            .count_and_insert_account("did:plc:fresh", "fresh.test", None, "phc-3")
            .await
            .expect("independent write after a forced failure must still succeed");
        assert_eq!(
            count_before, 1,
            "count_before should reflect the one account inserted in phase 1"
        );
    }
}
