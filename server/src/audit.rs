//! Append-only, write-only audit log.
//!
//! The server records security-relevant events sealed to the account's public key. It
//! can append and it cannot read back -- there is no private key on this machine.
//! Devices pull the sealed entries and open them locally.
//!
//! Be clear about what that buys. Encryption protects the log against later seizure of
//! this database, which is the realistic threat for a server sitting on someone else's
//! hardware. It protects nothing against a server compromised while running: at the
//! moment it seals "device X revoked" it obviously knows that fact. The entry sequence
//! also leaks how many events happened and when, which for an audit log is more or less
//! the point of having one.

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::db::now;
use tracker_core::crypto;

pub type Result<T> = std::result::Result<T, AuditError>;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("serialisation error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("this account has no audit key yet")]
    NoAuditKey,
    #[error("the audit key is already set and cannot be replaced")]
    KeyAlreadySet,
}

/// What happened. Kept coarse on purpose: an audit entry should say enough to notice
/// something wrong without becoming a second copy of the data it is guarding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditEvent {
    DeviceEnrolled {
        device_id: String,
        display_name: String,
        fingerprint: String,
    },
    DeviceRevoked {
        device_id: String,
        by_device: String,
    },
    InviteCreated {
        by_device: Option<String>,
    },
    LeaseAcquired {
        device_id: String,
    },
    LeaseRotated {
        device_id: String,
    },
    EpochPublished {
        epoch: i64,
        by_device: String,
        sealed_to: usize,
    },
    /// Ein Gerät hat einem anderen Zugang zu älteren Epochen gegeben.
    WrapsBackfilled {
        by_device: String,
        added: usize,
    },
    AuthenticationFailed {
        device_id: String,
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub at: i64,
    #[serde(flatten)]
    pub event: AuditEvent,
}

/// Install the account's audit public key.
///
/// First writer wins and there is no replacement path. Allowing a later device to swap
/// the key would let it redirect the log to itself, so the key is fixed at the moment
/// the account gains its first device.
pub fn set_audit_key(conn: &Connection, account_id: &str, audit_pub: &[u8]) -> Result<()> {
    let existing: Option<Option<Vec<u8>>> = conn
        .query_row(
            "SELECT audit_pub FROM accounts WHERE id = ?1",
            params![account_id],
            |row| row.get(0),
        )
        .optional()?;
    if matches!(existing, Some(Some(_))) {
        return Err(AuditError::KeyAlreadySet);
    }
    conn.execute(
        "UPDATE accounts SET audit_pub = ?1 WHERE id = ?2",
        params![audit_pub, account_id],
    )?;
    Ok(())
}

pub fn audit_key(conn: &Connection, account_id: &str) -> Result<Option<Vec<u8>>> {
    Ok(conn
        .query_row(
            "SELECT audit_pub FROM accounts WHERE id = ?1",
            params![account_id],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()?
        .flatten())
}

/// Seal and append one event.
pub fn record(conn: &Connection, account_id: &str, event: AuditEvent) -> Result<()> {
    let key = audit_key(conn, account_id)?.ok_or(AuditError::NoAuditKey)?;
    let key = crypto::to_key(&key)?;

    let entry = AuditEntry { at: now(), event };
    let plaintext = serde_json::to_vec(&entry)?;
    let sealed = crypto::seal_anonymous(&key, &plaintext)?;

    conn.execute(
        "INSERT INTO audit_log (account_id, sealed_entry, created_at) VALUES (?1, ?2, ?3)",
        params![account_id, sealed, now()],
    )?;
    Ok(())
}

/// Record without letting a logging failure break the operation being logged.
///
/// An audit trail that can take the server down is worse than one with a gap in it, and
/// the commonest reason for failure here is simply that no device has enrolled yet.
pub fn record_best_effort(conn: &Connection, account_id: &str, event: AuditEvent) {
    match record(conn, account_id, event) {
        Ok(()) => {}
        Err(AuditError::NoAuditKey) => {
            tracing::debug!("audit entry dropped: account has no audit key yet");
        }
        Err(error) => tracing::error!(%error, "failed to write audit entry"),
    }
}

#[derive(Debug, Clone)]
pub struct SealedEntry {
    pub seq: i64,
    pub sealed_entry: Vec<u8>,
}

pub fn entries_since(
    conn: &Connection,
    account_id: &str,
    after_seq: i64,
    limit: i64,
) -> Result<Vec<SealedEntry>> {
    let mut stmt = conn.prepare(
        "SELECT seq, sealed_entry FROM audit_log
         WHERE account_id = ?1 AND seq > ?2 ORDER BY seq ASC LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![account_id, after_seq, limit], |row| {
        Ok(SealedEntry {
            seq: row.get(0)?,
            sealed_entry: row.get(1)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use x25519_dalek::StaticSecret;

    fn setup() -> (Connection, StaticSecret) {
        let conn = open_in_memory().unwrap();
        conn.execute(
            "INSERT INTO accounts (id, created_at) VALUES ('acct', 0)",
            [],
        )
        .unwrap();
        let (secret, public) = crypto::generate_static_keypair().unwrap();
        set_audit_key(&conn, "acct", public.as_bytes()).unwrap();
        (conn, secret)
    }

    #[test]
    fn an_entry_is_readable_by_the_account_and_not_by_the_server() {
        let (conn, secret) = setup();
        record(
            &conn,
            "acct",
            AuditEvent::DeviceRevoked {
                device_id: "phone".into(),
                by_device: "laptop".into(),
            },
        )
        .unwrap();

        let stored = entries_since(&conn, "acct", 0, 10).unwrap();
        assert_eq!(stored.len(), 1);

        // Everything the server has is opaque: no substring of the plaintext survives.
        let blob = &stored[0].sealed_entry;
        assert!(
            !blob.windows(5).any(|w| w == b"phone"),
            "the device id must not be readable in the stored blob"
        );

        let opened = crypto::open_anonymous(&secret, blob).unwrap();
        let entry: AuditEntry = serde_json::from_slice(&opened).unwrap();
        assert_eq!(
            entry.event,
            AuditEvent::DeviceRevoked {
                device_id: "phone".into(),
                by_device: "laptop".into()
            }
        );
    }

    #[test]
    fn the_audit_key_cannot_be_replaced_once_set() {
        let (conn, _) = setup();
        let (_, other) = crypto::generate_static_keypair().unwrap();
        assert!(
            matches!(
                set_audit_key(&conn, "acct", other.as_bytes()),
                Err(AuditError::KeyAlreadySet)
            ),
            "a later device must not be able to redirect the log to itself"
        );
    }

    #[test]
    fn entries_without_a_key_are_dropped_rather_than_failing_the_operation() {
        let conn = open_in_memory().unwrap();
        conn.execute(
            "INSERT INTO accounts (id, created_at) VALUES ('fresh', 0)",
            [],
        )
        .unwrap();

        assert!(matches!(
            record(
                &conn,
                "fresh",
                AuditEvent::InviteCreated { by_device: None }
            ),
            Err(AuditError::NoAuditKey)
        ));
        // The best-effort wrapper must not panic or propagate.
        record_best_effort(
            &conn,
            "fresh",
            AuditEvent::InviteCreated { by_device: None },
        );
        assert!(entries_since(&conn, "fresh", 0, 10).unwrap().is_empty());
    }

    #[test]
    fn the_log_is_ordered_and_pageable() {
        let (conn, secret) = setup();
        for i in 0..5 {
            record(
                &conn,
                "acct",
                AuditEvent::LeaseAcquired {
                    device_id: format!("dev{i}"),
                },
            )
            .unwrap();
        }
        let all = entries_since(&conn, "acct", 0, 100).unwrap();
        assert_eq!(all.len(), 5);

        let tail = entries_since(&conn, "acct", all[2].seq, 100).unwrap();
        assert_eq!(tail.len(), 2);

        let opened = crypto::open_anonymous(&secret, &tail[0].sealed_entry).unwrap();
        let entry: AuditEntry = serde_json::from_slice(&opened).unwrap();
        assert_eq!(
            entry.event,
            AuditEvent::LeaseAcquired {
                device_id: "dev3".into()
            }
        );
    }
}
