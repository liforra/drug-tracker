//! Periodic housekeeping.
//!
//! Two motivations, and only one of them is tidiness. The other is that some rows are
//! sensitive while they exist: a completed enrollment still holds the account root key
//! sealed to a device, and an unclaimed invite is a credential. Neither should sit in
//! the database indefinitely because nothing ever came back to remove it.

use rusqlite::{Connection, params};

use crate::db::now;

pub type Result<T> = std::result::Result<T, rusqlite::Error>;

/// How long a fulfilled enrollment is kept before its sealed payload is deleted.
///
/// Not deleted on collection: a device that fetches the payload and then dies before
/// writing it to disk would be stranded. An hour is long enough to retry and short
/// enough that the sealed root key is not lying around.
const ENROLLMENT_GRACE_SECS: i64 = 3600;

/// Unclaimed enrollments are dropped once the invite that created them is long dead.
const ENROLLMENT_ABANDONED_SECS: i64 = 24 * 3600;

/// Spent and expired invites are kept briefly so a duplicate claim gets a clear
/// "already used" rather than "unknown code".
const INVITE_GRACE_SECS: i64 = 24 * 3600;

#[derive(Debug, Default, PartialEq)]
pub struct SweepReport {
    pub challenges: usize,
    pub tokens: usize,
    pub enrollments: usize,
    pub invites: usize,
    pub events: usize,
    pub audit_entries: usize,
}

impl SweepReport {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Optional age-based deletion. Both default to off: silently discarding someone's
/// history because a default said so would be the wrong way round.
#[derive(Debug, Clone, Copy, Default)]
pub struct Retention {
    pub event_days: Option<i64>,
    pub audit_days: Option<i64>,
}

impl Retention {
    /// Read from `TRACKER_EVENT_RETENTION_DAYS` and `TRACKER_AUDIT_RETENTION_DAYS`.
    pub fn from_env() -> Self {
        fn days(key: &str) -> Option<i64> {
            let raw = std::env::var(key).ok()?;
            match raw.parse::<i64>() {
                Ok(d) if d > 0 => Some(d),
                _ => {
                    tracing::warn!(%key, value = %raw, "ignoring unusable retention setting");
                    None
                }
            }
        }
        Self {
            event_days: days("TRACKER_EVENT_RETENTION_DAYS"),
            audit_days: days("TRACKER_AUDIT_RETENTION_DAYS"),
        }
    }
}

/// Run one maintenance pass.
#[allow(clippy::field_reassign_with_default)] // the counters are filled in as each DELETE runs
pub fn sweep(conn: &Connection, retention: Retention) -> Result<SweepReport> {
    let cutoff = now();
    let mut report = SweepReport::default();

    report.challenges = conn.execute(
        "DELETE FROM challenges WHERE expires_at <= ?1",
        params![cutoff],
    )?;
    report.tokens = conn.execute("DELETE FROM tokens WHERE expires_at <= ?1", params![cutoff])?;

    // Fulfilled enrollments: the sealed root key goes once the grace period is up.
    report.enrollments += conn.execute(
        "DELETE FROM enrollments WHERE claimed_at IS NOT NULL AND claimed_at <= ?1",
        params![cutoff - ENROLLMENT_GRACE_SECS],
    )?;
    // Abandoned ones: a device that started enrolling and never came back.
    report.enrollments += conn.execute(
        "DELETE FROM enrollments WHERE claimed_at IS NULL AND created_at <= ?1",
        params![cutoff - ENROLLMENT_ABANDONED_SECS],
    )?;

    report.invites = conn.execute(
        "DELETE FROM invites WHERE expires_at <= ?1",
        params![cutoff - INVITE_GRACE_SECS],
    )?;

    if let Some(days) = retention.event_days {
        // By arrival time, which is the only time the server has. It is not the
        // consumption time and does not pretend to be.
        report.events = conn.execute(
            "DELETE FROM events WHERE received_at <= ?1",
            params![cutoff - days * 86400],
        )?;
    }
    if let Some(days) = retention.audit_days {
        report.audit_entries = conn.execute(
            "DELETE FROM audit_log WHERE created_at <= ?1",
            params![cutoff - days * 86400],
        )?;
    }

    Ok(report)
}

/// Permanently remove an account and everything belonging to it.
///
/// Ordered so foreign keys stay satisfied. Irreversible, hence CLI-only -- an endpoint
/// for this would be one compromised token away from deleting everything.
pub fn purge_account(conn: &mut Connection, account_id: &str) -> Result<()> {
    let tx = conn.transaction()?;
    for statement in [
        "DELETE FROM audit_log WHERE account_id = ?1",
        "DELETE FROM events WHERE account_id = ?1",
        "DELETE FROM dek_wraps WHERE account_id = ?1",
        "DELETE FROM dek_epochs WHERE account_id = ?1",
        "DELETE FROM enrollments WHERE account_id = ?1",
        "DELETE FROM invites WHERE account_id = ?1",
        "DELETE FROM tokens WHERE device_id IN (SELECT id FROM devices WHERE account_id = ?1)",
        "DELETE FROM challenges WHERE device_id IN (SELECT id FROM devices WHERE account_id = ?1)",
        "DELETE FROM devices WHERE account_id = ?1",
        "DELETE FROM accounts WHERE id = ?1",
    ] {
        tx.execute(statement, params![account_id])?;
    }
    tx.commit()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        conn.execute(
            "INSERT INTO accounts (id, created_at) VALUES ('acct', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO devices (id, account_id, display_name, ed25519_pub, x25519_pub, created_at)
             VALUES ('phone', 'acct', 'phone', x'00', x'00', 0)",
            [],
        )
        .unwrap();
        conn
    }

    #[test]
    fn a_fulfilled_enrollment_loses_its_sealed_root_key_after_the_grace_period() {
        let conn = setup();
        let long_ago = now() - ENROLLMENT_GRACE_SECS - 60;
        conn.execute(
            "INSERT INTO enrollments (id, account_id, new_device_id, wrapped_payload, created_at, claimed_at)
             VALUES ('old', 'acct', 'phone', x'DEADBEEF', ?1, ?1)",
            params![long_ago],
        )
        .unwrap();
        // Just collected: must survive, in case the device needs to retry.
        conn.execute(
            "INSERT INTO enrollments (id, account_id, new_device_id, wrapped_payload, created_at, claimed_at)
             VALUES ('fresh', 'acct', 'phone', x'DEADBEEF', ?1, ?1)",
            params![now()],
        )
        .unwrap();

        let report = sweep(&conn, Retention::default()).unwrap();
        assert_eq!(report.enrollments, 1);

        let left: Vec<String> = conn
            .prepare("SELECT id FROM enrollments")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(left, vec!["fresh".to_string()]);
    }

    #[test]
    fn an_abandoned_enrollment_is_eventually_dropped() {
        let conn = setup();
        conn.execute(
            "INSERT INTO enrollments (id, account_id, new_device_id, created_at)
             VALUES ('stale', 'acct', 'phone', ?1)",
            params![now() - ENROLLMENT_ABANDONED_SECS - 60],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO enrollments (id, account_id, new_device_id, created_at)
             VALUES ('pending', 'acct', 'phone', ?1)",
            params![now()],
        )
        .unwrap();

        assert_eq!(sweep(&conn, Retention::default()).unwrap().enrollments, 1);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM enrollments", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "an in-flight enrollment must not be swept away");
    }

    #[test]
    fn expired_auth_material_is_removed() {
        let conn = setup();
        conn.execute(
            "INSERT INTO challenges (nonce, device_id, expires_at) VALUES ('dead', 'phone', ?1)",
            params![now() - 10],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO challenges (nonce, device_id, expires_at) VALUES ('live', 'phone', ?1)",
            params![now() + 600],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO tokens (token, device_id, expires_at) VALUES ('dead', 'phone', ?1)",
            params![now() - 10],
        )
        .unwrap();

        let report = sweep(&conn, Retention::default()).unwrap();
        assert_eq!((report.challenges, report.tokens), (1, 1));
        let live: i64 = conn
            .query_row("SELECT COUNT(*) FROM challenges", [], |r| r.get(0))
            .unwrap();
        assert_eq!(live, 1, "a valid challenge must survive the sweep");
    }

    #[test]
    fn retention_is_off_unless_asked_for() {
        let conn = setup();
        conn.execute(
            "INSERT INTO events (account_id, event_id, epoch, nonce, ciphertext, received_at)
             VALUES ('acct', 'ancient', 1, x'00', x'00', ?1)",
            params![now() - 3650 * 86400],
        )
        .unwrap();

        let report = sweep(&conn, Retention::default()).unwrap();
        assert_eq!(
            report.events, 0,
            "ten-year-old records must survive by default"
        );

        let report = sweep(
            &conn,
            Retention {
                event_days: Some(30),
                audit_days: None,
            },
        )
        .unwrap();
        assert_eq!(
            report.events, 1,
            "and be removed once retention is configured"
        );
    }

    #[test]
    fn purging_an_account_leaves_nothing_behind() {
        let mut conn = setup();
        conn.execute(
            "INSERT INTO events (account_id, event_id, epoch, nonce, ciphertext, received_at)
             VALUES ('acct', 'e1', 1, x'00', x'00', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO dek_epochs (account_id, epoch, created_at) VALUES ('acct', 1, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO dek_wraps (account_id, epoch, device_id, wrapped_dek, created_at)
             VALUES ('acct', 1, 'phone', x'00', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO audit_log (account_id, sealed_entry, created_at) VALUES ('acct', x'00', 0)",
            [],
        )
        .unwrap();

        purge_account(&mut conn, "acct").unwrap();

        for table in [
            "events",
            "devices",
            "dek_wraps",
            "dek_epochs",
            "audit_log",
            "accounts",
        ] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 0, "{table} still has rows after purge");
        }
    }

    #[test]
    fn a_clean_database_sweeps_to_nothing() {
        let conn = setup();
        assert!(sweep(&conn, Retention::default()).unwrap().is_empty());
    }
}
