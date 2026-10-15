//! Device leases and revocation.
//!
//! Each device's local database key is derived from two halves:
//!
//! ```text
//! DBMK_wrapper = wrap(DBMK, KDF(device_secret, key_share))
//! ```
//!
//! `device_secret` lives in the platform keystore and never reaches us. `key_share`
//! (S_d) lives here and never touches the device's disk -- the client holds it in RAM
//! only, with an expiry. Neither half alone opens anything, so a seized server yields
//! nothing and a seized device goes dark once its RAM copy is gone.
//!
//! Revoking a device NULLs its key share. There is no undo path, deliberately.

use rand::TryRngCore;
use rusqlite::{Connection, OptionalExtension, params};

use crate::db::now;

/// How long a client may keep using a key share it already fetched. The client retries
/// renewal hourly, so in practice it always sits on a nearly-full window; the TTL only
/// bites when the device has had no connectivity at all for a full day.
pub const LEASE_TTL_SECS: i64 = 24 * 3600;

pub type Result<T> = std::result::Result<T, LeaseError>;

#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("device is revoked")]
    Revoked,
    #[error("no such device")]
    UnknownDevice,
    #[error("entropy source failed: {0}")]
    Rng(String),
}

fn random_share() -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| LeaseError::Rng(e.to_string()))?;
    Ok(buf)
}

#[derive(Debug, Clone)]
pub struct Lease {
    /// The share the on-disk wrapper is currently built from.
    pub key_share: Vec<u8>,
    /// A newer share mid-rotation. Present only if a rotate was issued but never
    /// acknowledged; the client should try this one too, because it may have written
    /// the new wrapper and then died before telling us.
    pub key_share_pending: Option<Vec<u8>>,
    pub expires_at: i64,
}

fn require_active(conn: &Connection, device_id: &str) -> Result<()> {
    let revoked: Option<Option<i64>> = conn
        .query_row(
            "SELECT revoked_at FROM devices WHERE id = ?1",
            params![device_id],
            |row| row.get(0),
        )
        .optional()?;
    match revoked {
        None => Err(LeaseError::UnknownDevice),
        Some(Some(_)) => Err(LeaseError::Revoked),
        Some(None) => Ok(()),
    }
}

/// Cold start: hand back the share(s) that can open this device's local database.
/// Creates one on first call, which is what happens right after enrollment.
pub fn acquire(conn: &Connection, device_id: &str) -> Result<Lease> {
    require_active(conn, device_id)?;

    let (existing, pending): (Option<Vec<u8>>, Option<Vec<u8>>) = conn.query_row(
        "SELECT key_share, key_share_pending FROM devices WHERE id = ?1",
        params![device_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    let share = match existing {
        Some(share) => share,
        None => {
            let fresh = random_share()?;
            conn.execute(
                "UPDATE devices SET key_share = ?1 WHERE id = ?2",
                params![fresh, device_id],
            )?;
            fresh
        }
    };

    let expires_at = now() + LEASE_TTL_SECS;
    conn.execute(
        "UPDATE devices SET lease_expires_at = ?1 WHERE id = ?2",
        params![expires_at, device_id],
    )?;

    Ok(Lease {
        key_share: share,
        key_share_pending: pending,
        expires_at,
    })
}

/// Phase one of rotation: mint a replacement share and keep the old one valid. The
/// client rewraps its database key under the new share and then calls `commit`.
///
/// Both shares stay usable in between on purpose. A crash between "server issued" and
/// "client finished writing the wrapper" must not brick the device, and we cannot tell
/// from here which side of that write it died on.
pub fn rotate(conn: &Connection, device_id: &str) -> Result<Lease> {
    require_active(conn, device_id)?;

    let current: Option<Vec<u8>> = conn.query_row(
        "SELECT key_share FROM devices WHERE id = ?1",
        params![device_id],
        |row| row.get(0),
    )?;
    let current = match current {
        Some(share) => share,
        // Nothing to rotate from yet; a plain acquire establishes the first share.
        None => return acquire(conn, device_id),
    };

    let fresh = random_share()?;
    let expires_at = now() + LEASE_TTL_SECS;
    conn.execute(
        "UPDATE devices SET key_share_pending = ?1, lease_expires_at = ?2 WHERE id = ?3",
        params![fresh, expires_at, device_id],
    )?;

    Ok(Lease {
        key_share: current,
        key_share_pending: Some(fresh),
        expires_at,
    })
}

/// Phase two: the client confirms its on-disk wrapper now uses the pending share.
/// The previous share is dropped, which is what makes a leaked old share worthless.
pub fn commit(conn: &Connection, device_id: &str) -> Result<()> {
    require_active(conn, device_id)?;
    conn.execute(
        "UPDATE devices
         SET key_share = COALESCE(key_share_pending, key_share), key_share_pending = NULL
         WHERE id = ?1",
        params![device_id],
    )?;
    Ok(())
}

/// Destroy a device's ability to read its own local database.
///
/// This is the whole point of the split-key design, so be clear about what it does and
/// does not achieve. It guarantees the device cannot derive its database key again once
/// its RAM copy is gone -- reboot, app kill, or TTL expiry. It does not reach out and
/// erase anything, and it cannot un-read data the device already synced and displayed.
/// A device that is online learns it is revoked at its next hourly poll and wipes
/// immediately, so the practical window is usually well under an hour.
pub fn revoke(conn: &Connection, device_id: &str) -> Result<()> {
    let affected = conn.execute(
        "UPDATE devices
         SET revoked_at = COALESCE(revoked_at, ?1), key_share = NULL, key_share_pending = NULL
         WHERE id = ?2",
        params![now(), device_id],
    )?;
    if affected == 0 {
        return Err(LeaseError::UnknownDevice);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    fn setup() -> (Connection, String) {
        let conn = open_in_memory().unwrap();
        conn.execute(
            "INSERT INTO accounts (id, created_at) VALUES ('acct', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO devices (id, account_id, display_name, ed25519_pub, x25519_pub, created_at)
             VALUES ('dev', 'acct', 'phone', x'00', x'00', 0)",
            [],
        )
        .unwrap();
        (conn, "dev".to_string())
    }

    #[test]
    fn first_acquire_mints_a_share_and_repeats_are_stable() {
        let (conn, dev) = setup();
        let first = acquire(&conn, &dev).unwrap();
        let second = acquire(&conn, &dev).unwrap();
        assert_eq!(first.key_share.len(), 32);
        assert_eq!(
            first.key_share, second.key_share,
            "the share must stay stable or the on-disk wrapper stops opening"
        );
    }

    #[test]
    fn rotation_keeps_both_shares_valid_until_committed() {
        let (conn, dev) = setup();
        let original = acquire(&conn, &dev).unwrap().key_share;
        let rotated = rotate(&conn, &dev).unwrap();

        assert_eq!(
            rotated.key_share, original,
            "old share still usable pre-commit"
        );
        let pending = rotated.key_share_pending.expect("a new share was minted");
        assert_ne!(pending, original);

        // A client that crashed before committing comes back and still sees both.
        let after_crash = acquire(&conn, &dev).unwrap();
        assert_eq!(after_crash.key_share, original);
        assert_eq!(after_crash.key_share_pending, Some(pending));
    }

    #[test]
    fn committing_discards_the_superseded_share() {
        let (conn, dev) = setup();
        let original = acquire(&conn, &dev).unwrap().key_share;
        let pending = rotate(&conn, &dev).unwrap().key_share_pending.unwrap();
        commit(&conn, &dev).unwrap();

        let after = acquire(&conn, &dev).unwrap();
        assert_eq!(
            after.key_share, pending,
            "the new share is now the live one"
        );
        assert_ne!(after.key_share, original);
        assert!(
            after.key_share_pending.is_none(),
            "a leaked old share is now worthless"
        );
    }

    #[test]
    fn revoking_destroys_the_share_permanently() {
        let (conn, dev) = setup();
        acquire(&conn, &dev).unwrap();
        revoke(&conn, &dev).unwrap();

        assert!(matches!(acquire(&conn, &dev), Err(LeaseError::Revoked)));
        assert!(matches!(rotate(&conn, &dev), Err(LeaseError::Revoked)));

        let share: Option<Vec<u8>> = conn
            .query_row("SELECT key_share FROM devices WHERE id = 'dev'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(
            share.is_none(),
            "the share must be gone from storage, not just flagged"
        );
    }

    #[test]
    fn revocation_is_idempotent_and_keeps_the_original_timestamp() {
        let (conn, dev) = setup();
        revoke(&conn, &dev).unwrap();
        let first: i64 = conn
            .query_row("SELECT revoked_at FROM devices WHERE id = 'dev'", [], |r| {
                r.get(0)
            })
            .unwrap();
        revoke(&conn, &dev).unwrap();
        let second: i64 = conn
            .query_row("SELECT revoked_at FROM devices WHERE id = 'dev'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn unknown_devices_are_rejected_rather_than_provisioned() {
        let (conn, _) = setup();
        assert!(matches!(
            acquire(&conn, "ghost"),
            Err(LeaseError::UnknownDevice)
        ));
        assert!(matches!(
            revoke(&conn, "ghost"),
            Err(LeaseError::UnknownDevice)
        ));
    }
}
