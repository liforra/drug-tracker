//! Data-encryption-key epochs.
//!
//! Records are sealed under a DEK that belongs to an epoch. When a device is revoked,
//! a remaining device mints a fresh DEK, seals it to every device that is still
//! trusted, and publishes it as the next epoch. Everything written from then on is
//! unreadable to the revoked device.
//!
//! The server stores wrapped keys it cannot open and hands each device only its own.
//! It never sees a DEK, which is why minting has to happen on a client.
//!
//! What rotation does not do: earlier epochs stay readable by whoever holds those DEKs.
//! A device that synced the history before being revoked still has that history on
//! disk. Rotation protects what comes next; the lease mechanism in [`crate::lease`] is
//! what addresses the copy already on the device.

use rusqlite::{Connection, OptionalExtension, params};

use crate::db::now;

pub type Result<T> = std::result::Result<T, DekError>;

#[derive(Debug, thiserror::Error)]
pub enum DekError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("epoch {given} is not newer than the current epoch {current}")]
    StaleEpoch { given: i64, current: i64 },
    #[error("a new epoch must be sealed to at least one device")]
    NoWraps,
    #[error("device {0} is revoked or not part of this account")]
    UntrustedTarget(String),
    #[error("epoch {0} does not exist")]
    UnknownEpoch(i64),
}

/// The highest published epoch, or `None` before any device has published one.
pub fn current_epoch(conn: &Connection, account_id: &str) -> Result<Option<i64>> {
    Ok(conn
        .query_row(
            "SELECT MAX(epoch) FROM dek_epochs WHERE account_id = ?1",
            params![account_id],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()?
        .flatten())
}

/// One device's sealed copy of a DEK.
#[derive(Debug, Clone)]
pub struct Wrap {
    pub epoch: i64,
    pub wrapped_dek: Vec<u8>,
}

/// Every epoch key this device can open, oldest first. A device needs the whole set to
/// read history, not just the current one.
pub fn wraps_for_device(
    conn: &Connection,
    account_id: &str,
    device_id: &str,
    since_epoch: i64,
) -> Result<Vec<Wrap>> {
    let mut stmt = conn.prepare(
        "SELECT epoch, wrapped_dek FROM dek_wraps
         WHERE account_id = ?1 AND device_id = ?2 AND epoch >= ?3
         ORDER BY epoch ASC",
    )?;
    let rows = stmt.query_map(params![account_id, device_id, since_epoch], |row| {
        Ok(Wrap {
            epoch: row.get(0)?,
            wrapped_dek: row.get(1)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// Active device ids for an account.
fn active_devices(conn: &Connection, account_id: &str) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT id FROM devices WHERE account_id = ?1 AND revoked_at IS NULL ORDER BY id",
    )?;
    let rows = stmt.query_map(params![account_id], |row| row.get(0))?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

#[derive(Debug)]
pub struct Published {
    pub epoch: i64,
    /// Active devices the publisher did not seal to. They will not be able to read
    /// anything written under this epoch, so a client should treat a non-empty list as
    /// a bug on its own side rather than a normal outcome.
    pub uncovered: Vec<String>,
}

/// Publish a new epoch with the DEK sealed to each trusted device.
///
/// The server refuses to store a wrap addressed to a revoked device. That is defence in
/// depth rather than the actual protection -- the real guarantee is that the publishing
/// client never seals to one -- but it means a buggy or coerced client cannot quietly
/// re-admit a device that was cut off.
pub fn publish_epoch(
    conn: &mut Connection,
    account_id: &str,
    created_by: &str,
    epoch: i64,
    wraps: &[(String, Vec<u8>)],
) -> Result<Published> {
    if wraps.is_empty() {
        return Err(DekError::NoWraps);
    }

    let current = current_epoch(conn, account_id)?.unwrap_or(0);
    if epoch <= current {
        return Err(DekError::StaleEpoch {
            given: epoch,
            current,
        });
    }

    let active = active_devices(conn, account_id)?;
    for (device_id, _) in wraps {
        if !active.contains(device_id) {
            return Err(DekError::UntrustedTarget(device_id.clone()));
        }
    }

    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO dek_epochs (account_id, epoch, created_at, created_by)
         VALUES (?1, ?2, ?3, ?4)",
        params![account_id, epoch, now(), created_by],
    )?;
    for (device_id, wrapped) in wraps {
        tx.execute(
            "INSERT INTO dek_wraps (account_id, epoch, device_id, wrapped_dek, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![account_id, epoch, device_id, wrapped, now()],
        )?;
    }
    tx.commit()?;

    let covered: Vec<&String> = wraps.iter().map(|(id, _)| id).collect();
    let uncovered = active
        .into_iter()
        .filter(|id| !covered.contains(&id))
        .collect();
    Ok(Published { epoch, uncovered })
}

/// Reicht Schlüssel für Epochen nach, die es bereits gibt.
///
/// Der Gegenpart zu [`publish_epoch`]: Der stellt eine neue Epoche auf und lehnt
/// alte ab, damit niemand den Fortschritt zurückdrehen kann. Hier geht es um den
/// umgekehrten Fall -- ein frisch aufgenommenes Gerät braucht Zugang zu dem, was
/// vor ihm geschrieben wurde, und den kann nur ein Gerät geben, das die Schlüssel
/// hat. Der Server reicht Umschläge durch, die er nicht öffnen kann.
///
/// Zwei Bedingungen, beide notwendig: Die Epoche muss existieren (sonst könnte ein
/// Client Epochen erfinden und die Reihenfolge unterlaufen), und das Zielgerät darf
/// nicht gesperrt sein (sonst wäre eine Sperre durch Nachreichen aufhebbar).
///
/// `INSERT OR IGNORE`: Ein bereits vorhandener Umschlag bleibt, wie er ist. Das macht
/// den Aufruf wiederholbar und nimmt einem fehlerhaften Client die Möglichkeit,
/// einen gültigen Schlüssel durch einen unbrauchbaren zu ersetzen.
pub fn backfill_wraps(
    conn: &mut Connection,
    account_id: &str,
    wraps: &[(i64, String, Vec<u8>)],
) -> Result<usize> {
    if wraps.is_empty() {
        return Err(DekError::NoWraps);
    }

    let active = active_devices(conn, account_id)?;
    for (_, device_id, _) in wraps {
        if !active.contains(device_id) {
            return Err(DekError::UntrustedTarget(device_id.clone()));
        }
    }

    let tx = conn.transaction()?;
    let mut added = 0usize;
    for (epoch, device_id, wrapped) in wraps {
        let known: i64 = tx.query_row(
            "SELECT COUNT(*) FROM dek_epochs WHERE account_id = ?1 AND epoch = ?2",
            params![account_id, epoch],
            |row| row.get(0),
        )?;
        if known == 0 {
            return Err(DekError::UnknownEpoch(*epoch));
        }
        added += tx.execute(
            "INSERT OR IGNORE INTO dek_wraps (account_id, epoch, device_id, wrapped_dek, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![account_id, epoch, device_id, wrapped, now()],
        )?;
    }
    tx.commit()?;
    Ok(added)
}

/// Remove a device's sealed keys. Called on revocation.
///
/// Housekeeping, not protection: a device that already pulled its wraps has them. What
/// actually cuts it off is that the next epoch is never sealed to it.
pub fn drop_wraps_for_device(conn: &Connection, device_id: &str) -> Result<usize> {
    Ok(conn.execute(
        "DELETE FROM dek_wraps WHERE device_id = ?1",
        params![device_id],
    )?)
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
        for id in ["phone", "laptop"] {
            conn.execute(
                "INSERT INTO devices (id, account_id, display_name, ed25519_pub, x25519_pub, created_at)
                 VALUES (?1, 'acct', ?1, x'00', x'00', 0)",
                params![id],
            )
            .unwrap();
        }
        conn
    }

    #[test]
    fn an_account_starts_with_no_epoch() {
        let conn = setup();
        assert_eq!(current_epoch(&conn, "acct").unwrap(), None);
    }

    #[test]
    fn publishing_seals_a_key_to_each_device() {
        let mut conn = setup();
        let published = publish_epoch(
            &mut conn,
            "acct",
            "phone",
            1,
            &[
                ("phone".into(), b"for-phone".to_vec()),
                ("laptop".into(), b"for-laptop".to_vec()),
            ],
        )
        .unwrap();

        assert!(published.uncovered.is_empty());
        assert_eq!(current_epoch(&conn, "acct").unwrap(), Some(1));

        let phone = wraps_for_device(&conn, "acct", "phone", 0).unwrap();
        assert_eq!(phone.len(), 1);
        assert_eq!(phone[0].wrapped_dek, b"for-phone");

        let laptop = wraps_for_device(&conn, "acct", "laptop", 0).unwrap();
        assert_eq!(
            laptop[0].wrapped_dek, b"for-laptop",
            "each device gets only its own"
        );
    }

    #[test]
    fn a_revoked_device_cannot_be_sealed_to() {
        let mut conn = setup();
        publish_epoch(
            &mut conn,
            "acct",
            "phone",
            1,
            &[
                ("phone".into(), b"a".to_vec()),
                ("laptop".into(), b"b".to_vec()),
            ],
        )
        .unwrap();

        crate::lease::revoke(&conn, "laptop").unwrap();

        // This is the whole point of rotation: the next epoch must not reach it.
        let refused = publish_epoch(
            &mut conn,
            "acct",
            "phone",
            2,
            &[
                ("phone".into(), b"c".to_vec()),
                ("laptop".into(), b"d".to_vec()),
            ],
        );
        assert!(
            matches!(refused, Err(DekError::UntrustedTarget(ref id)) if id == "laptop"),
            "the server must refuse to re-admit a revoked device"
        );

        // Sealing to the remaining device alone is accepted.
        let ok = publish_epoch(
            &mut conn,
            "acct",
            "phone",
            2,
            &[("phone".into(), b"c".to_vec())],
        )
        .unwrap();
        assert!(
            ok.uncovered.is_empty(),
            "the revoked device is no longer 'active'"
        );
        assert_eq!(current_epoch(&conn, "acct").unwrap(), Some(2));
    }

    #[test]
    fn the_revoked_device_keeps_no_wraps_on_the_server() {
        let mut conn = setup();
        publish_epoch(
            &mut conn,
            "acct",
            "phone",
            1,
            &[
                ("phone".into(), b"a".to_vec()),
                ("laptop".into(), b"b".to_vec()),
            ],
        )
        .unwrap();
        assert_eq!(
            wraps_for_device(&conn, "acct", "laptop", 0).unwrap().len(),
            1
        );

        crate::lease::revoke(&conn, "laptop").unwrap();
        drop_wraps_for_device(&conn, "laptop").unwrap();

        assert!(
            wraps_for_device(&conn, "acct", "laptop", 0)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            wraps_for_device(&conn, "acct", "phone", 0).unwrap().len(),
            1,
            "the remaining device is untouched"
        );
    }

    #[test]
    fn epochs_only_move_forward() {
        let mut conn = setup();
        publish_epoch(
            &mut conn,
            "acct",
            "phone",
            5,
            &[("phone".into(), b"a".to_vec())],
        )
        .unwrap();

        for stale in [1, 5] {
            let refused = publish_epoch(
                &mut conn,
                "acct",
                "phone",
                stale,
                &[("phone".into(), b"x".to_vec())],
            );
            assert!(
                matches!(refused, Err(DekError::StaleEpoch { .. })),
                "epoch {stale} should have been rejected as stale"
            );
        }
        assert_eq!(current_epoch(&conn, "acct").unwrap(), Some(5));
    }

    #[test]
    fn omitting_an_active_device_is_reported() {
        let mut conn = setup();
        let published = publish_epoch(
            &mut conn,
            "acct",
            "phone",
            1,
            &[("phone".into(), b"a".to_vec())],
        )
        .unwrap();
        assert_eq!(
            published.uncovered,
            vec!["laptop".to_string()],
            "a client must be able to notice it locked a device out by accident"
        );
    }

    #[test]
    fn a_device_can_fetch_every_epoch_it_holds() {
        let mut conn = setup();
        for epoch in 1..=3 {
            publish_epoch(
                &mut conn,
                "acct",
                "phone",
                epoch,
                &[("phone".into(), format!("dek-{epoch}").into_bytes())],
            )
            .unwrap();
        }
        // History needs every epoch, not just the newest.
        let all = wraps_for_device(&conn, "acct", "phone", 0).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].epoch, 1);
        assert_eq!(all[2].wrapped_dek, b"dek-3");

        let recent = wraps_for_device(&conn, "acct", "phone", 3).unwrap();
        assert_eq!(
            recent.len(),
            1,
            "an up-to-date device can skip what it already has"
        );
    }

    #[test]
    fn an_epoch_must_be_sealed_to_someone() {
        let mut conn = setup();
        assert!(matches!(
            publish_epoch(&mut conn, "acct", "phone", 1, &[]),
            Err(DekError::NoWraps)
        ));
    }
}
