//! Server-side storage. Everything payload-shaped in here is an opaque blob.
//!
//! The server is deliberately incapable of understanding what it stores. It knows that
//! an account has devices, that devices push and pull encrypted records, and which
//! devices are allowed to hold a key share. It does not know what substance was taken,
//! how much, or -- importantly -- *when*. Consumption timestamps live inside the
//! ciphertext. The only time the server records is `received_at`, which exists to order
//! the sync cursor and is explicitly not the time of consumption: clients batch uploads
//! on a jittered schedule precisely so the two cannot be equated.

use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

pub type Result<T> = std::result::Result<T, rusqlite::Error>;

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS accounts (
    id          TEXT PRIMARY KEY,
    created_at  INTEGER NOT NULL,
    -- X25519 public key the audit log is sealed to. Deposited by the first device and
    -- derived from the account root key, so the server can append entries it can never
    -- read back. Write-only logging by construction.
    audit_pub   BLOB
);

-- The server's own static X25519 identity, used for the request-encryption tunnel.
-- Generated once at bootstrap; its fingerprint is pinned by clients so a compromised
-- CA terminating TLS in front of us still cannot read anything.
CREATE TABLE IF NOT EXISTS server_identity (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    secret_key  BLOB NOT NULL,
    public_key  BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id                TEXT PRIMARY KEY,
    account_id        TEXT NOT NULL REFERENCES accounts(id),
    display_name      TEXT NOT NULL,
    ed25519_pub       BLOB NOT NULL,   -- request authentication
    x25519_pub        BLOB NOT NULL,   -- enrollment target for key wrapping
    created_at        INTEGER NOT NULL,
    revoked_at        INTEGER,
    -- Lease state. key_share is S_d: one half of the local-database key derivation.
    -- The other half never leaves the device, so holding this is useless to us.
    -- Revocation sets it to NULL, which is irreversible by construction.
    key_share         BLOB,
    key_share_pending BLOB,            -- S_d' mid-rotation, see two-phase renew
    lease_expires_at  INTEGER
);
CREATE INDEX IF NOT EXISTS devices_by_account ON devices(account_id);

-- Which data-encryption-key generation is current for an account. Rotated by a client
-- whenever a device is revoked: the remaining devices mint a new DEK and publish it
-- wrapped only to themselves, so the revoked device cannot read anything written from
-- that point on.
--
-- Note what this does NOT do: records already sealed under earlier epochs stay readable
-- by anyone holding those DEKs, including a device that synced them before revocation.
-- Rotation protects the future, never the past.
CREATE TABLE IF NOT EXISTS dek_epochs (
    account_id  TEXT NOT NULL REFERENCES accounts(id),
    epoch       INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    created_by  TEXT REFERENCES devices(id),
    PRIMARY KEY (account_id, epoch)
);

-- The DEK for one epoch, sealed to one device's X25519 public key. The server stores a
-- blob it cannot open and hands each device only its own.
CREATE TABLE IF NOT EXISTS dek_wraps (
    account_id  TEXT NOT NULL REFERENCES accounts(id),
    epoch       INTEGER NOT NULL,
    device_id   TEXT NOT NULL REFERENCES devices(id),
    wrapped_dek BLOB NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (account_id, epoch, device_id)
);
CREATE INDEX IF NOT EXISTS dek_wraps_by_device ON dek_wraps(device_id);

-- Security-relevant events, each sealed to the account's audit key. The server appends
-- and cannot read its own log back.
--
-- Encryption protects the log at rest -- against later seizure of this database. It
-- does not hide anything from a server that is compromised while running, which
-- necessarily knows what it is doing at the moment it does it. The sequence of entries
-- also leaks their count and timing, which for an audit log is largely the point.
CREATE TABLE IF NOT EXISTS audit_log (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id   TEXT NOT NULL REFERENCES accounts(id),
    sealed_entry BLOB NOT NULL,
    created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_by_account ON audit_log(account_id, seq);

-- Single-user today, but every row that belongs to a person carries account_id from
-- the start. Retrofitting a tenant boundary onto a live encrypted store is the kind of
-- migration that is not worth having.


CREATE TABLE IF NOT EXISTS events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id  TEXT NOT NULL REFERENCES accounts(id),
    event_id    TEXT NOT NULL,        -- client-generated ULID; makes push idempotent
    epoch       INTEGER NOT NULL,     -- which DEK generation this was sealed under
    nonce       BLOB NOT NULL,
    ciphertext  BLOB NOT NULL,        -- opaque. contains the real timestamps.
    received_at INTEGER NOT NULL,     -- server clock, NOT consumption time
    UNIQUE(account_id, event_id)
);
CREATE INDEX IF NOT EXISTS events_cursor ON events(account_id, seq);

CREATE TABLE IF NOT EXISTS challenges (
    nonce      TEXT PRIMARY KEY,
    device_id  TEXT NOT NULL REFERENCES devices(id),
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    token      TEXT PRIMARY KEY,
    device_id  TEXT NOT NULL REFERENCES devices(id),
    expires_at INTEGER NOT NULL
);

-- An enrolling device publishes its public keys; an already-trusted device wraps the
-- root key to them and drops the result here. The server relays a blob it cannot open.
-- A trusted device mints a short code; the user reads it out to the new device. Only a
-- device that presents a live code may join the account, so enrollment cannot be
-- initiated by anyone who merely knows the server address.
CREATE TABLE IF NOT EXISTS invites (
    code       TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    created_by TEXT REFERENCES devices(id),  -- NULL for the bootstrap invite
    expires_at INTEGER NOT NULL,
    claimed_by TEXT
);

CREATE TABLE IF NOT EXISTS enrollments (
    id              TEXT PRIMARY KEY,
    account_id      TEXT NOT NULL REFERENCES accounts(id),
    new_device_id   TEXT NOT NULL REFERENCES devices(id),
    wrapped_payload BLOB,
    created_at      INTEGER NOT NULL,
    claimed_at      INTEGER
);
"#;

pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

pub fn open_in_memory() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

#[derive(Debug, Clone)]
pub struct Device {
    pub id: String,
    pub account_id: String,
    pub display_name: String,
    pub ed25519_pub: Vec<u8>,
    pub revoked_at: Option<i64>,
}

impl Device {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

pub fn load_device(conn: &Connection, id: &str) -> Result<Option<Device>> {
    conn.query_row(
        "SELECT id, account_id, display_name, ed25519_pub, revoked_at FROM devices WHERE id = ?1",
        params![id],
        |row| {
            Ok(Device {
                id: row.get(0)?,
                account_id: row.get(1)?,
                display_name: row.get(2)?,
                ed25519_pub: row.get(3)?,
                revoked_at: row.get(4)?,
            })
        },
    )
    .optional()
}

/// Append one encrypted record. Returns the assigned cursor position, or the existing
/// one if this event_id was already stored -- pushes retry freely without duplicating.
pub fn append_event(
    conn: &Connection,
    account_id: &str,
    event_id: &str,
    epoch: i64,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<i64> {
    conn.execute(
        "INSERT OR IGNORE INTO events (account_id, event_id, epoch, nonce, ciphertext, received_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![account_id, event_id, epoch, nonce, ciphertext, now()],
    )?;
    conn.query_row(
        "SELECT seq FROM events WHERE account_id = ?1 AND event_id = ?2",
        params![account_id, event_id],
        |row| row.get(0),
    )
}

#[derive(Debug, Clone)]
pub struct StoredEvent {
    pub seq: i64,
    pub event_id: String,
    pub epoch: i64,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Pull records after a cursor position. The client folds these into its own log; the
/// server has no opinion about what they mean or how they order in real time.
pub fn events_since(
    conn: &Connection,
    account_id: &str,
    after_seq: i64,
    limit: i64,
) -> Result<Vec<StoredEvent>> {
    let mut stmt = conn.prepare(
        "SELECT seq, event_id, epoch, nonce, ciphertext FROM events
         WHERE account_id = ?1 AND seq > ?2 ORDER BY seq ASC LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![account_id, after_seq, limit], |row| {
        Ok(StoredEvent {
            seq: row.get(0)?,
            event_id: row.get(1)?,
            epoch: row.get(2)?,
            nonce: row.get(3)?,
            ciphertext: row.get(4)?,
        })
    })?;
    rows.collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(conn: &Connection) {
        conn.execute(
            "INSERT INTO accounts (id, created_at) VALUES ('acct', 0)",
            [],
        )
        .unwrap();
    }

    #[test]
    fn appending_the_same_event_twice_is_idempotent() {
        let conn = open_in_memory().unwrap();
        seed(&conn);
        let a = append_event(&conn, "acct", "ev1", 1, b"nonce", b"ct").unwrap();
        let b = append_event(&conn, "acct", "ev1", 1, b"nonce", b"ct").unwrap();
        assert_eq!(a, b, "a retried push must not create a second record");
        assert_eq!(events_since(&conn, "acct", 0, 100).unwrap().len(), 1);
    }

    #[test]
    fn cursor_returns_only_newer_records() {
        let conn = open_in_memory().unwrap();
        seed(&conn);
        let first = append_event(&conn, "acct", "ev1", 1, b"n", b"a").unwrap();
        append_event(&conn, "acct", "ev2", 1, b"n", b"b").unwrap();
        let tail = events_since(&conn, "acct", first, 100).unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].event_id, "ev2");
    }

    #[test]
    fn accounts_do_not_see_each_others_records() {
        let conn = open_in_memory().unwrap();
        seed(&conn);
        conn.execute(
            "INSERT INTO accounts (id, created_at) VALUES ('other', 0)",
            [],
        )
        .unwrap();
        append_event(&conn, "acct", "ev1", 1, b"n", b"a").unwrap();
        append_event(&conn, "other", "ev2", 1, b"n", b"b").unwrap();
        let mine = events_since(&conn, "acct", 0, 100).unwrap();
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].event_id, "ev1");
    }
}
