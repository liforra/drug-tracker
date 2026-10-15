//! Local storage.
//!
//! The database holds exactly what the server holds: sealed blobs. There is no
//! SQLCipher and no encrypted database file, because there is nothing to protect at
//! that level -- the records are already sealed under a DEK, and the DEKs are what the
//! lease mechanism guards.
//!
//! That gives the same guarantee with less machinery: when the lease expires the DEK
//! bundle cannot be unwrapped, and the rows in this file become noise.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use crate::{
    crypto::keys::{Dek, local_wrapping_key, unwrap_local, wrap_local},
    log::LogEntry,
};

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("serialisation error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("no key for epoch {0}; this device was not sealed to it")]
    MissingEpoch(i64),
}

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS entries (
    id         TEXT PRIMARY KEY,
    epoch      INTEGER NOT NULL,
    nonce      BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    -- NULL until the server has acknowledged it. Drives the push queue.
    server_seq INTEGER
);
CREATE INDEX IF NOT EXISTS entries_unsynced ON entries(server_seq) WHERE server_seq IS NULL;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- DEKs, encrypted under KDF(device_secret, lease_share). Kept in the same file for
-- convenience; it is useless without both halves.
CREATE TABLE IF NOT EXISTS dek_bundle (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    wrapped BLOB NOT NULL
);
"#;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    // ----------------------------------------------------------------- metadata

    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| r.get(0))
            .optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Highest server cursor this device has pulled.
    pub fn cursor(&self) -> Result<i64> {
        Ok(self.meta("cursor")?.and_then(|v| v.parse().ok()).unwrap_or(0))
    }

    pub fn set_cursor(&self, seq: i64) -> Result<()> {
        self.set_meta("cursor", &seq.to_string())
    }

    // -------------------------------------------------------------- DEK bundle

    /// Store the device's keys under the split wrapping key.
    pub fn save_deks(
        &self,
        deks: &[(i64, Dek)],
        device_secret: &[u8],
        lease_share: &[u8],
    ) -> Result<()> {
        let plain: Vec<(i64, Vec<u8>)> =
            deks.iter().map(|(epoch, dek)| (*epoch, dek.as_bytes().to_vec())).collect();
        let serialised = serde_json::to_vec(&plain)?;
        let wrapped = wrap_local(&local_wrapping_key(device_secret, lease_share), &serialised)?;

        self.conn.execute(
            "INSERT INTO dek_bundle (id, wrapped) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET wrapped = excluded.wrapped",
            params![wrapped],
        )?;
        Ok(())
    }

    pub fn load_deks(&self, device_secret: &[u8], lease_share: &[u8]) -> Result<Vec<(i64, Dek)>> {
        let wrapped: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT wrapped FROM dek_bundle WHERE id = 1", [], |r| r.get(0))
            .optional()?;
        let Some(wrapped) = wrapped else {
            return Ok(Vec::new());
        };

        let plain = unwrap_local(&local_wrapping_key(device_secret, lease_share), &wrapped)?;
        let raw: Vec<(i64, Vec<u8>)> = serde_json::from_slice(&plain)?;

        raw.into_iter()
            .map(|(epoch, bytes)| {
                Ok((epoch, Dek::from_bytes(crate::crypto::to_key(&bytes)?)))
            })
            .collect()
    }

    /// Destroy the local keys. Called when the server says this device is revoked --
    /// waiting for the lease to lapse would leave a window open for no reason.
    pub fn wipe_keys(&self) -> Result<()> {
        self.conn.execute("DELETE FROM dek_bundle", [])?;
        Ok(())
    }

    // ------------------------------------------------------------------ entries

    /// Seal an entry and queue it for the server.
    pub fn append(&self, entry: &LogEntry, epoch: i64, dek: &Dek) -> Result<()> {
        let plaintext = serde_json::to_vec(entry)?;
        let (nonce, ciphertext) = dek.seal(&entry.id, &plaintext)?;
        self.conn.execute(
            "INSERT OR IGNORE INTO entries (id, epoch, nonce, ciphertext, server_seq)
             VALUES (?1, ?2, ?3, ?4, NULL)",
            params![entry.id, epoch, nonce, ciphertext],
        )?;
        Ok(())
    }

    /// Store a sealed record pulled from the server. Already acknowledged by definition.
    pub fn ingest(
        &self,
        id: &str,
        epoch: i64,
        nonce: &[u8],
        ciphertext: &[u8],
        server_seq: i64,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO entries (id, epoch, nonce, ciphertext, server_seq)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET server_seq = excluded.server_seq",
            params![id, epoch, nonce, ciphertext, server_seq],
        )?;
        Ok(())
    }

    pub fn pending(&self, limit: i64) -> Result<Vec<(String, i64, Vec<u8>, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, epoch, nonce, ciphertext FROM entries
             WHERE server_seq IS NULL ORDER BY id ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn mark_synced(&self, id: &str, server_seq: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE entries SET server_seq = ?1 WHERE id = ?2",
            params![server_seq, id],
        )?;
        Ok(())
    }

    pub fn pending_count(&self) -> Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM entries WHERE server_seq IS NULL",
            [],
            |r| r.get(0),
        )?)
    }

    /// Decrypt the whole log.
    ///
    /// An entry sealed under an epoch this device has no key for is skipped rather than
    /// failing the load: that is the normal state of affairs for a device enrolled after
    /// some history already existed, and refusing to start would be the wrong response.
    /// Cheap fingerprint of the log, for noticing writes by another process.
    ///
    /// The count is enough: entries are only ever added, never edited or removed, so any
    /// change moves it. And it is an index-only query, which is what makes it cheap
    /// enough to ask on a short timer.
    pub fn revision(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))?)
    }

    pub fn load_entries(&self, deks: &[(i64, Dek)]) -> Result<(Vec<LogEntry>, usize)> {
        let mut stmt =
            self.conn.prepare("SELECT id, epoch, nonce, ciphertext FROM entries ORDER BY id ASC")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;

        let mut entries = Vec::new();
        let mut unreadable = 0usize;
        for row in rows {
            let (id, epoch, nonce, ciphertext) = row?;
            let Some((_, dek)) = deks.iter().find(|(e, _)| *e == epoch) else {
                unreadable += 1;
                continue;
            };
            match dek.open(&id, &nonce, &ciphertext) {
                Ok(plain) => entries.push(serde_json::from_slice(&plain)?),
                Err(_) => unreadable += 1,
            }
        }
        Ok((entries, unreadable))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::{Event, LogEntry, seed_products};

    fn dek_set() -> Vec<(i64, Dek)> {
        vec![(1, Dek::generate().unwrap())]
    }

    #[test]
    fn an_appended_entry_comes_back_out_intact() {
        let store = Store::open_in_memory().unwrap();
        let deks = dek_set();
        let entry = seed_products("phone").remove(0);

        store.append(&entry, 1, &deks[0].1).unwrap();
        let (loaded, unreadable) = store.load_entries(&deks).unwrap();

        assert_eq!(unreadable, 0);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], entry);
    }

    #[test]
    fn what_is_on_disk_is_not_readable_without_the_key() {
        let store = Store::open_in_memory().unwrap();
        let deks = dek_set();
        store.append(&seed_products("phone").remove(0), 1, &deks[0].1).unwrap();

        let blob: Vec<u8> = store
            .conn
            .query_row("SELECT ciphertext FROM entries", [], |r| r.get(0))
            .unwrap();
        assert!(
            !blob.windows(4).any(|w| w == b"CUBA"),
            "the product name must not be readable in the stored row"
        );

        // A different key set yields nothing rather than garbage.
        let (loaded, unreadable) = store.load_entries(&dek_set()).unwrap();
        assert!(loaded.is_empty());
        assert_eq!(unreadable, 1);
    }

    #[test]
    fn entries_from_an_epoch_this_device_lacks_are_skipped_not_fatal() {
        let store = Store::open_in_memory().unwrap();
        let epoch1 = Dek::generate().unwrap();
        let epoch2 = Dek::generate().unwrap();

        let mine = LogEntry::new("phone", Event::ProductRetired { product_id: "p".into() });
        store.append(&mine, 2, &epoch2).unwrap();
        let theirs = LogEntry::new("laptop", Event::ProductRetired { product_id: "q".into() });
        store.append(&theirs, 1, &epoch1).unwrap();

        // A device enrolled late holds only epoch 2.
        let (loaded, unreadable) = store.load_entries(&[(2, epoch2)]).unwrap();
        assert_eq!(loaded.len(), 1, "the readable entry still loads");
        assert_eq!(unreadable, 1, "and the older one is reported, not fatal");
    }

    #[test]
    fn the_push_queue_drains_as_the_server_acknowledges() {
        let store = Store::open_in_memory().unwrap();
        let deks = dek_set();
        let entry = seed_products("phone").remove(0);
        store.append(&entry, 1, &deks[0].1).unwrap();

        assert_eq!(store.pending_count().unwrap(), 1);
        let pending = store.pending(10).unwrap();
        assert_eq!(pending.len(), 1);

        store.mark_synced(&pending[0].0, 42).unwrap();
        assert_eq!(store.pending_count().unwrap(), 0);
    }

    #[test]
    fn a_record_pulled_from_the_server_is_not_queued_for_pushing_back() {
        let store = Store::open_in_memory().unwrap();
        store.ingest("remote-1", 1, b"nonce", b"ct", 7).unwrap();
        assert_eq!(store.pending_count().unwrap(), 0, "sync must not loop records forever");
    }

    #[test]
    fn deks_survive_a_restart_only_with_both_key_halves() {
        let store = Store::open_in_memory().unwrap();
        let deks = dek_set();
        store.save_deks(&deks, b"device-secret", b"lease-share").unwrap();

        let restored = store.load_deks(b"device-secret", b"lease-share").unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].1.as_bytes(), deks[0].1.as_bytes());

        // The server's half withheld, which is what revocation produces.
        assert!(store.load_deks(b"device-secret", b"stale-share").is_err());
    }

    #[test]
    fn wiping_keys_leaves_the_records_unreadable() {
        let store = Store::open_in_memory().unwrap();
        let deks = dek_set();
        store.save_deks(&deks, b"secret", b"share").unwrap();
        store.append(&seed_products("phone").remove(0), 1, &deks[0].1).unwrap();

        store.wipe_keys().unwrap();

        assert!(store.load_deks(b"secret", b"share").unwrap().is_empty());
        let (loaded, unreadable) = store.load_entries(&[]).unwrap();
        assert!(loaded.is_empty());
        assert_eq!(unreadable, 1, "the row is still there, and is now noise");
    }

    #[test]
    fn the_sync_cursor_persists() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.cursor().unwrap(), 0);
        store.set_cursor(99).unwrap();
        assert_eq!(store.cursor().unwrap(), 99);
    }
}
