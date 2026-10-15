//! Adding a device to an account.
//!
//! The server relays a blob it cannot open. A trusted device wraps the account's root
//! key to the newcomer's X25519 public key; we store the ciphertext and hand it over.
//! At no point does the plaintext root key exist on this machine.
//!
//! Joining requires a short code minted by an already-trusted device, so knowing the
//! server address is not enough to enroll. Clients should additionally show the new
//! device's key fingerprint on both screens for the user to compare out of band --
//! that is what actually defends against a server that lies about which public key
//! belongs to the newcomer.

use base64::prelude::*;
use rand::TryRngCore;
use rusqlite::{Connection, OptionalExtension, params};

use crate::db::now;

const INVITE_TTL_SECS: i64 = 600;
/// Crockford-style alphabet: no I, L, O, U, so a code read aloud is unambiguous.
const CODE_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_LEN: usize = 10;

pub type Result<T> = std::result::Result<T, EnrollError>;

#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("invite code is unknown, expired, or already used")]
    BadInvite,
    #[error("no such enrollment")]
    UnknownEnrollment,
    #[error("enrollment belongs to another account")]
    WrongAccount,
    #[error("entropy source failed: {0}")]
    Rng(String),
}

fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| EnrollError::Rng(e.to_string()))?;
    Ok(buf)
}

fn random_id() -> Result<String> {
    Ok(BASE64_URL_SAFE_NO_PAD.encode(random_bytes(16)?))
}

fn random_code() -> Result<String> {
    let raw = random_bytes(CODE_LEN)?;
    Ok(raw
        .iter()
        .map(|b| CODE_ALPHABET[(*b as usize) % CODE_ALPHABET.len()] as char)
        .collect())
}

pub fn create_invite(
    conn: &Connection,
    account_id: &str,
    created_by: Option<&str>,
) -> Result<(String, i64)> {
    let code = random_code()?;
    let expires_at = now() + INVITE_TTL_SECS;
    conn.execute(
        "INSERT INTO invites (code, account_id, created_by, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![code, account_id, created_by, expires_at],
    )?;
    Ok((code, expires_at))
}

pub struct Claimed {
    pub device_id: String,
    pub account_id: String,
    pub enrollment_id: String,
}

/// Redeem a code: register the newcomer's public keys and open an enrollment slot for
/// a trusted device to drop the wrapped root key into.
pub fn claim_invite(
    conn: &mut Connection,
    code: &str,
    display_name: &str,
    ed25519_pub: &[u8],
    x25519_pub: &[u8],
) -> Result<Claimed> {
    let tx = conn.transaction()?;

    let account_id: Option<String> = tx
        .query_row(
            "SELECT account_id FROM invites WHERE code = ?1 AND expires_at > ?2 AND claimed_by IS NULL",
            params![code, now()],
            |row| row.get(0),
        )
        .optional()?;
    let account_id = account_id.ok_or(EnrollError::BadInvite)?;

    let device_id = random_id()?;
    let enrollment_id = random_id()?;

    tx.execute(
        "INSERT INTO devices (id, account_id, display_name, ed25519_pub, x25519_pub, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![device_id, account_id, display_name, ed25519_pub, x25519_pub, now()],
    )?;
    tx.execute(
        "UPDATE invites SET claimed_by = ?1 WHERE code = ?2",
        params![device_id, code],
    )?;
    tx.execute(
        "INSERT INTO enrollments (id, account_id, new_device_id, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![enrollment_id, account_id, device_id, now()],
    )?;

    tx.commit()?;
    Ok(Claimed { device_id, account_id, enrollment_id })
}

#[derive(Debug)]
pub struct Pending {
    pub enrollment_id: String,
    pub device_id: String,
    pub display_name: String,
    pub x25519_pub: Vec<u8>,
}

/// Enrollments still waiting for a trusted device to wrap the root key.
pub fn pending(conn: &Connection, account_id: &str) -> Result<Vec<Pending>> {
    let mut stmt = conn.prepare(
        "SELECT e.id, e.new_device_id, d.display_name, d.x25519_pub
         FROM enrollments e JOIN devices d ON d.id = e.new_device_id
         WHERE e.account_id = ?1 AND e.wrapped_payload IS NULL AND d.revoked_at IS NULL
         ORDER BY e.created_at ASC",
    )?;
    let rows = stmt.query_map(params![account_id], |row| {
        Ok(Pending {
            enrollment_id: row.get(0)?,
            device_id: row.get(1)?,
            display_name: row.get(2)?,
            x25519_pub: row.get(3)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

/// A trusted device deposits the root key sealed to the newcomer's public key.
pub fn deposit(
    conn: &Connection,
    enrollment_id: &str,
    account_id: &str,
    wrapped_payload: &[u8],
) -> Result<()> {
    let owner: Option<String> = conn
        .query_row(
            "SELECT account_id FROM enrollments WHERE id = ?1",
            params![enrollment_id],
            |row| row.get(0),
        )
        .optional()?;
    match owner {
        None => return Err(EnrollError::UnknownEnrollment),
        Some(owner) if owner != account_id => return Err(EnrollError::WrongAccount),
        Some(_) => {}
    }
    conn.execute(
        "UPDATE enrollments SET wrapped_payload = ?1 WHERE id = ?2",
        params![wrapped_payload, enrollment_id],
    )?;
    Ok(())
}

/// The newcomer collects its sealed root key. Only the device the enrollment was opened
/// for may fetch it.
pub fn collect(
    conn: &Connection,
    enrollment_id: &str,
    device_id: &str,
) -> Result<Option<Vec<u8>>> {
    let row: Option<(String, Option<Vec<u8>>)> = conn
        .query_row(
            "SELECT new_device_id, wrapped_payload FROM enrollments WHERE id = ?1",
            params![enrollment_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (owner, payload) = row.ok_or(EnrollError::UnknownEnrollment)?;
    if owner != device_id {
        return Err(EnrollError::WrongAccount);
    }
    if payload.is_some() {
        conn.execute(
            "UPDATE enrollments SET claimed_at = ?1 WHERE id = ?2",
            params![now(), enrollment_id],
        )?;
    }
    Ok(payload)
}

/// The first invite for an account, issued by no device because none exists yet.
///
/// Idempotent on purpose: an unclaimed invite is a credential, so running bootstrap
/// repeatedly must reuse the live one rather than scatter several valid codes. Returns
/// the code, its expiry, and whether an existing one was reused.
pub fn bootstrap_invite(conn: &Connection, account_id: &str) -> Result<(String, i64, bool)> {
    let live: Option<(String, i64)> = conn
        .query_row(
            "SELECT code, expires_at FROM invites
             WHERE account_id = ?1 AND claimed_by IS NULL AND expires_at > ?2
             ORDER BY expires_at DESC LIMIT 1",
            params![account_id, now()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    match live {
        Some((code, expires_at)) => Ok((code, expires_at, true)),
        None => {
            let (code, expires_at) = create_invite(conn, account_id, None)?;
            Ok((code, expires_at, false))
        }
    }
}

/// How many devices an account has, used to decide whether bootstrap still applies.
pub fn device_count(conn: &Connection, account_id: &str) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM devices WHERE account_id = ?1",
        params![account_id],
        |row| row.get(0),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        conn.execute("INSERT INTO accounts (id, created_at) VALUES ('acct', 0)", []).unwrap();
        conn
    }

    #[test]
    fn a_code_admits_exactly_one_device() {
        let mut conn = setup();
        let (code, _) = create_invite(&conn, "acct", None).unwrap();
        let first = claim_invite(&mut conn, &code, "phone", &[1u8; 32], &[2u8; 32]).unwrap();
        assert_eq!(first.account_id, "acct");
        let second = claim_invite(&mut conn, &code, "laptop", &[3u8; 32], &[4u8; 32]);
        assert!(matches!(second, Err(EnrollError::BadInvite)), "codes are single-use");
    }

    #[test]
    fn an_unknown_code_is_rejected() {
        let mut conn = setup();
        let result = claim_invite(&mut conn, "AAAAAAAAAA", "rogue", &[1u8; 32], &[2u8; 32]);
        assert!(matches!(result, Err(EnrollError::BadInvite)));
    }

    #[test]
    fn the_newcomer_collects_only_its_own_sealed_key() {
        let mut conn = setup();
        let (code, _) = create_invite(&conn, "acct", None).unwrap();
        let claimed = claim_invite(&mut conn, &code, "phone", &[1u8; 32], &[2u8; 32]).unwrap();

        assert!(collect(&conn, &claimed.enrollment_id, &claimed.device_id).unwrap().is_none());

        deposit(&conn, &claimed.enrollment_id, "acct", b"sealed-root-key").unwrap();
        let got = collect(&conn, &claimed.enrollment_id, &claimed.device_id).unwrap();
        assert_eq!(got.as_deref(), Some(b"sealed-root-key".as_slice()));

        let wrong = collect(&conn, &claimed.enrollment_id, "someone-else");
        assert!(matches!(wrong, Err(EnrollError::WrongAccount)));
    }

    #[test]
    fn bootstrap_reuses_a_live_invite_instead_of_minting_more() {
        let conn = setup();
        let (first, _, reused) = bootstrap_invite(&conn, "acct").unwrap();
        assert!(!reused, "the first call mints");

        for _ in 0..3 {
            let (again, _, reused) = bootstrap_invite(&conn, "acct").unwrap();
            assert!(reused, "later calls must reuse");
            assert_eq!(again, first);
        }

        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM invites", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1, "an unclaimed invite is a credential; do not scatter them");
    }

    #[test]
    fn bootstrap_mints_afresh_once_the_old_invite_is_claimed() {
        let mut conn = setup();
        let (code, _, _) = bootstrap_invite(&conn, "acct").unwrap();
        claim_invite(&mut conn, &code, "phone", &[1u8; 32], &[2u8; 32]).unwrap();
        assert_eq!(device_count(&conn, "acct").unwrap(), 1);

        let (next, _, reused) = bootstrap_invite(&conn, "acct").unwrap();
        assert!(!reused);
        assert_ne!(next, code, "a spent code must never be handed out again");
    }

    #[test]
    fn pending_lists_only_unfulfilled_enrollments() {
        let mut conn = setup();
        let (code, _) = create_invite(&conn, "acct", None).unwrap();
        let claimed = claim_invite(&mut conn, &code, "phone", &[1u8; 32], &[2u8; 32]).unwrap();
        assert_eq!(pending(&conn, "acct").unwrap().len(), 1);
        deposit(&conn, &claimed.enrollment_id, "acct", b"x").unwrap();
        assert!(pending(&conn, "acct").unwrap().is_empty());
    }
}
