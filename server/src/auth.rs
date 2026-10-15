//! Device authentication by Ed25519 challenge-response.
//!
//! There are no passwords here. A device proves it holds the private half of the
//! identity key it enrolled with, and gets a short-lived bearer token. That keeps the
//! server free of any secret worth stealing: the identity keys are public, and the key
//! shares it does hold are useless without the device half.

use base64::prelude::*;
use ed25519_dalek::{Signature, VerifyingKey};
use rand::TryRngCore;
use rusqlite::{Connection, OptionalExtension, params};

use crate::db::{Device, load_device, now};

/// Challenges are single-use and short-lived; this only has to outlast a round trip.
const CHALLENGE_TTL_SECS: i64 = 120;
/// Tokens are cheap to re-mint, so keep the window that a stolen one is useful small.
const TOKEN_TTL_SECS: i64 = 3600;

pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("no such device")]
    UnknownDevice,
    #[error("device is revoked")]
    Revoked,
    #[error("challenge is unknown, expired, or already used")]
    BadChallenge,
    #[error("signature did not verify")]
    BadSignature,
    #[error("malformed key or signature")]
    Malformed,
    #[error("entropy source failed: {0}")]
    Rng(String),
}

fn random_b64(len: usize) -> Result<String> {
    let mut buf = vec![0u8; len];
    rand::rngs::OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| AuthError::Rng(e.to_string()))?;
    Ok(BASE64_URL_SAFE_NO_PAD.encode(buf))
}

/// Hand out a nonce for the device to sign. We check revocation here as well as at
/// verification time so a revoked device gets a clear answer immediately.
pub fn issue_challenge(conn: &Connection, device_id: &str) -> Result<String> {
    let device = load_device(conn, device_id)?.ok_or(AuthError::UnknownDevice)?;
    if !device.is_active() {
        return Err(AuthError::Revoked);
    }
    let nonce = random_b64(32)?;
    conn.execute(
        "INSERT INTO challenges (nonce, device_id, expires_at) VALUES (?1, ?2, ?3)",
        params![nonce, device_id, now() + CHALLENGE_TTL_SECS],
    )?;
    Ok(nonce)
}

pub struct Session {
    pub token: String,
    pub expires_at: i64,
    pub device: Device,
}

/// Verify a signed challenge and mint a bearer token.
pub fn verify_challenge(conn: &Connection, nonce: &str, signature_b64: &str) -> Result<Session> {
    let device_id: Option<String> = conn
        .query_row(
            "SELECT device_id FROM challenges WHERE nonce = ?1 AND expires_at > ?2",
            params![nonce, now()],
            |row| row.get(0),
        )
        .optional()?;
    let device_id = device_id.ok_or(AuthError::BadChallenge)?;

    // Burn the challenge before checking the signature: a failed attempt must not leave
    // a nonce lying around for a second try.
    conn.execute("DELETE FROM challenges WHERE nonce = ?1", params![nonce])?;

    let device = load_device(conn, &device_id)?.ok_or(AuthError::UnknownDevice)?;
    if !device.is_active() {
        return Err(AuthError::Revoked);
    }

    let key_bytes: [u8; 32] = device
        .ed25519_pub
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::Malformed)?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| AuthError::Malformed)?;

    let sig_bytes = BASE64_URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| AuthError::Malformed)?;
    let sig_bytes: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::Malformed)?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify_strict(nonce.as_bytes(), &signature)
        .map_err(|_| AuthError::BadSignature)?;

    let token = random_b64(32)?;
    let expires_at = now() + TOKEN_TTL_SECS;
    conn.execute(
        "INSERT INTO tokens (token, device_id, expires_at) VALUES (?1, ?2, ?3)",
        params![token, device_id, expires_at],
    )?;

    Ok(Session { token, expires_at, device })
}

/// Resolve a bearer token to its device, rejecting revoked devices even if the token
/// itself is still within its window -- revocation must take effect immediately.
pub fn authenticate(conn: &Connection, token: &str) -> Result<Device> {
    let device_id: Option<String> = conn
        .query_row(
            "SELECT device_id FROM tokens WHERE token = ?1 AND expires_at > ?2",
            params![token, now()],
            |row| row.get(0),
        )
        .optional()?;
    let device_id = device_id.ok_or(AuthError::BadChallenge)?;
    let device = load_device(conn, &device_id)?.ok_or(AuthError::UnknownDevice)?;
    if !device.is_active() {
        return Err(AuthError::Revoked);
    }
    Ok(device)
}

/// Drop every token belonging to a device. Called on revocation so an in-flight session
/// dies with it.
pub fn drop_tokens(conn: &Connection, device_id: &str) -> Result<()> {
    conn.execute("DELETE FROM tokens WHERE device_id = ?1", params![device_id])?;
    Ok(())
}
