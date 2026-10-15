//! The key hierarchy.
//!
//! ```text
//! passphrase --Argon2id--> RootKey ----HKDF----> audit keypair (X25519)
//!
//! DEK (random per epoch)  --sealed to--> each trusted device's X25519 key
//!                                        (never derived from RootKey: a revoked
//!                                         device still holds that, so deriving
//!                                         would make revocation meaningless)
//!
//! DEKs at rest on a device --wrapped under--> KDF(device_secret, lease_key_share)
//! ```
//!
//! There is deliberately no recovery path. Losing every enrolled device means the
//! records are gone: the DEKs only ever existed sealed to those devices. That is a
//! consequence of the threat model rather than an oversight -- a recovery key that
//! works from the passphrase alone would also work for anyone who takes the database
//! and persuades you to hand the passphrase over.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::TryRngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::primitives::{self, CryptoError, KEY_LEN, NONCE_LEN, Result};

/// Argon2id cost. Tuned for a one-time unlock rather than a per-request check: 64 MiB
/// is heavy enough to make offline guessing expensive and still finishes in well under
/// a second on a phone.
const ARGON_MEMORY_KIB: u32 = 65536;
const ARGON_ITERATIONS: u32 = 3;
const ARGON_LANES: u32 = 1;

/// Argon2's own floor. Enforced here so the failure names the actual problem instead of
/// surfacing as a generic derivation error three layers down.
pub const MIN_SALT_LEN: usize = 8;
/// What [`generate_salt`] produces. Not secret -- it only has to be unique per account.
pub const SALT_LEN: usize = 16;

const INFO_AUDIT_KEY: &[u8] = b"tracker/root/audit-keypair/v1";
const INFO_LOCAL_WRAP: &[u8] = b"tracker/local/dek-wrap/v1";

/// Account-wide secret, transferred to a new device during enrollment.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey([u8; KEY_LEN]);

impl std::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RootKey(<redacted>)")
    }
}

impl RootKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Stretch a passphrase into the root key.
    ///
    /// The salt must be stable for an account or the same passphrase yields a different
    /// key on every device. It is not secret; storing it alongside the account is fine.
    pub fn from_passphrase(passphrase: &str, salt: &[u8]) -> Result<Self> {
        if salt.len() < MIN_SALT_LEN {
            return Err(CryptoError::SaltTooShort {
                minimum: MIN_SALT_LEN,
                got: salt.len(),
            });
        }
        let params = Params::new(
            ARGON_MEMORY_KIB,
            ARGON_ITERATIONS,
            ARGON_LANES,
            Some(KEY_LEN),
        )
        .map_err(|e| CryptoError::Derivation(e.to_string()))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut out = [0u8; KEY_LEN];
        argon
            .hash_password_into(passphrase.as_bytes(), salt, &mut out)
            .map_err(|e| CryptoError::Derivation(e.to_string()))?;
        Ok(Self(out))
    }

    /// A fresh account salt. Stored in the clear next to the account; it exists to keep
    /// the same passphrase from producing the same key across accounts, not to be secret.
    pub fn generate_salt() -> Result<[u8; SALT_LEN]> {
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|e| CryptoError::Rng(e.to_string()))?;
        Ok(salt)
    }

    pub fn random() -> Result<Self> {
        let mut out = [0u8; KEY_LEN];
        rand::rngs::OsRng
            .try_fill_bytes(&mut out)
            .map_err(|e| CryptoError::Rng(e.to_string()))?;
        Ok(Self(out))
    }

    /// The keypair the server seals audit entries to. Every device derives the same one,
    /// so any of them can read the log; the server only ever learns the public half.
    pub fn audit_keypair(&self) -> (StaticSecret, PublicKey) {
        let mut material = [0u8; KEY_LEN];
        Hkdf::<Sha256>::new(None, &self.0)
            .expand(INFO_AUDIT_KEY, &mut material)
            .expect("32 bytes is a valid HKDF output length");
        let secret = StaticSecret::from(material);
        let public = PublicKey::from(&secret);
        (secret, public)
    }
}

/// The key records are sealed under. One per epoch, random, never derived.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Dek([u8; KEY_LEN]);

impl std::fmt::Debug for Dek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dek(<redacted>)")
    }
}

impl Dek {
    pub fn generate() -> Result<Self> {
        let mut out = [0u8; KEY_LEN];
        rand::rngs::OsRng
            .try_fill_bytes(&mut out)
            .map_err(|e| CryptoError::Rng(e.to_string()))?;
        Ok(Self(out))
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Seal one log entry. The associated data binds the entry id, so a record cannot be
    /// moved to a different slot without the tag failing.
    pub fn seal(&self, entry_id: &str, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let nonce = primitives::random_nonce()?;
        let ciphertext = primitives::aead_seal(&self.0, &nonce, entry_id.as_bytes(), plaintext)?;
        Ok((nonce.to_vec(), ciphertext))
    }

    pub fn open(&self, entry_id: &str, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = primitives::to_nonce(nonce)?;
        primitives::aead_open(&self.0, &nonce, entry_id.as_bytes(), ciphertext)
    }

    /// Seal this key to a device's X25519 public key, for the server to relay.
    pub fn wrap_to(&self, device_pub: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
        primitives::seal_anonymous(device_pub, &self.0)
    }

    pub fn unwrap_with(device_secret: &StaticSecret, wrapped: &[u8]) -> Result<Self> {
        let bytes = primitives::open_anonymous(device_secret, wrapped)?;
        Ok(Self(primitives::to_key(&bytes)?))
    }
}

/// A device's own keys. The X25519 half receives sealed DEKs; the Ed25519 half
/// authenticates to the server.
pub struct DeviceIdentity {
    pub x25519: StaticSecret,
    pub ed25519: ed25519_dalek::SigningKey,
}

impl DeviceIdentity {
    pub fn generate() -> Result<Self> {
        let mut x = [0u8; KEY_LEN];
        let mut e = [0u8; KEY_LEN];
        rand::rngs::OsRng
            .try_fill_bytes(&mut x)
            .map_err(|err| CryptoError::Rng(err.to_string()))?;
        rand::rngs::OsRng
            .try_fill_bytes(&mut e)
            .map_err(|err| CryptoError::Rng(err.to_string()))?;
        Ok(Self {
            x25519: StaticSecret::from(x),
            ed25519: ed25519_dalek::SigningKey::from_bytes(&e),
        })
    }

    pub fn from_bytes(x: [u8; KEY_LEN], e: [u8; KEY_LEN]) -> Self {
        Self {
            x25519: StaticSecret::from(x),
            ed25519: ed25519_dalek::SigningKey::from_bytes(&e),
        }
    }

    pub fn x25519_public(&self) -> [u8; KEY_LEN] {
        *PublicKey::from(&self.x25519).as_bytes()
    }

    pub fn ed25519_public(&self) -> [u8; KEY_LEN] {
        self.ed25519.verifying_key().to_bytes()
    }
}

/// The at-rest key for a device's local DEK store.
///
/// Both halves are required and neither side holds both: `device_secret` lives in the
/// platform keystore and never reaches the server, `lease_share` comes from the server
/// and is never written to disk. Revoking the device destroys the server's half, so once
/// the in-memory copy is gone the local records cannot be opened again.
pub fn local_wrapping_key(device_secret: &[u8], lease_share: &[u8]) -> [u8; KEY_LEN] {
    let mut material = Vec::with_capacity(device_secret.len() + lease_share.len());
    material.extend_from_slice(device_secret);
    material.extend_from_slice(lease_share);

    let mut key = [0u8; KEY_LEN];
    Hkdf::<Sha256>::new(Some(b"tracker/local"), &material)
        .expand(INFO_LOCAL_WRAP, &mut key)
        .expect("32 bytes is a valid HKDF output length");
    material.zeroize();
    key
}

/// Encrypt the on-disk DEK bundle under the split key.
pub fn wrap_local(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = primitives::random_nonce()?;
    let ciphertext = primitives::aead_seal(key, &nonce, b"dek-bundle", plaintext)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn unwrap_local(key: &[u8; KEY_LEN], wrapped: &[u8]) -> Result<Vec<u8>> {
    if wrapped.len() < NONCE_LEN {
        return Err(CryptoError::Malformed);
    }
    let (nonce, ciphertext) = wrapped.split_at(NONCE_LEN);
    primitives::aead_open(
        key,
        &primitives::to_nonce(nonce)?,
        b"dek-bundle",
        ciphertext,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_passphrase_and_salt_give_the_same_root_key() {
        let a = RootKey::from_passphrase("correct horse battery staple", b"account-salt").unwrap();
        let b = RootKey::from_passphrase("correct horse battery staple", b"account-salt").unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn a_different_salt_gives_a_different_key() {
        let a = RootKey::from_passphrase("same passphrase", b"salt-one").unwrap();
        let b = RootKey::from_passphrase("same passphrase", b"salt-two").unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn every_device_derives_the_same_audit_keypair() {
        let salt = b"account-salt-16b";
        let (_, first) = RootKey::from_passphrase("shared", salt)
            .unwrap()
            .audit_keypair();
        let (_, second) = RootKey::from_passphrase("shared", salt)
            .unwrap()
            .audit_keypair();
        assert_eq!(
            first.as_bytes(),
            second.as_bytes(),
            "all devices must read the same log"
        );
    }

    #[test]
    fn a_short_salt_is_refused_with_a_useful_message() {
        let err = RootKey::from_passphrase("passphrase", b"tiny").unwrap_err();
        assert!(
            matches!(err, CryptoError::SaltTooShort { got: 4, .. }),
            "the error should name the real problem, got: {err}"
        );
        assert!(RootKey::generate_salt().unwrap().len() >= MIN_SALT_LEN);
    }

    #[test]
    fn a_sealed_record_needs_its_own_entry_id() {
        let dek = Dek::generate().unwrap();
        let (nonce, ciphertext) = dek.seal("entry-a", b"session started").unwrap();

        assert_eq!(
            dek.open("entry-a", &nonce, &ciphertext).unwrap(),
            b"session started"
        );
        assert!(
            dek.open("entry-b", &nonce, &ciphertext).is_err(),
            "a record must not be replayable under a different id"
        );
    }

    #[test]
    fn a_dek_travels_sealed_to_one_device_only() {
        let dek = Dek::generate().unwrap();
        let device = DeviceIdentity::generate().unwrap();
        let other = DeviceIdentity::generate().unwrap();

        let wrapped = dek.wrap_to(&device.x25519_public()).unwrap();
        let recovered = Dek::unwrap_with(&device.x25519, &wrapped).unwrap();
        assert_eq!(recovered.as_bytes(), dek.as_bytes());

        assert!(
            Dek::unwrap_with(&other.x25519, &wrapped).is_err(),
            "another device must not be able to open it"
        );
    }

    #[test]
    fn the_local_wrapping_key_needs_both_halves() {
        let full = local_wrapping_key(b"device-secret", b"lease-share");
        assert_ne!(full, local_wrapping_key(b"device-secret", b"other-share"));
        assert_ne!(full, local_wrapping_key(b"other-secret", b"lease-share"));
    }

    #[test]
    fn losing_the_lease_share_makes_the_local_bundle_unreadable() {
        let dek = Dek::generate().unwrap();
        let key = local_wrapping_key(b"device-secret", b"lease-share");
        let on_disk = wrap_local(&key, dek.as_bytes()).unwrap();

        assert_eq!(unwrap_local(&key, &on_disk).unwrap(), dek.as_bytes());

        // What a revoked device is left with: its own half, and nothing else.
        let without_server = local_wrapping_key(b"device-secret", b"");
        assert!(
            unwrap_local(&without_server, &on_disk).is_err(),
            "the device half alone must not open the bundle"
        );
    }

    #[test]
    fn a_root_key_does_not_print_itself() {
        let root = RootKey::from_bytes([7u8; KEY_LEN]);
        assert_eq!(format!("{root:?}"), "RootKey(<redacted>)");
        let dek = Dek::from_bytes([7u8; KEY_LEN]);
        assert!(!format!("{dek:?}").contains('7'));
    }
}
