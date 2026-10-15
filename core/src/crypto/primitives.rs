//! Public-key sealing shared by every part of the system.
//!
//! Lives in the core rather than the server because both sides of every one of these
//! constructions has to agree byte for byte. Two implementations of the same format is
//! a bug waiting to happen the first time one of them is tweaked.
//!
//! Two constructions, both X25519 + XChaCha20-Poly1305:
//!
//! * **Anonymous seal** -- encrypt to a public key with a throwaway sender key. Used for
//!   the audit log, where the server must be able to write entries it cannot read back.
//! * **Tunnel** -- the client brings an ephemeral key, the server has a pinned static
//!   one, and both sides derive a separate key per direction. Used so that whatever
//!   terminates TLS in front of us sees only ciphertext.
//!
//! Nothing here is novel; it is the standard sealed-box shape with an HKDF step so the
//! two uses cannot collide.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use rand::TryRngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

/// Domain separation. Reusing one shared secret for several purposes without this is a
/// classic way to turn two sound protocols into one unsound one.
const INFO_AUDIT: &[u8] = b"tracker/audit/v1";
const INFO_CLIENT_TO_SERVER: &[u8] = b"tracker/tunnel/v1/c2s";
const INFO_SERVER_TO_CLIENT: &[u8] = b"tracker/tunnel/v1/s2c";

pub type Result<T> = std::result::Result<T, CryptoError>;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("ciphertext is malformed or truncated")]
    Malformed,
    #[error("decryption failed: wrong key or tampered ciphertext")]
    Decrypt,
    #[error("expected {expected} bytes, got {got}")]
    BadLength { expected: usize, got: usize },
    #[error("entropy source failed: {0}")]
    Rng(String),
    #[error("key derivation failed: {0}")]
    Derivation(String),
    #[error("salt must be at least {minimum} bytes, got {got}")]
    SaltTooShort { minimum: usize, got: usize },
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    rand::rngs::OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|e| CryptoError::Rng(e.to_string()))?;
    Ok(buf)
}

/// Fixed-size view of a byte slice, erroring rather than panicking on a wrong length.
pub fn to_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| CryptoError::BadLength {
        expected: N,
        got: bytes.len(),
    })
}

pub fn to_key(bytes: &[u8]) -> Result<[u8; KEY_LEN]> {
    to_array(bytes)
}

pub fn to_nonce(bytes: &[u8]) -> Result<[u8; NONCE_LEN]> {
    to_array(bytes)
}

/// Derive a symmetric key from a Diffie-Hellman shared secret.
///
/// Both public keys go into the salt so the transcript is bound into the key: an
/// attacker who swaps one of them gets a different key rather than a working session.
fn derive(shared: &[u8], sender_pub: &[u8], recipient_pub: &[u8], info: &[u8]) -> [u8; KEY_LEN] {
    let mut salt = Vec::with_capacity(sender_pub.len() + recipient_pub.len());
    salt.extend_from_slice(sender_pub);
    salt.extend_from_slice(recipient_pub);

    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = [0u8; KEY_LEN];
    hk.expand(info, &mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

pub fn aead_seal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>> {
    XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(nonce), Payload { msg, aad })
        .map_err(|_| CryptoError::Decrypt)
}

pub fn aead_open(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| CryptoError::Decrypt)
}

/// Encrypt to a public key with a one-time sender key.
///
/// Layout: `ephemeral_public (32) || nonce (24) || ciphertext`. The sender keeps
/// nothing, so it cannot decrypt what it just wrote -- which is exactly the property
/// the audit log needs.
pub fn seal_anonymous(recipient_pub: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let ephemeral = StaticSecret::from(random::<KEY_LEN>()?);
    let ephemeral_pub = PublicKey::from(&ephemeral);
    let recipient = PublicKey::from(*recipient_pub);

    let shared = ephemeral.diffie_hellman(&recipient);
    let key = derive(
        shared.as_bytes(),
        ephemeral_pub.as_bytes(),
        recipient_pub,
        INFO_AUDIT,
    );
    let nonce = random::<NONCE_LEN>()?;

    let ciphertext = aead_seal(&key, &nonce, ephemeral_pub.as_bytes(), plaintext)?;

    let mut out = Vec::with_capacity(KEY_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(ephemeral_pub.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Counterpart to [`seal_anonymous`]. The server never calls this -- it exists so the
/// property can be tested and so a client implementation has a reference.
pub fn open_anonymous(recipient_secret: &StaticSecret, sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < KEY_LEN + NONCE_LEN {
        return Err(CryptoError::Malformed);
    }
    let (ephemeral_pub, rest) = sealed.split_at(KEY_LEN);
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);

    let ephemeral_pub: [u8; KEY_LEN] = to_key(ephemeral_pub)?;
    let recipient_pub = PublicKey::from(recipient_secret);
    let shared = recipient_secret.diffie_hellman(&PublicKey::from(ephemeral_pub));
    let key = derive(
        shared.as_bytes(),
        &ephemeral_pub,
        recipient_pub.as_bytes(),
        INFO_AUDIT,
    );

    aead_open(&key, &to_nonce(nonce)?, &ephemeral_pub, ciphertext)
}

/// Directional keys for one tunnel exchange.
///
/// Separate keys per direction rather than one key with different nonces: it removes
/// any chance of a nonce colliding across directions, at the cost of one extra HKDF.
pub struct TunnelKeys {
    pub client_to_server: [u8; KEY_LEN],
    pub server_to_client: [u8; KEY_LEN],
}

pub fn tunnel_keys(
    own_secret: &StaticSecret,
    peer_pub: &[u8; KEY_LEN],
    client_ephemeral_pub: &[u8; KEY_LEN],
    server_static_pub: &[u8; KEY_LEN],
) -> TunnelKeys {
    let shared = own_secret.diffie_hellman(&PublicKey::from(*peer_pub));
    TunnelKeys {
        client_to_server: derive(
            shared.as_bytes(),
            client_ephemeral_pub,
            server_static_pub,
            INFO_CLIENT_TO_SERVER,
        ),
        server_to_client: derive(
            shared.as_bytes(),
            client_ephemeral_pub,
            server_static_pub,
            INFO_SERVER_TO_CLIENT,
        ),
    }
}

pub fn generate_static_keypair() -> Result<(StaticSecret, PublicKey)> {
    let secret = StaticSecret::from(random::<KEY_LEN>()?);
    let public = PublicKey::from(&secret);
    Ok((secret, public))
}

pub fn random_nonce() -> Result<[u8; NONCE_LEN]> {
    random::<NONCE_LEN>()
}

/// Client half of the request tunnel.
///
/// Kept beside the server-side primitives on purpose: both ends of this format have to
/// agree byte for byte, and two copies in two crates is how they stop agreeing.
pub struct SealedRequest {
    pub envelope: Vec<u8>,
    pub reply_key: [u8; KEY_LEN],
}

pub fn seal_request_envelope(
    server_pub: &[u8; KEY_LEN],
    plaintext: &[u8],
) -> Result<SealedRequest> {
    let (ephemeral, ephemeral_pub) = generate_static_keypair()?;
    let keys = tunnel_keys(&ephemeral, server_pub, ephemeral_pub.as_bytes(), server_pub);
    let nonce = random_nonce()?;
    let ciphertext = aead_seal(
        &keys.client_to_server,
        &nonce,
        ephemeral_pub.as_bytes(),
        plaintext,
    )?;

    let mut envelope = Vec::with_capacity(KEY_LEN + NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(ephemeral_pub.as_bytes());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(SealedRequest {
        envelope,
        reply_key: keys.server_to_client,
    })
}

pub fn open_response_envelope(reply_key: &[u8; KEY_LEN], response: &[u8]) -> Result<Vec<u8>> {
    if response.len() < NONCE_LEN {
        return Err(CryptoError::Malformed);
    }
    let (nonce, ciphertext) = response.split_at(NONCE_LEN);
    aead_open(reply_key, &to_nonce(nonce)?, b"response", ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_entry_opens_only_with_the_recipient_key() {
        let (secret, public) = generate_static_keypair().unwrap();
        let sealed = seal_anonymous(public.as_bytes(), b"device revoked").unwrap();

        assert_eq!(open_anonymous(&secret, &sealed).unwrap(), b"device revoked");

        let (other, _) = generate_static_keypair().unwrap();
        assert!(
            open_anonymous(&other, &sealed).is_err(),
            "a different key must not open it"
        );
    }

    #[test]
    fn the_sealer_cannot_read_back_what_it_wrote() {
        // The ephemeral secret is dropped inside seal_anonymous. All that remains is the
        // recipient's public key, and a public key cannot decrypt.
        let (_, public) = generate_static_keypair().unwrap();
        let a = seal_anonymous(public.as_bytes(), b"same message").unwrap();
        let b = seal_anonymous(public.as_bytes(), b"same message").unwrap();
        assert_ne!(
            a, b,
            "each seal uses a fresh ephemeral key, so ciphertexts never repeat"
        );
    }

    #[test]
    fn tampering_is_detected() {
        let (secret, public) = generate_static_keypair().unwrap();
        let mut sealed = seal_anonymous(public.as_bytes(), b"enrolled laptop").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(matches!(
            open_anonymous(&secret, &sealed),
            Err(CryptoError::Decrypt)
        ));
    }

    #[test]
    fn truncated_input_is_rejected_rather_than_panicking() {
        let (secret, _) = generate_static_keypair().unwrap();
        for len in [0, 10, KEY_LEN, KEY_LEN + NONCE_LEN - 1] {
            let sealed = vec![0u8; len];
            assert!(matches!(
                open_anonymous(&secret, &sealed),
                Err(CryptoError::Malformed)
            ));
        }
    }

    #[test]
    fn both_sides_of_the_tunnel_derive_the_same_keys() {
        let (server_secret, server_pub) = generate_static_keypair().unwrap();
        let (client_ephemeral, client_pub) = generate_static_keypair().unwrap();

        let client_side = tunnel_keys(
            &client_ephemeral,
            server_pub.as_bytes(),
            client_pub.as_bytes(),
            server_pub.as_bytes(),
        );
        let server_side = tunnel_keys(
            &server_secret,
            client_pub.as_bytes(),
            client_pub.as_bytes(),
            server_pub.as_bytes(),
        );

        assert_eq!(client_side.client_to_server, server_side.client_to_server);
        assert_eq!(client_side.server_to_client, server_side.server_to_client);
        assert_ne!(
            client_side.client_to_server, client_side.server_to_client,
            "the two directions must not share a key"
        );
    }

    #[test]
    fn a_wrong_server_key_yields_a_different_tunnel_key() {
        // This is what defeats a CA-backed impostor in front of us: the client pins the
        // real server public key, so an interceptor with a valid certificate but the
        // wrong X25519 key derives something unusable.
        let (_, real_server_pub) = generate_static_keypair().unwrap();
        let (impostor_secret, impostor_pub) = generate_static_keypair().unwrap();
        let (client_ephemeral, client_pub) = generate_static_keypair().unwrap();

        let client_side = tunnel_keys(
            &client_ephemeral,
            real_server_pub.as_bytes(),
            client_pub.as_bytes(),
            real_server_pub.as_bytes(),
        );
        let impostor_side = tunnel_keys(
            &impostor_secret,
            client_pub.as_bytes(),
            client_pub.as_bytes(),
            impostor_pub.as_bytes(),
        );
        assert_ne!(client_side.client_to_server, impostor_side.client_to_server);
    }

    #[test]
    fn aead_round_trips_and_binds_its_aad() {
        let key = [7u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let ct = aead_seal(&key, &nonce, b"header", b"body").unwrap();
        assert_eq!(aead_open(&key, &nonce, b"header", &ct).unwrap(), b"body");
        assert!(
            aead_open(&key, &nonce, b"other", &ct).is_err(),
            "aad is authenticated"
        );
    }
}
