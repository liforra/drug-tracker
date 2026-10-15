//! Application-layer request encryption.
//!
//! TLS is terminated by a reverse proxy, which means the proxy sees plaintext. So does
//! anyone holding a certificate a browser would trust for this hostname. This layer
//! sits inside HTTP so that neither of them sees anything: the client pins the server's
//! X25519 public key, brings a fresh ephemeral key per request, and both sides derive
//! keys that an interceptor cannot reproduce.
//!
//! Deliberately stateless -- no handshake, no session table. Every request carries its
//! own ephemeral public key, so there is nothing to expire, resume, or leak.
//!
//! The tradeoff being made: there is no forward secrecy against compromise of the
//! server's *static* key. Someone who records traffic today and steals that key later
//! can decrypt the recording. A Noise handshake would fix that at the cost of session
//! state on both ends; rotating the server key periodically narrows the window instead.

use rusqlite::{Connection, OptionalExtension, params};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::db::now;
use tracker_core::crypto::{self, KEY_LEN, NONCE_LEN};

pub type Result<T> = std::result::Result<T, TunnelError>;

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("the server has no identity key; run bootstrap first")]
    NoIdentity,
    #[error("envelope is malformed or truncated")]
    Malformed,
}

/// The server's long-term tunnel key. Generated once and pinned by clients.
pub struct Identity {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl Identity {
    /// Short rendering of the public key for the user to compare against what their
    /// client shows. This is the actual defence against an impostor in front of us, so
    /// it needs to be something a person will really check.
    pub fn fingerprint(&self) -> String {
        use base64::prelude::*;
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(self.public.as_bytes());
        encoded
            .chars()
            .take(16)
            .collect::<Vec<_>>()
            .chunks(4)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("-")
    }
}

/// Load the server identity, creating it on first call.
pub fn load_or_create(conn: &Connection) -> Result<Identity> {
    let existing: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT secret_key, public_key FROM server_identity WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    if let Some((secret, public)) = existing {
        let secret = StaticSecret::from(crypto::to_key(&secret)?);
        let public = PublicKey::from(crypto::to_key(&public)?);
        return Ok(Identity { secret, public });
    }

    let (secret, public) = crypto::generate_static_keypair()?;
    conn.execute(
        "INSERT INTO server_identity (id, secret_key, public_key, created_at) VALUES (1, ?1, ?2, ?3)",
        params![secret.to_bytes().as_slice(), public.as_bytes().as_slice(), now()],
    )?;
    Ok(Identity { secret, public })
}

pub fn load(conn: &Connection) -> Result<Identity> {
    let row: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT secret_key, public_key FROM server_identity WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (secret, public) = row.ok_or(TunnelError::NoIdentity)?;
    Ok(Identity {
        secret: StaticSecret::from(crypto::to_key(&secret)?),
        public: PublicKey::from(crypto::to_key(&public)?),
    })
}

/// Wire format: `client_ephemeral_public (32) || nonce (24) || ciphertext`.
pub struct Envelope {
    pub client_ephemeral_pub: [u8; KEY_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < KEY_LEN + NONCE_LEN {
            return Err(TunnelError::Malformed);
        }
        let (ephemeral, rest) = bytes.split_at(KEY_LEN);
        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        Ok(Self {
            client_ephemeral_pub: crypto::to_key(ephemeral)?,
            nonce: crypto::to_nonce(nonce)?,
            ciphertext: ciphertext.to_vec(),
        })
    }

    pub fn encode(
        client_ephemeral_pub: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(KEY_LEN + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(client_ephemeral_pub);
        out.extend_from_slice(nonce);
        out.extend_from_slice(ciphertext);
        out
    }
}

/// Decrypt an inbound request and return both the plaintext and the key to answer with.
pub fn open_request(identity: &Identity, envelope: &Envelope) -> Result<(Vec<u8>, [u8; KEY_LEN])> {
    let keys = crypto::tunnel_keys(
        &identity.secret,
        &envelope.client_ephemeral_pub,
        &envelope.client_ephemeral_pub,
        identity.public.as_bytes(),
    );
    // The ephemeral public key is authenticated as associated data, so an interceptor
    // cannot swap it for one of its own without the tag failing.
    let plaintext = crypto::aead_open(
        &keys.client_to_server,
        &envelope.nonce,
        &envelope.client_ephemeral_pub,
        &envelope.ciphertext,
    )?;
    Ok((plaintext, keys.server_to_client))
}

/// Encrypt a response under the reply key from [`open_request`].
///
/// Response wire format is just `nonce (24) || ciphertext` -- the client already holds
/// the reply key from sealing its request, so there is no key material to carry back.
pub fn seal_response(reply_key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let nonce = crypto::random_nonce()?;
    let ciphertext = crypto::aead_seal(reply_key, &nonce, b"response", plaintext)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Client-side counterpart, kept here so the two halves stay in step and the round trip
/// is testable without a client implementation.
pub mod client {
    use super::*;

    pub struct Sealed {
        pub envelope: Vec<u8>,
        pub reply_key: [u8; KEY_LEN],
    }

    pub fn seal_request(server_pub: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Sealed> {
        let (ephemeral, ephemeral_pub) = crypto::generate_static_keypair()?;
        let keys =
            crypto::tunnel_keys(&ephemeral, server_pub, ephemeral_pub.as_bytes(), server_pub);
        let nonce = crypto::random_nonce()?;
        let ciphertext = crypto::aead_seal(
            &keys.client_to_server,
            &nonce,
            ephemeral_pub.as_bytes(),
            plaintext,
        )?;
        Ok(Sealed {
            envelope: Envelope::encode(ephemeral_pub.as_bytes(), &nonce, &ciphertext),
            reply_key: keys.server_to_client,
        })
    }

    pub fn open_response(reply_key: &[u8; KEY_LEN], response: &[u8]) -> Result<Vec<u8>> {
        if response.len() < NONCE_LEN {
            return Err(TunnelError::Malformed);
        }
        let (nonce, ciphertext) = response.split_at(NONCE_LEN);
        Ok(crypto::aead_open(
            reply_key,
            &crypto::to_nonce(nonce)?,
            b"response",
            ciphertext,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    #[test]
    fn identity_is_generated_once_and_then_stable() {
        let conn = open_in_memory().unwrap();
        let first = load_or_create(&conn).unwrap();
        let second = load_or_create(&conn).unwrap();
        assert_eq!(first.public.as_bytes(), second.public.as_bytes());
        assert_eq!(first.fingerprint(), second.fingerprint());
    }

    #[test]
    fn loading_before_bootstrap_is_an_error_not_a_fresh_key() {
        let conn = open_in_memory().unwrap();
        assert!(matches!(load(&conn), Err(TunnelError::NoIdentity)));
    }

    #[test]
    fn a_request_and_its_response_round_trip() {
        let conn = open_in_memory().unwrap();
        let identity = load_or_create(&conn).unwrap();

        let sealed = client::seal_request(identity.public.as_bytes(), b"GET /v1/events").unwrap();
        let envelope = Envelope::parse(&sealed.envelope).unwrap();
        let (plaintext, reply_key) = open_request(&identity, &envelope).unwrap();
        assert_eq!(plaintext, b"GET /v1/events");

        let response = seal_response(&reply_key, b"{\"events\":[]}").unwrap();
        let answer = client::open_response(&sealed.reply_key, &response).unwrap();
        assert_eq!(answer, b"{\"events\":[]}");
    }

    #[test]
    fn an_interceptor_with_its_own_key_cannot_read_the_request() {
        // Models exactly the feared case: something in front of us holds a certificate
        // the client's TLS stack accepts, but not the pinned X25519 key.
        let conn = open_in_memory().unwrap();
        let real = load_or_create(&conn).unwrap();

        let other = open_in_memory().unwrap();
        let impostor = load_or_create(&other).unwrap();
        assert_ne!(real.public.as_bytes(), impostor.public.as_bytes());

        let sealed = client::seal_request(real.public.as_bytes(), b"secret payload").unwrap();
        let envelope = Envelope::parse(&sealed.envelope).unwrap();

        assert!(
            open_request(&impostor, &envelope).is_err(),
            "a proxy holding a valid certificate but the wrong key must learn nothing"
        );
    }

    #[test]
    fn swapping_the_ephemeral_key_breaks_the_tag() {
        let conn = open_in_memory().unwrap();
        let identity = load_or_create(&conn).unwrap();
        let sealed = client::seal_request(identity.public.as_bytes(), b"payload").unwrap();

        let mut tampered = sealed.envelope.clone();
        tampered[0] ^= 0xff;
        let envelope = Envelope::parse(&tampered).unwrap();
        assert!(open_request(&identity, &envelope).is_err());
    }

    #[test]
    fn every_request_uses_a_fresh_ephemeral_key() {
        let conn = open_in_memory().unwrap();
        let identity = load_or_create(&conn).unwrap();
        let a = client::seal_request(identity.public.as_bytes(), b"same").unwrap();
        let b = client::seal_request(identity.public.as_bytes(), b"same").unwrap();
        assert_ne!(
            &a.envelope[..KEY_LEN],
            &b.envelope[..KEY_LEN],
            "identical plaintexts must not produce a linkable envelope"
        );
        assert_ne!(a.envelope, b.envelope);
    }

    #[test]
    fn truncated_envelopes_are_rejected() {
        for len in [0, 1, KEY_LEN, KEY_LEN + NONCE_LEN - 1] {
            assert!(matches!(
                Envelope::parse(&vec![0u8; len]),
                Err(TunnelError::Malformed)
            ));
        }
    }
}
