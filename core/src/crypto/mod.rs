//! Cryptography: sealing primitives, key hierarchy, and platform key storage.
pub mod keys;
pub mod primitives;

pub use primitives::{
    CryptoError, KEY_LEN, NONCE_LEN, Result, TunnelKeys, aead_open, aead_seal,
    generate_static_keypair, open_anonymous, random_nonce, seal_anonymous, to_array, to_key,
    to_nonce, tunnel_keys,
};
