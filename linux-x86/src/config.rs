//! On-disk state for this device: where the server is, who we are, and the cached
//! lease share.

use std::{
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};

use base64::prelude::*;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use tracker_core::crypto::keys::DeviceIdentity;

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("config is malformed: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("not enrolled yet -- run `snus enroll <code>` first")]
    NotEnrolled,
    #[error("decoding failed: {0}")]
    Decode(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_url: String,
    /// The server's pinned tunnel key, base64. Compared against the fingerprint printed
    /// by `tracker-server bootstrap` at enrollment time.
    pub server_pub: String,
    pub device_id: String,
    pub display_name: String,
}

impl Config {
    pub fn server_pub_bytes(&self) -> Result<[u8; 32]> {
        let raw = BASE64_STANDARD
            .decode(&self.server_pub)
            .map_err(|e| ConfigError::Decode(e.to_string()))?;
        raw.as_slice()
            .try_into()
            .map_err(|_| ConfigError::Decode("expected 32 bytes".into()))
    }
}

pub struct Paths {
    pub config_file: PathBuf,
    pub identity_file: PathBuf,
    pub lease_file: PathBuf,
    pub database: PathBuf,
}

impl Paths {
    pub fn resolve() -> Result<Self> {
        let dirs = ProjectDirs::from("de", "liforra", "snus-tracker")
            .ok_or_else(|| ConfigError::Decode("no home directory".into()))?;
        fs::create_dir_all(dirs.config_dir())?;
        fs::create_dir_all(dirs.data_dir())?;
        // The data directory holds the device secret and the sealed records.
        fs::set_permissions(dirs.data_dir(), fs::Permissions::from_mode(0o700))?;

        Ok(Self {
            config_file: dirs.config_dir().join("config.json"),
            identity_file: dirs.data_dir().join("identity.bin"),
            lease_file: dirs.data_dir().join("lease.bin"),
            database: dirs.data_dir().join("records.db"),
        })
    }

    pub fn load_config(&self) -> Result<Config> {
        if !self.config_file.exists() {
            return Err(ConfigError::NotEnrolled);
        }
        Ok(serde_json::from_slice(&fs::read(&self.config_file)?)?)
    }

    pub fn save_config(&self, config: &Config) -> Result<()> {
        write_private(&self.config_file, &serde_json::to_vec_pretty(config)?)
    }
}

/// This device's long-term secrets: two key pairs and the local half of the storage key.
pub struct Identity {
    pub device: DeviceIdentity,
    /// The device's half of the local wrapping key. See the note in [`load_identity`]
    /// about what this is and is not worth on Linux.
    pub device_secret: [u8; 32],
}

const IDENTITY_LEN: usize = 96;

/// Load or create this device's secrets.
///
/// On Android the equivalent of `device_secret` lives in the hardware-backed Keystore
/// and genuinely cannot be extracted. There is no such thing here without a TPM, and
/// this machine has none, so it is a 0600 file. That is an honest weak point: anyone
/// who can read the disk holds the device half. What still holds is the server half --
/// revoke the device and the pair stops being derivable once the cached lease expires.
pub fn load_identity(paths: &Paths) -> Result<Identity> {
    if paths.identity_file.exists() {
        let raw = fs::read(&paths.identity_file)?;
        if raw.len() != IDENTITY_LEN {
            return Err(ConfigError::Decode(
                "identity file is the wrong size".into(),
            ));
        }
        let x: [u8; 32] = raw[0..32].try_into().unwrap();
        let e: [u8; 32] = raw[32..64].try_into().unwrap();
        let secret: [u8; 32] = raw[64..96].try_into().unwrap();
        return Ok(Identity {
            device: DeviceIdentity::from_bytes(x, e),
            device_secret: secret,
        });
    }

    let device = DeviceIdentity::generate().map_err(|e| ConfigError::Decode(e.to_string()))?;
    let mut device_secret = [0u8; 32];
    use rand::TryRngCore;
    rand::rngs::OsRng
        .try_fill_bytes(&mut device_secret)
        .map_err(|e| ConfigError::Decode(e.to_string()))?;

    let mut blob = Vec::with_capacity(IDENTITY_LEN);
    blob.extend_from_slice(&device.x25519.to_bytes());
    blob.extend_from_slice(&device.ed25519.to_bytes());
    blob.extend_from_slice(&device_secret);
    write_private(&paths.identity_file, &blob)?;

    Ok(Identity {
        device,
        device_secret,
    })
}

/// The server's half of the storage key, cached with the expiry the server set.
///
/// Caching it is what makes the client work offline at all: a fresh process has no
/// memory of the last session, so without this the tray would be unusable after a
/// reboot with no network. The cost is that the revocation guarantee is exactly the
/// lease TTL and not a second shorter -- a device taken offline stays readable until
/// the cached share expires. That is the trade that was chosen when the TTL was set to
/// 24 hours with hourly renewal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedLease {
    pub key_share: String,
    pub key_share_pending: Option<String>,
    pub expires_at: i64,
}

impl CachedLease {
    pub fn is_valid(&self) -> bool {
        chrono::Utc::now().timestamp() < self.expires_at
    }

    pub fn share_bytes(&self) -> Result<Vec<u8>> {
        BASE64_STANDARD
            .decode(&self.key_share)
            .map_err(|e| ConfigError::Decode(e.to_string()))
    }

    pub fn pending_bytes(&self) -> Option<Vec<u8>> {
        self.key_share_pending
            .as_ref()
            .and_then(|encoded| BASE64_STANDARD.decode(encoded).ok())
    }
}

pub fn load_lease(paths: &Paths) -> Result<Option<CachedLease>> {
    if !paths.lease_file.exists() {
        return Ok(None);
    }
    let lease: CachedLease = serde_json::from_slice(&fs::read(&paths.lease_file)?)?;
    Ok(Some(lease))
}

pub fn save_lease(paths: &Paths, lease: &CachedLease) -> Result<()> {
    write_private(&paths.lease_file, &serde_json::to_vec(lease)?)
}

/// Remove the cached share. Called the moment the server says this device is revoked,
/// rather than waiting for the expiry.
pub fn clear_lease(paths: &Paths) -> Result<()> {
    if paths.lease_file.exists() {
        fs::remove_file(&paths.lease_file)?;
    }
    Ok(())
}

fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    // Write through a temporary file so a crash mid-write cannot leave a truncated
    // identity or a half-replaced lease behind.
    let temporary = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    Ok(())
}
