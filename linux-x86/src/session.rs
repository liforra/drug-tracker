//! Opening the tracker: authenticate, obtain the storage key, unlock the records.

use base64::prelude::*;
use tracker_core::{
    crypto::keys::{Dek, RootKey},
    store::Store,
    sync::{ServerConfig, SyncClient, SyncError},
    tracker::{SyncReport, Tracker},
};

use crate::config::{self, CachedLease, Config, ConfigError, Identity, Paths};

pub type Result<T> = std::result::Result<T, SessionError>;

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("storage error: {0}")]
    Store(#[from] tracker_core::store::StoreError),
    #[error("sync error: {0}")]
    Sync(#[from] SyncError),
    #[error("tracker error: {0}")]
    Tracker(#[from] tracker_core::tracker::TrackerError),
    #[error("crypto error: {0}")]
    Crypto(#[from] tracker_core::crypto::CryptoError),
    #[error("this device has been revoked; its local records have been wiped")]
    Revoked,
    #[error("locked: no valid lease and the server is unreachable")]
    Locked,
    #[error("no data key yet -- run `snus approve` on an already-enrolled device")]
    NoDataKey,
}

pub struct Session {
    pub tracker: Tracker,
    pub client: SyncClient,
    pub paths: Paths,
    pub identity: Identity,
    #[allow(dead_code)]
    pub config: Config,
    lease: CachedLease,
    /// False when we could not reach the server and fell back to the cached lease.
    pub online: bool,
}

impl Session {
    /// The full start-up path, in the order that keeps a device usable offline.
    pub fn open() -> Result<Self> {
        let paths = Paths::resolve()?;
        let config = paths.load_config()?;
        let identity = config::load_identity(&paths)?;

        let client = SyncClient::new(ServerConfig {
            base_url: config.server_url.clone(),
            server_pub: config.server_pub_bytes()?,
        });

        // Try the network first so the lease is as fresh as possible, but never make
        // start-up depend on it.
        let mut online = false;
        let mut lease = config::load_lease(&paths)?;

        match client.authenticate(&config.device_id, &identity.device.ed25519) {
            Ok(()) => match client.lease_acquire() {
                Ok(fresh) => {
                    let cached = CachedLease {
                        key_share: fresh.key_share,
                        key_share_pending: fresh.key_share_pending,
                        expires_at: fresh.expires_at,
                    };
                    config::save_lease(&paths, &cached)?;
                    lease = Some(cached);
                    online = true;
                }
                Err(e) if e.is_revoked() => return Self::handle_revocation(&paths),
                Err(_) => {}
            },
            Err(e) if e.is_revoked() => return Self::handle_revocation(&paths),
            Err(_) => {}
        }

        let lease = lease
            .filter(CachedLease::is_valid)
            .ok_or(SessionError::Locked)?;

        let store = Store::open(&paths.database)?;
        let deks = unlock_deks(&store, &identity, &lease)?;

        let mut session = Session {
            tracker: Tracker::open(store, deks, config.device_id.clone())?,
            client,
            paths,
            identity,
            config,
            lease,
            online,
        };

        // A device enrolled after the account already existed starts with no keys and
        // collects them here. An unlocked one checks too: an approving device can seal
        // older epochs for it later, and those sit below the highest epoch it already
        // holds, so they would otherwise never be fetched.
        if session.online {
            if session.tracker.is_locked() {
                session.collect_keys()?;
            } else {
                let _ = session.collect_keys();
            }
        }
        Ok(session)
    }

    /// Wipe on revocation rather than waiting for the cached lease to lapse.
    fn handle_revocation(paths: &Paths) -> Result<Self> {
        config::clear_lease(paths)?;
        if let Ok(store) = Store::open(&paths.database) {
            let _ = store.wipe_keys();
        }
        Err(SessionError::Revoked)
    }

    /// Pull sealed data keys from the server and unwrap them with this device's key.
    pub fn collect_keys(&mut self) -> Result<()> {
        // From epoch 0, not just above the highest held: backfilled wraps for older epochs
        // arrive after the fact. `add_dek` ignores epochs already held, so this is cheap.
        let wraps = self.client.deks(0)?;
        if wraps.is_empty() && self.tracker.is_locked() {
            return Err(SessionError::NoDataKey);
        }

        for wrap in wraps {
            let sealed = BASE64_STANDARD
                .decode(&wrap.wrapped_dek)
                .map_err(|e| SyncError::Transport(e.to_string()))?;
            let dek = Dek::unwrap_with(&self.identity.device.x25519, &sealed)?;
            self.tracker.add_dek(wrap.epoch, dek)?;
        }

        self.persist_keys()
    }

    fn persist_keys(&self) -> Result<()> {
        self.tracker
            .persist_deks(&self.identity.device_secret, &self.lease.share_bytes()?)?;
        Ok(())
    }

    pub fn sync(&mut self) -> Result<SyncReport> {
        match self.tracker.sync(&self.client) {
            Ok(report) => Ok(report),
            Err(tracker_core::tracker::TrackerError::Sync(e)) if e.is_revoked() => {
                config::clear_lease(&self.paths)?;
                self.tracker.lock_and_wipe()?;
                Err(SessionError::Revoked)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Two-phase lease rotation: take the new share, rewrap the local keys under it,
    /// then acknowledge. The old share stays valid until the acknowledgement, so a
    /// crash in the middle costs nothing.
    pub fn renew_lease(&mut self) -> Result<()> {
        let rotated = self.client.lease_rotate()?;
        let Some(pending) = rotated.key_share_pending.clone() else {
            return Ok(());
        };

        let next = CachedLease {
            key_share: pending,
            key_share_pending: None,
            expires_at: rotated.expires_at,
        };
        self.tracker
            .persist_deks(&self.identity.device_secret, &next.share_bytes()?)?;
        config::save_lease(&self.paths, &next)?;
        self.client.lease_commit()?;
        self.lease = next;
        Ok(())
    }
}

/// Recover the data keys from the local store.
///
/// Tries the pending share too: a rotation that was written to disk but never
/// acknowledged leaves the bundle wrapped under the newer of the two, and only the
/// device knows which.
fn unlock_deks(store: &Store, identity: &Identity, lease: &CachedLease) -> Result<Vec<(i64, Dek)>> {
    let current = lease.share_bytes()?;
    if let Ok(deks) = store.load_deks(&identity.device_secret, &current)
        && !deks.is_empty()
    {
        return Ok(deks);
    }
    if let Some(pending) = lease.pending_bytes()
        && let Ok(deks) = store.load_deks(&identity.device_secret, &pending)
    {
        return Ok(deks);
    }
    Ok(Vec::new())
}

/// First-time setup: claim an invite and become this account's device.
pub fn enroll(
    server_url: &str,
    server_pub_b64: &str,
    code: &str,
    display_name: &str,
) -> Result<String> {
    let paths = Paths::resolve()?;
    let identity = config::load_identity(&paths)?;

    let server_pub: [u8; 32] = BASE64_STANDARD
        .decode(server_pub_b64)
        .map_err(|e| ConfigError::Decode(e.to_string()))?
        .as_slice()
        .try_into()
        .map_err(|_| ConfigError::Decode("server key must be 32 bytes".into()))?;

    let client = SyncClient::new(ServerConfig {
        base_url: server_url.to_string(),
        server_pub,
    });

    // The first device establishes the account's audit key; later ones send nothing and
    // the server keeps the original.
    let root = RootKey::random()?;
    let (_, audit_pub) = root.audit_keypair();

    let claimed = client.claim_invite(
        code,
        display_name,
        &identity.device.ed25519_public(),
        &identity.device.x25519_public(),
        Some(audit_pub.as_bytes()),
    )?;
    let device_id = claimed["device_id"]
        .as_str()
        .ok_or_else(|| ConfigError::Decode("server did not return a device id".into()))?
        .to_string();

    paths.save_config(&Config {
        server_url: server_url.to_string(),
        server_pub: server_pub_b64.to_string(),
        device_id: device_id.clone(),
        display_name: display_name.to_string(),
    })?;

    client.authenticate(&device_id, &identity.device.ed25519)?;
    let lease = client.lease_acquire()?;
    let cached = CachedLease {
        key_share: lease.key_share,
        key_share_pending: lease.key_share_pending,
        expires_at: lease.expires_at,
    };
    config::save_lease(&paths, &cached)?;

    // If nobody has minted a data key yet, this device is the first: mint one, seal it
    // to itself, and seed the starting variety.
    let store = Store::open(&paths.database)?;
    if client.current_epoch()?.is_none() {
        let dek = Dek::generate()?;
        client.publish_epoch(
            1,
            &[(
                device_id.clone(),
                dek.wrap_to(&identity.device.x25519_public())?,
            )],
        )?;

        let mut tracker = Tracker::open(store, vec![(1, dek)], device_id.clone())?;
        tracker.persist_deks(&identity.device_secret, &cached.share_bytes()?)?;
        for entry in tracker_core::log::seed_products(&device_id) {
            if let tracker_core::log::Event::ProductDefined {
                name,
                substance_id,
                route_id,
                nominal_mg,
                default_duration_secs,
                accent,
                image,
                ..
            } = entry.event
            {
                tracker.define_product(
                    name,
                    substance_id,
                    route_id,
                    nominal_mg,
                    default_duration_secs,
                    accent,
                    image,
                )?;
            }
        }
        tracker.sync(&client)?;
    }

    Ok(device_id)
}

/// Bring newly enrolled devices into the fold: mint a fresh epoch sealed to every
/// device that is currently trusted.
///
/// Has to run from a device that already holds a key, because the server has none to
/// give -- that is the whole point of the design. Returns the devices covered.
pub fn approve_devices(session: &mut Session) -> Result<Vec<String>> {
    let listed = session.client.devices()?;
    let mut targets: Vec<(String, [u8; 32])> = Vec::new();

    for row in listed.as_array().map(Vec::as_slice).unwrap_or_default() {
        if !row["revoked_at"].is_null() {
            continue;
        }
        let (Some(device_id), Some(encoded)) =
            (row["device_id"].as_str(), row["x25519_pub"].as_str())
        else {
            continue;
        };
        let Ok(raw) = BASE64_STANDARD.decode(encoded) else {
            continue;
        };
        let Ok(key): std::result::Result<[u8; 32], _> = raw.as_slice().try_into() else {
            continue;
        };
        targets.push((device_id.to_string(), key));
    }

    if targets.len() < 2 {
        // Only ourselves: nothing to admit.
        return Ok(Vec::new());
    }

    let next_epoch = session.client.current_epoch()?.unwrap_or(0) + 1;
    let dek = Dek::generate()?;
    let wraps = targets
        .iter()
        .map(|(device_id, key)| Ok((device_id.clone(), dek.wrap_to(key)?)))
        .collect::<Result<Vec<_>>>()?;

    session.client.publish_epoch(next_epoch, &wraps)?;
    session.tracker.add_dek(next_epoch, dek)?;
    session.persist_keys()?;

    // Die neue Epoche allein macht ein frisch aufgenommenes Gerät noch nicht
    // sehend: Alles, was vorher geschrieben wurde, steckt unter älteren Epochen.
    // Also jede Epoche, die dieses Gerät besitzt, für jedes Ziel versiegeln. Der
    // Server nimmt Doppelte hin, ohne etwas zu überschreiben -- das darf also
    // ruhig bei jedem Freischalten laufen.
    let mut backfill: Vec<(i64, String, Vec<u8>)> = Vec::new();
    for (device_id, key) in &targets {
        for (epoch, wrapped) in session.tracker.wrap_all_to(key)? {
            backfill.push((epoch, device_id.clone(), wrapped));
        }
    }
    if !backfill.is_empty() {
        session.client.publish_wraps(&backfill)?;
    }

    Ok(targets.into_iter().map(|(id, _)| id).collect())
}
