//! The API the Android app calls, expressed without any JNI in sight.
//!
//! Everything crosses the boundary as JSON. A binding generator would give nicer types,
//! but the surface here is a dozen calls and the JSON keeps the Kotlin side free of
//! generated code and the Rust side free of `jni` types outside one file.

use std::sync::Mutex;

use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracker_core::{
    crypto::keys::{Dek, DeviceIdentity, RootKey},
    levels,
    store::Store,
    sync::{ServerConfig, SyncClient},
    tracker::Tracker,
};

/// One process, one tracker. Android may recreate the Activity freely; the native side
/// stays put so unlocking does not happen on every rotation.
static INSTANCE: Mutex<Option<Instance>> = Mutex::new(None);

struct Instance {
    tracker: Tracker,
    client: SyncClient,
    identity: DeviceIdentity,
    device_secret: [u8; 32],
    lease_share: Vec<u8>,
    online: bool,
}

#[derive(Serialize, Deserialize)]
pub struct OpenRequest {
    pub data_dir: String,
    pub server_url: String,
    pub server_pub: String,
    pub device_id: String,
    /// Hex or base64 of the 96-byte identity blob held in the Android Keystore.
    pub identity: String,
    pub cached_lease: Option<String>,
    pub cached_lease_expires_at: Option<i64>,
}

/// Everything the home screen needs, in one call.
///
/// Deliberately one round trip: the first frame has to show the varieties and any live
/// session immediately, and three separate calls would mean three chances to render a
/// half-populated screen.
#[derive(Serialize)]
pub struct Snapshot {
    pub locked: bool,
    pub online: bool,
    pub pending: i64,
    pub products: Vec<ProductView>,
    pub open_session: Option<OpenSessionView>,
    pub nicotine_ng_ml: f64,
    /// ng/mL per minute. How a pouch feels tracks this far better than the level does.
    pub nicotine_rate_per_min: f64,
    pub cotinine_ng_ml: f64,
    pub today_count: usize,
    pub today_mg: f64,
    /// Relative to this person's own 90-day peak, not to any clinical scale. Null when
    /// there is too little history for a ratio to mean anything.
    pub tolerance_index: Option<f64>,
    /// What the curves were computed with. Shown so a default is visibly a default.
    pub body_mass_kg: f64,
    pub body_mass_is_default: bool,
}

#[derive(Serialize)]
pub struct ProductView {
    pub id: String,
    pub name: String,
    pub nominal_mg: f64,
    pub accent: Option<String>,
    /// How long this variety goes on releasing, in seconds. Null means it follows the
    /// substance model rather than stating its own figure.
    pub default_duration_secs: Option<f64>,
}

#[derive(Serialize)]
pub struct OpenSessionView {
    pub session_id: String,
    pub product_name: String,
    /// Epoch seconds. The UI ticks its own clock from this rather than asking us every
    /// second.
    pub started_at: i64,
    pub elapsed_secs: i64,
    /// Out of the mouth and resting: the session runs on, absorption does not.
    pub paused: bool,
    /// Contact time left before the pouch is spent, or null when the product has no
    /// release profile.
    pub release_left_secs: Option<i64>,
}

fn error(message: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": message.to_string() }).to_string()
}

fn ok(value: Value) -> String {
    json!({ "ok": true, "data": value }).to_string()
}

fn decode32(encoded: &str, what: &str) -> Result<[u8; 32], String> {
    let raw = BASE64_STANDARD
        .decode(encoded)
        .map_err(|e| format!("{what}: {e}"))?;
    raw.as_slice()
        .try_into()
        .map_err(|_| format!("{what} must be 32 bytes"))
}

/// Create this device's long-term keys. The caller stores the blob in the Android
/// Keystore, which is the whole reason the phone is the stronger of the two platforms:
/// there the device half of the storage key is hardware-bound and cannot be extracted.
pub fn generate_identity() -> String {
    match DeviceIdentity::generate() {
        Ok(identity) => {
            use rand::TryRngCore;
            let mut device_secret = [0u8; 32];
            if rand::rngs::OsRng
                .try_fill_bytes(&mut device_secret)
                .is_err()
            {
                return error("entropy source failed");
            }
            let mut blob = Vec::with_capacity(96);
            blob.extend_from_slice(&identity.x25519.to_bytes());
            blob.extend_from_slice(&identity.ed25519.to_bytes());
            blob.extend_from_slice(&device_secret);

            ok(json!({
                "identity": BASE64_STANDARD.encode(&blob),
                "x25519_pub": BASE64_STANDARD.encode(identity.x25519_public()),
                "ed25519_pub": BASE64_STANDARD.encode(identity.ed25519_public()),
            }))
        }
        Err(e) => error(e),
    }
}

fn split_identity(encoded: &str) -> Result<(DeviceIdentity, [u8; 32]), String> {
    let blob = BASE64_STANDARD.decode(encoded).map_err(|e| e.to_string())?;
    if blob.len() != 96 {
        return Err("identity blob must be 96 bytes".into());
    }
    let x: [u8; 32] = blob[0..32].try_into().unwrap();
    let e: [u8; 32] = blob[32..64].try_into().unwrap();
    let secret: [u8; 32] = blob[64..96].try_into().unwrap();
    Ok((DeviceIdentity::from_bytes(x, e), secret))
}

/// Claim an invite and become a device on the account.
pub fn enroll(request_json: &str) -> String {
    #[derive(Deserialize)]
    struct Request {
        server_url: String,
        server_pub: String,
        code: String,
        display_name: String,
        identity: String,
    }

    let request: Request = match serde_json::from_str(request_json) {
        Ok(r) => r,
        Err(e) => return error(e),
    };
    let server_pub = match decode32(&request.server_pub, "server_pub") {
        Ok(k) => k,
        Err(e) => return error(e),
    };
    let (identity, _) = match split_identity(&request.identity) {
        Ok(v) => v,
        Err(e) => return error(e),
    };

    let client = SyncClient::new(ServerConfig {
        base_url: request.server_url,
        server_pub,
    });

    // Only honoured for the account's first device; later ones send it and the server
    // keeps the key it already has.
    let root = match RootKey::random() {
        Ok(r) => r,
        Err(e) => return error(e),
    };
    let (_, audit_pub) = root.audit_keypair();

    let claimed = match client.claim_invite(
        &request.code,
        &request.display_name,
        &identity.ed25519_public(),
        &identity.x25519_public(),
        Some(audit_pub.as_bytes()),
    ) {
        Ok(v) => v,
        Err(e) => return error(e),
    };

    let Some(device_id) = claimed["device_id"].as_str() else {
        return error("server returned no device id");
    };
    if let Err(e) = client.authenticate(device_id, &identity.ed25519) {
        return error(e);
    }

    ok(json!({ "device_id": device_id }))
}

/// Authenticate, take a lease, unlock the records.
pub fn open(request_json: &str) -> String {
    let request: OpenRequest = match serde_json::from_str(request_json) {
        Ok(r) => r,
        Err(e) => return error(e),
    };
    let server_pub = match decode32(&request.server_pub, "server_pub") {
        Ok(k) => k,
        Err(e) => return error(e),
    };
    let (identity, device_secret) = match split_identity(&request.identity) {
        Ok(v) => v,
        Err(e) => return error(e),
    };

    let client = SyncClient::new(ServerConfig {
        base_url: request.server_url.clone(),
        server_pub,
    });

    // Try the network, but never let start-up depend on it: the home screen has to come
    // up on the tube with no signal exactly as it does at home.
    let mut online = false;
    let mut lease_share = request
        .cached_lease
        .as_deref()
        .filter(|_| {
            request
                .cached_lease_expires_at
                .is_some_and(|expires| chrono::Utc::now().timestamp() < expires)
        })
        .and_then(|encoded| BASE64_STANDARD.decode(encoded).ok());
    let mut lease_expires = request.cached_lease_expires_at.unwrap_or(0);

    if client
        .authenticate(&request.device_id, &identity.ed25519)
        .is_ok()
    {
        match client.lease_acquire() {
            Ok(lease) => {
                if let Ok(share) = BASE64_STANDARD.decode(&lease.key_share) {
                    lease_share = Some(share);
                    lease_expires = lease.expires_at;
                    online = true;
                }
            }
            Err(e) if e.is_revoked() => return error("revoked"),
            Err(_) => {}
        }
    }

    let Some(lease_share) = lease_share else {
        return error("locked: no valid lease and the server is unreachable");
    };

    let store = match Store::open(
        std::path::Path::new(&request.data_dir)
            .join("records.db")
            .as_path(),
    ) {
        Ok(s) => s,
        Err(e) => return error(e),
    };
    let deks = store
        .load_deks(&device_secret, &lease_share)
        .unwrap_or_default();

    let mut tracker = match Tracker::open(store, deks, request.device_id.clone()) {
        Ok(t) => t,
        Err(e) => return error(e),
    };

    // A device that just enrolled has no key yet; collect whatever has been sealed to it.
    if tracker.is_locked()
        && online
        && let Ok(wraps) = client.deks(0)
    {
        for wrap in wraps {
            let Ok(sealed) = BASE64_STANDARD.decode(&wrap.wrapped_dek) else {
                continue;
            };
            if let Ok(dek) = Dek::unwrap_with(&identity.x25519, &sealed) {
                let _ = tracker.add_dek(wrap.epoch, dek);
            }
        }
        let _ = tracker.persist_deks(&device_secret, &lease_share);
    }

    let locked = tracker.is_locked();
    *INSTANCE.lock().unwrap() = Some(Instance {
        tracker,
        client,
        identity,
        device_secret,
        lease_share: lease_share.clone(),
        online,
    });

    ok(json!({
        "locked": locked,
        "online": online,
        "lease": BASE64_STANDARD.encode(&lease_share),
        "lease_expires_at": lease_expires,
    }))
}

fn with_instance<T>(f: impl FnOnce(&mut Instance) -> Result<T, String>) -> Result<T, String> {
    let mut guard = INSTANCE.lock().unwrap();
    let instance = guard.as_mut().ok_or_else(|| "not opened".to_string())?;
    f(instance)
}

fn build_snapshot(instance: &Instance) -> Snapshot {
    let state = instance.tracker.state();
    let now = chrono::Utc::now();
    // Same code path the laptop uses. Two implementations of "your nicotine level"
    // would be two answers to a question that has one.
    let curves = levels::build_at(state, now);

    Snapshot {
        locked: instance.tracker.is_locked(),
        online: instance.online,
        pending: instance.tracker.store().pending_count().unwrap_or(0),
        products: state
            .active_products()
            .into_iter()
            .map(|p| ProductView {
                id: p.id.clone(),
                name: p.name.clone(),
                nominal_mg: p.nominal_mg,
                accent: p.accent.clone(),
                default_duration_secs: p.default_duration_secs,
            })
            .collect(),
        open_session: state.open_sessions().first().map(|s| OpenSessionView {
            session_id: s.id.clone(),
            product_name: state
                .product(&s.product_id)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "Unbekannt".into()),
            started_at: s.started_at.timestamp(),
            elapsed_secs: (now - s.started_at).num_seconds().max(0),
            paused: s.is_paused(),
            release_left_secs: levels::remaining_release(state, s, now)
                .map(|left| left.num_seconds()),
        }),
        nicotine_ng_ml: curves.nicotine_at(now),
        nicotine_rate_per_min: curves.nicotine_rate_at(now),
        cotinine_ng_ml: curves.cotinine_at(now),
        today_count: levels::today_count(state),
        today_mg: levels::today_mg(state),
        tolerance_index: levels::tolerance_index(&curves, now),
        body_mass_kg: curves.subject.body_mass_kg,
        body_mass_is_default: state.body_mass_kg.is_none(),
    }
}

pub fn snapshot() -> String {
    match with_instance(|instance| Ok(build_snapshot(instance))) {
        Ok(snapshot) => ok(serde_json::to_value(snapshot).unwrap_or(Value::Null)),
        Err(e) => error(e),
    }
}

pub fn start_session(product_id: &str) -> String {
    let result = with_instance(|instance| {
        instance
            .tracker
            .start_session(product_id)
            .map_err(|e| e.to_string())?;
        // Best effort: a failed push is not a failed action, the record is already on
        // disk and the next sync will carry it.
        let _ = instance.tracker.sync(&instance.client);
        Ok(build_snapshot(instance))
    });
    match result {
        Ok(snapshot) => ok(serde_json::to_value(snapshot).unwrap_or(Value::Null)),
        Err(e) => error(e),
    }
}

pub fn end_session(session_id: &str) -> String {
    let result = with_instance(|instance| {
        instance
            .tracker
            .end_session(session_id)
            .map_err(|e| e.to_string())?;
        let _ = instance.tracker.sync(&instance.client);
        Ok(build_snapshot(instance))
    });
    match result {
        Ok(snapshot) => ok(serde_json::to_value(snapshot).unwrap_or(Value::Null)),
        Err(e) => error(e),
    }
}

/// Take the pouch out without ending the session: absorption stops, the session runs on.
pub fn pause_session(session_id: &str) -> String {
    let result = with_instance(|instance| {
        instance
            .tracker
            .pause_session(session_id)
            .map_err(|e| e.to_string())?;
        let _ = instance.tracker.sync(&instance.client);
        Ok(build_snapshot(instance))
    });
    match result {
        Ok(snapshot) => ok(serde_json::to_value(snapshot).unwrap_or(Value::Null)),
        Err(e) => error(e),
    }
}

pub fn resume_session(session_id: &str) -> String {
    let result = with_instance(|instance| {
        instance
            .tracker
            .resume_session(session_id)
            .map_err(|e| e.to_string())?;
        let _ = instance.tracker.sync(&instance.client);
        Ok(build_snapshot(instance))
    });
    match result {
        Ok(snapshot) => ok(serde_json::to_value(snapshot).unwrap_or(Value::Null)),
        Err(e) => error(e),
    }
}

/// Remove a session that should never have existed. Distinct from ending one, which
/// records a real consumption -- without this the only way to undo a mis-tap would be
/// to write a wrong record.
pub fn discard_session(session_id: &str) -> String {
    let result = with_instance(|instance| {
        instance
            .tracker
            .discard_session(session_id)
            .map_err(|e| e.to_string())?;
        let _ = instance.tracker.sync(&instance.client);
        Ok(build_snapshot(instance))
    });
    match result {
        Ok(snapshot) => ok(serde_json::to_value(snapshot).unwrap_or(Value::Null)),
        Err(e) => error(e),
    }
}

/// Hide a variety from the buttons.
///
/// Retiring, not deleting: the log is append-only, and sessions already recorded
/// against this variety still need it to compute their curves.
pub fn retire_product(product_id: &str) -> String {
    let result = with_instance(|instance| {
        instance
            .tracker
            .retire_product(product_id)
            .map_err(|e| e.to_string())?;
        let _ = instance.tracker.sync(&instance.client);
        Ok(build_snapshot(instance))
    });
    match result {
        Ok(snapshot) => ok(serde_json::to_value(snapshot).unwrap_or(Value::Null)),
        Err(e) => error(e),
    }
}

/// How long a variety goes on releasing. Brands differ enough that this is worth
/// setting per product rather than arguing about a single default.
pub fn set_product_duration(product_id: &str, minutes: f64) -> String {
    let result = with_instance(|instance| {
        instance
            .tracker
            .update_product(product_id, None, None, Some(minutes * 60.0), None, None)
            .map_err(|e| e.to_string())?;
        let _ = instance.tracker.sync(&instance.client);
        Ok(build_snapshot(instance))
    });
    match result {
        Ok(snapshot) => ok(serde_json::to_value(snapshot).unwrap_or(Value::Null)),
        Err(e) => error(e),
    }
}

/// Body mass scales every concentration in the app, because volume of distribution is
/// expressed per kilogram. It is the largest correctable error in the model and needs
/// no laboratory.
pub fn update_subject(body_mass_kg: Option<f64>, metabolism_factor: Option<f64>) -> String {
    let result = with_instance(|instance| {
        instance
            .tracker
            .update_subject(body_mass_kg, metabolism_factor)
            .map_err(|e| e.to_string())?;
        let _ = instance.tracker.sync(&instance.client);
        Ok(build_snapshot(instance))
    });
    match result {
        Ok(snapshot) => ok(serde_json::to_value(snapshot).unwrap_or(Value::Null)),
        Err(e) => error(e),
    }
}

/// Both curves sampled over a window, for the chart. Returned as parallel arrays rather
/// than objects: this crosses the JNI boundary as text, and a few hundred points of
/// `{"t":...,"n":...}` is a lot of punctuation to serialise and parse for nothing.
pub fn samples(from_secs: i64, to_secs: i64, steps: usize) -> String {
    let result = with_instance(|instance| {
        let state = instance.tracker.state();
        let from =
            chrono::DateTime::from_timestamp(from_secs, 0).ok_or_else(|| "bad from".to_string())?;
        let to =
            chrono::DateTime::from_timestamp(to_secs, 0).ok_or_else(|| "bad to".to_string())?;
        let curves = levels::build_at(state, to);
        let points = curves.samples(from, to, steps.clamp(2, 2000));
        Ok(json!({
            "t": points.iter().map(|p| p.0.timestamp()).collect::<Vec<_>>(),
            "nicotine": points.iter().map(|p| p.1).collect::<Vec<_>>(),
            "cotinine": points.iter().map(|p| p.2).collect::<Vec<_>>(),
        }))
    });
    match result {
        Ok(value) => ok(value),
        Err(e) => error(e),
    }
}

pub fn add_product(name: &str, nominal_mg: f64, accent: Option<String>) -> String {
    let result = with_instance(|instance| {
        instance
            .tracker
            .define_product(
                name,
                "nicotine",
                "buccal_pouch",
                nominal_mg,
                Some(1800.0),
                accent,
                None,
            )
            .map_err(|e| e.to_string())?;
        let _ = instance.tracker.sync(&instance.client);
        Ok(build_snapshot(instance))
    });
    match result {
        Ok(snapshot) => ok(serde_json::to_value(snapshot).unwrap_or(Value::Null)),
        Err(e) => error(e),
    }
}

pub fn sync() -> String {
    let result = with_instance(|instance| {
        match instance.tracker.sync(&instance.client) {
            Ok(_) => instance.online = true,
            Err(tracker_core::tracker::TrackerError::Sync(e)) if e.is_revoked() => {
                let _ = instance.tracker.lock_and_wipe();
                return Err("revoked".to_string());
            }
            Err(_) => instance.online = false,
        }
        // Rewrap under a fresh lease share while we are online anyway.
        if instance.online
            && let Ok(rotated) = instance.client.lease_rotate()
            && let Some(pending) = rotated.key_share_pending
            && let Ok(share) = BASE64_STANDARD.decode(&pending)
            && instance
                .tracker
                .persist_deks(&instance.device_secret, &share)
                .is_ok()
            && instance.client.lease_commit().is_ok()
        {
            instance.lease_share = share;
        }
        Ok(build_snapshot(instance))
    });
    match result {
        Ok(snapshot) => ok(serde_json::to_value(snapshot).unwrap_or(Value::Null)),
        Err(e) => error(e),
    }
}

/// The current lease share, so the app can cache it for an offline start.
pub fn lease_share() -> String {
    match with_instance(|instance| Ok(BASE64_STANDARD.encode(&instance.lease_share))) {
        Ok(share) => ok(json!({ "lease": share })),
        Err(e) => error(e),
    }
}

/// Publish a new data key sealed to every trusted device. Run on a device that already
/// holds one, to bring a newly enrolled phone or laptop into the fold.
pub fn approve_devices() -> String {
    let result = with_instance(|instance| {
        let listed = instance.client.devices().map_err(|e| e.to_string())?;
        let mut targets: Vec<(String, [u8; 32])> = Vec::new();
        for row in listed.as_array().map(Vec::as_slice).unwrap_or_default() {
            if !row["revoked_at"].is_null() {
                continue;
            }
            let (Some(id), Some(key)) = (row["device_id"].as_str(), row["x25519_pub"].as_str())
            else {
                continue;
            };
            if let Ok(bytes) = decode32(key, "x25519_pub") {
                targets.push((id.to_string(), bytes));
            }
        }
        if targets.len() < 2 {
            return Ok(0usize);
        }

        let next = instance
            .client
            .current_epoch()
            .map_err(|e| e.to_string())?
            .unwrap_or(0)
            + 1;
        let dek = Dek::generate().map_err(|e| e.to_string())?;
        let mut wraps = Vec::new();
        for (id, key) in &targets {
            wraps.push((id.clone(), dek.wrap_to(key).map_err(|e| e.to_string())?));
        }
        instance
            .client
            .publish_epoch(next, &wraps)
            .map_err(|e| e.to_string())?;
        instance
            .tracker
            .add_dek(next, dek)
            .map_err(|e| e.to_string())?;
        let _ = instance
            .tracker
            .persist_deks(&instance.device_secret, &instance.lease_share);

        // The new epoch alone leaves a freshly enrolled device blind to everything written
        // before it, which sits under older epochs. Seal every epoch this device holds for
        // every target too, as `snus approve` does; the server ignores duplicates, so this
        // is safe to run on every approval.
        let mut backfill: Vec<(i64, String, Vec<u8>)> = Vec::new();
        for (id, key) in &targets {
            for (epoch, wrapped) in instance
                .tracker
                .wrap_all_to(key)
                .map_err(|e| e.to_string())?
            {
                backfill.push((epoch, id.clone(), wrapped));
            }
        }
        if !backfill.is_empty() {
            instance
                .client
                .publish_wraps(&backfill)
                .map_err(|e| e.to_string())?;
        }
        Ok(targets.len())
    });
    match result {
        Ok(count) => ok(json!({ "devices": count })),
        Err(e) => error(e),
    }
}

/// Mint a one-time invite so another device can join the account.
///
/// Only the code and its expiry come from the server. The address and the pinned key are
/// already on this phone, so the app assembles the QR payload around them -- the same
/// `snus://enroll` shape `snus invite` prints on the laptop.
pub fn create_invite() -> String {
    let result =
        with_instance(|instance| instance.client.create_invite().map_err(|e| e.to_string()));
    match result {
        Ok(response) => match response["code"].as_str() {
            Some(code) => ok(json!({
                "code": code,
                "expires_at": response["expires_at"].as_i64().unwrap_or_default(),
            })),
            None => error("server returned no invite code"),
        },
        Err(e) => error(e),
    }
}

/// Mint the account's first data key and seed the starting variety.
pub fn bootstrap_account() -> String {
    let result = with_instance(|instance| {
        if instance
            .client
            .current_epoch()
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Ok(false);
        }
        let dek = Dek::generate().map_err(|e| e.to_string())?;
        instance
            .client
            .publish_epoch(
                1,
                &[(
                    instance.tracker.device_id().to_string(),
                    dek.wrap_to(&instance.identity.x25519_public())
                        .map_err(|e| e.to_string())?,
                )],
            )
            .map_err(|e| e.to_string())?;
        instance
            .tracker
            .add_dek(1, dek)
            .map_err(|e| e.to_string())?;
        instance
            .tracker
            .persist_deks(&instance.device_secret, &instance.lease_share)
            .map_err(|e| e.to_string())?;

        instance
            .tracker
            .define_product(
                "CUBA PEACH",
                "nicotine",
                "buccal_pouch",
                10.4,
                Some(1800.0),
                Some("#F2994A".into()),
                None,
            )
            .map_err(|e| e.to_string())?;
        let _ = instance.tracker.sync(&instance.client);
        Ok(true)
    });
    match result {
        Ok(seeded) => ok(json!({ "seeded": seeded })),
        Err(e) => error(e),
    }
}

pub fn close() -> String {
    *INSTANCE.lock().unwrap() = None;
    ok(Value::Null)
}
