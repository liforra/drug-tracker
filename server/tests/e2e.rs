//! The whole stack, end to end, over a real socket.
//!
//! Two devices, the real HTTP server, the real encrypting tunnel, and the real client
//! facade. Everything else in the suite tests a layer; this tests that the layers fit.

use std::sync::{Arc, Mutex};

use tracker_core::{
    crypto::keys::{Dek, DeviceIdentity, RootKey},
    log::Event,
    store::Store,
    sync::{ServerConfig, SyncClient},
    tracker::Tracker,
};
use tracker_server::{api, db, enroll, tunnel};

/// Boot a server on an ephemeral port and return its base URL and pinned public key.
async fn spawn_server() -> (String, [u8; 32], Arc<Mutex<rusqlite::Connection>>) {
    let conn = db::open_in_memory().unwrap();
    conn.execute("INSERT INTO accounts (id, created_at) VALUES ('primary', 0)", []).unwrap();
    let server_pub = *tunnel::load_or_create(&conn).unwrap().public.as_bytes();

    let db = Arc::new(Mutex::new(conn));
    let app = api::router(api::AppState::new(db.clone()));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{addr}"), server_pub, db)
}

fn invite(db: &Arc<Mutex<rusqlite::Connection>>) -> String {
    let conn = db.lock().unwrap();
    enroll::bootstrap_invite(&conn, "primary").unwrap().0
}

struct Device {
    tracker: Tracker,
    client: SyncClient,
    id: String,
    identity: DeviceIdentity,
}

/// Enrol a device: claim a code, authenticate, and open an empty local store.
fn enrol(base_url: &str, server_pub: [u8; 32], code: &str, name: &str, audit_pub: Option<&[u8]>) -> Device {
    let identity = DeviceIdentity::generate().unwrap();
    let client =
        SyncClient::new(ServerConfig { base_url: base_url.to_string(), server_pub });

    let claimed = client
        .claim_invite(
            code,
            name,
            &identity.ed25519_public(),
            &identity.x25519_public(),
            audit_pub,
        )
        .unwrap();
    let device_id = claimed["device_id"].as_str().unwrap().to_string();

    client.authenticate(&device_id, &identity.ed25519).unwrap();

    let tracker = Tracker::open(Store::open_in_memory().unwrap(), Vec::new(), &device_id).unwrap();
    Device { tracker, client, id: device_id, identity }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_devices_share_one_log_through_the_encrypted_tunnel() {
    let (base_url, server_pub, db) = spawn_server().await;

    let root = RootKey::random().unwrap();
    let (_, audit_pub) = root.audit_keypair();

    // --- first device --------------------------------------------------------
    let code = invite(&db);
    let mut phone = tokio::task::spawn_blocking({
        let base_url = base_url.clone();
        move || enrol(&base_url, server_pub, &code, "phone", Some(audit_pub.as_bytes()))
    })
    .await
    .unwrap();

    // --- second device, invited by the first ---------------------------------
    let laptop_code = phone.client.create_invite().unwrap()["code"].as_str().unwrap().to_string();
    let mut laptop = tokio::task::spawn_blocking({
        let base_url = base_url.clone();
        move || enrol(&base_url, server_pub, &laptop_code, "laptop", None)
    })
    .await
    .unwrap();

    // --- the phone mints a data key and seals it to both devices -------------
    let dek = Dek::generate().unwrap();
    phone
        .client
        .publish_epoch(
            1,
            &[
                (phone.id.clone(), dek.wrap_to(&phone.identity.x25519_public()).unwrap()),
                (laptop.id.clone(), dek.wrap_to(&laptop.identity.x25519_public()).unwrap()),
            ],
        )
        .unwrap();

    for device in [&mut phone, &mut laptop] {
        let wraps = device.client.deks(0).unwrap();
        assert_eq!(wraps.len(), 1, "each device must receive its own sealed copy");
        let wrapped = base64_decode(&wraps[0].wrapped_dek);
        let key = Dek::unwrap_with(&device.identity.x25519, &wrapped).unwrap();
        device.tracker.add_dek(wraps[0].epoch, key).unwrap();
    }

    // --- the phone defines a variety and starts a session --------------------
    let product = phone
        .tracker
        .define_product("CUBA PEACH", "nicotine", "buccal_pouch", 10.4, Some(1800.0), Some("#F2994A".into()), None)
        .unwrap();
    let session = phone.tracker.start_session(&product).unwrap();

    let pushed = phone.tracker.sync(&phone.client).unwrap();
    assert_eq!(pushed.pushed, 2, "the product and the session both went up");

    // --- the laptop sees both without ever being told about them -------------
    let pulled = laptop.tracker.sync(&laptop.client).unwrap();
    assert_eq!(pulled.pulled, 2);
    assert_eq!(pulled.unreadable, 0);

    let products = laptop.tracker.state().active_products();
    assert_eq!(products.len(), 1, "the variety synced across");
    assert_eq!(products[0].name, "CUBA PEACH");
    assert_eq!(products[0].nominal_mg, 10.4);

    let open = laptop.tracker.state().open_sessions();
    assert_eq!(open.len(), 1, "the laptop knows a pouch is in right now");
    assert_eq!(open[0].id, session);

    // --- the laptop ends the session the phone started -----------------------
    laptop.tracker.end_session(&session).unwrap();
    laptop.tracker.sync(&laptop.client).unwrap();

    phone.tracker.sync(&phone.client).unwrap();
    assert!(
        phone.tracker.state().open_sessions().is_empty(),
        "ending on one device must clear it on the other"
    );
    assert!(phone.tracker.state().sessions[&session].ended_at.is_some());

    // --- the server learned nothing ------------------------------------------
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare("SELECT ciphertext FROM events").unwrap();
    let blobs: Vec<Vec<u8>> =
        stmt.query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap();
    assert_eq!(blobs.len(), 3, "product, start, end");
    for blob in &blobs {
        for needle in [b"CUBA".as_slice(), b"nicotine".as_slice(), b"session".as_slice()] {
            assert!(
                !blob.windows(needle.len()).any(|w| w == needle),
                "the server stored something readable: {:?}",
                String::from_utf8_lossy(needle)
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_device_is_told_so_and_wipes_itself() {
    let (base_url, server_pub, db) = spawn_server().await;

    let code = invite(&db);
    let mut phone = tokio::task::spawn_blocking({
        let base_url = base_url.clone();
        move || enrol(&base_url, server_pub, &code, "phone", None)
    })
    .await
    .unwrap();

    let laptop_code = phone.client.create_invite().unwrap()["code"].as_str().unwrap().to_string();
    let mut laptop = tokio::task::spawn_blocking({
        let base_url = base_url.clone();
        move || enrol(&base_url, server_pub, &laptop_code, "laptop", None)
    })
    .await
    .unwrap();

    let dek = Dek::generate().unwrap();
    phone
        .client
        .publish_epoch(
            1,
            &[
                (phone.id.clone(), dek.wrap_to(&phone.identity.x25519_public()).unwrap()),
                (laptop.id.clone(), dek.wrap_to(&laptop.identity.x25519_public()).unwrap()),
            ],
        )
        .unwrap();
    for device in [&mut phone, &mut laptop] {
        let wraps = device.client.deks(0).unwrap();
        let key = Dek::unwrap_with(&device.identity.x25519, &base64_decode(&wraps[0].wrapped_dek))
            .unwrap();
        device.tracker.add_dek(wraps[0].epoch, key).unwrap();
    }

    let product = phone
        .tracker
        .define_product("CUBA PEACH", "nicotine", "buccal_pouch", 10.4, None, None, None)
        .unwrap();
    phone.tracker.record(Event::SessionStarted {
        session_id: "s1".into(),
        product_id: product,
        started_at: chrono::Utc::now(),
    })
    .unwrap();
    phone.tracker.sync(&phone.client).unwrap();

    // The laptop is lost; the phone revokes it.
    phone.client.revoke(&laptop.id, false).unwrap();

    // The laptop learns this at its next sync, distinguishably from any other failure.
    let error = laptop.tracker.sync(&laptop.client).unwrap_err();
    let is_revoked = matches!(
        &error,
        tracker_core::tracker::TrackerError::Sync(e) if e.is_revoked()
    );
    assert!(is_revoked, "the client must be able to tell revocation apart: {error}");

    // And acts on it rather than waiting for the lease to lapse.
    laptop.tracker.lock_and_wipe().unwrap();
    assert!(laptop.tracker.is_locked());
    assert!(laptop.tracker.state().active_products().is_empty());
}

fn base64_decode(encoded: &str) -> Vec<u8> {
    use base64::prelude::*;
    BASE64_STANDARD.decode(encoded).unwrap()
}
