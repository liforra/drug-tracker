//! End-to-end lifecycle over the real HTTP surface.
//!
//! Drives the router directly rather than binding a socket, so the whole enrol → sync →
//! revoke path runs deterministically. What these assert is the set of promises the
//! design makes: the server never sees plaintext, a revoked device is told so in a way
//! it can act on, and its key share is destroyed rather than merely flagged.

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::prelude::*;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

use tracker_server::{api, db, enroll};

/// A client-side device: the keys the server only ever sees the public half of.
struct TestDevice {
    signing_key: SigningKey,
    device_id: String,
    token: String,
}

fn build() -> (Router, Arc<Mutex<rusqlite::Connection>>) {
    let conn = db::open_in_memory().unwrap();
    conn.execute("INSERT INTO accounts (id, created_at) VALUES ('primary', 0)", [])
        .unwrap();
    let db = Arc::new(Mutex::new(conn));
    (api::router(api::AppState::new(db.clone())), db)
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

fn post(path: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn post_auth(path: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get_auth(path: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// Enrol a device: claim an invite with fresh keys, then authenticate.
async fn enrol(app: &Router, code: &str, name: &str) -> TestDevice {
    let signing_key = SigningKey::from_bytes(&rand_bytes());
    let ed_pub = BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes());
    // Stand-in for a real X25519 key; the server only relays it.
    let x_pub = BASE64_STANDARD.encode([7u8; 32]);

    let (status, claimed) = call(
        app,
        post(
            "/v1/enroll/claim",
            json!({ "code": code, "display_name": name,
                    "ed25519_pub": ed_pub, "x25519_pub": x_pub }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "claim failed: {claimed}");
    let device_id = claimed["device_id"].as_str().unwrap().to_string();

    let token = authenticate(app, &device_id, &signing_key).await.expect("auth");
    TestDevice { signing_key, device_id, token }
}

/// Challenge-response. Returns None if the server refuses, which is what a revoked
/// device sees.
async fn authenticate(app: &Router, device_id: &str, key: &SigningKey) -> Option<String> {
    let (status, challenge) =
        call(app, post("/v1/auth/challenge", json!({ "device_id": device_id }))).await;
    if status != StatusCode::OK {
        return None;
    }
    let nonce = challenge["nonce"].as_str().unwrap();
    let signature = BASE64_URL_SAFE_NO_PAD.encode(key.sign(nonce.as_bytes()).to_bytes());

    let (status, verified) = call(
        app,
        post("/v1/auth/verify", json!({ "nonce": nonce, "signature": signature })),
    )
    .await;
    if status != StatusCode::OK {
        return None;
    }
    Some(verified["token"].as_str().unwrap().to_string())
}

fn rand_bytes() -> [u8; 32] {
    use rand::TryRngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut buf).unwrap();
    buf
}

async fn bootstrap_code(db: &Arc<Mutex<rusqlite::Connection>>) -> String {
    let conn = db.lock().unwrap();
    enroll::create_invite(&conn, "primary", None).unwrap().0
}

#[tokio::test]
async fn a_device_enrols_syncs_and_is_revoked() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;
    let phone = enrol(&app, &code, "phone").await;

    // --- the device can take a lease -------------------------------------------
    let (status, lease) = call(&app, post_auth("/v1/lease/acquire", &phone.token, json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    let share = lease["key_share"].as_str().unwrap().to_string();
    assert_eq!(BASE64_STANDARD.decode(&share).unwrap().len(), 32);
    assert_eq!(lease["ttl_secs"].as_i64().unwrap(), 24 * 3600);

    // --- it pushes sealed records ----------------------------------------------
    let (status, pushed) = call(
        &app,
        post_auth(
            "/v1/events",
            &phone.token,
            json!({ "events": [
                { "event_id": "01J8SESSIONSTART", "epoch": 1,
                  "nonce": BASE64_STANDARD.encode([1u8; 24]),
                  "ciphertext": BASE64_STANDARD.encode(b"sealed-session-started") },
            ]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "push failed: {pushed}");
    assert_eq!(pushed["accepted"].as_u64().unwrap(), 1);

    // --- and reads them back ----------------------------------------------------
    let (status, pulled) = call(&app, get_auth("/v1/events?since=0", &phone.token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(pulled["events"].as_array().unwrap().len(), 1);
    assert_eq!(pulled["events"][0]["event_id"], "01J8SESSIONSTART");

    // --- revocation -------------------------------------------------------------
    // force=true because this is the account's only device; the unforced path is
    // guarded and covered in hardening.rs.
    let (status, _) = call(
        &app,
        post_auth(
            &format!("/v1/devices/{}/revoke?force=true", phone.device_id),
            &phone.token,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The existing token dies with the device: revocation drops it outright, so the
    // bearer is no longer recognised at all.
    let (status, _) = call(&app, get_auth("/v1/events?since=0", &phone.token)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a token issued before revocation must stop working immediately"
    );

    // Re-authenticating fails too, and says why: this flag is what triggers the wipe.
    let (status, err) =
        call(&app, post("/v1/auth/challenge", json!({ "device_id": phone.device_id }))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(err["revoked"], json!(true), "the client must be able to tell revoked apart");
    assert!(authenticate(&app, &phone.device_id, &phone.signing_key).await.is_none());
}

#[tokio::test]
async fn revocation_destroys_the_key_share_not_just_a_flag() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;
    let phone = enrol(&app, &code, "phone").await;
    call(&app, post_auth("/v1/lease/acquire", &phone.token, json!({}))).await;

    {
        let conn = db.lock().unwrap();
        let share: Option<Vec<u8>> = conn
            .query_row("SELECT key_share FROM devices WHERE id = ?1", [&phone.device_id], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(share.is_some(), "precondition: a share exists");
    }

    call(
        &app,
        post_auth(
            &format!("/v1/devices/{}/revoke?force=true", phone.device_id),
            &phone.token,
            json!({}),
        ),
    )
    .await;

    let conn = db.lock().unwrap();
    let share: Option<Vec<u8>> = conn
        .query_row("SELECT key_share FROM devices WHERE id = ?1", [&phone.device_id], |r| r.get(0))
        .unwrap();
    assert!(
        share.is_none(),
        "the share must be gone from storage -- a flag alone would be reversible"
    );
}

#[tokio::test]
async fn the_two_phase_rotation_survives_a_crash_before_commit() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;
    let phone = enrol(&app, &code, "phone").await;

    let (_, first) = call(&app, post_auth("/v1/lease/acquire", &phone.token, json!({}))).await;
    let original = first["key_share"].as_str().unwrap().to_string();

    let (_, rotated) = call(&app, post_auth("/v1/lease/rotate", &phone.token, json!({}))).await;
    assert_eq!(rotated["key_share"], json!(original), "old share stays valid pre-commit");
    let pending = rotated["key_share_pending"].as_str().unwrap().to_string();
    assert_ne!(pending, original);

    // Simulate the client dying here: it never sent the commit. On restart it acquires
    // again and must still be offered both, because we cannot know which wrapper it
    // managed to write.
    let (_, recovered) = call(&app, post_auth("/v1/lease/acquire", &phone.token, json!({}))).await;
    assert_eq!(recovered["key_share"], json!(original));
    assert_eq!(recovered["key_share_pending"], json!(pending));

    // After a successful commit the superseded share is dropped for good.
    call(&app, post_auth("/v1/lease/commit", &phone.token, json!({}))).await;
    let (_, settled) = call(&app, post_auth("/v1/lease/acquire", &phone.token, json!({}))).await;
    assert_eq!(settled["key_share"], json!(pending));
    assert!(settled["key_share_pending"].is_null());
}

#[tokio::test]
async fn a_second_device_sees_the_first_devices_records() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;
    let phone = enrol(&app, &code, "phone").await;

    // The phone invites the laptop; only an enrolled device can mint a code.
    let (status, invite) =
        call(&app, post_auth("/v1/enroll/invite", &phone.token, json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    let laptop = enrol(&app, invite["code"].as_str().unwrap(), "laptop").await;

    // A session opened on the phone...
    call(
        &app,
        post_auth(
            "/v1/events",
            &phone.token,
            json!({ "events": [{ "event_id": "01J8START", "epoch": 1,
                                 "nonce": BASE64_STANDARD.encode([1u8; 24]),
                                 "ciphertext": BASE64_STANDARD.encode(b"started") }]}),
        ),
    )
    .await;

    // ...is visible to the laptop, which can close it. The end time is the laptop's to
    // record; the server neither knows nor cares what either blob means.
    let (status, pulled) = call(&app, get_auth("/v1/events?since=0", &laptop.token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(pulled["events"].as_array().unwrap().len(), 1);

    let (status, _) = call(
        &app,
        post_auth(
            "/v1/events",
            &laptop.token,
            json!({ "events": [{ "event_id": "01J8END", "epoch": 1,
                                 "nonce": BASE64_STANDARD.encode([2u8; 24]),
                                 "ciphertext": BASE64_STANDARD.encode(b"ended") }]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, phone_view) = call(&app, get_auth("/v1/events?since=0", &phone.token)).await;
    assert_eq!(
        phone_view["events"].as_array().unwrap().len(),
        2,
        "both devices converge on the same log"
    );
}

#[tokio::test]
async fn the_server_stores_no_consumption_timestamp() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;
    let phone = enrol(&app, &code, "phone").await;

    call(
        &app,
        post_auth(
            "/v1/events",
            &phone.token,
            json!({ "events": [{ "event_id": "01J8X", "epoch": 1,
                                 "nonce": BASE64_STANDARD.encode([1u8; 24]),
                                 "ciphertext": BASE64_STANDARD.encode(b"opaque") }]}),
        ),
    )
    .await;

    // The events table has exactly one time column and it is the arrival time. If a
    // consumption timestamp ever appears here in plaintext, this test should fail.
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare("SELECT name FROM pragma_table_info('events')").unwrap();
    let columns: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let time_columns: Vec<&String> =
        columns.iter().filter(|c| c.contains("_at") || c.contains("time")).collect();
    assert_eq!(
        time_columns,
        vec!["received_at"],
        "the only time the server may record is when the blob arrived"
    );
}

#[tokio::test]
async fn a_retried_push_does_not_duplicate() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;
    let phone = enrol(&app, &code, "phone").await;

    let batch = json!({ "events": [{ "event_id": "01J8SAME", "epoch": 1,
                                     "nonce": BASE64_STANDARD.encode([1u8; 24]),
                                     "ciphertext": BASE64_STANDARD.encode(b"once") }]});
    for _ in 0..3 {
        let (status, _) = call(&app, post_auth("/v1/events", &phone.token, batch.clone())).await;
        assert_eq!(status, StatusCode::OK);
    }

    let (_, pulled) = call(&app, get_auth("/v1/events?since=0", &phone.token)).await;
    assert_eq!(pulled["events"].as_array().unwrap().len(), 1, "flaky networks must be safe");
}

#[tokio::test]
async fn an_unenrolled_device_cannot_join_or_read() {
    let (app, _db) = build();
    let stranger = SigningKey::from_bytes(&rand_bytes());

    // No invite code, no entry.
    let (status, _) = call(
        &app,
        post(
            "/v1/enroll/claim",
            json!({ "code": "AAAAAAAAAA", "display_name": "rogue",
                    "ed25519_pub": BASE64_STANDARD.encode(stranger.verifying_key().to_bytes()),
                    "x25519_pub": BASE64_STANDARD.encode([9u8; 32]) }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // No token, no records.
    let (status, _) = call(
        &app,
        Request::builder().uri("/v1/events?since=0").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
