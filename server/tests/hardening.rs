//! End-to-end checks on the three hardening layers: DEK rotation, the encrypting
//! request tunnel, and the write-only audit log.
//!
//! These are the tests that actually verify the security claims. The unit tests confirm
//! each piece behaves; these confirm the pieces together do what was promised.

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
use x25519_dalek::StaticSecret;

use tracker_core::crypto;
use tracker_server::{api, audit, db, enroll, tunnel};

struct TestDevice {
    device_id: String,
    token: String,
}

fn build() -> (Router, Arc<Mutex<rusqlite::Connection>>) {
    let conn = db::open_in_memory().unwrap();
    conn.execute("INSERT INTO accounts (id, created_at) VALUES ('primary', 0)", [])
        .unwrap();
    tunnel::load_or_create(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));
    (api::router(api::AppState::new(db.clone())), db)
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

async fn call_raw(app: &Router, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = app.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, bytes.to_vec())
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

fn rand32() -> [u8; 32] {
    use rand::TryRngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut buf).unwrap();
    buf
}

async fn enrol(app: &Router, code: &str, name: &str, audit_pub: Option<&[u8]>) -> TestDevice {
    let signing_key = SigningKey::from_bytes(&rand32());
    let mut body = json!({
        "code": code,
        "display_name": name,
        "ed25519_pub": BASE64_STANDARD.encode(signing_key.verifying_key().to_bytes()),
        "x25519_pub": BASE64_STANDARD.encode(rand32()),
    });
    if let Some(key) = audit_pub {
        body["audit_pub"] = json!(BASE64_STANDARD.encode(key));
    }

    let (status, claimed) = call(app, post("/v1/enroll/claim", body)).await;
    assert_eq!(status, StatusCode::OK, "claim failed: {claimed}");
    let device_id = claimed["device_id"].as_str().unwrap().to_string();

    let (_, challenge) =
        call(app, post("/v1/auth/challenge", json!({ "device_id": device_id }))).await;
    let nonce = challenge["nonce"].as_str().unwrap();
    let signature = BASE64_URL_SAFE_NO_PAD.encode(signing_key.sign(nonce.as_bytes()).to_bytes());
    let (_, verified) = call(
        app,
        post("/v1/auth/verify", json!({ "nonce": nonce, "signature": signature })),
    )
    .await;

    TestDevice { device_id, token: verified["token"].as_str().unwrap().to_string() }
}

async fn bootstrap_code(db: &Arc<Mutex<rusqlite::Connection>>) -> String {
    let conn = db.lock().unwrap();
    enroll::bootstrap_invite(&conn, "primary").unwrap().0
}

// ------------------------------------------------------------------ DEK rotation

#[tokio::test]
async fn rotation_after_revocation_cuts_the_device_out_of_future_epochs() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;
    let phone = enrol(&app, &code, "phone", None).await;

    let (_, invite) = call(&app, post_auth("/v1/enroll/invite", &phone.token, json!({}))).await;
    let laptop = enrol(&app, invite["code"].as_str().unwrap(), "laptop", None).await;

    // Epoch 1 goes to both devices.
    let (status, published) = call(
        &app,
        post_auth(
            "/v1/deks",
            &phone.token,
            json!({ "epoch": 1, "wraps": [
                { "device_id": phone.device_id, "wrapped_dek": BASE64_STANDARD.encode(b"dek1-phone") },
                { "device_id": laptop.device_id, "wrapped_dek": BASE64_STANDARD.encode(b"dek1-laptop") },
            ]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "publish failed: {published}");
    assert!(published["uncovered"].as_array().unwrap().is_empty());

    let (_, laptop_keys) = call(&app, get_auth("/v1/deks", &laptop.token)).await;
    assert_eq!(laptop_keys.as_array().unwrap().len(), 1, "laptop holds epoch 1");

    // --- the laptop is lost, the phone revokes it -------------------------------
    call(
        &app,
        post_auth(&format!("/v1/devices/{}/revoke", laptop.device_id), &phone.token, json!({})),
    )
    .await;

    // Trying to keep it in the new epoch is refused by the server.
    let (status, refused) = call(
        &app,
        post_auth(
            "/v1/deks",
            &phone.token,
            json!({ "epoch": 2, "wraps": [
                { "device_id": phone.device_id, "wrapped_dek": BASE64_STANDARD.encode(b"dek2-phone") },
                { "device_id": laptop.device_id, "wrapped_dek": BASE64_STANDARD.encode(b"dek2-laptop") },
            ]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "must refuse to re-admit: {refused}");

    // Sealing to the phone alone succeeds and becomes the current epoch.
    let (status, _) = call(
        &app,
        post_auth(
            "/v1/deks",
            &phone.token,
            json!({ "epoch": 2, "wraps": [
                { "device_id": phone.device_id, "wrapped_dek": BASE64_STANDARD.encode(b"dek2-phone") },
            ]}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, current) = call(&app, get_auth("/v1/deks/current", &phone.token)).await;
    assert_eq!(current["epoch"], json!(2));

    // The revoked device holds nothing on the server any more.
    let conn = db.lock().unwrap();
    let remaining: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM dek_wraps WHERE device_id = ?1",
            [&laptop.device_id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(remaining, 0, "a revoked device keeps no sealed keys here");
}

#[tokio::test]
async fn a_device_can_collect_every_epoch_it_is_entitled_to() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;
    let phone = enrol(&app, &code, "phone", None).await;

    for epoch in 1..=3 {
        call(
            &app,
            post_auth(
                "/v1/deks",
                &phone.token,
                json!({ "epoch": epoch, "wraps": [
                    { "device_id": phone.device_id,
                      "wrapped_dek": BASE64_STANDARD.encode(format!("dek{epoch}")) },
                ]}),
            ),
        )
        .await;
    }

    // Reading history needs every epoch, not just the newest.
    let (_, all) = call(&app, get_auth("/v1/deks", &phone.token)).await;
    assert_eq!(all.as_array().unwrap().len(), 3);

    let (_, recent) = call(&app, get_auth("/v1/deks?since_epoch=3", &phone.token)).await;
    assert_eq!(recent.as_array().unwrap().len(), 1, "a caught-up device skips what it has");
}

// ----------------------------------------------------------------- the tunnel

#[tokio::test]
async fn a_request_through_the_tunnel_is_opaque_on_the_wire() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;
    let phone = enrol(&app, &code, "phone", None).await;

    let server_pub: [u8; 32] = {
        let conn = db.lock().unwrap();
        *tunnel::load(&conn).unwrap().public.as_bytes()
    };

    // Push an event through the tunnel rather than the plain route.
    let inner = json!({
        "method": "POST",
        "path": "/v1/events",
        "authorization": format!("Bearer {}", phone.token),
        "body": json!({ "events": [{
            "event_id": "01J8TUNNELLED", "epoch": 1,
            "nonce": BASE64_STANDARD.encode([1u8; 24]),
            "ciphertext": BASE64_STANDARD.encode(b"sealed") }]}).to_string(),
    })
    .to_string();

    let sealed = tunnel::client::seal_request(&server_pub, inner.as_bytes()).unwrap();

    // Nothing recognisable survives into the bytes that cross the wire.
    for needle in [b"/v1/events".as_slice(), b"Bearer".as_slice(), b"01J8TUNNELLED".as_slice()] {
        assert!(
            !sealed.envelope.windows(needle.len()).any(|w| w == needle),
            "the envelope leaked {:?}",
            String::from_utf8_lossy(needle)
        );
    }

    let (status, response) = call_raw(
        &app,
        Request::builder()
            .method("POST")
            .uri("/v1/tunnel")
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(Body::from(sealed.envelope.clone()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let plaintext = tunnel::client::open_response(&sealed.reply_key, &response).unwrap();
    let decoded: Value = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(decoded["status"], json!(200));

    let inner_body: Value = serde_json::from_str(decoded["body"].as_str().unwrap()).unwrap();
    assert_eq!(inner_body["accepted"], json!(1));

    // The record really did land.
    let (_, pulled) = call(&app, get_auth("/v1/events?since=0", &phone.token)).await;
    assert_eq!(pulled["events"][0]["event_id"], "01J8TUNNELLED");
}

#[tokio::test]
async fn an_impostor_holding_a_valid_certificate_still_learns_nothing() {
    // A proxy that terminates TLS, or anyone with a certificate the client's TLS stack
    // accepts, is modelled here as a party with a different X25519 key.
    let (app, db) = build();
    let real_pub: [u8; 32] = {
        let conn = db.lock().unwrap();
        *tunnel::load(&conn).unwrap().public.as_bytes()
    };

    let other = db::open_in_memory().unwrap();
    let impostor = tunnel::load_or_create(&other).unwrap();
    assert_ne!(&real_pub, impostor.public.as_bytes());

    // The client pins the real key, so an envelope it produces is useless to the impostor.
    let sealed = tunnel::client::seal_request(&real_pub, b"{\"method\":\"GET\"}").unwrap();
    let envelope = tunnel::Envelope::parse(&sealed.envelope).unwrap();
    assert!(tunnel::open_request(&impostor, &envelope).is_err());

    // And an envelope sealed to the impostor is rejected by the real server, so a
    // downgrade attempt fails loudly rather than silently.
    let to_impostor =
        tunnel::client::seal_request(impostor.public.as_bytes(), b"{\"method\":\"GET\"}").unwrap();
    let (status, _) = call_raw(
        &app,
        Request::builder()
            .method("POST")
            .uri("/v1/tunnel")
            .body(Body::from(to_impostor.envelope))
            .unwrap(),
    )
    .await;
    assert!(status.is_client_error(), "the real server must reject it, got {status}");
}

#[tokio::test]
async fn the_tunnel_hides_whether_a_request_succeeded() {
    let (app, db) = build();
    let server_pub: [u8; 32] = {
        let conn = db.lock().unwrap();
        *tunnel::load(&conn).unwrap().public.as_bytes()
    };

    // An unauthenticated inner request: rejected inside, but indistinguishable outside.
    let inner = json!({ "method": "GET", "path": "/v1/events?since=0" }).to_string();
    let sealed = tunnel::client::seal_request(&server_pub, inner.as_bytes()).unwrap();

    let (status, response) = call_raw(
        &app,
        Request::builder()
            .method("POST")
            .uri("/v1/tunnel")
            .body(Body::from(sealed.envelope))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the outer status must not reveal the inner one");

    let plaintext = tunnel::client::open_response(&sealed.reply_key, &response).unwrap();
    let decoded: Value = serde_json::from_slice(&plaintext).unwrap();
    assert_eq!(decoded["status"], json!(401), "the real answer is inside the ciphertext");
}

// -------------------------------------------------------------- the audit log

#[tokio::test]
async fn the_audit_log_is_written_by_the_server_and_readable_only_by_the_account() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;

    // The first device installs the account audit key.
    let audit_secret = StaticSecret::from(rand32());
    let audit_pub = x25519_dalek::PublicKey::from(&audit_secret);
    let phone = enrol(&app, &code, "phone", Some(audit_pub.as_bytes())).await;

    let (_, invite) = call(&app, post_auth("/v1/enroll/invite", &phone.token, json!({}))).await;
    let laptop = enrol(&app, invite["code"].as_str().unwrap(), "laptop", None).await;
    call(
        &app,
        post_auth(&format!("/v1/devices/{}/revoke", laptop.device_id), &phone.token, json!({})),
    )
    .await;

    let (status, entries) = call(&app, get_auth("/v1/audit?since=0", &phone.token)).await;
    assert_eq!(status, StatusCode::OK);
    let entries = entries.as_array().unwrap();
    assert!(entries.len() >= 3, "enrolment, invite and revocation should all be logged");

    // Nothing readable is stored: the device id does not appear in any blob.
    {
        let conn = db.lock().unwrap();
        let mut stmt = conn.prepare("SELECT sealed_entry FROM audit_log").unwrap();
        let blobs: Vec<Vec<u8>> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let needle = laptop.device_id.as_bytes();
        for blob in &blobs {
            assert!(
                !blob.windows(needle.len()).any(|w| w == needle),
                "a device id was readable in the stored audit blob"
            );
        }
    }

    // The account key opens them.
    let mut kinds = Vec::new();
    for entry in entries {
        let sealed = BASE64_STANDARD.decode(entry["sealed_entry"].as_str().unwrap()).unwrap();
        let opened = crypto::open_anonymous(&audit_secret, &sealed).unwrap();
        let parsed: audit::AuditEntry = serde_json::from_slice(&opened).unwrap();
        kinds.push(parsed.event);
    }

    assert!(
        kinds.iter().any(|e| matches!(
            e,
            audit::AuditEvent::DeviceRevoked { device_id, .. } if *device_id == laptop.device_id
        )),
        "the revocation must be in the log: {kinds:?}"
    );
    assert!(
        kinds
            .iter()
            .any(|e| matches!(e, audit::AuditEvent::DeviceEnrolled { display_name, .. }
                if display_name == "laptop")),
        "enrolment must be in the log"
    );
}

#[tokio::test]
async fn a_later_device_cannot_redirect_the_audit_log() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;

    let account_secret = StaticSecret::from(rand32());
    let account_pub = x25519_dalek::PublicKey::from(&account_secret);
    let phone = enrol(&app, &code, "phone", Some(account_pub.as_bytes())).await;

    // A second device tries to install its own key.
    let attacker_secret = StaticSecret::from(rand32());
    let attacker_pub = x25519_dalek::PublicKey::from(&attacker_secret);
    let (_, invite) = call(&app, post_auth("/v1/enroll/invite", &phone.token, json!({}))).await;
    enrol(&app, invite["code"].as_str().unwrap(), "rogue", Some(attacker_pub.as_bytes())).await;

    let (_, entries) = call(&app, get_auth("/v1/audit?since=0", &phone.token)).await;
    let sealed = BASE64_STANDARD
        .decode(entries[0]["sealed_entry"].as_str().unwrap())
        .unwrap();

    assert!(
        crypto::open_anonymous(&account_secret, &sealed).is_ok(),
        "the original key must still open the log"
    );
    assert!(
        crypto::open_anonymous(&attacker_secret, &sealed).is_err(),
        "a later device must not be able to point the log at itself"
    );
}

// ------------------------------------------------------------- rate limiting

#[tokio::test]
async fn repeated_challenges_for_one_device_are_throttled() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;
    let phone = enrol(&app, &code, "phone", None).await;

    // The burst allowance is per device id; enrolling already spent one.
    let mut throttled_at = None;
    for attempt in 0..40 {
        let (status, _) = call(
            &app,
            post("/v1/auth/challenge", json!({ "device_id": phone.device_id })),
        )
        .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            throttled_at = Some(attempt);
            break;
        }
    }
    assert!(throttled_at.is_some(), "an unauthenticated route must eventually push back");
}

#[tokio::test]
async fn throttling_one_device_does_not_lock_out_another() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;
    let phone = enrol(&app, &code, "phone", None).await;
    let (_, invite) = call(&app, post_auth("/v1/enroll/invite", &phone.token, json!({}))).await;
    let laptop = enrol(&app, invite["code"].as_str().unwrap(), "laptop", None).await;

    // Exhaust the phone's bucket.
    for _ in 0..40 {
        call(&app, post("/v1/auth/challenge", json!({ "device_id": phone.device_id }))).await;
    }
    let (phone_status, _) =
        call(&app, post("/v1/auth/challenge", json!({ "device_id": phone.device_id }))).await;
    assert_eq!(phone_status, StatusCode::TOO_MANY_REQUESTS);

    // The laptop is on its own bucket and must still be able to authenticate.
    let (laptop_status, _) =
        call(&app, post("/v1/auth/challenge", json!({ "device_id": laptop.device_id }))).await;
    assert_eq!(
        laptop_status,
        StatusCode::OK,
        "per-device buckets: one device under attack must not deny service to the rest"
    );
}

#[tokio::test]
async fn a_throttled_response_says_when_to_come_back() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;
    let phone = enrol(&app, &code, "phone", None).await;

    let mut retry_after = None;
    for _ in 0..40 {
        let response = app
            .clone()
            .oneshot(post("/v1/auth/challenge", json!({ "device_id": phone.device_id })))
            .await
            .unwrap();
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            retry_after = response
                .headers()
                .get(header::RETRY_AFTER)
                .map(|v| v.to_str().unwrap().to_string());
            break;
        }
    }
    let retry_after = retry_after.expect("the limiter should have tripped");
    assert!(
        retry_after.parse::<u64>().is_ok_and(|s| s >= 1),
        "Retry-After must be a usable number of seconds, got {retry_after:?}"
    );
}

// --------------------------------------------------- revoking the last device

#[tokio::test]
async fn the_last_device_cannot_be_revoked_by_accident() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;
    let phone = enrol(&app, &code, "phone", None).await;

    let (status, refused) = call(
        &app,
        post_auth(&format!("/v1/devices/{}/revoke", phone.device_id), &phone.token, json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "revoking the only device destroys the account");
    assert!(
        refused["error"].as_str().unwrap().contains("last active device"),
        "the refusal must explain itself: {refused}"
    );

    // Still usable afterwards: the refusal must not have half-applied.
    let (status, _) = call(&app, get_auth("/v1/events?since=0", &phone.token)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_last_device_can_still_be_revoked_deliberately() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;
    let phone = enrol(&app, &code, "phone", None).await;

    let (status, _) = call(
        &app,
        post_auth(
            &format!("/v1/devices/{}/revoke?force=true", phone.device_id),
            &phone.token,
            json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the panic button must still work");

    let (status, _) = call(&app, get_auth("/v1/events?since=0", &phone.token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoking_is_unguarded_while_another_device_remains() {
    let (app, db) = build();
    let code = bootstrap_code(&db).await;
    let phone = enrol(&app, &code, "phone", None).await;
    let (_, invite) = call(&app, post_auth("/v1/enroll/invite", &phone.token, json!({}))).await;
    let laptop = enrol(&app, invite["code"].as_str().unwrap(), "laptop", None).await;

    // The common case -- a lost device with others still enrolled -- needs no ceremony.
    let (status, _) = call(
        &app,
        post_auth(&format!("/v1/devices/{}/revoke", laptop.device_id), &phone.token, json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
