//! HTTP surface.
//!
//! Every payload field that could describe consumption is base64 of ciphertext. The
//! server validates structure and authorisation, never content.

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::prelude::*;
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tower::ServiceExt;

use crate::{
    audit, auth, db, deks, enroll, lease,
    ratelimit::{self, RateLimiter},
    tunnel,
};

/// Bound on how many records one pull returns.
const MAX_PULL: i64 = 1000;
/// Bound on how many records one push carries.
const MAX_PUSH: usize = 500;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Connection>>,
    /// Shared with the tunnel routes so a caller cannot dodge a limit by switching
    /// between the plain and tunnelled path.
    pub limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn new(db: Arc<Mutex<Connection>>) -> Self {
        Self {
            db,
            limiter: Arc::new(RateLimiter::new()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    Auth(#[from] auth::AuthError),
    #[error("{0}")]
    Lease(#[from] lease::LeaseError),
    #[error("{0}")]
    Enroll(#[from] enroll::EnrollError),
    #[error("{0}")]
    Dek(#[from] deks::DekError),
    #[error("{0}")]
    Audit(#[from] audit::AuditError),
    #[error("{0}")]
    Tunnel(#[from] tunnel::TunnelError),
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("serialisation error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("{0}")]
    BadRequest(String),
    #[error("missing or malformed Authorization header")]
    NoToken,
    #[error("too many requests")]
    RateLimited { retry_after_secs: u64 },
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        use auth::AuthError as A;
        use enroll::EnrollError as E;
        use lease::LeaseError as L;

        let status = match &self {
            // A revoked device must be able to tell "you are revoked" apart from any
            // other failure -- that response is what triggers the local wipe.
            ApiError::Auth(A::Revoked) | ApiError::Lease(L::Revoked) => StatusCode::FORBIDDEN,
            ApiError::Auth(A::UnknownDevice | A::BadChallenge | A::BadSignature | A::Malformed)
            | ApiError::NoToken => StatusCode::UNAUTHORIZED,
            ApiError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            ApiError::Lease(L::UnknownDevice)
            | ApiError::Enroll(E::UnknownEnrollment | E::WrongAccount) => StatusCode::NOT_FOUND,
            // An envelope we cannot open is the caller's problem, not ours. Mapping it
            // to 500 would also mean every junk packet gets logged at error level,
            // which hands an attacker a cheap way to flood the log.
            ApiError::Enroll(E::BadInvite)
            | ApiError::BadRequest(_)
            | ApiError::Dek(_)
            | ApiError::Audit(audit::AuditError::KeyAlreadySet)
            | ApiError::Tunnel(tunnel::TunnelError::Malformed | tunnel::TunnelError::Crypto(_)) => {
                StatusCode::BAD_REQUEST
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        // Log the detail, return a shape the client can branch on without leaking
        // whether a device id merely exists.
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self, "request failed");
        }
        let revoked = matches!(
            &self,
            ApiError::Auth(A::Revoked) | ApiError::Lease(L::Revoked)
        );

        if let ApiError::RateLimited { retry_after_secs } = &self {
            return (
                status,
                [(header::RETRY_AFTER, retry_after_secs.to_string())],
                Json(ErrorBody {
                    error: self.to_string(),
                    revoked,
                }),
            )
                .into_response();
        }
        (
            status,
            Json(ErrorBody {
                error: self.to_string(),
                revoked,
            }),
        )
            .into_response()
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
    /// The client watches this flag: true means stop, wipe the local database, and do
    /// not retry.
    revoked: bool,
}

type ApiResult<T> = std::result::Result<Json<T>, ApiError>;

fn b64(bytes: &[u8]) -> String {
    BASE64_STANDARD.encode(bytes)
}

fn unb64(s: &str, field: &str) -> Result<Vec<u8>, ApiError> {
    BASE64_STANDARD
        .decode(s)
        .map_err(|_| ApiError::BadRequest(format!("{field} is not valid base64")))
}

fn bearer(headers: &HeaderMap) -> Result<String, ApiError> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned)
        .ok_or(ApiError::NoToken)
}

fn session(conn: &Connection, headers: &HeaderMap) -> Result<db::Device, ApiError> {
    Ok(auth::authenticate(conn, &bearer(headers)?)?)
}

fn throttle(limiter: &RateLimiter, key: &str, quota: ratelimit::Quota) -> Result<(), ApiError> {
    limiter
        .check(key, quota)
        .map_err(|denied| ApiError::RateLimited {
            retry_after_secs: denied.retry_after.as_secs().max(1),
        })
}

/// Build the full surface: the plain routes plus the encrypting tunnel in front of
/// them.
///
/// When `TRACKER_REQUIRE_TUNNEL` is set, the plain routes are not mounted at all and
/// everything must arrive through `/v1/tunnel`. That is the setting to use in front of
/// a reverse proxy: it makes it impossible for a client to skip the inner encryption by
/// accident, which is otherwise an easy mistake to make and a silent one.
pub fn router(state: AppState) -> Router {
    let inner = plain_router(state.clone());
    let require_tunnel = std::env::var("TRACKER_REQUIRE_TUNNEL")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false);

    let tunnel_routes = Router::new()
        .route("/v1/tunnel", post(tunnel_request))
        .route("/v1/tunnel/identity", get(tunnel_identity))
        .route("/v1/health", get(|| async { "ok" }))
        .with_state(TunnelState {
            db: state.db.clone(),
            inner: inner.clone(),
            limiter: state.limiter.clone(),
        });

    if require_tunnel {
        tracing::info!("tunnel required: plain routes are not mounted");
        tunnel_routes
    } else {
        tunnel_routes.merge(inner)
    }
}

fn plain_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/auth/challenge", post(auth_challenge))
        .route("/v1/auth/verify", post(auth_verify))
        .route("/v1/events", post(push_events).get(pull_events))
        .route("/v1/lease/acquire", post(lease_acquire))
        .route("/v1/lease/rotate", post(lease_rotate))
        .route("/v1/lease/commit", post(lease_commit))
        .route("/v1/devices", get(list_devices))
        .route("/v1/devices/{device_id}/revoke", post(revoke_device))
        .route("/v1/enroll/invite", post(create_invite))
        .route("/v1/enroll/claim", post(claim_invite))
        .route("/v1/enroll/pending", get(list_pending))
        .route("/v1/enroll/{enrollment_id}/deposit", post(deposit_wrapped))
        .route("/v1/enroll/{enrollment_id}", get(collect_wrapped))
        .route("/v1/deks", get(list_deks).post(publish_dek_epoch))
        .route("/v1/deks/wraps", post(backfill_dek_wraps))
        .route("/v1/deks/current", get(current_dek_epoch))
        .route("/v1/audit", get(read_audit))
        .with_state(state)
}

// ------------------------------------------------------------- request tunnel

#[derive(Clone)]
struct TunnelState {
    db: Arc<Mutex<Connection>>,
    inner: Router,
    limiter: Arc<RateLimiter>,
}

#[derive(Serialize)]
struct IdentityResponse {
    /// Pin this in the client. Everything the tunnel protects rests on the client
    /// checking that it talks to this key and no other.
    public_key: String,
    fingerprint: String,
}

/// Publish the server's tunnel public key.
///
/// Fetching it over an untrusted channel proves nothing -- an interceptor would simply
/// substitute its own. The value has to be confirmed out of band, which is what the
/// fingerprint printed by `bootstrap` is for.
async fn tunnel_identity(State(state): State<TunnelState>) -> ApiResult<IdentityResponse> {
    let conn = state.db.lock().unwrap();
    let identity = tunnel::load(&conn)?;
    Ok(Json(IdentityResponse {
        public_key: b64(identity.public.as_bytes()),
        fingerprint: identity.fingerprint(),
    }))
}

/// One request, carried inside the encrypted envelope.
#[derive(Deserialize)]
struct InnerRequest {
    method: String,
    path: String,
    #[serde(default)]
    authorization: Option<String>,
    #[serde(default)]
    body: Option<String>,
}

#[derive(Serialize)]
struct InnerResponse {
    status: u16,
    body: String,
}

/// Decrypt an envelope, run the request against the plain router, and encrypt the
/// answer. Whatever terminates TLS in front of us sees two opaque byte strings.
async fn tunnel_request(
    State(state): State<TunnelState>,
    envelope_bytes: Bytes,
) -> std::result::Result<Response, ApiError> {
    // Every tunnelled request costs an X25519 exchange before we know who is calling.
    throttle(&state.limiter, "tunnel", ratelimit::quotas::TUNNEL)?;

    let (plaintext, reply_key) = {
        let conn = state.db.lock().unwrap();
        let identity = tunnel::load(&conn)?;
        let envelope = tunnel::Envelope::parse(&envelope_bytes)?;
        tunnel::open_request(&identity, &envelope)?
    };

    let inner: InnerRequest = serde_json::from_slice(&plaintext)
        .map_err(|e| ApiError::BadRequest(format!("inner request is not valid JSON: {e}")))?;

    let mut builder = Request::builder()
        .method(inner.method.as_str())
        .uri(inner.path.as_str())
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = &inner.authorization {
        builder = builder.header(header::AUTHORIZATION, token);
    }
    let request = builder
        .body(Body::from(inner.body.unwrap_or_default()))
        .map_err(|e| ApiError::BadRequest(format!("inner request is malformed: {e}")))?;

    let response = state
        .inner
        .clone()
        .oneshot(request)
        .await
        .map_err(|e| ApiError::BadRequest(format!("inner routing failed: {e}")))?;

    let status = response.status().as_u16();
    let body = response
        .into_body()
        .collect()
        .await
        .map_err(|e| ApiError::BadRequest(format!("inner response was unreadable: {e}")))?
        .to_bytes();

    let payload = serde_json::to_vec(&InnerResponse {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    })?;
    let sealed = tunnel::seal_response(&reply_key, &payload)?;

    // Always 200 on the outside: the inner status travels inside the ciphertext, so an
    // observer cannot even tell a rejected request from an accepted one.
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        sealed,
    )
        .into_response())
}

// -------------------------------------------------------------- DEK epochs

#[derive(Serialize)]
struct DekWrap {
    epoch: i64,
    wrapped_dek: String,
}

/// Every epoch key sealed to the calling device. A device needs all of them to read
/// history, not just the newest.
async fn list_deks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DekQuery>,
) -> ApiResult<Vec<DekWrap>> {
    let conn = state.db.lock().unwrap();
    let device = session(&conn, &headers)?;
    let wraps = deks::wraps_for_device(&conn, &device.account_id, &device.id, query.since_epoch)?;
    Ok(Json(
        wraps
            .into_iter()
            .map(|w| DekWrap {
                epoch: w.epoch,
                wrapped_dek: b64(&w.wrapped_dek),
            })
            .collect(),
    ))
}

#[derive(Deserialize, Default)]
struct DekQuery {
    #[serde(default)]
    since_epoch: i64,
}

#[derive(Serialize)]
struct CurrentEpoch {
    epoch: Option<i64>,
}

async fn current_dek_epoch(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<CurrentEpoch> {
    let conn = state.db.lock().unwrap();
    let device = session(&conn, &headers)?;
    Ok(Json(CurrentEpoch {
        epoch: deks::current_epoch(&conn, &device.account_id)?,
    }))
}

#[derive(Deserialize)]
struct WrapInput {
    device_id: String,
    wrapped_dek: String,
}

#[derive(Deserialize)]
struct PublishEpochRequest {
    epoch: i64,
    wraps: Vec<WrapInput>,
}

#[derive(Deserialize)]
struct BackfillRequest {
    wraps: Vec<BackfillInput>,
}

#[derive(Deserialize)]
struct BackfillInput {
    epoch: i64,
    device_id: String,
    wrapped_dek: String,
}

#[derive(Serialize)]
struct BackfillResponse {
    added: usize,
}

#[derive(Serialize)]
struct PublishEpochResponse {
    epoch: i64,
    /// Active devices that were not sealed to. A non-empty list means the publisher
    /// locked someone out, which is almost always a client bug.
    uncovered: Vec<String>,
}

/// Hand an already-admitted device the keys for epochs that predate it.
///
/// Without this a second device reads nothing that was written before it joined: every
/// record is sealed under the epoch that was current when it was written, and the new
/// device only ever received the epoch minted at admission. The server cannot repair
/// that on its own -- it holds no key -- so an existing device has to pass the sealed
/// envelopes along.
async fn backfill_dek_wraps(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<BackfillRequest>,
) -> ApiResult<BackfillResponse> {
    let mut conn = state.db.lock().unwrap();
    let device = session(&conn, &headers)?;

    let mut wraps = Vec::with_capacity(req.wraps.len());
    for wrap in &req.wraps {
        wraps.push((
            wrap.epoch,
            wrap.device_id.clone(),
            unb64(&wrap.wrapped_dek, "wrapped_dek")?,
        ));
    }

    let added = deks::backfill_wraps(&mut conn, &device.account_id, &wraps)?;

    audit::record_best_effort(
        &conn,
        &device.account_id,
        audit::AuditEvent::WrapsBackfilled {
            by_device: device.id.clone(),
            added,
        },
    );

    Ok(Json(BackfillResponse { added }))
}

/// Publish a new DEK generation.
///
/// The key itself is minted on a client -- the server has no plaintext DEK and must not
/// acquire one. This is what makes revocation stick: after a device is cut off, a
/// remaining device rotates and seals only to those still trusted.
async fn publish_dek_epoch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PublishEpochRequest>,
) -> ApiResult<PublishEpochResponse> {
    let mut conn = state.db.lock().unwrap();
    let device = session(&conn, &headers)?;

    let mut wraps = Vec::with_capacity(req.wraps.len());
    for wrap in &req.wraps {
        wraps.push((
            wrap.device_id.clone(),
            unb64(&wrap.wrapped_dek, "wrapped_dek")?,
        ));
    }

    let published =
        deks::publish_epoch(&mut conn, &device.account_id, &device.id, req.epoch, &wraps)?;

    audit::record_best_effort(
        &conn,
        &device.account_id,
        audit::AuditEvent::EpochPublished {
            epoch: published.epoch,
            by_device: device.id.clone(),
            sealed_to: wraps.len(),
        },
    );
    if !published.uncovered.is_empty() {
        tracing::warn!(
            uncovered = ?published.uncovered,
            epoch = published.epoch,
            "new epoch was not sealed to every active device"
        );
    }

    Ok(Json(PublishEpochResponse {
        epoch: published.epoch,
        uncovered: published.uncovered,
    }))
}

// ------------------------------------------------------------------- audit

#[derive(Serialize)]
struct AuditEntryOut {
    seq: i64,
    sealed_entry: String,
}

/// Sealed audit entries. Only a device holding the account's audit key can read them --
/// this server cannot open its own log.
async fn read_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PullQuery>,
) -> ApiResult<Vec<AuditEntryOut>> {
    let conn = state.db.lock().unwrap();
    let device = session(&conn, &headers)?;
    let limit = query.limit.unwrap_or(MAX_PULL).clamp(1, MAX_PULL);
    let entries = audit::entries_since(&conn, &device.account_id, query.since, limit)?;
    Ok(Json(
        entries
            .into_iter()
            .map(|e| AuditEntryOut {
                seq: e.seq,
                sealed_entry: b64(&e.sealed_entry),
            })
            .collect(),
    ))
}

// ---------------------------------------------------------------- authentication

#[derive(Deserialize)]
struct ChallengeRequest {
    device_id: String,
}

#[derive(Serialize)]
struct ChallengeResponse {
    nonce: String,
}

async fn auth_challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> ApiResult<ChallengeResponse> {
    // Keyed on the device id: one device being hammered must not lock out the others.
    throttle(
        &state.limiter,
        &format!("challenge:{}", req.device_id),
        ratelimit::quotas::CHALLENGE,
    )?;
    let conn = state.db.lock().unwrap();
    let nonce = auth::issue_challenge(&conn, &req.device_id)?;
    Ok(Json(ChallengeResponse { nonce }))
}

#[derive(Deserialize)]
struct VerifyRequest {
    nonce: String,
    /// Ed25519 signature over the nonce bytes, base64url without padding.
    signature: String,
}

#[derive(Serialize)]
struct VerifyResponse {
    token: String,
    expires_at: i64,
    device_id: String,
    account_id: String,
}

async fn auth_verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> ApiResult<VerifyResponse> {
    throttle(&state.limiter, "verify", ratelimit::quotas::VERIFY)?;
    let conn = state.db.lock().unwrap();
    let s = auth::verify_challenge(&conn, &req.nonce, &req.signature)?;
    Ok(Json(VerifyResponse {
        token: s.token,
        expires_at: s.expires_at,
        device_id: s.device.id,
        account_id: s.device.account_id,
    }))
}

// ---------------------------------------------------------------------- sync

#[derive(Deserialize)]
struct PushEvent {
    /// Client-generated ULID. Makes retries idempotent and carries no meaning.
    event_id: String,
    epoch: i64,
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct PushRequest {
    events: Vec<PushEvent>,
}

#[derive(Serialize)]
struct PushResponse {
    cursor: i64,
    accepted: usize,
}

/// Accept a batch of sealed records.
///
/// Clients upload on a jittered schedule rather than on every consumption, because the
/// arrival time is the one timing signal we unavoidably observe. The real timestamps --
/// when a session started, when the user marked it over -- are inside the ciphertext
/// and are supplied by whichever client happens to record them.
async fn push_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PushRequest>,
) -> ApiResult<PushResponse> {
    if req.events.len() > MAX_PUSH {
        return Err(ApiError::BadRequest(format!(
            "at most {MAX_PUSH} events per push"
        )));
    }
    let mut conn = state.db.lock().unwrap();
    let device = session(&conn, &headers)?;

    let tx = conn.transaction()?;
    let mut cursor = 0i64;
    for event in &req.events {
        let nonce = unb64(&event.nonce, "nonce")?;
        let ciphertext = unb64(&event.ciphertext, "ciphertext")?;
        cursor = db::append_event(
            &tx,
            &device.account_id,
            &event.event_id,
            event.epoch,
            &nonce,
            &ciphertext,
        )?;
    }
    tx.commit()?;

    Ok(Json(PushResponse {
        cursor,
        accepted: req.events.len(),
    }))
}

#[derive(Deserialize)]
struct PullQuery {
    #[serde(default)]
    since: i64,
    limit: Option<i64>,
}

#[derive(Serialize)]
struct PulledEvent {
    seq: i64,
    event_id: String,
    epoch: i64,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize)]
struct PullResponse {
    events: Vec<PulledEvent>,
    cursor: i64,
    /// True when the batch hit the limit and another pull is worthwhile.
    more: bool,
}

async fn pull_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PullQuery>,
) -> ApiResult<PullResponse> {
    let conn = state.db.lock().unwrap();
    let device = session(&conn, &headers)?;
    let limit = query.limit.unwrap_or(MAX_PULL).clamp(1, MAX_PULL);

    let rows = db::events_since(&conn, &device.account_id, query.since, limit)?;
    let more = rows.len() as i64 == limit;
    let cursor = rows.last().map(|e| e.seq).unwrap_or(query.since);

    Ok(Json(PullResponse {
        events: rows
            .into_iter()
            .map(|e| PulledEvent {
                seq: e.seq,
                event_id: e.event_id,
                epoch: e.epoch,
                nonce: b64(&e.nonce),
                ciphertext: b64(&e.ciphertext),
            })
            .collect(),
        cursor,
        more,
    }))
}

// --------------------------------------------------------------------- leases

#[derive(Serialize)]
struct LeaseResponse {
    key_share: String,
    /// Present mid-rotation. The client tries this one too: it may have written the new
    /// wrapper and crashed before acknowledging.
    key_share_pending: Option<String>,
    expires_at: i64,
    ttl_secs: i64,
}

fn lease_response(l: lease::Lease) -> LeaseResponse {
    LeaseResponse {
        key_share: b64(&l.key_share),
        key_share_pending: l.key_share_pending.as_deref().map(b64),
        expires_at: l.expires_at,
        ttl_secs: lease::LEASE_TTL_SECS,
    }
}

async fn lease_acquire(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<LeaseResponse> {
    let conn = state.db.lock().unwrap();
    let device = session(&conn, &headers)?;
    let lease = lease::acquire(&conn, &device.id)?;
    audit::record_best_effort(
        &conn,
        &device.account_id,
        audit::AuditEvent::LeaseAcquired {
            device_id: device.id.clone(),
        },
    );
    Ok(Json(lease_response(lease)))
}

async fn lease_rotate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<LeaseResponse> {
    let conn = state.db.lock().unwrap();
    let device = session(&conn, &headers)?;
    let lease = lease::rotate(&conn, &device.id)?;
    audit::record_best_effort(
        &conn,
        &device.account_id,
        audit::AuditEvent::LeaseRotated {
            device_id: device.id.clone(),
        },
    );
    Ok(Json(lease_response(lease)))
}

#[derive(Serialize)]
struct Empty {}

async fn lease_commit(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Empty> {
    let conn = state.db.lock().unwrap();
    let device = session(&conn, &headers)?;
    lease::commit(&conn, &device.id)?;
    Ok(Json(Empty {}))
}

// -------------------------------------------------------------------- devices

#[derive(Serialize)]
struct DeviceSummary {
    device_id: String,
    display_name: String,
    created_at: i64,
    revoked_at: Option<i64>,
    lease_expires_at: Option<i64>,
    /// Fingerprint of the identity key, for out-of-band comparison by the user.
    fingerprint: String,
    /// Needed by a peer device to seal a new data key to this one. Public by nature;
    /// only devices of the same account can ask.
    x25519_pub: String,
}

async fn list_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Vec<DeviceSummary>> {
    let conn = state.db.lock().unwrap();
    let device = session(&conn, &headers)?;

    let mut stmt = conn.prepare(
        "SELECT id, display_name, created_at, revoked_at, lease_expires_at, ed25519_pub, x25519_pub
         FROM devices WHERE account_id = ?1 ORDER BY created_at ASC",
    )?;
    let rows = stmt.query_map([&device.account_id], |row| {
        let pubkey: Vec<u8> = row.get(5)?;
        let wrapping_key: Vec<u8> = row.get(6)?;
        Ok(DeviceSummary {
            device_id: row.get(0)?,
            display_name: row.get(1)?,
            created_at: row.get(2)?,
            revoked_at: row.get(3)?,
            lease_expires_at: row.get(4)?,
            fingerprint: fingerprint(&pubkey),
            x25519_pub: b64(&wrapping_key),
        })
    })?;
    Ok(Json(rows.collect::<Result<Vec<_>, _>>()?))
}

/// Short human-comparable rendering of a public key.
fn fingerprint(pubkey: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD
        .encode(pubkey)
        .chars()
        .take(12)
        .collect::<String>()
        .chars()
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

#[derive(Deserialize, Default)]
struct RevokeQuery {
    /// Required to revoke the last remaining device, because doing so destroys the
    /// account rather than merely securing it.
    #[serde(default)]
    force: bool,
}

async fn revoke_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Query(query): Query<RevokeQuery>,
) -> ApiResult<Empty> {
    let conn = state.db.lock().unwrap();
    let caller = session(&conn, &headers)?;

    let target = db::load_device(&conn, &device_id)?
        .ok_or(ApiError::Lease(lease::LeaseError::UnknownDevice))?;
    if target.account_id != caller.account_id {
        return Err(ApiError::Lease(lease::LeaseError::UnknownDevice));
    }

    // Revoking the last device is not a security action, it is account destruction:
    // its key share is destroyed so its local database becomes unreadable, and with no
    // trusted device left there is nobody who can mint an invite or unwrap a DEK for a
    // replacement. Every record on the server stays, permanently unreadable.
    let remaining: i64 = conn.query_row(
        "SELECT COUNT(*) FROM devices
         WHERE account_id = ?1 AND revoked_at IS NULL AND id != ?2",
        rusqlite::params![caller.account_id, device_id],
        |row| row.get(0),
    )?;
    if remaining == 0 && target.is_active() && !query.force {
        return Err(ApiError::BadRequest(
            "this is the last active device; revoking it makes the account permanently \
             unreadable. Enrol a replacement first, or repeat with ?force=true."
                .into(),
        ));
    }

    lease::revoke(&conn, &device_id)?;
    auth::drop_tokens(&conn, &device_id)?;
    let dropped = deks::drop_wraps_for_device(&conn, &device_id)?;

    audit::record_best_effort(
        &conn,
        &caller.account_id,
        audit::AuditEvent::DeviceRevoked {
            device_id: device_id.clone(),
            by_device: caller.id.clone(),
        },
    );
    if remaining == 0 {
        tracing::error!(
            account = %caller.account_id,
            "last device revoked by force; this account can no longer be read by anyone"
        );
    }
    tracing::warn!(
        device = %device_id, by = %caller.id, dropped_wraps = dropped,
        "device revoked; key share destroyed. A remaining device must now publish a new \
         DEK epoch, or records written from here on stay readable to it."
    );
    Ok(Json(Empty {}))
}

// ----------------------------------------------------------------- enrollment

#[derive(Serialize)]
struct InviteResponse {
    code: String,
    expires_at: i64,
}

async fn create_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<InviteResponse> {
    let conn = state.db.lock().unwrap();
    let device = session(&conn, &headers)?;
    let (code, expires_at) = enroll::create_invite(&conn, &device.account_id, Some(&device.id))?;
    audit::record_best_effort(
        &conn,
        &device.account_id,
        audit::AuditEvent::InviteCreated {
            by_device: Some(device.id.clone()),
        },
    );
    Ok(Json(InviteResponse { code, expires_at }))
}

#[derive(Deserialize)]
struct ClaimRequest {
    code: String,
    display_name: String,
    ed25519_pub: String,
    x25519_pub: String,
    /// X25519 public key the audit log is sealed to, derived from the account root key.
    /// Only honoured for the first device; afterwards the key is fixed, so a later
    /// device cannot redirect the log to itself.
    #[serde(default)]
    audit_pub: Option<String>,
}

#[derive(Serialize)]
struct ClaimResponse {
    device_id: String,
    account_id: String,
    enrollment_id: String,
}

/// Unauthenticated by necessity -- the newcomer has no credentials yet. The invite code
/// is the credential, and it came from an already-trusted device.
async fn claim_invite(
    State(state): State<AppState>,
    Json(req): Json<ClaimRequest>,
) -> ApiResult<ClaimResponse> {
    throttle(&state.limiter, "claim", ratelimit::quotas::CLAIM)?;
    let ed = unb64(&req.ed25519_pub, "ed25519_pub")?;
    let x = unb64(&req.x25519_pub, "x25519_pub")?;
    if ed.len() != 32 || x.len() != 32 {
        return Err(ApiError::BadRequest("public keys must be 32 bytes".into()));
    }
    let mut conn = state.db.lock().unwrap();
    let claimed = enroll::claim_invite(&mut conn, &req.code, &req.display_name, &ed, &x)?;

    if let Some(audit_pub) = &req.audit_pub {
        let audit_pub = unb64(audit_pub, "audit_pub")?;
        if audit_pub.len() != 32 {
            return Err(ApiError::BadRequest("audit_pub must be 32 bytes".into()));
        }
        // Already-set is not an error here: the second device simply sends a key we
        // ignore, and the account keeps the one it started with.
        match audit::set_audit_key(&conn, &claimed.account_id, &audit_pub) {
            Ok(()) | Err(audit::AuditError::KeyAlreadySet) => {}
            Err(e) => return Err(e.into()),
        }
    }

    audit::record_best_effort(
        &conn,
        &claimed.account_id,
        audit::AuditEvent::DeviceEnrolled {
            device_id: claimed.device_id.clone(),
            display_name: req.display_name.clone(),
            fingerprint: fingerprint(&ed),
        },
    );

    Ok(Json(ClaimResponse {
        device_id: claimed.device_id,
        account_id: claimed.account_id,
        enrollment_id: claimed.enrollment_id,
    }))
}

#[derive(Serialize)]
struct PendingEnrollment {
    enrollment_id: String,
    device_id: String,
    display_name: String,
    x25519_pub: String,
    /// Show this on both screens. If they differ, the server is lying about which key
    /// belongs to the new device.
    fingerprint: String,
}

async fn list_pending(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Vec<PendingEnrollment>> {
    let conn = state.db.lock().unwrap();
    let device = session(&conn, &headers)?;
    let rows = enroll::pending(&conn, &device.account_id)?;
    Ok(Json(
        rows.into_iter()
            .map(|p| PendingEnrollment {
                fingerprint: fingerprint(&p.x25519_pub),
                x25519_pub: b64(&p.x25519_pub),
                enrollment_id: p.enrollment_id,
                device_id: p.device_id,
                display_name: p.display_name,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct DepositRequest {
    /// Root key sealed to the newcomer's X25519 public key. Opaque to us.
    wrapped_payload: String,
}

async fn deposit_wrapped(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(enrollment_id): Path<String>,
    Json(req): Json<DepositRequest>,
) -> ApiResult<Empty> {
    let conn = state.db.lock().unwrap();
    let device = session(&conn, &headers)?;
    let payload = unb64(&req.wrapped_payload, "wrapped_payload")?;
    enroll::deposit(&conn, &enrollment_id, &device.account_id, &payload)?;
    Ok(Json(Empty {}))
}

#[derive(Serialize)]
struct CollectResponse {
    wrapped_payload: Option<String>,
}

async fn collect_wrapped(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(enrollment_id): Path<String>,
) -> ApiResult<CollectResponse> {
    let conn = state.db.lock().unwrap();
    let device = session(&conn, &headers)?;
    let payload = enroll::collect(&conn, &enrollment_id, &device.id)?;
    Ok(Json(CollectResponse {
        wrapped_payload: payload.as_deref().map(b64),
    }))
}
