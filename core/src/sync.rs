//! Talking to the sync server.
//!
//! Every call goes through the encrypting tunnel, so whatever terminates TLS in front
//! of the server sees one opaque POST body and one opaque response. The server's public
//! key is pinned by the caller; fetching it over the network would prove nothing.

use base64::prelude::*;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use std::{io::Read, sync::Mutex};

use crate::crypto::{self, KEY_LEN};

pub type Result<T> = std::result::Result<T, SyncError>;

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("serialisation error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("this device has been revoked")]
    Revoked,
    #[error("not authenticated")]
    NotAuthenticated,
    #[error("server returned {status}: {message}")]
    Server { status: u16, message: String },
}

impl SyncError {
    /// The one failure a client must react to rather than retry: wipe local keys.
    pub fn is_revoked(&self) -> bool {
        matches!(self, SyncError::Revoked)
    }
}

pub struct ServerConfig {
    pub base_url: String,
    /// Pinned out of band, from the fingerprint `tracker-server bootstrap` prints.
    pub server_pub: [u8; KEY_LEN],
}

pub struct SyncClient {
    config: ServerConfig,
    token: Mutex<Option<String>>,
    /// Kept so an expired token can be replaced without the caller noticing. Tokens
    /// last an hour, so any client that cannot re-authenticate on its own is broken by
    /// design -- and it is on this path that a revoked device finds out it is revoked,
    /// because revocation drops the token and the refusal only surfaces at the
    /// challenge step.
    credentials: Mutex<Option<(String, SigningKey)>>,
}

#[derive(Debug, Deserialize)]
pub struct Lease {
    pub key_share: String,
    pub key_share_pending: Option<String>,
    pub expires_at: i64,
    pub ttl_secs: i64,
}

#[derive(Debug, Deserialize)]
pub struct DekWrap {
    pub epoch: i64,
    pub wrapped_dek: String,
}

#[derive(Debug, Serialize)]
pub struct OutboundEvent {
    pub event_id: String,
    pub epoch: i64,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Deserialize)]
pub struct InboundEvent {
    pub seq: i64,
    pub event_id: String,
    pub epoch: i64,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Deserialize)]
pub struct PullPage {
    pub events: Vec<InboundEvent>,
    pub cursor: i64,
    pub more: bool,
}

impl SyncClient {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            token: Mutex::new(None),
            credentials: Mutex::new(None),
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.token.lock().unwrap().is_some()
    }

    /// One request through the tunnel. Returns the inner status and body.
    fn tunnelled(&self, method: &str, path: &str, body: Option<Value>) -> Result<(u16, String)> {
        let mut inner = json!({ "method": method, "path": path });
        if let Some(token) = self.token.lock().unwrap().as_ref() {
            inner["authorization"] = json!(format!("Bearer {token}"));
        }
        if let Some(body) = body {
            inner["body"] = json!(body.to_string());
        }

        let sealed = crypto::primitives::seal_request_envelope(
            &self.config.server_pub,
            inner.to_string().as_bytes(),
        )?;

        let response = ureq::post(&format!("{}/v1/tunnel", self.config.base_url))
            .header("content-type", "application/octet-stream")
            .send(&sealed.envelope[..])
            .map_err(|e| SyncError::Transport(e.to_string()))?;

        let mut bytes = Vec::new();
        response
            .into_body()
            .into_reader()
            .read_to_end(&mut bytes)
            .map_err(|e| SyncError::Transport(e.to_string()))?;

        let plaintext = crypto::primitives::open_response_envelope(&sealed.reply_key, &bytes)?;
        let decoded: Value = serde_json::from_slice(&plaintext)?;

        let status = decoded["status"].as_u64().unwrap_or(0) as u16;
        let body = decoded["body"].as_str().unwrap_or_default().to_string();
        Ok((status, body))
    }

    fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        match self.call_once(method, path, body.clone()) {
            // An expired or dropped token: re-authenticate and try once more. If the
            // device has been revoked, the retry fails at the challenge with a flag the
            // caller can act on.
            Err(SyncError::Server { status: 401, .. }) => {
                self.reauthenticate()?;
                self.call_once(method, path, body)
            }
            other => other,
        }
    }

    fn reauthenticate(&self) -> Result<()> {
        let credentials = self.credentials.lock().unwrap().clone();
        let Some((device_id, signing_key)) = credentials else {
            return Err(SyncError::NotAuthenticated);
        };
        *self.token.lock().unwrap() = None;
        self.perform_handshake(&device_id, &signing_key)
    }

    fn call_once(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let (status, body) = self.tunnelled(method, path, body)?;
        let parsed: Value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&body).unwrap_or(Value::Null)
        };

        if status == 200 {
            return Ok(parsed);
        }
        // The server flags revocation explicitly so it is never confused with a
        // transient failure that a client would sensibly retry.
        if parsed
            .get("revoked")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(SyncError::Revoked);
        }
        Err(SyncError::Server {
            status,
            message: parsed
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
                .to_string(),
        })
    }

    pub fn authenticate(&self, device_id: &str, signing_key: &SigningKey) -> Result<()> {
        *self.credentials.lock().unwrap() = Some((device_id.to_string(), signing_key.clone()));
        *self.token.lock().unwrap() = None;
        self.perform_handshake(device_id, signing_key)
    }

    fn perform_handshake(&self, device_id: &str, signing_key: &SigningKey) -> Result<()> {
        let challenge = self.call_once(
            "POST",
            "/v1/auth/challenge",
            Some(json!({ "device_id": device_id })),
        )?;
        let nonce = challenge["nonce"]
            .as_str()
            .ok_or(SyncError::NotAuthenticated)?;
        let signature =
            BASE64_URL_SAFE_NO_PAD.encode(signing_key.sign(nonce.as_bytes()).to_bytes());

        let verified = self.call_once(
            "POST",
            "/v1/auth/verify",
            Some(json!({ "nonce": nonce, "signature": signature })),
        )?;
        *self.token.lock().unwrap() = Some(
            verified["token"]
                .as_str()
                .ok_or(SyncError::NotAuthenticated)?
                .to_string(),
        );
        Ok(())
    }

    pub fn claim_invite(
        &self,
        code: &str,
        display_name: &str,
        ed25519_pub: &[u8],
        x25519_pub: &[u8],
        audit_pub: Option<&[u8]>,
    ) -> Result<Value> {
        let mut body = json!({
            "code": code,
            "display_name": display_name,
            "ed25519_pub": BASE64_STANDARD.encode(ed25519_pub),
            "x25519_pub": BASE64_STANDARD.encode(x25519_pub),
        });
        if let Some(audit) = audit_pub {
            body["audit_pub"] = json!(BASE64_STANDARD.encode(audit));
        }
        self.call("POST", "/v1/enroll/claim", Some(body))
    }

    pub fn collect_enrollment(&self, enrollment_id: &str) -> Result<Option<Vec<u8>>> {
        let response = self.call("GET", &format!("/v1/enroll/{enrollment_id}"), None)?;
        match response["wrapped_payload"].as_str() {
            Some(encoded) => Ok(Some(
                BASE64_STANDARD
                    .decode(encoded)
                    .map_err(|e| SyncError::Transport(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    pub fn lease_acquire(&self) -> Result<Lease> {
        Ok(serde_json::from_value(self.call(
            "POST",
            "/v1/lease/acquire",
            Some(json!({})),
        )?)?)
    }

    pub fn lease_rotate(&self) -> Result<Lease> {
        Ok(serde_json::from_value(self.call(
            "POST",
            "/v1/lease/rotate",
            Some(json!({})),
        )?)?)
    }

    pub fn lease_commit(&self) -> Result<()> {
        self.call("POST", "/v1/lease/commit", Some(json!({})))
            .map(|_| ())
    }

    pub fn deks(&self, since_epoch: i64) -> Result<Vec<DekWrap>> {
        Ok(serde_json::from_value(self.call(
            "GET",
            &format!("/v1/deks?since_epoch={since_epoch}"),
            None,
        )?)?)
    }

    pub fn current_epoch(&self) -> Result<Option<i64>> {
        Ok(self.call("GET", "/v1/deks/current", None)?["epoch"].as_i64())
    }

    pub fn publish_epoch(&self, epoch: i64, wraps: &[(String, Vec<u8>)]) -> Result<Value> {
        let wraps: Vec<Value> = wraps
            .iter()
            .map(|(device_id, wrapped)| {
                json!({ "device_id": device_id, "wrapped_dek": BASE64_STANDARD.encode(wrapped) })
            })
            .collect();
        self.call(
            "POST",
            "/v1/deks",
            Some(json!({ "epoch": epoch, "wraps": wraps })),
        )
    }

    /// Reicht Schlüssel für bereits bestehende Epochen nach.
    ///
    /// Getrennt von `publish_epoch`, weil das eine neue Epoche verlangt und ältere
    /// bewusst ablehnt -- eine Epoche zurückzudrehen wäre ein Angriff, eine schon
    /// bestehende einem berechtigten Gerät zugänglich zu machen ist das Gegenteil.
    pub fn publish_wraps(&self, wraps: &[(i64, String, Vec<u8>)]) -> Result<Value> {
        let wraps: Vec<Value> = wraps
            .iter()
            .map(|(epoch, device_id, wrapped)| {
                json!({
                    "epoch": epoch,
                    "device_id": device_id,
                    "wrapped_dek": BASE64_STANDARD.encode(wrapped),
                })
            })
            .collect();
        self.call("POST", "/v1/deks/wraps", Some(json!({ "wraps": wraps })))
    }

    pub fn push(&self, events: &[OutboundEvent]) -> Result<i64> {
        if events.is_empty() {
            return Ok(0);
        }
        let response = self.call("POST", "/v1/events", Some(json!({ "events": events })))?;
        Ok(response["cursor"].as_i64().unwrap_or(0))
    }

    pub fn pull(&self, since: i64, limit: i64) -> Result<PullPage> {
        Ok(serde_json::from_value(self.call(
            "GET",
            &format!("/v1/events?since={since}&limit={limit}"),
            None,
        )?)?)
    }

    pub fn devices(&self) -> Result<Value> {
        self.call("GET", "/v1/devices", None)
    }

    pub fn create_invite(&self) -> Result<Value> {
        self.call("POST", "/v1/enroll/invite", Some(json!({})))
    }

    pub fn revoke(&self, device_id: &str, force: bool) -> Result<()> {
        let suffix = if force { "?force=true" } else { "" };
        self.call(
            "POST",
            &format!("/v1/devices/{device_id}/revoke{suffix}"),
            Some(json!({})),
        )
        .map(|_| ())
    }
}
