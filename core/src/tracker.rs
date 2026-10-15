//! The facade both clients drive.
//!
//! Holds the sealed store, the keys, and the projected state, and keeps them in step.
//! A client calls `start_session` and reads `state()`; it never touches ciphertext.

use chrono::{DateTime, Utc};

use crate::{
    crypto::keys::Dek,
    log::{Event, ImageRef, LogEntry, ProductId, SessionId, State, new_id, project},
    store::{Store, StoreError},
    sync::{OutboundEvent, SyncClient, SyncError},
};
use base64::prelude::*;

pub type Result<T> = std::result::Result<T, TrackerError>;

#[derive(Debug, thiserror::Error)]
pub enum TrackerError {
    #[error("storage error: {0}")]
    Store(#[from] StoreError),
    #[error("sync error: {0}")]
    Sync(#[from] SyncError),
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("no data key: this device is locked")]
    Locked,
    #[error("no such session: {0}")]
    UnknownSession(String),
    #[error("no such product: {0}")]
    UnknownProduct(String),
    #[error("implausible value: {0}")]
    InvalidValue(String),
}

#[derive(Debug, Default, PartialEq)]
pub struct SyncReport {
    pub pushed: usize,
    pub pulled: usize,
    /// Entries whose epoch this device holds no key for. Non-zero is normal on a device
    /// enrolled after some history already existed.
    pub unreadable: usize,
}

pub struct Tracker {
    store: Store,
    deks: Vec<(i64, Dek)>,
    device_id: String,
    state: State,
    /// The log revision `state` was projected from, so a change made elsewhere can be
    /// spotted without re-reading and re-decrypting everything.
    revision: i64,
}

impl Tracker {
    /// Open a store with the keys already unwrapped.
    pub fn open(store: Store, deks: Vec<(i64, Dek)>, device_id: impl Into<String>) -> Result<Self> {
        let mut tracker = Self {
            store,
            deks,
            device_id: device_id.into(),
            state: State::default(),
            revision: 0,
        };
        tracker.reproject()?;
        Ok(tracker)
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn is_locked(&self) -> bool {
        self.deks.is_empty()
    }

    /// The epoch new records are sealed under: always the newest key this device holds.
    fn current_epoch(&self) -> Result<(i64, &Dek)> {
        self.deks
            .iter()
            .max_by_key(|(epoch, _)| *epoch)
            .map(|(epoch, dek)| (*epoch, dek))
            .ok_or(TrackerError::Locked)
    }

    fn reproject(&mut self) -> Result<()> {
        let (entries, _) = self.store.load_entries(&self.deks)?;
        self.state = project(&entries);
        self.revision = self.store.revision()?;
        Ok(())
    }

    /// Re-read the log if another process has written to it. Returns whether anything
    /// changed.
    ///
    /// The tray, the statistics window and the command line are three processes over
    /// one SQLite file. Without this the tray's projection is a private opinion rather
    /// than a view of the log: a variety added from the command line stays invisible
    /// until the next sync, which is an hour away.
    pub fn refresh(&mut self) -> Result<bool> {
        if self.store.revision()? == self.revision {
            return Ok(false);
        }
        self.reproject()?;
        Ok(true)
    }

    /// Append one event and refresh the projected state.
    pub fn record(&mut self, event: Event) -> Result<LogEntry> {
        let entry = LogEntry::new(self.device_id.clone(), event);
        let (epoch, dek) = self.current_epoch()?;
        self.store.append(&entry, epoch, dek)?;
        self.reproject()?;
        Ok(entry)
    }

    // ------------------------------------------------------------------ actions

    #[allow(clippy::too_many_arguments)]
    pub fn define_product(
        &mut self,
        name: impl Into<String>,
        substance_id: impl Into<String>,
        route_id: impl Into<String>,
        nominal_mg: f64,
        default_duration_secs: Option<f64>,
        accent: Option<String>,
        image: Option<ImageRef>,
    ) -> Result<ProductId> {
        let product_id = new_id();
        self.record(Event::ProductDefined {
            product_id: product_id.clone(),
            name: name.into(),
            substance_id: substance_id.into(),
            route_id: route_id.into(),
            nominal_mg,
            default_duration_secs,
            accent,
            image,
        })?;
        Ok(product_id)
    }

    pub fn retire_product(&mut self, product_id: &str) -> Result<()> {
        if !self.state.products.contains_key(product_id) {
            return Err(TrackerError::UnknownProduct(product_id.to_string()));
        }
        self.record(Event::ProductRetired { product_id: product_id.to_string() })?;
        Ok(())
    }

    /// Begin a session now.
    pub fn start_session(&mut self, product_id: &str) -> Result<SessionId> {
        self.start_session_at(product_id, Utc::now())
    }

    /// Begin a session at a stated time, for entering something after the fact.
    pub fn start_session_at(
        &mut self,
        product_id: &str,
        started_at: DateTime<Utc>,
    ) -> Result<SessionId> {
        if !self.state.products.contains_key(product_id) {
            return Err(TrackerError::UnknownProduct(product_id.to_string()));
        }
        let session_id = new_id();
        self.record(Event::SessionStarted {
            session_id: session_id.clone(),
            product_id: product_id.to_string(),
            started_at,
        })?;
        Ok(session_id)
    }

    pub fn end_session(&mut self, session_id: &str) -> Result<()> {
        self.end_session_at(session_id, Utc::now())
    }

    pub fn end_session_at(&mut self, session_id: &str, ended_at: DateTime<Utc>) -> Result<()> {
        if !self.state.sessions.contains_key(session_id) {
            return Err(TrackerError::UnknownSession(session_id.to_string()));
        }
        self.record(Event::SessionEnded { session_id: session_id.to_string(), ended_at })?;
        Ok(())
    }

    /// Change fields on an existing variety. Every field is optional and `None` means
    /// "leave alone", which is what lets two devices edit different fields of the same
    /// product without one silently reverting the other.
    pub fn update_product(
        &mut self,
        product_id: &str,
        name: Option<String>,
        nominal_mg: Option<f64>,
        default_duration_secs: Option<f64>,
        accent: Option<String>,
        image: Option<ImageRef>,
    ) -> Result<()> {
        if !self.state.products.contains_key(product_id) {
            return Err(TrackerError::UnknownProduct(product_id.to_string()));
        }
        self.record(Event::ProductUpdated {
            product_id: product_id.to_string(),
            name,
            nominal_mg,
            default_duration_secs,
            accent,
            image,
        })?;
        Ok(())
    }

    /// Record body mass and, if known, how fast this person metabolises nicotine.
    ///
    /// Body mass matters more than it looks: volume of distribution is expressed per
    /// kilogram, so every concentration in the app scales with it. The default of 75 kg
    /// is a literature figure, not a measurement, and it is the largest correctable
    /// error in the model.
    ///
    /// `metabolism_factor` scales all elimination rates. 1.0 is the population average;
    /// individual CYP2A6 activity spans roughly a threefold range, which is why the
    /// nicotine metabolite ratio is worth measuring if it can be had.
    pub fn update_subject(
        &mut self,
        body_mass_kg: Option<f64>,
        metabolism_factor: Option<f64>,
    ) -> Result<()> {
        if let Some(mass) = body_mass_kg
            && !(20.0..=400.0).contains(&mass)
        {
            return Err(TrackerError::InvalidValue(format!("{mass} kg")));
        }
        if let Some(factor) = metabolism_factor
            && !(0.2..=5.0).contains(&factor)
        {
            return Err(TrackerError::InvalidValue(format!("Faktor {factor}")));
        }
        self.record(Event::SubjectUpdated { body_mass_kg, metabolism_factor })?;
        Ok(())
    }

    /// Take the pouch out without ending the session.
    pub fn pause_session(&mut self, session_id: &str) -> Result<()> {
        self.pause_session_at(session_id, Utc::now())
    }

    pub fn pause_session_at(
        &mut self,
        session_id: &str,
        paused_at: DateTime<Utc>,
    ) -> Result<()> {
        let Some(session) = self.state.sessions.get(session_id) else {
            return Err(TrackerError::UnknownSession(session_id.to_string()));
        };
        if !session.is_active() {
            return Err(TrackerError::UnknownSession(session_id.to_string()));
        }
        if session.is_paused() {
            return Ok(());
        }
        self.record(Event::SessionPaused {
            session_id: session_id.to_string(),
            paused_at,
        })?;
        Ok(())
    }

    /// Put it back in.
    pub fn resume_session(&mut self, session_id: &str) -> Result<()> {
        self.resume_session_at(session_id, Utc::now())
    }

    pub fn resume_session_at(
        &mut self,
        session_id: &str,
        resumed_at: DateTime<Utc>,
    ) -> Result<()> {
        let Some(session) = self.state.sessions.get(session_id) else {
            return Err(TrackerError::UnknownSession(session_id.to_string()));
        };
        if !session.is_paused() {
            return Ok(());
        }
        self.record(Event::SessionResumed {
            session_id: session_id.to_string(),
            resumed_at,
        })?;
        Ok(())
    }

    pub fn discard_session(&mut self, session_id: &str) -> Result<()> {
        self.record(Event::SessionDiscarded { session_id: session_id.to_string() })?;
        Ok(())
    }

    // --------------------------------------------------------------------- sync

    /// Push queued records, pull new ones, reproject.
    ///
    /// Push before pull so a record made on this device is on the server before it takes
    /// anyone else's view of the log into account.
    pub fn sync(&mut self, client: &SyncClient) -> Result<SyncReport> {
        let mut report = SyncReport::default();

        let pending = self.store.pending(500)?;
        if !pending.is_empty() {
            let outbound: Vec<OutboundEvent> = pending
                .iter()
                .map(|(id, epoch, nonce, ciphertext)| OutboundEvent {
                    event_id: id.clone(),
                    epoch: *epoch,
                    nonce: BASE64_STANDARD.encode(nonce),
                    ciphertext: BASE64_STANDARD.encode(ciphertext),
                })
                .collect();
            let cursor = client.push(&outbound)?;
            for (id, _, _, _) in &pending {
                self.store.mark_synced(id, cursor)?;
            }
            report.pushed = pending.len();
        }

        loop {
            let page = client.pull(self.store.cursor()?, 500)?;
            for event in &page.events {
                let nonce = BASE64_STANDARD
                    .decode(&event.nonce)
                    .map_err(|e| SyncError::Transport(e.to_string()))?;
                let ciphertext = BASE64_STANDARD
                    .decode(&event.ciphertext)
                    .map_err(|e| SyncError::Transport(e.to_string()))?;
                self.store.ingest(&event.event_id, event.epoch, &nonce, &ciphertext, event.seq)?;
            }
            report.pulled += page.events.len();
            self.store.set_cursor(page.cursor)?;
            if !page.more {
                break;
            }
        }

        let (entries, unreadable) = self.store.load_entries(&self.deks)?;
        self.state = project(&entries);
        self.revision = self.store.revision()?;
        report.unreadable = unreadable;
        Ok(report)
    }

    /// Take on a newly published key. Called after pulling wraps from the server.
    /// Verpackt jede Epoche, die dieses Gerät besitzt, für ein anderes Gerät.
    ///
    /// Ein neu aufgenommenes Gerät bekommt sonst nur die Epoche, die beim Aufnehmen
    /// entsteht -- und ist damit blind für alles, was vorher geschrieben wurde. Der
    /// Server kann das nicht ausgleichen: Er hat keinen der Schlüssel.
    ///
    /// Die Schlüssel verlassen den Tracker dabei nicht; heraus kommen nur die für
    /// den Empfänger versiegelten Fassungen.
    pub fn wrap_all_to(&self, device_pub: &[u8; 32]) -> Result<Vec<(i64, Vec<u8>)>> {
        self.deks
            .iter()
            .map(|(epoch, dek)| Ok((*epoch, dek.wrap_to(device_pub)?)))
            .collect()
    }

    pub fn add_dek(&mut self, epoch: i64, dek: Dek) -> Result<()> {
        if !self.deks.iter().any(|(e, _)| *e == epoch) {
            self.deks.push((epoch, dek));
            self.reproject()?;
        }
        Ok(())
    }

    pub fn epochs(&self) -> Vec<i64> {
        let mut epochs: Vec<i64> = self.deks.iter().map(|(e, _)| *e).collect();
        epochs.sort_unstable();
        epochs
    }

    pub fn persist_deks(&self, device_secret: &[u8], lease_share: &[u8]) -> Result<()> {
        self.store.save_deks(&self.deks, device_secret, lease_share)?;
        Ok(())
    }

    /// React to the server reporting this device revoked: drop the keys immediately
    /// rather than waiting for the lease to lapse.
    pub fn lock_and_wipe(&mut self) -> Result<()> {
        self.deks.clear();
        self.store.wipe_keys()?;
        self.state = State::default();
        Ok(())
    }
}
