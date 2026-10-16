//! The thread that owns the tracker.
//!
//! `Session` holds a SQLite connection, which is not `Sync`, and the tray's callbacks
//! are synchronous. Rather than wrapping everything in locks, one thread owns the state
//! and everyone else sends it commands and receives snapshots.

use std::{sync::mpsc, time::Duration};

use chrono::{DateTime, Utc};
use tracker_core::log::ProductId;

use crate::{
    levels,
    session::{Session, SessionError, approve_devices},
};

#[derive(Debug, Clone)]
pub enum Command {
    StartSession(ProductId),
    EndSession(String),
    PauseSession(String),
    ResumeSession(String),
    Sync,
    Approve,
    OpenStats,
    Quit,
}

#[derive(Debug, Clone)]
pub struct ProductButton {
    pub id: ProductId,
    pub name: String,
    pub nominal_mg: f64,
}

#[derive(Debug, Clone)]
pub struct OpenSession {
    pub session_id: String,
    pub product_name: String,
    pub started_at: DateTime<Utc>,
    /// Out of the mouth, resting. The session is still open.
    pub paused: bool,
    /// Contact time the pouch has left before it is spent. `None` when the product has
    /// no release profile to count against.
    pub release_left: Option<chrono::Duration>,
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub products: Vec<ProductButton>,
    pub open: Option<OpenSession>,
    pub locked: bool,
    pub online: bool,
    pub pending: i64,
    pub today_count: usize,
    pub nicotine_ng_ml: f64,
    /// ng/mL per minute. What a pouch feels like tracks this, not the level.
    pub nicotine_rate: f64,
    pub status: String,
    pub quit: bool,
}

impl Snapshot {
    fn locked_with(status: impl Into<String>) -> Self {
        Self {
            locked: true,
            status: status.into(),
            ..Default::default()
        }
    }
}

fn snapshot(session: &Session, status: String) -> Snapshot {
    let state = session.tracker.state();
    let curves = levels::build(state);
    let now = Utc::now();

    Snapshot {
        products: state
            .active_products()
            .into_iter()
            .map(|p| ProductButton {
                id: p.id.clone(),
                name: p.name.clone(),
                nominal_mg: p.nominal_mg,
            })
            .collect(),
        open: state.open_sessions().first().map(|s| OpenSession {
            session_id: s.id.clone(),
            product_name: state
                .product(&s.product_id)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "Unbekannt".into()),
            started_at: s.started_at,
            paused: s.is_paused(),
            release_left: levels::remaining_release(state, s, now),
        }),
        locked: session.tracker.is_locked(),
        online: session.online,
        pending: session.tracker.store().pending_count().unwrap_or(0),
        today_count: levels::today_count(state),
        nicotine_ng_ml: curves.nicotine_at(now),
        nicotine_rate: curves.nicotine_rate_at(now),
        status,
        quit: false,
    }
}

/// How often to push pending records and pull the phone's changes.
///
/// This used to be hourly, which left everything logged from the tray unsynced for up to
/// an hour and made the phone look like it was ignoring the laptop. A sync with nothing to
/// move is a single request, so a short interval costs next to nothing.
const SYNC_INTERVAL: Duration = Duration::from_secs(15);
/// How often to take a fresh lease. Hourly renewal against a 24 hour TTL means the device
/// is almost always sitting on a nearly full window, so losing the network for an
/// afternoon is invisible.
const LEASE_INTERVAL: Duration = Duration::from_secs(3600);
/// How long to block waiting for a command before doing the periodic work.
///
/// Short, because this is also how quickly the tray notices a change made somewhere
/// else -- `snus add` in a terminal, or the statistics window. The work done on a tick
/// with nothing to do is one indexed COUNT, so a few seconds costs nothing.
const POLL: Duration = Duration::from_secs(3);

pub fn spawn(updates: tokio::sync::mpsc::UnboundedSender<Snapshot>) -> mpsc::Sender<Command> {
    let (tx, rx) = mpsc::channel::<Command>();

    std::thread::spawn(move || {
        let mut session = match Session::open() {
            Ok(session) => session,
            Err(error) => {
                let _ = updates.send(Snapshot::locked_with(error.to_string()));
                // Stay alive so the tray still shows why, and so Quit still works.
                while let Ok(command) = rx.recv() {
                    if matches!(command, Command::Quit) {
                        let _ = updates.send(Snapshot {
                            quit: true,
                            ..Default::default()
                        });
                        return;
                    }
                }
                return;
            }
        };

        let _ = updates.send(snapshot(&session, String::new()));
        let mut last_sync = std::time::Instant::now();
        let mut last_lease = std::time::Instant::now();
        // Which session we have already announced as spent. Per process, so a restart
        // may repeat one notification -- the alternative is persisting UI state into
        // the log, and the log is for what happened to you, not for what the tray has
        // already said.
        let mut announced_empty: Option<String> = None;

        loop {
            let command = rx.recv_timeout(POLL);
            let mut status = String::new();
            // A write made here goes out straight away instead of waiting for the timer.
            let wrote = matches!(
                command,
                Ok(Command::StartSession(_)
                    | Command::EndSession(_)
                    | Command::PauseSession(_)
                    | Command::ResumeSession(_))
            );

            match command {
                Ok(Command::StartSession(product_id)) => {
                    status = match session.tracker.start_session(&product_id) {
                        Ok(_) => String::new(),
                        Err(e) => format!("Konnte nicht starten: {e}"),
                    };
                }
                Ok(Command::EndSession(session_id)) => {
                    status = match session.tracker.end_session(&session_id) {
                        Ok(()) => String::new(),
                        Err(e) => format!("Konnte nicht beenden: {e}"),
                    };
                }
                Ok(Command::PauseSession(session_id)) => {
                    status = match session.tracker.pause_session(&session_id) {
                        Ok(()) => String::new(),
                        Err(e) => format!("Konnte nicht pausieren: {e}"),
                    };
                }
                Ok(Command::ResumeSession(session_id)) => {
                    status = match session.tracker.resume_session(&session_id) {
                        Ok(()) => String::new(),
                        Err(e) => format!("Konnte nicht fortsetzen: {e}"),
                    };
                }
                Ok(Command::Sync) => {
                    status = report_sync(&mut session);
                    last_sync = std::time::Instant::now();
                }
                Ok(Command::Approve) => {
                    status = match approve_devices(&mut session) {
                        Ok(devices) if devices.is_empty() => "Keine neuen Geräte".into(),
                        Ok(devices) => format!("{} Gerät(e) freigeschaltet", devices.len()),
                        Err(e) => format!("Freischalten fehlgeschlagen: {e}"),
                    };
                }
                Ok(Command::OpenStats) => {
                    if let Err(e) = open_stats_window() {
                        status = format!("Statistik ließ sich nicht öffnen: {e}");
                    }
                }
                Ok(Command::Quit) => {
                    // Best effort: get anything queued onto the server before going.
                    let _ = session.sync();
                    let _ = updates.send(Snapshot {
                        quit: true,
                        ..Default::default()
                    });
                    return;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }

            // Another process may have written to the same log: the command line, or
            // the statistics window. Cheap to ask, and without it the tray shows a
            // private opinion instead of the log.
            if let Err(e) = session.tracker.refresh() {
                status = format!("Konnte lokale Daten nicht neu lesen: {e}");
            }

            if last_lease.elapsed() >= LEASE_INTERVAL {
                let _ = session.renew_lease();
                last_lease = std::time::Instant::now();
            }
            if wrote || last_sync.elapsed() >= SYNC_INTERVAL {
                // Keep an error from the command itself: it is the more useful message.
                let synced = report_sync(&mut session);
                if status.is_empty() {
                    status = synced;
                }
                last_sync = std::time::Instant::now();
            }

            let current = snapshot(&session, status);
            announce_if_spent(&current, &mut announced_empty);
            if updates.send(current).is_err() {
                return;
            }
        }
    });

    tx
}

/// Tell the user once when the pouch stops giving anything back.
///
/// Only while it is actually in: a resting pouch is not consuming its budget, so
/// announcing it as spent would be wrong, and announcing it later when it goes back in
/// is what the user needs anyway.
fn announce_if_spent(snapshot: &Snapshot, announced: &mut Option<String>) {
    let Some(open) = &snapshot.open else {
        // Session over: forget it, so the next pouch gets its own announcement.
        *announced = None;
        return;
    };
    if announced.as_deref() == Some(open.session_id.as_str()) {
        return;
    }
    if open.paused || open.release_left.is_none_or(|left| left.num_seconds() > 0) {
        return;
    }

    *announced = Some(open.session_id.clone());
    let _ = crate::notify::send(
        &format!("{} ist leer", open.product_name),
        "Der Pouch gibt nichts mehr ab — rausnehmen lohnt sich.",
    );
}

fn report_sync(session: &mut Session) -> String {
    // The online flag was fixed when the session opened, so the tray kept saying
    // "Offline" after the network came back (and the reverse). Follow the real outcome.
    let result = session.sync();
    session.online = result.is_ok();
    match result {
        Ok(report) if report.pushed == 0 && report.pulled == 0 => String::new(),
        Ok(report) => format!("Sync: {} hoch, {} runter", report.pushed, report.pulled),
        Err(SessionError::Revoked) => "Gerät wurde gesperrt — lokale Daten gelöscht".into(),
        Err(e) => format!("Sync fehlgeschlagen: {e}"),
    }
}

/// Launch the statistics window as its own process.
///
/// egui owns the main thread's event loop, and the tray owns this one. A second process
/// is far less trouble than trying to share.
fn open_stats_window() -> std::io::Result<()> {
    let executable = std::env::current_exe()?;
    std::process::Command::new(executable)
        .arg("stats")
        .spawn()
        .map(|_| ())
}
