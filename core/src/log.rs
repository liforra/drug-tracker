//! The event log and the state it folds into.
//!
//! Everything the user has is derived from an append-only list of immutable events.
//! Nothing is ever mutated in place, which is what makes multi-device sync trivial:
//! merging two devices' logs is set union, and every device that has seen the same
//! entries computes byte-identical state.
//!
//! Products live in here too. A variety is not configuration baked into a client, it is
//! a `ProductDefined` entry like any other -- so adding one on the phone makes it appear
//! on the laptop through exactly the same path as a consumption record.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type ProductId = String;
pub type SessionId = String;
pub type EntryId = String;

/// Pointer to an image in the encrypted blob channel.
///
/// The channel itself is not built yet -- images are too large to sit inside log
/// entries, so they need their own transfer path with its own chunking. The reference
/// lives here from the start because retrofitting a field onto entries that are already
/// sealed and synced would mean rewriting history.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImageRef {
    pub blob_id: String,
    /// Hex-encoded content hash, so a client can tell a stale cached image from a
    /// current one without fetching it.
    pub content_hash: String,
}

/// What a client records. Deliberately coarse and additive: new variants are safe,
/// changed semantics on an existing one are not, because old entries stay in the log
/// forever.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    ProductDefined {
        product_id: ProductId,
        name: String,
        substance_id: String,
        route_id: String,
        /// As printed on the tin, before bioavailability.
        nominal_mg: f64,
        default_duration_secs: Option<f64>,
        /// Drives the button colour, so varieties stay distinguishable at a glance.
        accent: Option<String>,
        image: Option<ImageRef>,
    },
    ProductUpdated {
        product_id: ProductId,
        name: Option<String>,
        nominal_mg: Option<f64>,
        default_duration_secs: Option<f64>,
        accent: Option<String>,
        image: Option<ImageRef>,
    },
    ProductRetired {
        product_id: ProductId,
    },
    /// Timestamps come from whichever client observed the event, never from the server.
    SessionStarted {
        session_id: SessionId,
        product_id: ProductId,
        started_at: DateTime<Utc>,
    },
    /// May be recorded by a different device than the one that started the session.
    SessionEnded {
        session_id: SessionId,
        ended_at: DateTime<Utc>,
    },
    /// The pouch came out but the session is not over: it is resting somewhere and
    /// absorbing nothing. Recorded separately from `SessionEnded` because the drug
    /// still in the body keeps being distributed and eliminated either way -- only the
    /// delivery stops.
    SessionPaused {
        session_id: SessionId,
        paused_at: DateTime<Utc>,
    },
    SessionResumed {
        session_id: SessionId,
        resumed_at: DateTime<Utc>,
    },
    SessionDiscarded {
        session_id: SessionId,
    },
    SubjectUpdated {
        body_mass_kg: Option<f64>,
        metabolism_factor: Option<f64>,
    },
}

/// One sealed record's contents.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LogEntry {
    /// UUIDv7: random enough to carry no meaning, ordered enough to sort usefully.
    /// Doubles as the server's opaque `event_id`.
    pub id: EntryId,
    /// When this client wrote the entry -- not necessarily when the thing happened.
    pub recorded_at: DateTime<Utc>,
    pub device_id: String,
    pub event: Event,
}

impl LogEntry {
    pub fn new(device_id: impl Into<String>, event: Event) -> Self {
        Self {
            id: Uuid::now_v7().to_string(),
            recorded_at: Utc::now(),
            device_id: device_id.into(),
            event,
        }
    }
}

pub fn new_id() -> String {
    Uuid::now_v7().to_string()
}

#[derive(Clone, Debug, PartialEq)]
pub struct Product {
    pub id: ProductId,
    pub name: String,
    pub substance_id: String,
    pub route_id: String,
    pub nominal_mg: f64,
    pub default_duration_secs: Option<f64>,
    pub accent: Option<String>,
    pub image: Option<ImageRef>,
    pub retired: bool,
}

/// One interval during which the pouch was out of the mouth. Open while resting.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Pause {
    pub paused_at: DateTime<Utc>,
    pub resumed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Session {
    pub id: SessionId,
    pub product_id: ProductId,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    /// Sorted by `paused_at`. Empty for the common case of an uninterrupted pouch.
    pub pauses: Vec<Pause>,
}

impl Session {
    pub fn is_active(&self) -> bool {
        self.ended_at.is_none()
    }

    /// True while the pouch is out but the session is still open.
    pub fn is_paused(&self) -> bool {
        self.is_active() && self.pauses.last().is_some_and(|p| p.resumed_at.is_none())
    }

    /// How long this session has run, or ran. The number the phone shows under an
    /// active pouch. Wall-clock, pauses included -- this answers "since when", not
    /// "how much was absorbed".
    pub fn elapsed(&self, now: DateTime<Utc>) -> Duration {
        self.ended_at.unwrap_or(now) - self.started_at
    }

    /// The intervals during which the pouch was actually in the mouth.
    ///
    /// This is what drives absorption; `elapsed` is not. A pouch that spent an hour on
    /// the desk delivered nothing during that hour, but the nicotine already in the
    /// blood kept being eliminated -- which falls out of the model for free, because
    /// elimination is a property of the body, not of the pouch.
    pub fn contact_intervals(&self, now: DateTime<Utc>) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
        let end = self.ended_at.unwrap_or(now);
        let mut intervals = Vec::new();
        let mut cursor = self.started_at;

        for pause in &self.pauses {
            // A pause recorded after the session ended, or before it started, is a
            // clock skew artefact between devices. Clamping is the honest response:
            // dropping it would silently credit absorption that did not happen.
            let paused_at = pause.paused_at.clamp(cursor, end);
            if paused_at > cursor {
                intervals.push((cursor, paused_at));
            }
            match pause.resumed_at {
                Some(resumed_at) => cursor = resumed_at.clamp(paused_at, end),
                // Still resting: nothing after this point counts.
                None => return intervals,
            }
        }

        if end > cursor {
            intervals.push((cursor, end));
        }
        intervals
    }

    /// Total time the pouch was in the mouth.
    pub fn contact_duration(&self, now: DateTime<Utc>) -> Duration {
        self.contact_intervals(now)
            .into_iter()
            .fold(Duration::zero(), |acc, (a, b)| acc + (b - a))
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct State {
    pub products: BTreeMap<ProductId, Product>,
    pub sessions: BTreeMap<SessionId, Session>,
    pub body_mass_kg: Option<f64>,
    pub metabolism_factor: Option<f64>,
}

impl State {
    /// Varieties offered on the home screen, ordered by name so the buttons do not
    /// shuffle between launches.
    pub fn active_products(&self) -> Vec<&Product> {
        let mut products: Vec<&Product> = self.products.values().filter(|p| !p.retired).collect();
        products.sort_by(|a, b| a.name.cmp(&b.name));
        products
    }

    /// Sessions with no recorded end: what is in right now.
    pub fn open_sessions(&self) -> Vec<&Session> {
        let mut open: Vec<&Session> = self.sessions.values().filter(|s| s.is_active()).collect();
        open.sort_by_key(|s| s.started_at);
        open
    }

    pub fn product(&self, id: &str) -> Option<&Product> {
        self.products.get(id)
    }

    /// Completed sessions, oldest first. The input to the pharmacokinetic engine.
    pub fn finished_sessions(&self) -> Vec<&Session> {
        let mut done: Vec<&Session> = self.sessions.values().filter(|s| !s.is_active()).collect();
        done.sort_by_key(|s| s.started_at);
        done
    }
}

/// Fold a log into state.
///
/// Entries are sorted before folding rather than applied in arrival order. Two devices
/// see the same records in different orders all the time -- one syncs before the other,
/// or a batch arrives late -- and a fold that depended on arrival order would give them
/// different answers. Sorting on `(recorded_at, id)` gives every device the same
/// sequence from the same set, with the id breaking ties that a clock cannot.
pub fn project(entries: &[LogEntry]) -> State {
    let mut ordered: Vec<&LogEntry> = entries.iter().collect();
    ordered.sort_by(|a, b| {
        a.recorded_at
            .cmp(&b.recorded_at)
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut state = State::default();
    let mut discarded: Vec<&str> = Vec::new();

    for entry in ordered {
        match &entry.event {
            Event::ProductDefined {
                product_id,
                name,
                substance_id,
                route_id,
                nominal_mg,
                default_duration_secs,
                accent,
                image,
            } => {
                state
                    .products
                    .entry(product_id.clone())
                    .or_insert_with(|| Product {
                        id: product_id.clone(),
                        name: name.clone(),
                        substance_id: substance_id.clone(),
                        route_id: route_id.clone(),
                        nominal_mg: *nominal_mg,
                        default_duration_secs: *default_duration_secs,
                        accent: accent.clone(),
                        image: image.clone(),
                        retired: false,
                    });
            }

            Event::ProductUpdated {
                product_id,
                name,
                nominal_mg,
                default_duration_secs,
                accent,
                image,
            } => {
                if let Some(product) = state.products.get_mut(product_id) {
                    // Each field is independently optional, so two devices editing
                    // different fields do not overwrite each other's work.
                    if let Some(name) = name {
                        product.name = name.clone();
                    }
                    if let Some(mg) = nominal_mg {
                        product.nominal_mg = *mg;
                    }
                    if default_duration_secs.is_some() {
                        product.default_duration_secs = *default_duration_secs;
                    }
                    if accent.is_some() {
                        product.accent = accent.clone();
                    }
                    if image.is_some() {
                        product.image = image.clone();
                    }
                }
            }

            Event::ProductRetired { product_id } => {
                if let Some(product) = state.products.get_mut(product_id) {
                    // Retired, never deleted: historical sessions still point at it and
                    // must keep resolving to a name and a dose.
                    product.retired = true;
                }
            }

            Event::SessionStarted {
                session_id,
                product_id,
                started_at,
            } => {
                state
                    .sessions
                    .entry(session_id.clone())
                    .or_insert_with(|| Session {
                        id: session_id.clone(),
                        product_id: product_id.clone(),
                        started_at: *started_at,
                        ended_at: None,
                        pauses: Vec::new(),
                    });
            }

            Event::SessionEnded {
                session_id,
                ended_at,
            } => {
                if let Some(session) = state.sessions.get_mut(session_id) {
                    // Earliest end wins. Two devices both marking a pouch done is a
                    // normal race, and the first observation is the accurate one.
                    session.ended_at = Some(match session.ended_at {
                        Some(existing) => existing.min(*ended_at),
                        None => *ended_at,
                    });
                }
            }

            Event::SessionPaused {
                session_id,
                paused_at,
            } => {
                if let Some(session) = state.sessions.get_mut(session_id) {
                    // Two devices pausing the same pouch is a normal race, and the
                    // pause is idempotent: while one is already open, a second one
                    // describes the same physical fact. Only its timestamp can be
                    // better, and earlier is better -- absorption stopped when the
                    // pouch came out, not when the slower device noticed.
                    match session.pauses.last_mut() {
                        Some(open) if open.resumed_at.is_none() => {
                            open.paused_at = open.paused_at.min(*paused_at);
                        }
                        _ => {
                            session.pauses.push(Pause {
                                paused_at: *paused_at,
                                resumed_at: None,
                            });
                            session.pauses.sort_by_key(|p| p.paused_at);
                        }
                    }
                }
            }

            Event::SessionResumed {
                session_id,
                resumed_at,
            } => {
                if let Some(session) = state.sessions.get_mut(session_id) {
                    match session.pauses.last_mut() {
                        // Closing the open rest. Earliest resume wins for the mirror
                        // reason the earliest pause does: delivery restarted when the
                        // pouch went back in.
                        Some(open) if open.resumed_at.is_none() => {
                            open.resumed_at = Some(*resumed_at);
                        }
                        // A resume with no matching pause. Out-of-order delivery makes
                        // this ordinary, and the pause that explains it may still be
                        // coming, so it is dropped rather than invented -- a resume on
                        // its own carries no absorption information.
                        _ => {}
                    }
                }
            }

            Event::SessionDiscarded { session_id } => {
                state.sessions.remove(session_id);
                discarded.push(session_id);
            }

            Event::SubjectUpdated {
                body_mass_kg,
                metabolism_factor,
            } => {
                if body_mass_kg.is_some() {
                    state.body_mass_kg = *body_mass_kg;
                }
                if metabolism_factor.is_some() {
                    state.metabolism_factor = *metabolism_factor;
                }
            }
        }
    }

    // A discard may have arrived before the entries it discards.
    for session_id in discarded {
        state.sessions.remove(session_id);
    }

    state
}

/// The variety the first device starts with. Everything else is added by the user, and
/// this one is only a starting point rather than anything special.
pub fn seed_products(device_id: &str) -> Vec<LogEntry> {
    vec![LogEntry::new(
        device_id,
        Event::ProductDefined {
            product_id: new_id(),
            name: "CUBA PEACH".into(),
            substance_id: "nicotine".into(),
            route_id: "buccal_pouch".into(),
            nominal_mg: 10.4,
            // Left open so the substance model decides. A number here would silently
            // outrank it, and this is a plain pouch with nothing special about it.
            default_duration_secs: None,
            accent: Some("#F2994A".into()),
            image: None,
        },
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap()
    }

    fn entry(id: &str, recorded: i64, device: &str, event: Event) -> LogEntry {
        LogEntry {
            id: id.into(),
            recorded_at: at(recorded),
            device_id: device.into(),
            event,
        }
    }

    fn cuba() -> Event {
        Event::ProductDefined {
            product_id: "prod-cuba".into(),
            name: "CUBA PEACH".into(),
            substance_id: "nicotine".into(),
            route_id: "buccal_pouch".into(),
            nominal_mg: 10.4,
            default_duration_secs: Some(1800.0),
            accent: Some("#F2994A".into()),
            image: None,
        }
    }

    #[test]
    fn a_product_defined_on_one_device_shows_up_in_the_state() {
        let state = project(&[entry("e1", 0, "phone", cuba())]);
        let products = state.active_products();
        assert_eq!(products.len(), 1);
        assert_eq!(products[0].name, "CUBA PEACH");
        assert_eq!(products[0].nominal_mg, 10.4);
    }

    #[test]
    fn a_session_started_on_one_device_can_be_ended_on_another() {
        let state = project(&[
            entry("e1", 0, "phone", cuba()),
            entry(
                "e2",
                10,
                "phone",
                Event::SessionStarted {
                    session_id: "s1".into(),
                    product_id: "prod-cuba".into(),
                    started_at: at(10),
                },
            ),
            // Recorded by the laptop, which never saw the start until it synced.
            entry(
                "e3",
                40,
                "laptop",
                Event::SessionEnded {
                    session_id: "s1".into(),
                    ended_at: at(1810),
                },
            ),
        ]);

        let session = &state.sessions["s1"];
        assert!(!session.is_active());
        assert_eq!(session.elapsed(at(9999)).num_minutes(), 30);
    }

    #[test]
    fn an_open_session_reports_how_long_it_has_been_in() {
        let state = project(&[
            entry("e1", 0, "phone", cuba()),
            entry(
                "e2",
                10,
                "phone",
                Event::SessionStarted {
                    session_id: "s1".into(),
                    product_id: "prod-cuba".into(),
                    started_at: at(10),
                },
            ),
        ]);

        let open = state.open_sessions();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].elapsed(at(910)).num_minutes(), 15);
        assert_eq!(
            state.product(&open[0].product_id).unwrap().name,
            "CUBA PEACH"
        );
    }

    #[test]
    fn the_order_entries_arrive_in_does_not_change_the_result() {
        let entries = vec![
            entry("e1", 0, "phone", cuba()),
            entry(
                "e2",
                10,
                "phone",
                Event::SessionStarted {
                    session_id: "s1".into(),
                    product_id: "prod-cuba".into(),
                    started_at: at(10),
                },
            ),
            entry(
                "e3",
                40,
                "laptop",
                Event::SessionEnded {
                    session_id: "s1".into(),
                    ended_at: at(1810),
                },
            ),
            entry(
                "e4",
                50,
                "phone",
                Event::ProductUpdated {
                    product_id: "prod-cuba".into(),
                    name: None,
                    nominal_mg: Some(12.0),
                    default_duration_secs: None,
                    accent: None,
                    image: None,
                },
            ),
        ];

        let forward = project(&entries);
        let mut backward = entries.clone();
        backward.reverse();
        let mut shuffled = entries.clone();
        shuffled.swap(0, 2);
        shuffled.swap(1, 3);

        assert_eq!(
            forward,
            project(&backward),
            "reversed arrival must fold identically"
        );
        assert_eq!(
            forward,
            project(&shuffled),
            "so must any other arrival order"
        );
    }

    #[test]
    fn two_devices_ending_the_same_session_settle_on_the_earlier_time() {
        let base = vec![
            entry("e1", 0, "phone", cuba()),
            entry(
                "e2",
                10,
                "phone",
                Event::SessionStarted {
                    session_id: "s1".into(),
                    product_id: "prod-cuba".into(),
                    started_at: at(10),
                },
            ),
        ];

        let mut race = base.clone();
        race.push(entry(
            "e3",
            100,
            "phone",
            Event::SessionEnded {
                session_id: "s1".into(),
                ended_at: at(1800),
            },
        ));
        race.push(entry(
            "e4",
            110,
            "laptop",
            Event::SessionEnded {
                session_id: "s1".into(),
                ended_at: at(1900),
            },
        ));

        let state = project(&race);
        assert_eq!(
            state.sessions["s1"].ended_at,
            Some(at(1800)),
            "the first observation of the end is the accurate one"
        );

        // And the outcome must not depend on which record arrived first.
        race.swap(2, 3);
        assert_eq!(project(&race).sessions["s1"].ended_at, Some(at(1800)));
    }

    #[test]
    fn concurrent_edits_to_different_fields_both_survive() {
        let state = project(&[
            entry("e1", 0, "phone", cuba()),
            entry(
                "e2",
                10,
                "phone",
                Event::ProductUpdated {
                    product_id: "prod-cuba".into(),
                    name: Some("CUBA PEACH X".into()),
                    nominal_mg: None,
                    default_duration_secs: None,
                    accent: None,
                    image: None,
                },
            ),
            entry(
                "e3",
                11,
                "laptop",
                Event::ProductUpdated {
                    product_id: "prod-cuba".into(),
                    name: None,
                    nominal_mg: Some(16.0),
                    default_duration_secs: None,
                    accent: None,
                    image: None,
                },
            ),
        ]);

        let product = state.product("prod-cuba").unwrap();
        assert_eq!(product.name, "CUBA PEACH X", "the phone's rename survived");
        assert_eq!(
            product.nominal_mg, 16.0,
            "and so did the laptop's dose change"
        );
    }

    #[test]
    fn a_retired_product_leaves_the_home_screen_but_not_the_history() {
        let state = project(&[
            entry("e1", 0, "phone", cuba()),
            entry(
                "e2",
                10,
                "phone",
                Event::SessionStarted {
                    session_id: "s1".into(),
                    product_id: "prod-cuba".into(),
                    started_at: at(10),
                },
            ),
            entry(
                "e3",
                20,
                "phone",
                Event::ProductRetired {
                    product_id: "prod-cuba".into(),
                },
            ),
        ]);

        assert!(state.active_products().is_empty(), "no longer offered");
        assert_eq!(
            state.product("prod-cuba").unwrap().name,
            "CUBA PEACH",
            "but past sessions must still resolve to a name and a dose"
        );
    }

    #[test]
    fn a_discard_applies_even_if_it_arrives_before_the_session() {
        let out_of_order = vec![
            entry(
                "e3",
                5,
                "phone",
                Event::SessionDiscarded {
                    session_id: "s1".into(),
                },
            ),
            entry("e1", 0, "phone", cuba()),
            entry(
                "e2",
                10,
                "phone",
                Event::SessionStarted {
                    session_id: "s1".into(),
                    product_id: "prod-cuba".into(),
                    started_at: at(10),
                },
            ),
        ];
        assert!(
            project(&out_of_order).sessions.is_empty(),
            "a mistaken entry must stay deleted no matter when the discard lands"
        );
    }

    #[test]
    fn a_replayed_start_does_not_create_a_second_session() {
        let start = Event::SessionStarted {
            session_id: "s1".into(),
            product_id: "prod-cuba".into(),
            started_at: at(10),
        };
        let state = project(&[
            entry("e1", 0, "phone", cuba()),
            entry("e2", 10, "phone", start.clone()),
            entry("e2", 10, "phone", start),
        ]);
        assert_eq!(state.sessions.len(), 1);
    }

    #[test]
    fn buttons_keep_a_stable_order_between_launches() {
        let mut entries = vec![entry("e1", 0, "phone", cuba())];
        for (i, name) in ["ZYN", "AROMA KING", "Killa"].iter().enumerate() {
            entries.push(entry(
                &format!("p{i}"),
                i as i64,
                "phone",
                Event::ProductDefined {
                    product_id: format!("prod-{i}"),
                    name: (*name).into(),
                    substance_id: "nicotine".into(),
                    route_id: "buccal_pouch".into(),
                    nominal_mg: 10.0,
                    default_duration_secs: None,
                    accent: None,
                    image: None,
                },
            ));
        }
        let state = project(&entries);
        let names: Vec<&str> = state
            .active_products()
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(names, vec!["AROMA KING", "CUBA PEACH", "Killa", "ZYN"]);
    }

    #[test]
    fn the_seeded_variety_is_the_one_that_was_asked_for() {
        let state = project(&seed_products("phone"));
        let product = state.active_products()[0];
        assert_eq!(product.name, "CUBA PEACH");
        assert_eq!(product.nominal_mg, 10.4);
        assert_eq!(product.route_id, "buccal_pouch");
    }
}
