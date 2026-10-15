//! What the log adds up to, with the pouch going in and out.

use chrono::{DateTime, Duration, TimeZone, Utc};
use tracker_core::{
    levels,
    log::{Event, LogEntry, State, project, seed_products},
};

fn at(minute: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap() + Duration::minutes(minute)
}

fn entry(id: &str, minute: i64, event: Event) -> LogEntry {
    LogEntry {
        id: id.to_string(),
        recorded_at: at(minute),
        device_id: "test".into(),
        event,
    }
}

/// The seeded product, and a projector that replays it plus whatever else is given.
///
/// The product id is generated, so it has to be captured once and reused: seeding twice
/// would produce two different products and sessions pointing at neither.
fn seeded() -> (Vec<LogEntry>, String) {
    let entries: Vec<LogEntry> = seed_products("test")
        .into_iter()
        .enumerate()
        .map(|(i, mut seeded)| {
            // Pin ids and timestamps so the fold is deterministic.
            seeded.id = format!("seed{i}");
            seeded.recorded_at = at(0);
            seeded
        })
        .collect();
    let product_id = match &entries[0].event {
        Event::ProductDefined { product_id, .. } => product_id.clone(),
        _ => panic!("first seeded event should define a product"),
    };
    (entries, product_id)
}

fn state_with(seed: &[LogEntry], events: Vec<LogEntry>) -> State {
    let mut entries = seed.to_vec();
    entries.extend(events);
    project(&entries)
}

fn session_started(id: &str, minute: i64, product_id: &str) -> LogEntry {
    entry(
        id,
        minute,
        Event::SessionStarted {
            session_id: "s1".into(),
            product_id: product_id.to_string(),
            started_at: at(minute),
        },
    )
}

#[test]
fn resting_the_pouch_stops_absorption_but_not_elimination() {
    let (seed, product) = seeded();
    let uninterrupted = state_with(&seed, vec![session_started("e1", 0, &product)]);
    let level_straight = levels::build_at(&uninterrupted, at(60)).nicotine_at(at(60));

    // Same wall-clock hour, but the pouch spent the middle half of it on a desk.
    let rested = state_with(&seed, vec![
        session_started("e1", 0, &product),
        entry("e2", 15, Event::SessionPaused { session_id: "s1".into(), paused_at: at(15) }),
        entry("e3", 45, Event::SessionResumed { session_id: "s1".into(), resumed_at: at(45) }),
    ]);
    let level_rested = levels::build_at(&rested, at(60)).nicotine_at(at(60));

    assert!(
        level_rested < level_straight,
        "a rested pouch must deliver less over the same hour ({level_rested:.1} vs {level_straight:.1})"
    );
    assert!(level_rested > 0.0, "resting must not erase what was already absorbed");
}

#[test]
fn a_rested_pouch_keeps_what_it_has_not_released_yet() {
    let (seed, product) = seeded();
    let state = state_with(&seed, vec![
        session_started("e1", 0, &product),
        entry("e2", 10, Event::SessionPaused { session_id: "s1".into(), paused_at: at(10) }),
        entry("e3", 240, Event::SessionResumed { session_id: "s1".into(), resumed_at: at(240) }),
    ]);
    let curves = levels::build_at(&state, at(250));
    // Four hours after the first ten minutes, nearly all of that early dose is gone --
    // so anything still arriving has to be coming out of the pouch that went back in.
    assert!(
        curves.nicotine_rate_at(at(245)) > 0.0,
        "a pouch that goes back in must start delivering again"
    );
}

#[test]
fn contact_time_is_what_the_pouch_spends_not_wall_clock() {
    let (seed, product) = seeded();
    let state = state_with(&seed, vec![
        session_started("e1", 0, &product),
        entry("e2", 5, Event::SessionPaused { session_id: "s1".into(), paused_at: at(5) }),
        entry("e3", 65, Event::SessionResumed { session_id: "s1".into(), resumed_at: at(65) }),
    ]);

    let session = &state.sessions["s1"];
    // Seventy minutes of session, ten of them with the pouch actually in.
    assert_eq!(session.elapsed(at(70)).num_minutes(), 70);
    assert_eq!(session.contact_duration(at(70)).num_minutes(), 10);
    assert!(session.is_paused() == false, "it went back in at minute 65");

    let left = levels::remaining_release(&state, session, at(70)).unwrap();
    assert_eq!(left.num_minutes(), 50, "resting must not burn the pouch's budget");
}

#[test]
fn a_pouch_still_resting_has_an_open_ended_pause() {
    let (seed, product) = seeded();
    let state = state_with(&seed, vec![
        session_started("e1", 0, &product),
        entry("e2", 20, Event::SessionPaused { session_id: "s1".into(), paused_at: at(20) }),
    ]);

    let session = &state.sessions["s1"];
    assert!(session.is_paused());
    assert_eq!(session.contact_duration(at(90)).num_minutes(), 20);
    // The clock stopped: an hour of resting adds nothing to what the pouch has spent.
    assert_eq!(
        levels::remaining_release(&state, session, at(90)).unwrap().num_minutes(),
        40
    );
}

#[test]
fn the_earliest_pause_wins_when_two_devices_race() {
    let (seed, product) = seeded();
    let state = state_with(&seed, vec![
        session_started("e1", 0, &product),
        // The laptop noticed late; the phone had it right.
        entry("e2", 30, Event::SessionPaused { session_id: "s1".into(), paused_at: at(30) }),
        entry("e3", 31, Event::SessionPaused { session_id: "s1".into(), paused_at: at(20) }),
    ]);

    let session = &state.sessions["s1"];
    assert_eq!(session.pauses.len(), 1, "one physical rest, one recorded pause");
    assert_eq!(session.contact_duration(at(90)).num_minutes(), 20);
}

/// The tray, the statistics window and the command line are three processes over one
/// SQLite file. A projection that never re-reads is a private opinion, and that is
/// exactly how a variety added in a terminal stayed invisible in the tray.
#[test]
fn a_tracker_picks_up_what_another_process_wrote() {
    use tracker_core::{
        crypto::keys::Dek,
        store::Store,
        tracker::Tracker,
    };

    let dir = std::env::temp_dir().join(format!("snus-refresh-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("records.db");
    let _ = std::fs::remove_file(&path);

    let dek = Dek::generate().unwrap();
    let open = || {
        let store = Store::open(&path).unwrap();
        Tracker::open(store, vec![(1, dek.clone())], "test").unwrap()
    };

    let mut writer = open();
    let mut reader = open();
    assert!(reader.state().active_products().is_empty());

    writer
        .define_product("CUBA BLACK", "nicotine", "buccal_pouch", 16.0, None, None, None)
        .unwrap();

    // Without a refresh the second view is stale, which is the bug this guards.
    assert!(reader.state().active_products().is_empty());
    assert!(reader.refresh().unwrap(), "a write elsewhere must be noticed");
    assert_eq!(reader.state().active_products().len(), 1);

    // And a refresh with nothing new must not claim a change: the tray redraws on it.
    assert!(!reader.refresh().unwrap());

    let _ = std::fs::remove_file(&path);
}
