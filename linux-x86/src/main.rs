//! Snus tracker for Linux.
//!
//! Two faces on one binary. `snus` with no arguments runs the tray, which is where
//! logging happens because logging has to be fast. `snus stats` opens the window, which
//! is where you read what the log adds up to.

mod config;
// Curves come from the core so the phone and the laptop cannot disagree about them.
pub use tracker_core::levels;
mod notify;
mod qr;
mod session;
mod stats;
mod tray;
mod worker;

use std::process::ExitCode;

fn usage() {
    eprintln!(
        "snus — Konsum-Tracker\n\
         \n\
         snus                          Tray starten (Standard)\n\
         snus stats                    Statistikfenster öffnen\n\
         snus enroll <url> <key> <code> [name]\n\
                                       Dieses Gerät am Server anmelden\n\
         snus add <name> <mg>          Sorte anlegen\n\
         snus body <kg> [faktor]       Körpergewicht setzen (Default 75 kg)\n\
         snus dauer <sorte> <minuten>  Wie lange diese Sorte abgibt\n\
         snus remove <sorte>           Sorte ausblenden (Verlauf bleibt)\n\
         snus start <sorte>            Pouch rein (Name oder ID, Teiltreffer reicht)\n\
         snus stop                     Pouch raus\n\
         snus pause                    Pouch raus zum Ruhen, Session läuft weiter\n\
         snus resume                   Pouch wieder rein\n\
         snus discard                  Laufende Session verwerfen (Fehlgriff)\n\
         snus status                   Aktuellen Stand ausgeben\n\
         snus approve                  Neu angemeldete Geräte freischalten\n\
         snus invite                   Einladung für ein neues Gerät (QR-Code)\n\
         \n\
         <key> ist der base64-Schlüssel aus `tracker-server bootstrap`."
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        None => run_tray(),
        Some("stats") => stats::run(),
        Some("enroll") => enroll(&args[1..]),
        Some("add") => add_product(&args[1..]),
        Some("body") => set_body(&args[1..]),
        Some("dauer") => set_duration(&args[1..]),
        Some("remove") => remove_product(&args[1..]),
        Some("start") => start_session(&args[1..]),
        Some("stop") => stop_session(),
        Some("pause") => pause_session(),
        Some("resume") => resume_session(),
        Some("discard") => discard_session(),
        Some("status") => status(),
        Some("approve") => approve(),
        Some("invite") => invite(),
        Some("-h" | "--help" | "help") => {
            usage();
            return ExitCode::SUCCESS;
        }
        Some(other) => {
            eprintln!("Unbekannter Befehl: {other}\n");
            usage();
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Fehler: {error}");
            ExitCode::FAILURE
        }
    }
}

type Result = std::result::Result<(), Box<dyn std::error::Error>>;

fn run_tray() -> Result {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        let (updates_tx, mut updates_rx) = tokio::sync::mpsc::unbounded_channel();
        let commands = worker::spawn(updates_tx);

        // Wait for the worker's first snapshot so the tray never appears empty.
        let initial = updates_rx.recv().await.unwrap_or_default();
        tray::run(initial, commands, updates_rx).await
    })
}

fn enroll(args: &[String]) -> Result {
    let [url, key, code, rest @ ..] = args else {
        usage();
        return Err("enroll braucht <url> <key> <code>".into());
    };
    let name = rest
        .first()
        .cloned()
        .unwrap_or_else(|| hostname().unwrap_or_else(|| "linux".into()));

    let device_id = session::enroll(url, key, code, &name)?;
    println!("Angemeldet als '{name}' (Geräte-ID {device_id}).");
    println!("Falls dies nicht das erste Gerät ist: `snus approve` auf einem bereits");
    println!("angemeldeten Gerät ausführen, damit dieses hier einen Datenschlüssel bekommt.");
    Ok(())
}

fn add_product(args: &[String]) -> Result {
    let [name, mg] = args else {
        return Err("add braucht <name> <mg>".into());
    };
    let nominal_mg: f64 = mg.replace(',', ".").parse()?;

    let mut session = session::Session::open()?;
    let id = session.tracker.define_product(
        name,
        "nicotine",
        "buccal_pouch",
        nominal_mg,
        // Inherit the substance model's release profile unless told otherwise.
        None,
        None,
        None,
    )?;
    session.sync()?;
    println!("Sorte '{name}' ({nominal_mg} mg) angelegt: {id}");
    Ok(())
}

/// Resolve a product by id or by a case-insensitive substring of its name, so the
/// common case is `snus start peach` rather than pasting a UUID.
/// Resolve a variety by id or by a fragment of its name.
///
/// Refuses an ambiguous match rather than guessing: acting on the wrong variety is a
/// record you then have to go and correct.
fn find_product(
    state: &tracker_core::log::State,
    query: &str,
) -> std::result::Result<(String, String), Box<dyn std::error::Error>> {
    let needle = query.to_lowercase();
    let matches: Vec<(String, String)> = state
        .active_products()
        .into_iter()
        .filter(|p| p.id == query || p.name.to_lowercase().contains(&needle))
        .map(|p| (p.id.clone(), p.name.clone()))
        .collect();

    match matches.len() {
        0 => Err(format!("Keine Sorte passt zu '{query}'").into()),
        1 => Ok(matches.into_iter().next().unwrap()),
        _ => {
            let names: Vec<String> = matches.into_iter().map(|(_, n)| n).collect();
            Err(format!("'{query}' passt auf mehrere: {}", names.join(", ")).into())
        }
    }
}

fn start_session(args: &[String]) -> Result {
    let Some(query) = args.first() else {
        return Err("start braucht <sorte>".into());
    };
    let mut session = session::Session::open()?;
    let (product_id, name) = find_product(session.tracker.state(), query)?;

    if let Some(open) = session.tracker.state().open_sessions().first() {
        return Err(format!(
            "Es läuft schon eine Session seit {} — erst `snus stop`",
            tray::format_elapsed(open.started_at)
        )
        .into());
    }

    session.tracker.start_session(&product_id)?;
    let _ = session.sync();
    println!("{name} gestartet.");
    Ok(())
}

fn stop_session() -> Result {
    let mut session = session::Session::open()?;
    let open = session
        .tracker
        .state()
        .open_sessions()
        .first()
        .map(|s| (s.id.clone(), s.started_at, s.product_id.clone()));

    let Some((session_id, started_at, product_id)) = open else {
        return Err("Es läuft gerade nichts.".into());
    };
    let name = session
        .tracker
        .state()
        .product(&product_id)
        .map(|p| p.name.clone())
        .unwrap_or_else(|| "Sorte".into());

    session.tracker.end_session(&session_id)?;
    let _ = session.sync();
    println!("{name} beendet nach {}.", tray::format_elapsed(started_at));
    Ok(())
}

/// Hide a variety from the buttons.
///
/// Retiring, not deleting: the log is append-only and sessions already recorded against
/// this variety still need it to compute their curves. A "delete" that silently
/// rewrote history would be the worse of the two options by a distance.
fn remove_product(args: &[String]) -> Result {
    let Some(query) = args.first() else {
        return Err("remove braucht <sorte>".into());
    };
    let mut session = session::Session::open()?;
    let (product_id, name) = find_product(session.tracker.state(), query)?;
    session.tracker.retire_product(&product_id)?;
    let _ = session.sync();
    println!("{name} ausgeblendet. Bisherige Sessions bleiben in der Rechnung.");
    Ok(())
}

/// How long a variety goes on releasing. Brands differ, and the number decides both
/// the shape of the curve and when the tray calls the pouch spent.
fn set_duration(args: &[String]) -> Result {
    let [needle, minutes] = args else {
        return Err("dauer braucht <sorte> <minuten>".into());
    };
    let minutes: f64 = minutes.replace(',', ".").parse().map_err(|_| "Minuten sind keine Zahl")?;
    if !(1.0..=600.0).contains(&minutes) {
        return Err("Minuten müssen zwischen 1 und 600 liegen".into());
    }

    let mut session = session::Session::open()?;
    let product = find_product(session.tracker.state(), needle)?;
    session.tracker.update_product(
        &product.0,
        None,
        None,
        Some(minutes * 60.0),
        None,
        None,
    )?;
    let _ = session.sync();
    println!("{}: gibt jetzt über {minutes:.0} Minuten ab.", product.1);
    Ok(())
}

/// Body mass is the cheapest accuracy win there is: every concentration scales with it
/// and it needs no laboratory.
fn set_body(args: &[String]) -> Result {
    let [mass, rest @ ..] = args else {
        return Err("body braucht <kg> [faktor]".into());
    };
    let parse = |s: &str| s.replace(',', ".").parse::<f64>();
    let mass: f64 = parse(mass).map_err(|_| "Gewicht ist keine Zahl")?;
    let factor = match rest.first() {
        Some(f) => Some(parse(f).map_err(|_| "Faktor ist keine Zahl")?),
        None => None,
    };

    let mut session = session::Session::open()?;
    session.tracker.update_subject(Some(mass), factor)?;
    let _ = session.sync();

    match factor {
        Some(f) => println!("Gewicht {mass:.1} kg, Metabolismusfaktor {f:.2}."),
        None => println!("Gewicht {mass:.1} kg."),
    }
    Ok(())
}

/// Takes the pouch out without ending the session. Absorption stops, elimination does
/// not -- which is exactly the distinction the level display exists to make.
fn pause_session() -> Result {
    let mut session = session::Session::open()?;
    let open = session
        .tracker
        .state()
        .open_sessions()
        .first()
        .map(|s| (s.id.clone(), s.product_id.clone(), s.is_paused()));

    let Some((session_id, product_id, already_paused)) = open else {
        return Err("Es läuft gerade nichts.".into());
    };
    let name = session
        .tracker
        .state()
        .product(&product_id)
        .map(|p| p.name.clone())
        .unwrap_or_else(|| "Sorte".into());

    if already_paused {
        println!("{name} ruht bereits.");
        return Ok(());
    }

    session.tracker.pause_session(&session_id)?;
    let _ = session.sync();

    let state = session.tracker.state();
    let left = state
        .sessions
        .get(&session_id)
        .and_then(|s| levels::remaining_release(state, s, chrono::Utc::now()));
    match left {
        Some(left) => println!(
            "{name} ruht. Noch {} Freisetzung übrig.",
            tray::format_duration(left)
        ),
        None => println!("{name} ruht."),
    }
    Ok(())
}

fn resume_session() -> Result {
    let mut session = session::Session::open()?;
    let open = session
        .tracker
        .state()
        .open_sessions()
        .first()
        .map(|s| (s.id.clone(), s.product_id.clone(), s.is_paused()));

    let Some((session_id, product_id, paused)) = open else {
        return Err("Es läuft gerade nichts.".into());
    };
    let name = session
        .tracker
        .state()
        .product(&product_id)
        .map(|p| p.name.clone())
        .unwrap_or_else(|| "Sorte".into());

    if !paused {
        println!("{name} ist schon drin.");
        return Ok(());
    }

    session.tracker.resume_session(&session_id)?;
    let _ = session.sync();
    println!("{name} wieder drin.");
    Ok(())
}

/// Removes a session that should never have existed -- a mis-tap, a test. Distinct
/// from `stop`, which records a real consumption that has ended. Conflating the two
/// would mean the only way to undo a wrong tap is to write a wrong record.
fn discard_session() -> Result {
    let mut session = session::Session::open()?;
    let open = session
        .tracker
        .state()
        .open_sessions()
        .first()
        .map(|s| (s.id.clone(), s.product_id.clone()));

    let Some((session_id, product_id)) = open else {
        return Err("Es läuft gerade nichts.".into());
    };
    let name = session
        .tracker
        .state()
        .product(&product_id)
        .map(|p| p.name.clone())
        .unwrap_or_else(|| "Sorte".into());

    session.tracker.discard_session(&session_id)?;
    let _ = session.sync();
    println!("{name} verworfen — zählt nicht als Konsum.");
    Ok(())
}

fn status() -> Result {
    let session = session::Session::open()?;
    let state = session.tracker.state();
    let curves = levels::build(state);
    let now = chrono::Utc::now();

    println!("Verbindung: {}", if session.online { "online" } else { "offline" });
    println!("Nikotin:    {:.1} ng/mL", curves.nicotine_at(now));
    // The number that matches how a pouch feels. Receptors respond to change and
    // desensitise under a steady level, so the slope says more than the level does.
    println!("Anflutung:  {:+.2} ng/mL pro Minute", curves.nicotine_rate_at(now));
    println!("Cotinin:    {:.0} ng/mL", curves.cotinine_at(now));
    println!("Heute:      {} Pouches, {:.1} mg", levels::today_count(state), levels::today_mg(state));
    println!(
        "Körper:     {:.0} kg{}",
        curves.subject.body_mass_kg,
        if state.body_mass_kg.is_none() { " (Default — `snus body <kg>` setzen)" } else { "" }
    );

    match state.open_sessions().first() {
        Some(open) => {
            let name = state.product(&open.product_id).map(|p| p.name.as_str()).unwrap_or("?");
            let what = if open.is_paused() { "ruht seit" } else { "seit" };
            println!("Aktiv:      {name} {what} {}", tray::format_elapsed(open.started_at));
            if let Some(left) = levels::remaining_release(state, open, now) {
                if left.num_seconds() == 0 {
                    println!("Pouch:      leer — gibt nichts mehr ab");
                } else {
                    println!("Pouch:      noch {} Freisetzung", tray::format_duration(left));
                }
            }
        }
        None => println!("Aktiv:      nichts"),
    }

    println!("\nSorten:");
    for product in state.active_products() {
        println!("  {:<24} {:>5.1} mg   {}", product.name, product.nominal_mg, product.id);
    }
    Ok(())
}

fn approve() -> Result {
    let mut session = session::Session::open()?;
    let devices = session::approve_devices(&mut session)?;
    if devices.is_empty() {
        println!("Keine weiteren Geräte.");
    } else {
        println!("Neuer Datenschlüssel für {} Gerät(e) veröffentlicht.", devices.len());
    }
    Ok(())
}

/// Stellt eine Einladung für ein weiteres Gerät aus und zeigt sie als QR-Code.
///
/// Der Server kann das nicht von sich aus: Einladungen werden von einem bereits
/// angemeldeten Gerät ausgestellt, weil sonst der Serverbetreiber sich selbst
/// eines ausstellen könnte. Er bekäme damit zwar immer noch keinen Datenschlüssel
/// -- den hat er nie --, aber die Trennung sauber zu halten kostet nichts.
fn invite() -> Result {
    let session = session::Session::open()?;
    let response = session.client.create_invite()?;

    let code = response["code"].as_str().ok_or("Server lieferte keinen Code")?;
    let expires_at = response["expires_at"].as_i64().unwrap_or_default();
    let minutes = ((expires_at - chrono::Utc::now().timestamp()) / 60).max(0);

    let uri = qr::enrollment_uri(&session.config.server_url, &session.config.server_pub, code);

    println!();
    match qr::Qr::encode(&uri) {
        Ok(code) => qr::print(&code),
        // Ein fehlender QR-Code ist kein Grund, die Anmeldung zu verhindern --
        // die Werte darunter reichen zum Abtippen.
        Err(error) => eprintln!("(QR-Code nicht darstellbar: {error})"),
    }
    println!();
    println!("  Server-Adresse:   {}", session.config.server_url);
    println!("  Server-Schlüssel: {}", session.config.server_pub);
    println!("  Einladungscode:   {code}");
    println!();
    println!("  Gültig für {minutes} Minuten, einmalig einlösbar.");
    println!("  Danach auf diesem Gerät `snus approve` ausführen, damit das neue");
    println!("  Gerät den Datenschlüssel bekommt.");
    Ok(())
}

fn hostname() -> Option<String> {
    std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}
