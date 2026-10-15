//! Zero-knowledge sync server for the consumption tracker.
//!
//! Run `tracker-server bootstrap` once to create the account and print an invite code
//! for the first device, then `tracker-server serve`.

use tracker_server::{api, db, enroll, maintenance, tunnel};

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use rusqlite::params;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

/// Ciphertext records are small; this is generous for a full push batch and keeps a
/// malformed client from exhausting memory.
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// How often housekeeping runs. Nothing here is urgent -- the point is that it happens
/// at all on a server that stays up for months, rather than only at startup.
const SWEEP_INTERVAL_SECS: u64 = 900;

/// Run maintenance on a timer for as long as the server is up.
fn spawn_sweeper(db: Arc<Mutex<rusqlite::Connection>>, retention: maintenance::Retention) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(SWEEP_INTERVAL_SECS));
        loop {
            ticker.tick().await;
            let outcome = {
                let conn = db.lock().unwrap();
                maintenance::sweep(&conn, retention)
            };
            match outcome {
                // Stay quiet when there was nothing to do, which is the normal case.
                Ok(report) if report.is_empty() => {}
                Ok(report) => tracing::info!(?report, "maintenance sweep"),
                Err(error) => tracing::error!(%error, "maintenance sweep failed"),
            }
        }
    });
}

const DEFAULT_ACCOUNT: &str = "primary";

fn database_path() -> PathBuf {
    std::env::var("TRACKER_DB")
        .unwrap_or_else(|_| "tracker-server.db".to_string())
        .into()
}

fn ensure_account(conn: &rusqlite::Connection, account_id: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO accounts (id, created_at) VALUES (?1, ?2)",
        params![account_id, db::now()],
    )?;
    Ok(())
}

fn bootstrap() -> Result<(), Box<dyn std::error::Error>> {
    let conn = db::open(&database_path())?;
    ensure_account(&conn, DEFAULT_ACCOUNT)?;

    // The tunnel identity is what clients pin. Print the fingerprint here because
    // fetching the key over the network proves nothing -- an interceptor would just
    // hand over its own. Comparing it out of band is the entire point.
    let identity = tunnel::load_or_create(&conn)?;
    println!("Server tunnel key: {}", identity.fingerprint());
    println!("Pin this in every client and verify it on first connect.");
    println!();

    let device_count = enroll::device_count(&conn, DEFAULT_ACCOUNT)?;
    if device_count > 0 {
        eprintln!(
            "Account already has {device_count} device(s). Mint further invites from an \
             enrolled device via POST /v1/enroll/invite."
        );
        return Ok(());
    }

    let (code, expires_at, reused) = enroll::bootstrap_invite(&conn, DEFAULT_ACCOUNT)?;
    if reused {
        eprintln!("An unclaimed invite is still valid; reusing it.");
    }
    let expires_in = (expires_at - db::now()).max(0) / 60;
    println!("Invite code: {code}");
    println!("Valid for {expires_in} minutes. Enter it on the first device.");
    Ok(())
}

async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let path = database_path();
    let conn = db::open(&path)?;
    ensure_account(&conn, DEFAULT_ACCOUNT)?;

    let identity = tunnel::load_or_create(&conn)?;
    tracing::info!(fingerprint = %identity.fingerprint(), "tunnel identity loaded");

    let retention = maintenance::Retention::from_env();
    if retention.event_days.is_some() || retention.audit_days.is_some() {
        tracing::info!(?retention, "age-based deletion is enabled");
    }

    let state = api::AppState::new(Arc::new(Mutex::new(conn)));
    spawn_sweeper(state.db.clone(), retention);

    let app = api::router(state)
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http());

    let bind: SocketAddr = std::env::var("TRACKER_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8787".to_string())
        .parse()?;

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, database = %path.display(), "sync server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutting down");
        })
        .await?;
    Ok(())
}

fn sweep_once() -> Result<(), Box<dyn std::error::Error>> {
    let conn = db::open(&database_path())?;
    let report = maintenance::sweep(&conn, maintenance::Retention::from_env())?;
    println!("{report:#?}");
    Ok(())
}

/// Irreversibly delete an account and everything belonging to it.
///
/// Deliberately not an HTTP endpoint: this is one compromised token away from being a
/// remote wipe if it were.
fn purge_account(account_id: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let Some(account_id) = account_id else {
        eprintln!("usage: tracker-server purge-account <account-id>");
        std::process::exit(2);
    };

    let mut conn = db::open(&database_path())?;
    let devices = enroll::device_count(&conn, &account_id)?;
    let events: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events WHERE account_id = ?1",
        params![account_id],
        |row| row.get(0),
    )?;

    eprintln!("About to permanently delete account '{account_id}':");
    eprintln!("  {devices} device(s), {events} record(s), plus keys and audit log.");
    eprintln!("This cannot be undone. Type the account id again to confirm:");

    let mut confirmation = String::new();
    std::io::stdin().read_line(&mut confirmation)?;
    if confirmation.trim() != account_id {
        eprintln!("Confirmation did not match. Nothing was deleted.");
        std::process::exit(1);
    }

    maintenance::purge_account(&mut conn, &account_id)?;
    println!("Account '{account_id}' deleted.");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tracker_server=info,tower_http=info".into()),
        )
        .init();

    match std::env::args().nth(1).as_deref() {
        Some("bootstrap") => bootstrap(),
        Some("serve") | None => serve().await,
        Some("sweep") => sweep_once(),
        Some("purge-account") => purge_account(std::env::args().nth(2)),
        Some(other) => {
            eprintln!(
                "unknown command: {other}\n\
                 usage: tracker-server [bootstrap|serve|sweep|purge-account <id>]"
            );
            std::process::exit(2);
        }
    }
}
