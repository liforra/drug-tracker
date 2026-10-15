//! Desktop notifications, over the same session bus the tray already lives on.
//!
//! Deliberately best-effort: a missing notification daemon is a normal state on a bare
//! session, and a tracker that refuses to run because nothing is listening would be
//! worse than one that quietly says nothing.

use std::collections::HashMap;

use zbus::zvariant::Value;

/// Send a notification. Errors are swallowed by the caller on purpose.
pub fn send(summary: &str, body: &str) -> zbus::Result<()> {
    let connection = zbus::blocking::Connection::session()?;
    let hints: HashMap<&str, Value> = HashMap::new();
    connection.call_method(
        Some("org.freedesktop.Notifications"),
        "/org/freedesktop/Notifications",
        Some("org.freedesktop.Notifications"),
        "Notify",
        &(
            "Snus Tracker",
            // 0 means "new notification" rather than replacing an existing one.
            0u32,
            "",
            summary,
            body,
            &[] as &[&str],
            hints,
            // Milliseconds. Long enough to notice, short enough not to pile up.
            8000i32,
        ),
    )?;
    Ok(())
}
