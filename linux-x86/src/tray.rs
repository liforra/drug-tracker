//! The tray applet: the fast path.
//!
//! Logging a pouch has to be two clicks or it will not happen consistently, so this is
//! where the app actually lives. Statistics get a real window, launched from here as a
//! separate process -- egui wants the main thread's event loop, and fighting that just
//! to avoid one `exec` would be a bad trade.

use std::sync::mpsc;

use chrono::Utc;
use ksni::{
    Icon, MenuItem, ToolTip, Tray, TrayMethods,
    menu::{StandardItem, SubMenu},
};

use crate::worker::{Command, Snapshot};

pub struct SnusTray {
    pub snapshot: Snapshot,
    pub commands: mpsc::Sender<Command>,
}

impl SnusTray {
    fn send(&self, command: Command) {
        // A failed send means the worker is gone, which happens during shutdown.
        let _ = self.commands.send(command);
    }
}

impl Tray for SnusTray {
    fn id(&self) -> String {
        "de.liforra.snus-tracker".into()
    }

    fn title(&self) -> String {
        match &self.snapshot.open {
            Some(open) => format!("{} · {}", open.product_name, format_elapsed(open.started_at)),
            None => "Snus Tracker".into(),
        }
    }

    /// Drawn rather than looked up in a theme: a themed name that the icon set happens
    /// not to have leaves an invisible tray item, which is a miserable failure mode for
    /// something whose entire job is being one click away.
    fn icon_pixmap(&self) -> Vec<Icon> {
        vec![draw_icon(22, self.snapshot.open.is_some()), draw_icon(44, self.snapshot.open.is_some())]
    }

    fn tool_tip(&self) -> ToolTip {
        let mut description = match &self.snapshot.open {
            Some(open) => format!(
                "{} seit {}",
                open.product_name,
                format_elapsed(open.started_at)
            ),
            None => "Nichts aktiv".to_string(),
        };
        description.push_str(&format!(
            "\nNikotin ca. {:.1} ng/mL ({:+.2}/min)\nHeute {} Pouches",
            self.snapshot.nicotine_ng_ml,
            self.snapshot.nicotine_rate,
            self.snapshot.today_count
        ));
        if !self.snapshot.status.is_empty() {
            description.push('\n');
            description.push_str(&self.snapshot.status);
        }

        ToolTip {
            title: "Snus Tracker".into(),
            description,
            icon_name: String::new(),
            icon_pixmap: Vec::new(),
        }
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut items: Vec<MenuItem<Self>> = Vec::new();

        // An open session takes the top slot: ending it is the most likely next action.
        if let Some(open) = &self.snapshot.open {
            let session_id = open.session_id.clone();
            // Say what the pouch is doing, then what is left in it. "leer" is worth
            // surfacing: a spent pouch in your lip delivers nothing, so the only reason
            // to keep it there is habit.
            let state = if open.paused { "ruht seit" } else { "seit" };
            let left = match open.release_left {
                Some(left) if left.num_seconds() == 0 => " · leer".to_string(),
                Some(left) => format!(" · noch {}", format_duration(left)),
                None => String::new(),
            };
            items.push(
                StandardItem {
                    label: format!(
                        "■  {} · {state} {}{left}",
                        open.product_name,
                        format_elapsed(open.started_at)
                    ),
                    activate: Box::new(move |tray: &mut Self| {
                        tray.send(Command::EndSession(session_id.clone()));
                    }),
                    ..Default::default()
                }
                .into(),
            );

            let session_id = open.session_id.clone();
            let paused = open.paused;
            items.push(
                StandardItem {
                    label: if paused {
                        "▶  Wieder rein".into()
                    } else {
                        "⏸  Pouch rausnehmen (ruhen)".to_string()
                    },
                    activate: Box::new(move |tray: &mut Self| {
                        let id = session_id.clone();
                        tray.send(if paused {
                            Command::ResumeSession(id)
                        } else {
                            Command::PauseSession(id)
                        });
                    }),
                    ..Default::default()
                }
                .into(),
            );
            items.push(MenuItem::Separator);
        }

        if self.snapshot.locked {
            items.push(
                StandardItem { label: "Gesperrt — kein gültiges Lease".into(), enabled: false, ..Default::default() }
                    .into(),
            );
        } else if self.snapshot.products.is_empty() {
            items.push(
                StandardItem { label: "Keine Sorten angelegt".into(), enabled: false, ..Default::default() }
                    .into(),
            );
        } else {
            for product in &self.snapshot.products {
                let product_id = product.id.clone();
                let busy = self.snapshot.open.is_some();
                items.push(
                    StandardItem {
                        label: format!("▶  {} · {:.1} mg", product.name, product.nominal_mg),
                        // One at a time: two pouches at once is not a thing, and an
                        // accidental double-start is a record you have to go and fix.
                        enabled: !busy,
                        activate: Box::new(move |tray: &mut Self| {
                            tray.send(Command::StartSession(product_id.clone()));
                        }),
                        ..Default::default()
                    }
                    .into(),
                );
            }
        }

        items.push(MenuItem::Separator);
        items.push(
            StandardItem {
                label: "Statistik…".into(),
                activate: Box::new(|tray: &mut Self| tray.send(Command::OpenStats)),
                ..Default::default()
            }
            .into(),
        );

        items.push(
            SubMenu {
                label: "Mehr".into(),
                submenu: vec![
                    StandardItem {
                        label: if self.snapshot.online {
                            format!("Synchronisieren ({} offen)", self.snapshot.pending)
                        } else {
                            "Offline".into()
                        },
                        enabled: self.snapshot.online,
                        activate: Box::new(|tray: &mut Self| tray.send(Command::Sync)),
                        ..Default::default()
                    }
                    .into(),
                    StandardItem {
                        label: "Neues Gerät freischalten".into(),
                        enabled: self.snapshot.online,
                        activate: Box::new(|tray: &mut Self| tray.send(Command::Approve)),
                        ..Default::default()
                    }
                    .into(),
                ],
                ..Default::default()
            }
            .into(),
        );

        items.push(MenuItem::Separator);
        items.push(
            StandardItem {
                label: "Beenden".into(),
                activate: Box::new(|tray: &mut Self| tray.send(Command::Quit)),
                ..Default::default()
            }
            .into(),
        );

        items
    }
}

/// "12 min" / "1 h 05" -- the number the user actually wants at a glance.
pub fn format_elapsed(started_at: chrono::DateTime<Utc>) -> String {
    format_duration(Utc::now() - started_at)
}

pub fn format_duration(span: chrono::Duration) -> String {
    let minutes = span.num_minutes().max(0);
    if minutes < 60 {
        format!("{minutes} min")
    } else {
        format!("{} h {:02}", minutes / 60, minutes % 60)
    }
}

/// A filled ring when something is active, a hollow one when not.
///
/// ksni wants ARGB32, and network byte order, which on a little-endian machine means
/// writing the bytes A,R,G,B in that order rather than storing a u32.
fn draw_icon(size: i32, active: bool) -> Icon {
    let dimension = size as usize;
    let mut data = vec![0u8; dimension * dimension * 4];

    let centre = (dimension as f32 - 1.0) / 2.0;
    let outer = centre - 1.0;
    let inner = outer * 0.55;

    // Warm amber when a pouch is in, muted grey when idle.
    let (r, g, b) = if active { (0xF2, 0x99, 0x4A) } else { (0xA0, 0xA4, 0xAC) };

    for y in 0..dimension {
        for x in 0..dimension {
            let dx = x as f32 - centre;
            let dy = y as f32 - centre;
            let distance = (dx * dx + dy * dy).sqrt();

            // Antialias the edges by fading over the last pixel, otherwise a small
            // circle reads as a jagged blob at tray sizes.
            let coverage = if active {
                (outer - distance + 0.5).clamp(0.0, 1.0)
            } else {
                let outside = (outer - distance + 0.5).clamp(0.0, 1.0);
                let hole = (distance - inner + 0.5).clamp(0.0, 1.0);
                outside * hole
            };
            if coverage <= 0.0 {
                continue;
            }

            let offset = (y * dimension + x) * 4;
            data[offset] = (255.0 * coverage) as u8;
            data[offset + 1] = r;
            data[offset + 2] = g;
            data[offset + 3] = b;
        }
    }

    Icon { width: size, height: size, data }
}

/// Run the tray until the worker asks to stop.
pub async fn run(
    initial: Snapshot,
    commands: mpsc::Sender<Command>,
    mut updates: tokio::sync::mpsc::UnboundedReceiver<Snapshot>,
) -> Result<(), Box<dyn std::error::Error>> {
    let handle = SnusTray { snapshot: initial, commands: commands.clone() }.spawn().await?;

    // The elapsed time in the title has to keep moving without anything happening, so
    // nudge the tray on a timer as well as on state changes.
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));

    loop {
        tokio::select! {
            snapshot = updates.recv() => match snapshot {
                Some(snapshot) => {
                    if snapshot.quit {
                        handle.shutdown().await;
                        return Ok(());
                    }
                    handle.update(move |tray: &mut SnusTray| tray.snapshot = snapshot).await;
                }
                None => return Ok(()),
            },
            _ = tick.tick() => {
                if handle.is_closed() {
                    return Ok(());
                }
                // Touch the tray so the "seit N min" label re-renders.
                handle.update(|_: &mut SnusTray| {}).await;
            }
            _ = tokio::signal::ctrl_c() => {
                handle.shutdown().await;
                return Ok(());
            }
        }
    }
}
