//! The window: everything the phone app can do, on the desktop.
//!
//! The tray is for logging at a glance; this is the full client -- start, rest, end and
//! discard a session, tune and retire varieties, set body mass, invite and approve
//! devices, and read what the log adds up to. It mirrors the Android app screen for
//! screen so the two cannot drift into being different products.

use std::time::{Duration as StdDuration, Instant};

use chrono::{DateTime, Duration, Utc};
use eframe::egui::{
    self, Align, Color32, CornerRadius, FontId, Layout, Pos2, RichText, Sense, Stroke, StrokeKind,
    Vec2,
};

use crate::{
    levels::{self, Levels},
    qr,
    session::{self, Session},
    theme::{self, *},
    tray::{format_duration, format_elapsed},
};

/// How often the window re-reads the log. Another process (the tray, `snus add` in a
/// terminal, a sync from the phone) may have written to it, and without this the window
/// keeps showing a private, stale opinion.
const REFRESH: StdDuration = StdDuration::from_secs(3);

pub struct StatsApp {
    session: Option<Session>,
    error: Option<String>,
    levels: Option<Levels>,
    last_refresh: Instant,
    notice: Notice,

    new_name: String,
    new_mg: String,
    body_mass: String,
    show_settings: bool,
    tuning: Option<Tuning>,
    invite: Option<Invite>,
    enroll: EnrollForm,
}

/// A line of feedback under the header. Errors and confirmations look different on
/// purpose: one asks for attention, the other only for a glance.
#[derive(Default)]
struct Notice {
    text: String,
    is_error: bool,
}

struct Tuning {
    product_id: String,
    name: String,
    minutes: String,
}

#[derive(Default)]
struct EnrollForm {
    url: String,
    key: String,
    code: String,
    name: String,
}

/// An issued invitation together with its finished texture.
///
/// The texture is built once when the invitation is issued, not per frame:
/// `load_texture` uploads to the GPU, and doing that sixty times a second for a pattern
/// that never changes would be pure waste.
struct Invite {
    code: String,
    url: String,
    key: String,
    minutes: i64,
    texture: egui::TextureHandle,
}

struct OpenView {
    session_id: String,
    name: String,
    started_at: DateTime<Utc>,
    paused: bool,
    left: Option<Duration>,
}

struct ProductView {
    id: String,
    name: String,
    nominal_mg: f64,
    duration_secs: Option<f64>,
    accent: Option<Color32>,
}

/// An owned snapshot for one frame.
///
/// Rendering used to read straight from `self.session`, which meant every widget held an
/// immutable borrow while the buttons needed a mutable one. Copying the few values a
/// frame actually needs is cheaper than threading lifetimes through the UI.
struct View {
    online: bool,
    pending: i64,
    open: Option<OpenView>,
    nicotine: f64,
    rate: f64,
    cotinine: f64,
    tolerance: Option<f64>,
    today_count: usize,
    today_mg: f64,
    body_mass: f64,
    body_mass_is_default: bool,
    products: Vec<ProductView>,
}

impl StatsApp {
    fn view(&self) -> Option<View> {
        let session = self.session.as_ref()?;
        let curves = self.levels.as_ref()?;
        let state = session.tracker.state();
        let now = Utc::now();

        Some(View {
            online: session.online,
            pending: session.tracker.store().pending_count().unwrap_or(0),
            open: state.open_sessions().first().map(|s| OpenView {
                session_id: s.id.clone(),
                name: state
                    .product(&s.product_id)
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| "Unbekannt".into()),
                started_at: s.started_at,
                paused: s.is_paused(),
                left: levels::remaining_release(state, s, now),
            }),
            nicotine: curves.nicotine_at(now),
            rate: curves.nicotine_rate_at(now),
            cotinine: curves.cotinine_at(now),
            tolerance: levels::tolerance_index(curves, now),
            today_count: levels::today_count(state),
            today_mg: levels::today_mg(state),
            body_mass: curves.subject.body_mass_kg,
            body_mass_is_default: state.body_mass_kg.is_none(),
            products: state
                .active_products()
                .into_iter()
                .map(|p| ProductView {
                    id: p.id.clone(),
                    name: p.name.clone(),
                    nominal_mg: p.nominal_mg,
                    duration_secs: p.default_duration_secs,
                    accent: p.accent.as_deref().and_then(parse_hex),
                })
                .collect(),
        })
    }

    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::install(&cc.egui_ctx);
        let mut app = Self {
            session: None,
            error: None,
            levels: None,
            last_refresh: Instant::now(),
            notice: Notice::default(),
            new_name: String::new(),
            new_mg: String::new(),
            body_mass: String::new(),
            show_settings: false,
            tuning: None,
            invite: None,
            enroll: EnrollForm {
                name: crate::hostname().unwrap_or_else(|| "linux".into()),
                ..Default::default()
            },
        };
        app.open_session();
        app
    }

    fn open_session(&mut self) {
        match Session::open() {
            Ok(session) => {
                self.levels = Some(levels::build(session.tracker.state()));
                self.session = Some(session);
                self.error = None;
            }
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    fn rebuild(&mut self) {
        if let Some(session) = &self.session {
            self.levels = Some(levels::build(session.tracker.state()));
        }
        self.last_refresh = Instant::now();
    }

    /// Pick up writes made by other processes.
    fn reload(&mut self) {
        if let Some(session) = self.session.as_mut() {
            let _ = session.tracker.refresh();
        }
        // Rebuilt even when nothing changed: the curves move on their own.
        self.rebuild();
    }

    /// Run a change against the tracker, push it to the server and show the outcome.
    ///
    /// Pushing straight away is what makes a variety added here appear on the phone
    /// without waiting for the next scheduled sync. A failed push is reported but is not
    /// an error: the record is safely in the local log and goes out with the next sync.
    fn act(&mut self, change: impl FnOnce(&mut Session) -> Result<String, String>) {
        let Some(session) = self.session.as_mut() else {
            self.notice = Notice {
                text: "Keine Verbindung zum Server".into(),
                is_error: true,
            };
            return;
        };
        match change(session) {
            Ok(message) => {
                let message = match session.sync() {
                    Ok(_) => message,
                    Err(e) => format!("{message} (Sync fehlgeschlagen: {e})"),
                };
                self.notice = Notice {
                    text: message,
                    is_error: false,
                };
            }
            Err(message) => {
                self.notice = Notice {
                    text: message,
                    is_error: true,
                }
            }
        }
        self.rebuild();
    }
}

impl eframe::App for StatsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.last_refresh.elapsed() >= REFRESH {
            self.reload();
        }
        // The session clock ticks every second while something is in; otherwise the
        // refresh interval is all the redraws needed.
        let ticking = self
            .session
            .as_ref()
            .is_some_and(|s| !s.tracker.state().open_sessions().is_empty());
        ctx.request_repaint_after(if ticking {
            StdDuration::from_secs(1)
        } else {
            REFRESH
        });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(BG)
                    .stroke(Stroke::new(2.0_f32, FRAME))
                    .inner_margin(egui::Margin::same(16)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        self.content(ui, ctx);
                    });
            });

        self.show_tuning(ctx);
        self.show_invite(ctx);
    }
}

impl StatsApp {
    fn content(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let Some(view) = self.view() else {
            self.unavailable(ui);
            return;
        };
        let now = Utc::now();

        self.header(ui, &view);
        self.notice_line(ui);

        if let Some(open) = &view.open {
            self.active_card(ui, open);
            ui.add_space(12.0);
        }

        let gap = ui.spacing().item_spacing.x;
        ui.horizontal(|ui| {
            let width = (ui.available_width() - 3.0 * gap) / 4.0;
            tile(
                ui,
                width,
                "NIKOTIN",
                &format!("{:.1}", view.nicotine),
                &format!("{:+.2}/min", view.rate),
                NICOTINE,
            );
            tile(
                ui,
                width,
                "COTININ",
                &format!("{:.0}", view.cotinine),
                "ng/mL",
                COTININE,
            );
            tile(
                ui,
                width,
                "HEUTE",
                &view.today_count.to_string(),
                &format!("{:.1} mg", view.today_mg),
                TEXT,
            );
            tile(
                ui,
                width,
                "TOLERANZ",
                &view
                    .tolerance
                    .map(|t| format!("{t:.0}"))
                    .unwrap_or_else(|| "–".into()),
                if view.tolerance.is_some() {
                    "% vom Hoch"
                } else {
                    "zu wenig Verlauf"
                },
                TEXT_DIM,
            );
        });
        ui.add_space(12.0);

        self.products(ui, &view);
        ui.add_space(12.0);

        if let Some(curves) = &self.levels {
            card(ui, DIVIDER, PANEL, |ui| {
                ui.horizontal(|ui| {
                    heading(ui, "LETZTE 24 STUNDEN");
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        legend(ui, COTININE, "Cotinin");
                        legend(ui, NICOTINE, "Nikotin");
                    });
                });
                ui.label(
                    RichText::new(
                        "Eigene Skalen: Cotinin baut sich über Tage auf, Nikotin schwankt im Stundentakt.",
                    )
                    .size(11.0)
                    .color(TEXT_DIM),
                );
                ui.add_space(6.0);
                draw_chart(ui, curves, now);
            });
            ui.add_space(12.0);
        }

        self.settings(ui, ctx, &view);
    }

    fn unavailable(&mut self, ui: &mut egui::Ui) {
        card(ui, DIVIDER, PANEL, |ui| {
            heading(ui, "ANMELDEN");
            if let Some(error) = &self.error {
                ui.label(RichText::new(error).size(12.0).color(TEXT_DIM));
            }
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "Server-Adresse, Server-Schlüssel und Einladungscode stehen in \
                     `tracker-server bootstrap` bzw. auf dem Einladungs-Bildschirm eines \
                     angemeldeten Geräts. Den Schlüssel von Hand eintragen: ihn über das \
                     Netz zu holen würde nichts beweisen.",
                )
                .size(12.0)
                .color(TEXT_BODY),
            );
            ui.add_space(8.0);
            field(
                ui,
                "Server-Adresse",
                &mut self.enroll.url,
                "https://tracker.example.de",
            );
            field(ui, "Server-Schlüssel", &mut self.enroll.key, "base64");
            field(ui, "Einladungscode", &mut self.enroll.code, "");
            field(ui, "Gerätename", &mut self.enroll.name, "");
            ui.add_space(4.0);
            let ready = !self.enroll.url.trim().is_empty()
                && !self.enroll.key.trim().is_empty()
                && !self.enroll.code.trim().is_empty();
            if ui.add_enabled(ready, primary("Anmelden")).clicked() {
                let form = &self.enroll;
                match session::enroll(
                    form.url.trim(),
                    form.key.trim(),
                    form.code.trim(),
                    form.name.trim(),
                ) {
                    Ok(_) => {
                        self.open_session();
                        self.notice = Notice {
                            text: "Angemeldet. Ist das nicht das erste Gerät, jetzt auf einem \
                                   angemeldeten Gerät »Neues Gerät freischalten« ausführen."
                                .into(),
                            is_error: false,
                        };
                    }
                    Err(e) => {
                        self.notice = Notice {
                            text: e.to_string(),
                            is_error: true,
                        }
                    }
                }
            }
        });
        self.notice_line(ui);
    }

    fn header(&mut self, ui: &mut egui::Ui, view: &View) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("SNUS TRACKER")
                    .family(theme::bold())
                    .size(18.0)
                    .color(ACCENT_STRONG),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui
                    .add_enabled(
                        view.online,
                        egui::Button::new(RichText::new("Sync").size(12.0)),
                    )
                    .on_hover_text("Jetzt mit dem Server abgleichen")
                    .clicked()
                {
                    self.act(|session| match session.sync() {
                        Ok(r) if r.pushed == 0 && r.pulled == 0 => Ok("Alles aktuell".into()),
                        Ok(r) => Ok(format!("{} hoch, {} runter", r.pushed, r.pulled)),
                        Err(e) => Err(format!("Sync fehlgeschlagen: {e}")),
                    });
                }
                let settings_label = if self.show_settings {
                    "Einstellungen [-]"
                } else {
                    "Einstellungen [+]"
                };
                if ui
                    .add(egui::Button::new(RichText::new(settings_label).size(12.0)))
                    .clicked()
                {
                    self.show_settings = !self.show_settings;
                }
                let (label, colour) = if view.online {
                    ("verbunden", GOOD)
                } else {
                    ("offline", TEXT_DIM)
                };
                ui.label(RichText::new(label).size(12.0).color(colour));
                dot(ui, colour);
                if view.pending > 0 {
                    ui.label(
                        RichText::new(format!("{} offen", view.pending))
                            .size(12.0)
                            .color(TEXT_DIM),
                    );
                }
            });
        });
        ui.add_space(6.0);
    }

    fn notice_line(&self, ui: &mut egui::Ui) {
        if self.notice.text.is_empty() {
            return;
        }
        let colour = if self.notice.is_error {
            BAD
        } else {
            ACCENT_STRONG
        };
        ui.label(RichText::new(&self.notice.text).size(12.0).color(colour));
        ui.add_space(6.0);
    }

    fn active_card(&mut self, ui: &mut egui::Ui, open: &OpenView) {
        enum Action {
            Rest,
            End,
            Discard,
        }
        let mut action = None;

        card(ui, ACCENT, ACCENT_WASH, |ui| {
            ui.horizontal(|ui| {
                dot(ui, ACCENT);
                ui.label(
                    RichText::new(&open.name)
                        .family(theme::bold())
                        .size(16.0)
                        .color(TEXT),
                );
            });
            ui.label(
                RichText::new(format_elapsed(open.started_at))
                    .family(theme::bold())
                    .size(32.0)
                    .color(ACCENT_STRONG),
            );
            ui.label(
                RichText::new(if open.paused {
                    "ruht — gibt gerade nichts ab"
                } else {
                    "seit dem Einlegen"
                })
                .size(12.0)
                .color(TEXT_DIM),
            );
            // What the pouch still has in it. A spent pouch in the lip does nothing, and
            // there is no way to tell by feel.
            if let Some(left) = open.left {
                let (text, colour) = if left.num_seconds() == 0 {
                    ("leer — gibt nichts mehr ab".to_string(), TEXT_DIM)
                } else {
                    (
                        format!("noch {} Freisetzung", format_duration(left)),
                        ACCENT,
                    )
                };
                ui.label(RichText::new(text).size(12.0).color(colour));
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui
                    .add(egui::Button::new(if open.paused {
                        "Wieder rein"
                    } else {
                        "Ruhen"
                    }))
                    .clicked()
                {
                    action = Some(Action::Rest);
                }
                if ui.add(primary("Beenden")).clicked() {
                    action = Some(Action::End);
                }
                // Small and last: this is the undo for a mis-tap, not a second way to
                // end. Ending records a consumption; discarding says it never happened.
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .add(egui::Button::new(
                            RichText::new("Verwerfen").size(12.0).color(TEXT_DIM),
                        ))
                        .on_hover_text("Zählt nicht als Konsum")
                        .clicked()
                    {
                        action = Some(Action::Discard);
                    }
                });
            });
        });

        let id = open.session_id.clone();
        let name = open.name.clone();
        let paused = open.paused;
        match action {
            Some(Action::Rest) => self.act(move |s| {
                let result = if paused {
                    s.tracker.resume_session(&id)
                } else {
                    s.tracker.pause_session(&id)
                };
                result
                    .map(|_| {
                        if paused {
                            format!("{name} wieder drin")
                        } else {
                            format!("{name} ruht")
                        }
                    })
                    .map_err(|e| e.to_string())
            }),
            Some(Action::End) => self.act(move |s| {
                s.tracker
                    .end_session(&id)
                    .map(|_| format!("{name} beendet"))
                    .map_err(|e| e.to_string())
            }),
            Some(Action::Discard) => self.act(move |s| {
                s.tracker
                    .discard_session(&id)
                    .map(|_| format!("{name} verworfen — zählt nicht als Konsum"))
                    .map_err(|e| e.to_string())
            }),
            None => {}
        }
    }

    fn products(&mut self, ui: &mut egui::Ui, view: &View) {
        let mut start: Option<String> = None;
        let mut tune: Option<Tuning> = None;
        let mut retire: Option<(String, String)> = None;
        let idle = view.open.is_none();

        let mut submitted = false;
        card(ui, DIVIDER, PANEL, |ui| {
            heading(ui, "SORTEN");
            ui.label(
                RichText::new("Klick startet. Rechtsklick: Dauer einstellen oder ausblenden.")
                    .size(11.0)
                    .color(TEXT_DIM),
            );
            ui.add_space(6.0);

            if view.products.is_empty() {
                ui.label(
                    RichText::new(
                        "Noch keine Sorten. Unten anlegen — sie erscheinen auf allen Geräten.",
                    )
                    .size(12.0)
                    .color(TEXT_BODY),
                );
            }

            let columns = 2;
            let gap = ui.spacing().item_spacing.x;
            let width = (ui.available_width() - gap * (columns as f32 - 1.0)) / columns as f32;
            for row in view.products.chunks(columns) {
                ui.horizontal(|ui| {
                    for product in row {
                        let response = product_tile(ui, width, product, idle);
                        if response.clicked() && idle {
                            start = Some(product.id.clone());
                        }
                        response.context_menu(|ui| {
                            if ui.button("Dauer einstellen…").clicked() {
                                tune = Some(Tuning {
                                    product_id: product.id.clone(),
                                    name: product.name.clone(),
                                    minutes: product
                                        .duration_secs
                                        .map(|s| format!("{:.0}", s / 60.0))
                                        .unwrap_or_else(|| "60".into()),
                                });
                                ui.close();
                            }
                            if ui.button("Ausblenden").clicked() {
                                retire = Some((product.id.clone(), product.name.clone()));
                                ui.close();
                            }
                        });
                    }
                });
            }

            ui.add_space(8.0);
            ui.separator();
            ui.label(RichText::new("Sorte anlegen").size(12.0).color(TEXT_DIM));
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_name)
                        .hint_text("Name")
                        .desired_width(220.0),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_mg)
                        .hint_text("mg")
                        .desired_width(70.0),
                );
                submitted = ui.add(primary("Anlegen")).clicked();
            });
        });

        if let Some(product_id) = start {
            self.act(move |s| {
                let name = s
                    .tracker
                    .state()
                    .product(&product_id)
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| "Sorte".into());
                s.tracker
                    .start_session(&product_id)
                    .map(|_| format!("{name} gestartet"))
                    .map_err(|e| format!("Konnte nicht starten: {e}"))
            });
        }
        if tune.is_some() {
            self.tuning = tune;
        }
        if let Some((id, name)) = retire {
            // "Ausblenden", not "Löschen": sessions already recorded against this
            // variety still need it to compute their curves.
            self.act(move |s| {
                s.tracker
                    .retire_product(&id)
                    .map(|_| {
                        format!("{name} ausgeblendet. Bisherige Sessions bleiben in der Rechnung.")
                    })
                    .map_err(|e| e.to_string())
            });
        }
        if submitted {
            let (name, mg) = (self.new_name.clone(), self.new_mg.clone());
            self.act(move |s| add_product(s, &name, &mg));
            if !self.notice.is_error {
                self.new_name.clear();
                self.new_mg.clear();
            }
        }
    }

    fn settings(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, view: &View) {
        if !self.show_settings {
            return;
        }
        let mut save_mass = false;
        let mut invite = false;
        let mut approve = false;

        card(ui, DIVIDER, PANEL, |ui| {
            heading(ui, "EINSTELLUNGEN");
            ui.add_space(6.0);

            ui.label(RichText::new("Körpergewicht").size(13.0).color(TEXT));
            ui.label(
                RichText::new(
                    "Das Verteilungsvolumen wird pro Kilogramm gerechnet, jeder Spiegel skaliert \
                     also damit. Ohne Angabe rechnet das Modell mit 75 kg.",
                )
                .size(11.0)
                .color(TEXT_DIM),
            );
            ui.horizontal(|ui| {
                if self.body_mass.is_empty() {
                    self.body_mass = format!("{:.0}", view.body_mass);
                }
                ui.add(egui::TextEdit::singleline(&mut self.body_mass).desired_width(70.0));
                ui.label(RichText::new("kg").size(12.0).color(TEXT_DIM));
                save_mass = ui.add(primary("Speichern")).clicked();
                if view.body_mass_is_default {
                    ui.label(RichText::new("Voreinstellung").size(11.0).color(TEXT_DIM));
                }
            });

            ui.add_space(8.0);
            ui.separator();
            ui.label(RichText::new("Geräte").size(13.0).color(TEXT));
            ui.label(
                RichText::new(
                    "Einladung: QR-Code und Code, einmalig, nur Minuten gültig. Danach hier \
                     freischalten, sonst bleibt das neue Gerät gesperrt.",
                )
                .size(11.0)
                .color(TEXT_DIM),
            );
            ui.horizontal(|ui| {
                invite = ui
                    .add_enabled(view.online, egui::Button::new("Gerät einladen"))
                    .clicked();
                approve = ui
                    .add_enabled(view.online, egui::Button::new("Neues Gerät freischalten"))
                    .clicked();
            });
        });

        if save_mass {
            let text = self.body_mass.clone();
            self.act(move |s| {
                let kg: f64 = text
                    .trim()
                    .replace(',', ".")
                    .parse()
                    .map_err(|_| "Gewicht ist keine Zahl".to_string())?;
                s.tracker
                    .update_subject(Some(kg), None)
                    .map_err(|e| e.to_string())?;
                Ok(format!("Gewicht {kg:.0} kg"))
            });
            self.body_mass.clear();
        }
        if approve {
            self.act(|s| match session::approve_devices(s) {
                Ok(devices) if devices.is_empty() => Ok("Keine neuen Geräte".into()),
                Ok(devices) => Ok(format!("{} Gerät(e) freigeschaltet", devices.len())),
                Err(e) => Err(format!("Freischalten fehlgeschlagen: {e}")),
            });
        }
        if invite {
            match self.session.as_ref() {
                Some(session) => match mint_invite(session, ctx) {
                    Ok(invite) => {
                        self.invite = Some(invite);
                        self.notice = Notice::default();
                    }
                    Err(error) => {
                        self.notice = Notice {
                            text: error,
                            is_error: true,
                        }
                    }
                },
                None => {
                    self.notice = Notice {
                        text: "Keine Verbindung zum Server".into(),
                        is_error: true,
                    }
                }
            }
        }
    }

    fn show_tuning(&mut self, ctx: &egui::Context) {
        let Some(tuning) = &mut self.tuning else {
            return;
        };
        let mut open = true;
        let mut save = false;

        egui::Window::new(RichText::new(tuning.name.to_uppercase()).color(ACCENT_STRONG))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_max_width(360.0);
                ui.label(
                    RichText::new(
                        "Wie lange gibt diese Sorte Nikotin ab? Nach dieser Zeit ist sie praktisch \
                         ausgeschöpft. Voreinstellung des Modells: 60 Minuten.",
                    )
                    .size(12.0)
                    .color(TEXT_DIM),
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut tuning.minutes).desired_width(80.0));
                    ui.label(RichText::new("Minuten").size(12.0).color(TEXT_DIM));
                    save = ui.add(primary("Speichern")).clicked();
                });
            });

        if save {
            let (id, name, minutes) = (
                tuning.product_id.clone(),
                tuning.name.clone(),
                tuning.minutes.clone(),
            );
            self.tuning = None;
            self.act(move |s| {
                let minutes: f64 = minutes
                    .trim()
                    .replace(',', ".")
                    .parse()
                    .map_err(|_| "Minuten sind keine Zahl".to_string())?;
                if !(1.0..=600.0).contains(&minutes) {
                    return Err("Minuten müssen zwischen 1 und 600 liegen".into());
                }
                s.tracker
                    .update_product(&id, None, None, Some(minutes * 60.0), None, None)
                    .map_err(|e| e.to_string())?;
                Ok(format!("{name}: gibt jetzt über {minutes:.0} Minuten ab"))
            });
        } else if !open {
            self.tuning = None;
        }
    }

    /// Shows the issued invitation as a window over the rest.
    ///
    /// A window rather than a screen of its own: the QR code is something you hold up
    /// to the phone and then close, not a place to stay.
    fn show_invite(&mut self, ctx: &egui::Context) {
        let Some(invite) = &self.invite else { return };

        let mut open = true;
        egui::Window::new(RichText::new("NEUES GERÄT").color(ACCENT_STRONG))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.set_max_width(420.0);
                ui.vertical_centered(|ui| {
                    ui.image(egui::load::SizedTexture::new(
                        invite.texture.id(),
                        Vec2::splat(260.0),
                    ));
                });
                ui.add_space(8.0);
                invite_field(ui, "Server-Adresse", &invite.url);
                invite_field(ui, "Server-Schlüssel", &invite.key);
                invite_field(ui, "Einladungscode", &invite.code);
                ui.add_space(4.0);
                ui.label(
                    RichText::new(format!(
                        "Gültig für {} Minuten, einmalig einlösbar. Danach hier in den \
                         Einstellungen »Neues Gerät freischalten«, sonst bleibt das neue \
                         Gerät gesperrt.",
                        invite.minutes
                    ))
                    .size(11.0)
                    .color(TEXT_DIM),
                );
            });

        if !open {
            self.invite = None;
        }
    }
}

fn invite_field(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).size(11.0).color(TEXT_DIM));
    // Selectable, so the values can be copied for the laptop, where scanning a phone
    // screen is clumsier than pasting three values.
    ui.add(
        egui::TextEdit::singleline(&mut value.to_string())
            .font(egui::TextStyle::Monospace)
            .desired_width(f32::INFINITY),
    );
}

/// Issues an invitation and builds the texture for it.
fn mint_invite(session: &Session, ctx: &egui::Context) -> Result<Invite, String> {
    let response = session.client.create_invite().map_err(|e| e.to_string())?;
    let code = response["code"]
        .as_str()
        .ok_or_else(|| "Server lieferte keinen Code".to_string())?
        .to_string();
    let expires_at = response["expires_at"].as_i64().unwrap_or_default();
    let minutes = ((expires_at - Utc::now().timestamp()) / 60).max(0);

    let uri = qr::enrollment_uri(
        &session.config.server_url,
        &session.config.server_pub,
        &code,
    );
    let matrix = qr::Qr::encode(&uri).map_err(|e| e.to_string())?;
    let (w, h, rgba) = matrix.to_rgba(6, 4);

    // NEAREST rather than the usual linear filter: a smoothed QR code loses exactly the
    // hard edges the scanner uses to separate modules.
    let texture = ctx.load_texture(
        "invite-qr",
        egui::ColorImage::from_rgba_unmultiplied([w, h], &rgba),
        egui::TextureOptions::NEAREST,
    );

    Ok(Invite {
        code,
        url: session.config.server_url.clone(),
        key: session.config.server_pub.clone(),
        minutes,
        texture,
    })
}

/// `None` for the duration: a new variety follows the substance model until it is tuned,
/// exactly as `snus add` and the Android app do. (This window used to pin 30 minutes,
/// which made the same variety behave differently depending on where it was created.)
fn add_product(session: &mut Session, name: &str, mg: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Name fehlt".into());
    }
    // Accept a comma: "10,4" is how the number is written on the tin here.
    let nominal_mg: f64 = mg
        .trim()
        .replace(',', ".")
        .parse()
        .map_err(|_| "mg ist keine Zahl".to_string())?;
    if nominal_mg <= 0.0 {
        return Err("mg muss größer als 0 sein".into());
    }
    session
        .tracker
        .define_product(
            name,
            "nicotine",
            "buccal_pouch",
            nominal_mg,
            None,
            None,
            None,
        )
        .map(|_| format!("Sorte '{name}' angelegt"))
        .map_err(|e| format!("Fehlgeschlagen: {e}"))
}

// ------------------------------------------------------------------ widgets

/// A filled circle, drawn: the font has no glyph for one.
fn dot(ui: &mut egui::Ui, colour: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.0, colour);
}

fn heading(ui: &mut egui::Ui, text: &str) {
    ui.label(
        RichText::new(text)
            .family(theme::bold())
            .size(13.0)
            .color(ACCENT),
    );
}

fn primary(text: &str) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).family(theme::bold()).color(BG))
        .fill(ACCENT)
        .stroke(Stroke::new(1.0_f32, ACCENT_STRONG))
}

fn field(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    ui.label(RichText::new(label).size(11.0).color(TEXT_DIM));
    ui.add(
        egui::TextEdit::singleline(value)
            .hint_text(hint)
            .desired_width(f32::INFINITY),
    );
}

fn legend(ui: &mut egui::Ui, colour: Color32, label: &str) {
    ui.label(RichText::new(label).size(11.0).color(TEXT_DIM));
    let (rect, _) = ui.allocate_exact_size(Vec2::new(10.0, 10.0), Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::ZERO, colour);
}

fn card(ui: &mut egui::Ui, border: Color32, fill: Color32, contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0_f32, border))
        .corner_radius(CornerRadius::ZERO)
        .inner_margin(14.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            contents(ui)
        });
}

fn tile(ui: &mut egui::Ui, width: f32, label: &str, value: &str, unit: &str, colour: Color32) {
    egui::Frame::new()
        .fill(PANEL)
        .stroke(Stroke::new(1.0_f32, DIVIDER))
        .inner_margin(10.0)
        .show(ui, |ui| {
            ui.set_width(width - 22.0);
            ui.vertical(|ui| {
                ui.label(RichText::new(label).size(10.0).color(TEXT_DIM));
                ui.label(
                    RichText::new(value)
                        .family(theme::bold())
                        .size(22.0)
                        .color(colour),
                );
                ui.label(RichText::new(unit).size(10.0).color(TEXT_DIM));
            });
        });
}

/// One variety. The whole tile is the button: a tracker that takes aim is one with gaps.
fn product_tile(
    ui: &mut egui::Ui,
    width: f32,
    product: &ProductView,
    enabled: bool,
) -> egui::Response {
    let height = 64.0;
    let sense = if enabled {
        Sense::click()
    } else {
        Sense::hover()
    };
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, height), sense);

    let hovered = enabled && response.hovered();
    let accent = product.accent.unwrap_or(ACCENT);
    let fade = |c: Color32| if enabled { c } else { c.gamma_multiply(0.4) };

    let painter = ui.painter();
    painter.rect_filled(
        rect,
        CornerRadius::ZERO,
        if hovered { HOVER } else { PANEL },
    );
    painter.rect_stroke(
        rect,
        CornerRadius::ZERO,
        Stroke::new(1.0_f32, if hovered { ACCENT } else { fade(DIVIDER) }),
        StrokeKind::Inside,
    );
    // The stripe stands in for the variety's colour, as it does on the phone.
    painter.rect_filled(
        egui::Rect::from_min_size(rect.min + Vec2::new(12.0, 12.0), Vec2::new(28.0, 3.0)),
        CornerRadius::ZERO,
        fade(accent),
    );
    painter.text(
        rect.min + Vec2::new(12.0, 24.0),
        egui::Align2::LEFT_TOP,
        &product.name,
        FontId::new(14.0, theme::bold()),
        fade(TEXT),
    );
    painter.text(
        rect.min + Vec2::new(12.0, 44.0),
        egui::Align2::LEFT_TOP,
        format!("{:.1} mg", product.nominal_mg),
        FontId::proportional(11.0),
        fade(TEXT_DIM),
    );
    response
}

/// Two curves on one panel with independent scales.
///
/// Independent because nicotine sits around 10-50 ng/mL and cotinine around 300-700: on
/// a shared axis the nicotine trace would be a flat line along the bottom. The point of
/// showing them together is the contrast in *shape* -- one saws, the other drifts -- and
/// that only survives if each gets its own range.
fn draw_chart(ui: &mut egui::Ui, levels: &Levels, now: DateTime<Utc>) {
    let height = 190.0;
    let (response, painter) =
        ui.allocate_painter(Vec2::new(ui.available_width(), height), Sense::hover());
    let rect = response.rect;

    painter.rect_filled(rect, CornerRadius::ZERO, BG);

    let from = now - Duration::hours(24);
    let samples = levels.samples(from, now, 180);
    if samples.len() < 2 {
        return;
    }

    let nicotine_max = samples.iter().map(|(_, n, _)| *n).fold(1.0f64, f64::max) * 1.15;
    let cotinine_max = samples.iter().map(|(_, _, c)| *c).fold(1.0f64, f64::max) * 1.15;

    // Room underneath for the hour labels, which used to be drawn over the baseline.
    let plot = egui::Rect::from_min_max(
        rect.min + Vec2::new(8.0, 10.0),
        rect.max - Vec2::new(8.0, 22.0),
    );

    for fraction in [0.0, 0.25, 0.5, 0.75, 1.0] {
        let y = plot.bottom() - plot.height() * fraction;
        painter.line_segment(
            [Pos2::new(plot.left(), y), Pos2::new(plot.right(), y)],
            Stroke::new(1.0_f32, ACCENT_WASH),
        );
    }
    for hours_ago in [18, 12, 6] {
        let fraction = 1.0 - hours_ago as f32 / 24.0;
        let x = plot.left() + plot.width() * fraction;
        painter.line_segment(
            [Pos2::new(x, plot.top()), Pos2::new(x, plot.bottom())],
            Stroke::new(1.0_f32, ACCENT_WASH),
        );
        painter.text(
            Pos2::new(x, plot.bottom() + 4.0),
            egui::Align2::CENTER_TOP,
            format!("-{hours_ago}h"),
            FontId::proportional(10.0),
            TEXT_DIM,
        );
    }

    let to_points = |pick: fn(&(DateTime<Utc>, f64, f64)) -> f64, max: f64| -> Vec<Pos2> {
        samples
            .iter()
            .enumerate()
            .map(|(i, sample)| {
                let x = plot.left() + plot.width() * (i as f32 / (samples.len() - 1) as f32);
                let y = plot.bottom() - plot.height() * (pick(sample) / max).clamp(0.0, 1.0) as f32;
                Pos2::new(x, y)
            })
            .collect()
    };

    let nicotine_points = to_points(|s| s.1, nicotine_max);
    let cotinine_points = to_points(|s| s.2, cotinine_max);

    // Filled area under nicotine, so the sawtooth reads as volume rather than a wire.
    // Built from vertical strips: a convex polygon silently draws garbage for a curve
    // that is not convex, and this one never is.
    let wash = Color32::from_rgba_unmultiplied(0xAC, 0x77, 0xFA, 36);
    for pair in nicotine_points.windows(2) {
        let (a, b) = (pair[0], pair[1]);
        painter.add(egui::Shape::convex_polygon(
            vec![
                a,
                b,
                Pos2::new(b.x, plot.bottom()),
                Pos2::new(a.x, plot.bottom()),
            ],
            wash,
            Stroke::NONE,
        ));
    }

    painter.add(egui::Shape::line(
        cotinine_points,
        Stroke::new(1.6_f32, COTININE),
    ));
    painter.add(egui::Shape::line(
        nicotine_points.clone(),
        Stroke::new(2.0_f32, NICOTINE),
    ));

    if let Some(last) = nicotine_points.last() {
        painter.circle_filled(*last, 3.5, NICOTINE);
    }

    painter.rect_stroke(
        rect,
        CornerRadius::ZERO,
        Stroke::new(1.0_f32, DIVIDER),
        StrokeKind::Inside,
    );
}

fn parse_hex(hex: &str) -> Option<Color32> {
    let hex = hex.trim_start_matches('#');
    if hex.len() != 6 {
        return None;
    }
    let value = u32::from_str_radix(hex, 16).ok()?;
    Some(Color32::from_rgb(
        ((value >> 16) & 0xFF) as u8,
        ((value >> 8) & 0xFF) as u8,
        (value & 0xFF) as u8,
    ))
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([820.0, 860.0])
            .with_min_inner_size([560.0, 520.0])
            .with_title("Snus Tracker")
            .with_app_id("snus-tracker"),
        ..Default::default()
    };
    eframe::run_native(
        "snus-tracker",
        options,
        Box::new(|cc| Ok(Box::new(StatsApp::new(cc)))),
    )?;
    Ok(())
}
