//! The statistics window.
//!
//! Deliberately read-mostly. Logging happens in the tray; this is where you come to look
//! at what the log adds up to, so it optimises for legibility rather than for speed of
//! interaction.

use chrono::{Duration, Local, Utc};
use eframe::egui::{
    self, Align, Color32, CornerRadius, FontId, Layout, Pos2, RichText, Sense, Stroke,
    StrokeKind, Vec2,
};

use crate::{
    levels::{self, Levels},
    qr,
    session::Session,
};

const BG: Color32 = Color32::from_rgb(0x14, 0x16, 0x1A);
const CARD: Color32 = Color32::from_rgb(0x1C, 0x1F, 0x25);
const CARD_EDGE: Color32 = Color32::from_rgb(0x2A, 0x2E, 0x36);
const TEXT: Color32 = Color32::from_rgb(0xE6, 0xE8, 0xEC);
const MUTED: Color32 = Color32::from_rgb(0x8C, 0x93, 0xA0);
const ACCENT: Color32 = Color32::from_rgb(0xF2, 0x99, 0x4A);
const ACCENT_SOFT: Color32 = Color32::from_rgb(0x6E, 0x4A, 0x28);
const COTININE: Color32 = Color32::from_rgb(0x56, 0xA8, 0xD8);

pub struct StatsApp {
    session: Option<Session>,
    error: Option<String>,
    levels: Option<Levels>,
    new_name: String,
    new_mg: String,
    notice: String,
    invite: Option<Invite>,
}

/// Eine ausgestellte Einladung samt fertiger Textur.
///
/// Die Textur wird einmal beim Ausstellen gebaut, nicht pro Bild: `load_texture`
/// lädt zur GPU hoch, und das sechzigmal in der Sekunde für ein unveränderliches
/// Muster zu tun wäre reine Verschwendung.
struct Invite {
    code: String,
    minutes: i64,
    texture: egui::TextureHandle,
}

/// An owned snapshot for one frame.
///
/// Rendering used to read straight from `self.session`, which meant every widget held an
/// immutable borrow while the "add variety" button needed a mutable one. Copying the few
/// values a frame actually needs is cheaper than threading lifetimes through the UI.
struct View {
    online: bool,
    open: Option<(String, i64)>,
    nicotine: f64,
    cotinine: f64,
    tolerance: Option<f64>,
    today_count: usize,
    today_mg: f64,
    products: Vec<(String, f64, Option<Color32>)>,
}

impl StatsApp {
    fn view(&self) -> Option<View> {
        let session = self.session.as_ref()?;
        let curves = self.levels.as_ref()?;
        let state = session.tracker.state();
        let now = Utc::now();

        Some(View {
            online: session.online,
            open: state.open_sessions().first().map(|s| {
                (
                    state
                        .product(&s.product_id)
                        .map(|p| p.name.clone())
                        .unwrap_or_else(|| "Unbekannt".into()),
                    (now - s.started_at).num_minutes().max(0),
                )
            }),
            nicotine: curves.nicotine_at(now),
            cotinine: curves.cotinine_at(now),
            tolerance: levels::tolerance_index(curves, now),
            today_count: levels::today_count(state),
            today_mg: levels::today_mg(state),
            products: state
                .active_products()
                .into_iter()
                .map(|p| {
                    (p.name.clone(), p.nominal_mg, p.accent.as_deref().and_then(parse_hex))
                })
                .collect(),
        })
    }

    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        install_theme(&cc.egui_ctx);
        let mut app = Self {
            session: None,
            error: None,
            levels: None,
            new_name: String::new(),
            new_mg: String::new(),
            notice: String::new(),
            invite: None,
        };
        match Session::open() {
            Ok(session) => {
                app.levels = Some(levels::build(session.tracker.state()));
                app.session = Some(session);
            }
            Err(e) => app.error = Some(e.to_string()),
        }
        app
    }

    fn refresh(&mut self) {
        if let Some(session) = &self.session {
            self.levels = Some(levels::build(session.tracker.state()));
        }
    }
}

fn install_theme(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.visuals.dark_mode = true;
    style.visuals.panel_fill = BG;
    style.visuals.window_fill = BG;
    style.visuals.override_text_color = Some(TEXT);
    style.visuals.widgets.noninteractive.bg_fill = CARD;
    style.visuals.widgets.inactive.bg_fill = CARD;
    style.visuals.widgets.hovered.bg_fill = CARD_EDGE;
    style.visuals.widgets.active.bg_fill = ACCENT_SOFT;
    style.spacing.item_spacing = Vec2::new(12.0, 10.0);
    style.spacing.button_padding = Vec2::new(14.0, 8.0);
    ctx.set_style(style);
}

impl eframe::App for StatsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // The level moves on its own even when nothing is logged, so keep redrawing.
        ctx.request_repaint_after(std::time::Duration::from_secs(10));

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(6.0);

            if let Some(error) = self.error.clone() {
                card(ui, |ui| {
                    ui.label(RichText::new("Nicht verfügbar").size(18.0).color(TEXT).strong());
                    ui.add_space(4.0);
                    ui.label(RichText::new(error).color(MUTED));
                });
                return;
            }

            let Some(view) = self.view() else { return };
            let now = Utc::now();

            // ---------------------------------------------------------- header
            ui.horizontal(|ui| {
                ui.label(RichText::new("Snus Tracker").size(22.0).strong().color(TEXT));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let (label, colour) = match view.online {
                        true => ("● verbunden", Color32::from_rgb(0x5C, 0xB8, 0x5C)),
                        false => ("● offline", MUTED),
                    };
                    ui.label(RichText::new(label).size(12.0).color(colour));
                });
            });
            ui.add_space(10.0);

            // ------------------------------------------------- active session
            if let Some((name, minutes)) = &view.open {
                card_accent(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("●").size(20.0).color(ACCENT));
                        ui.vertical(|ui| {
                            ui.label(RichText::new(name).size(17.0).strong().color(TEXT));
                            ui.label(
                                RichText::new(format!("seit {minutes} Minuten"))
                                    .size(13.0)
                                    .color(ACCENT),
                            );
                        });
                    });
                });
                ui.add_space(10.0);
            }

            // ------------------------------------------------------ stat tiles
            ui.horizontal(|ui| {
                let tile_width = (ui.available_width() - 3.0 * 12.0) / 4.0;
                stat_tile(ui, tile_width, "Nikotin", &format!("{:.1}", view.nicotine), "ng/mL", ACCENT);
                stat_tile(ui, tile_width, "Cotinin", &format!("{:.0}", view.cotinine), "ng/mL", COTININE);
                stat_tile(
                    ui,
                    tile_width,
                    "Heute",
                    &view.today_count.to_string(),
                    &format!("{:.1} mg", view.today_mg),
                    TEXT,
                );
                stat_tile(
                    ui,
                    tile_width,
                    "Toleranz",
                    &view.tolerance.map(|t| format!("{t:.0}")).unwrap_or_else(|| "–".into()),
                    "rel. Index",
                    MUTED,
                );
            });
            ui.add_space(12.0);

            // ----------------------------------------------------------- chart
            if let Some(curves) = &self.levels {
                egui::Frame::new()
                    .fill(CARD)
                    .stroke(Stroke::new(1.0_f32, CARD_EDGE))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(14.0)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Letzte 24 Stunden").size(15.0).strong().color(TEXT));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                legend(ui, COTININE, "Cotinin");
                                legend(ui, ACCENT, "Nikotin");
                            });
                        });
                        ui.add_space(8.0);
                        draw_chart(ui, curves, now);
                    });
            }
            ui.add_space(12.0);

            // -------------------------------------------------------- products
            let mut submitted = false;
            let mut mint_requested = false;
            card(ui, |ui| {
                ui.label(RichText::new("Sorten").size(15.0).strong().color(TEXT));
                ui.add_space(6.0);

                for (name, nominal_mg, accent) in &view.products {
                    ui.horizontal(|ui| {
                        let (rect, _) = ui.allocate_exact_size(Vec2::new(4.0, 20.0), Sense::hover());
                        ui.painter().rect_filled(
                            rect,
                            CornerRadius::same(2),
                            accent.unwrap_or(ACCENT),
                        );
                        ui.label(RichText::new(name).size(14.0).color(TEXT));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(
                                RichText::new(format!("{nominal_mg:.1} mg"))
                                    .size(13.0)
                                    .color(MUTED),
                            );
                        });
                    });
                }

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(6.0);
                ui.label(RichText::new("Sorte hinzufügen").size(13.0).color(MUTED));
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_name)
                            .hint_text("Name")
                            .desired_width(200.0),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_mg)
                            .hint_text("mg")
                            .desired_width(70.0),
                    );
                    submitted = ui.button("Anlegen").clicked();
                });
                if !self.notice.is_empty() {
                    ui.label(RichText::new(&self.notice).size(12.0).color(ACCENT));
                }

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    mint_requested = ui.button("Neues Gerät anmelden").clicked();
                    ui.label(
                        RichText::new("zeigt einen QR-Code zum Abscannen")
                            .size(12.0)
                            .color(MUTED),
                    );
                });
            });

            if submitted {
                if let Some(session) = self.session.as_mut() {
                    self.notice = add_product(session, &self.new_name, &self.new_mg);
                }
                if self.notice.is_empty() {
                    self.new_name.clear();
                    self.new_mg.clear();
                }
                self.refresh();
            }

            if mint_requested {
                // Blockiert kurz: der Server muss den Code ausstellen. Eine Sekunde
                // Standbild ist hier ehrlicher als ein Ladebalken, der mehr Maschinerie
                // braeuchte als der Vorgang selbst.
                match self.session.as_ref() {
                    Some(session) => match mint_invite(session, ctx) {
                        Ok(invite) => {
                            self.invite = Some(invite);
                            self.notice.clear();
                        }
                        Err(error) => self.notice = error,
                    },
                    None => self.notice = "Keine Verbindung zum Server".into(),
                }
            }
        });

        self.show_invite(ctx);
    }
}

impl StatsApp {
    /// Zeigt die ausgestellte Einladung als Fenster über dem Rest.
    ///
    /// Bewusst ein Fenster und kein eigener Bildschirm: Der QR-Code ist etwas, das
    /// man dem Handy hinhält und danach wieder schließt, kein Ort, an dem man sich
    /// aufhält.
    fn show_invite(&mut self, ctx: &egui::Context) {
        let Some(invite) = &self.invite else { return };

        let mut open = true;
        egui::Window::new("Neues Gerät")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(4.0);
                    ui.image(egui::load::SizedTexture::new(
                        invite.texture.id(),
                        Vec2::splat(280.0),
                    ));
                    ui.add_space(10.0);
                    ui.label(RichText::new(&invite.code).size(22.0).strong().monospace().color(TEXT));
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(format!("gültig für {} Minuten", invite.minutes))
                            .size(12.0)
                            .color(MUTED),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(
                            "Nach dem Anmelden hier »Geräte freischalten«, damit das \
                             neue Gerät den Datenschlüssel bekommt.",
                        )
                        .size(12.0)
                        .color(MUTED),
                    );
                    ui.add_space(4.0);
                });
            });

        if !open {
            self.invite = None;
        }
    }
}

/// Stellt eine Einladung aus und baut die Textur dafür.
fn mint_invite(session: &Session, ctx: &egui::Context) -> Result<Invite, String> {
    let response = session.client.create_invite().map_err(|e| e.to_string())?;
    let code = response["code"]
        .as_str()
        .ok_or_else(|| "Server lieferte keinen Code".to_string())?
        .to_string();
    let expires_at = response["expires_at"].as_i64().unwrap_or_default();
    let minutes = ((expires_at - Utc::now().timestamp()) / 60).max(0);

    let uri = qr::enrollment_uri(&session.config.server_url, &session.config.server_pub, &code);
    let matrix = qr::Qr::encode(&uri).map_err(|e| e.to_string())?;
    let (w, h, rgba) = matrix.to_rgba(6, 4);

    // NEAREST statt der üblichen linearen Filterung: Ein weichgezeichneter QR-Code
    // verliert genau die harten Kanten, an denen der Scanner die Module trennt.
    let texture = ctx.load_texture(
        "invite-qr",
        egui::ColorImage::from_rgba_unmultiplied([w, h], &rgba),
        egui::TextureOptions::NEAREST,
    );

    Ok(Invite { code, minutes, texture })
}

fn add_product(session: &mut Session, name: &str, mg: &str) -> String {
    let name = name.trim();
    if name.is_empty() {
        return "Name fehlt".into();
    }
    // Accept a comma: "10,4" is how the number is written on the tin here.
    let Ok(nominal_mg) = mg.trim().replace(',', ".").parse::<f64>() else {
        return "mg ist keine Zahl".into();
    };
    if nominal_mg <= 0.0 {
        return "mg muss größer als 0 sein".into();
    }

    match session.tracker.define_product(
        name,
        "nicotine",
        "buccal_pouch",
        nominal_mg,
        Some(30.0 * 60.0),
        None,
        None,
    ) {
        // Push straight away so the new variety reaches the phone without waiting for
        // the next scheduled sync.
        Ok(_) => match session.sync() {
            Ok(_) => String::new(),
            Err(e) => format!("Angelegt, aber Sync fehlgeschlagen: {e}"),
        },
        Err(e) => format!("Fehlgeschlagen: {e}"),
    }
}

fn legend(ui: &mut egui::Ui, colour: Color32, label: &str) {
    ui.label(RichText::new(label).size(12.0).color(MUTED));
    let (rect, _) = ui.allocate_exact_size(Vec2::new(10.0, 10.0), Sense::hover());
    ui.painter().rect_filled(rect, CornerRadius::same(2), colour);
}

fn card(ui: &mut egui::Ui, contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0_f32, CARD_EDGE))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(14.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            contents(ui)
        });
}

fn card_accent(ui: &mut egui::Ui, contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(Color32::from_rgb(0x24, 0x1E, 0x18))
        .stroke(Stroke::new(1.0_f32, ACCENT_SOFT))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(14.0)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            contents(ui)
        });
}

fn stat_tile(ui: &mut egui::Ui, width: f32, label: &str, value: &str, unit: &str, colour: Color32) {
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0_f32, CARD_EDGE))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(12.0)
        .show(ui, |ui| {
            ui.set_width(width);
            ui.vertical(|ui| {
                ui.label(RichText::new(label).size(11.0).color(MUTED));
                ui.add_space(2.0);
                ui.label(RichText::new(value).size(24.0).strong().color(colour));
                ui.label(RichText::new(unit).size(11.0).color(MUTED));
            });
        });
}

/// Two curves on one panel with independent scales.
///
/// Independent because nicotine sits around 10-50 ng/mL and cotinine around 300-700: on
/// a shared axis the nicotine trace would be a flat line along the bottom. The point of
/// showing them together is the contrast in *shape* -- one saws, the other drifts -- and
/// that only survives if each gets its own range.
fn draw_chart(ui: &mut egui::Ui, levels: &Levels, now: chrono::DateTime<Utc>) {
    let height = 190.0;
    let (response, painter) =
        ui.allocate_painter(Vec2::new(ui.available_width(), height), Sense::hover());
    let rect = response.rect;

    painter.rect_filled(rect, CornerRadius::same(6), Color32::from_rgb(0x17, 0x1A, 0x1F));

    let from = now - Duration::hours(24);
    let samples = levels.samples(from, now, 180);
    if samples.is_empty() {
        return;
    }

    let nicotine_max = samples.iter().map(|(_, n, _)| *n).fold(1.0f64, f64::max) * 1.15;
    let cotinine_max = samples.iter().map(|(_, _, c)| *c).fold(1.0f64, f64::max) * 1.15;

    let plot = rect.shrink2(Vec2::new(8.0, 10.0));

    // Horizontal guides, and hour marks every six hours.
    for fraction in [0.0, 0.25, 0.5, 0.75, 1.0] {
        let y = plot.bottom() - plot.height() * fraction;
        painter.line_segment(
            [Pos2::new(plot.left(), y), Pos2::new(plot.right(), y)],
            Stroke::new(1.0_f32, Color32::from_rgb(0x22, 0x26, 0x2C)),
        );
    }
    for hours_ago in [18, 12, 6] {
        let fraction = 1.0 - hours_ago as f32 / 24.0;
        let x = plot.left() + plot.width() * fraction;
        painter.line_segment(
            [Pos2::new(x, plot.top()), Pos2::new(x, plot.bottom())],
            Stroke::new(1.0_f32, Color32::from_rgb(0x20, 0x24, 0x2A)),
        );
        painter.text(
            Pos2::new(x, plot.bottom() + 2.0),
            egui::Align2::CENTER_TOP,
            format!("-{hours_ago}h"),
            FontId::proportional(10.0),
            MUTED,
        );
    }

    let to_points = |pick: fn(&(chrono::DateTime<Utc>, f64, f64)) -> f64, max: f64| -> Vec<Pos2> {
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
    let mut area = nicotine_points.clone();
    area.push(Pos2::new(plot.right(), plot.bottom()));
    area.push(Pos2::new(plot.left(), plot.bottom()));
    painter.add(egui::Shape::convex_polygon(
        area,
        Color32::from_rgba_unmultiplied(0xF2, 0x99, 0x4A, 28),
        Stroke::NONE,
    ));

    painter.add(egui::Shape::line(cotinine_points, Stroke::new(1.6_f32, COTININE)));
    painter.add(egui::Shape::line(nicotine_points.clone(), Stroke::new(2.0_f32, ACCENT)));

    if let Some(last) = nicotine_points.last() {
        painter.circle_filled(*last, 3.5, ACCENT);
    }

    painter.rect_stroke(
        rect,
        CornerRadius::same(6),
        Stroke::new(1.0_f32, CARD_EDGE),
        StrokeKind::Inside,
    );

    let _ = Local::now();
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
            .with_inner_size([760.0, 720.0])
            .with_min_inner_size([560.0, 480.0])
            .with_title("Snus Tracker — Statistik"),
        ..Default::default()
    };
    eframe::run_native(
        "snus-tracker-stats",
        options,
        Box::new(|cc| Ok(Box::new(StatsApp::new(cc)))),
    )?;
    Ok(())
}
