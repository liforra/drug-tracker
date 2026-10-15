//! The look: the liforra.de palette used by the desktop bar, in Space Mono.
//!
//! Square corners, a 2px frame around windows, 1px dividers around cards -- the same
//! vocabulary as the bar's popouts. The Android client carries the same tokens in
//! `ui/Theme.kt`; change them in both places or not at all.

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, Stroke, Vec2,
};

pub const BG: Color32 = Color32::from_rgb(0x03, 0x02, 0x05);
pub const PANEL: Color32 = Color32::from_rgb(0x09, 0x05, 0x0F);
pub const DIVIDER: Color32 = Color32::from_rgb(0x2B, 0x22, 0x39);
pub const FRAME: Color32 = Color32::from_rgb(0x9D, 0x5B, 0xF4);
pub const ACCENT: Color32 = Color32::from_rgb(0xAC, 0x77, 0xFA);
pub const ACCENT_STRONG: Color32 = Color32::from_rgb(0xC2, 0x95, 0xFF);
pub const ACCENT_WASH: Color32 = Color32::from_rgb(0x21, 0x16, 0x32);
pub const HOVER: Color32 = Color32::from_rgb(0x12, 0x0B, 0x1C);
pub const TEXT: Color32 = Color32::from_rgb(0xEC, 0xE9, 0xF4);
pub const TEXT_BODY: Color32 = Color32::from_rgb(0xBF, 0xBC, 0xC6);
pub const TEXT_DIM: Color32 = Color32::from_rgb(0x91, 0x8D, 0x9A);
pub const GOOD: Color32 = Color32::from_rgb(0x7E, 0xE2, 0xA8);
pub const WARN: Color32 = Color32::from_rgb(0xFF, 0xCF, 0x6B);
pub const BAD: Color32 = Color32::from_rgb(0xFF, 0x6B, 0x8B);

/// Nicotine takes the accent, cotinine the warm contrast, so the two curves stay apart
/// even for someone who cannot tell two purples apart.
pub const NICOTINE: Color32 = ACCENT;
pub const COTININE: Color32 = WARN;

const SPACE_MONO: &[u8] = include_bytes!("../../assets/res/font/space_mono_regular.ttf");
const SPACE_MONO_BOLD: &[u8] = include_bytes!("../../assets/res/font/space_mono_bold.ttf");

pub fn install(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert(
        "space-mono".into(),
        FontData::from_static(SPACE_MONO).into(),
    );
    fonts.font_data.insert(
        "space-mono-bold".into(),
        FontData::from_static(SPACE_MONO_BOLD).into(),
    );
    // One family for everything: the bar is monospace throughout, so is this.
    for family in [FontFamily::Proportional, FontFamily::Monospace] {
        let list = fonts.families.entry(family).or_default();
        list.insert(0, "space-mono".into());
    }
    // egui has no weight axis; a named family is how a bold face is selected.
    fonts.families.insert(
        FontFamily::Name("bold".into()),
        vec!["space-mono-bold".into(), "space-mono".into()],
    );
    ctx.set_fonts(fonts);

    let mut style = (*ctx.style()).clone();
    let v = &mut style.visuals;
    v.dark_mode = true;
    v.panel_fill = BG;
    v.window_fill = PANEL;
    v.extreme_bg_color = BG;
    v.faint_bg_color = HOVER;
    v.override_text_color = Some(TEXT);
    v.window_stroke = Stroke::new(2.0_f32, FRAME);
    v.window_corner_radius = CornerRadius::ZERO;
    v.menu_corner_radius = CornerRadius::ZERO;
    v.window_shadow = egui::Shadow::NONE;
    v.popup_shadow = egui::Shadow::NONE;
    v.selection.bg_fill = ACCENT_WASH;
    v.selection.stroke = Stroke::new(1.0_f32, ACCENT);
    v.hyperlink_color = ACCENT_STRONG;

    let widgets = [
        (&mut v.widgets.noninteractive, PANEL, DIVIDER, TEXT_BODY),
        (&mut v.widgets.inactive, PANEL, DIVIDER, TEXT),
        (&mut v.widgets.hovered, HOVER, ACCENT, TEXT),
        (&mut v.widgets.active, ACCENT_WASH, ACCENT_STRONG, TEXT),
        (&mut v.widgets.open, ACCENT_WASH, ACCENT, TEXT),
    ];
    for (widget, fill, stroke, text) in widgets {
        widget.bg_fill = fill;
        widget.weak_bg_fill = fill;
        widget.bg_stroke = Stroke::new(1.0_f32, stroke);
        widget.fg_stroke = Stroke::new(1.0_f32, text);
        widget.corner_radius = CornerRadius::ZERO;
        widget.expansion = 0.0;
    }

    style.spacing.item_spacing = Vec2::new(10.0, 8.0);
    style.spacing.button_padding = Vec2::new(12.0, 6.0);
    ctx.set_style(style);
}

pub fn bold() -> FontFamily {
    FontFamily::Name("bold".into())
}
