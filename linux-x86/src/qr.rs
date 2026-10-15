//! QR-Codes für die Geräteanmeldung.
//!
//! Ein Anmeldedatensatz besteht aus drei Werten, von denen einer 44 Zeichen
//! base64 ist. Den auf einem Handy abzutippen ist die Stelle, an der die
//! Sicherheitskonstruktion in der Praxis scheitert -- nicht weil sie falsch
//! wäre, sondern weil Menschen bei 44 Zeichen abkürzen. Der QR-Code überträgt
//! dieselben Werte über denselben Kanal (deinen Bildschirm, deine Augen), nur
//! ohne Tippfehler.
//!
//! Wichtig für das Bedrohungsmodell: Der Code enthält den Serverschlüssel im
//! Klartext. Das ist unbedenklich -- ein öffentlicher Schlüssel ist öffentlich.
//! Er enthält aber auch den Einladungscode, und der ist ein Einmalgeheimnis.
//! Deshalb hat er nur Minuten Gültigkeit und wird beim Einlösen verbraucht.

use qrcode::{Color, QrCode};

/// Ein fertig kodierter QR-Code als quadratische Modulmatrix.
pub struct Qr {
    pub width: usize,
    modules: Vec<bool>,
}

impl Qr {
    pub fn encode(data: &str) -> Result<Self, qrcode::types::QrError> {
        let code = QrCode::new(data.as_bytes())?;
        let width = code.width();
        let modules = code.to_colors().into_iter().map(|c| c == Color::Dark).collect();
        Ok(Self { width, modules })
    }

    fn dark(&self, x: usize, y: usize) -> bool {
        self.modules[y * self.width + x]
    }

    /// RGBA-Bild mit Ruhezone. `scale` ist die Kantenlänge eines Moduls in Pixeln.
    ///
    /// Die Ruhezone ist keine Kosmetik: Ohne mindestens vier helle Module am Rand
    /// findet ein Scanner die Begrenzungsmuster nicht zuverlässig.
    pub fn to_rgba(&self, scale: usize, quiet: usize) -> (usize, usize, Vec<u8>) {
        let side = (self.width + 2 * quiet) * scale;
        let mut buf = vec![0xFFu8; side * side * 4];
        for y in 0..self.width {
            for x in 0..self.width {
                if !self.dark(x, y) {
                    continue;
                }
                for py in 0..scale {
                    for px in 0..scale {
                        let gx = (x + quiet) * scale + px;
                        let gy = (y + quiet) * scale + py;
                        let i = (gy * side + gx) * 4;
                        buf[i] = 0x00;
                        buf[i + 1] = 0x00;
                        buf[i + 2] = 0x00;
                        buf[i + 3] = 0xFF;
                    }
                }
            }
        }
        (side, side, buf)
    }
}

/// Erkennt Terminals, die das Kitty-Grafikprotokoll sprechen.
///
/// Ghostty und WezTerm implementieren es ebenfalls, melden sich aber nicht als
/// kitty. Die Abfrage über eine Terminal-Antwort wäre exakter, würde aber einen
/// Timeout auf stdin brauchen -- für eine reine Darstellungsentscheidung ist das
/// den Aufwand nicht wert, zumal der Rückfall funktioniert.
fn kitty_graphics() -> bool {
    use std::env::var;
    if var("KITTY_WINDOW_ID").is_ok() || var("GHOSTTY_RESOURCES_DIR").is_ok() {
        return true;
    }
    if var("TERM_PROGRAM").is_ok_and(|t| t == "ghostty" || t == "WezTerm") {
        return true;
    }
    var("TERM").is_ok_and(|t| t.contains("kitty") || t.contains("ghostty"))
}

/// Gibt den Code als Bild über das Kitty-Grafikprotokoll aus.
///
/// Die Nutzlast wird in Stücke von 4096 base64-Zeichen zerlegt, weil das
/// Protokoll längere Steuersequenzen nicht garantiert. `m=1` heißt "es folgt
/// noch etwas", `m=0` schließt ab.
fn print_kitty(qr: &Qr, wrap_for_tmux: bool) {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::io::Write;

    // Feste Zellenzahl statt Pixelmaßen: Ohne c/r skaliert kitty nach Bildpunkten,
    // und wie viele Zeilen das belegt, wissen wir nicht -- also auch nicht, wie weit
    // der Cursor danach zu bewegen ist.
    const COLS: usize = 40;
    const ROWS: usize = 20;

    let (w, h, rgba) = qr.to_rgba(8, 4);
    let encoded = STANDARD.encode(&rgba);
    let chunks: Vec<&str> = encoded
        .as_bytes()
        .chunks(4096)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();

    let mut out = std::io::stdout().lock();
    for (i, chunk) in chunks.iter().enumerate() {
        let more = if i + 1 < chunks.len() { 1 } else { 0 };
        let sequence = if i == 0 {
            // f=32: RGBA. a=T: übertragen und anzeigen. C=1: Cursor stehen lassen,
            // damit wir ihn selbst um genau ROWS Zeilen weitersetzen können.
            format!("\x1b_Gf=32,s={w},v={h},c={COLS},r={ROWS},a=T,C=1,m={more};{chunk}\x1b\\")
        } else {
            format!("\x1b_Gm={more};{chunk}\x1b\\")
        };
        let _ = out.write_all(passthrough(&sequence, wrap_for_tmux).as_bytes());
    }

    // Platz schaffen: kitty zeichnet über den Text, der danach käme.
    let _ = writeln!(out, "{}", "\n".repeat(ROWS));
    let _ = out.flush();
}

/// Verpackt eine Sequenz für tmux, wenn nötig.
///
/// tmux reicht Unbekanntes nur durch, wenn es in einen eigenen DCS-Rahmen gehüllt
/// ist -- und darin muss jedes ESC verdoppelt werden, weil sonst der Rahmen selbst
/// vorzeitig endet.
fn passthrough(sequence: &str, wrap: bool) -> String {
    if !wrap {
        return sequence.to_string();
    }
    format!("\x1bPtmux;{}\x1b\\", sequence.replace('\x1b', "\x1b\x1b"))
}

/// Läuft die Ausgabe durch tmux?
fn in_tmux() -> bool {
    std::env::var("TMUX").is_ok()
}

/// Fragt tmux, ob es Sequenzen überhaupt durchreicht.
///
/// Seit tmux 3.3 ist das abgeschaltet, solange man es nicht einschaltet. Ohne die
/// Abfrage würden wir Bilddaten in ein Loch schicken und der Nutzer sähe eine leere
/// Fläche -- schlechter als der Textrückfall, den es ja gibt.
fn tmux_passes_through() -> bool {
    std::process::Command::new("tmux")
        .args(["show", "-gv", "allow-passthrough"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .is_some_and(|value| matches!(value.trim(), "on" | "all"))
}

/// Rückfall für Terminals ohne Grafik: zwei Leerzeichen je Modul mit ANSI-Hintergrund.
///
/// Bewusst nicht die üblichen Halbblock-Zeichen: die erben die Terminalfarben und
/// erscheinen auf dunklem Hintergrund invertiert, was manche Scanner ablehnen.
/// Ein explizit gesetzter Hintergrund ist unabhängig vom Farbschema korrekt.
fn print_ansi(qr: &Qr) {
    const QUIET: usize = 2;
    let light = "\x1b[107m  \x1b[0m";
    let dark = "\x1b[40m  \x1b[0m";
    let row = (qr.width + 2 * QUIET) * 2;

    for _ in 0..QUIET {
        println!("\x1b[107m{}\x1b[0m", " ".repeat(row));
    }
    for y in 0..qr.width {
        print!("{}", light.repeat(QUIET));
        for x in 0..qr.width {
            print!("{}", if qr.dark(x, y) { dark } else { light });
        }
        println!("{}", light.repeat(QUIET));
    }
    for _ in 0..QUIET {
        println!("\x1b[107m{}\x1b[0m", " ".repeat(row));
    }
}

/// Zeigt den Code im Terminal an, mit Grafik wo möglich.
pub fn print(qr: &Qr) {
    let tmux = in_tmux();
    if kitty_graphics() && (!tmux || tmux_passes_through()) {
        print_kitty(qr, tmux);
        return;
    }

    print_ansi(qr);
    if tmux && kitty_graphics() {
        eprintln!(
            "  (Für ein echtes Bild statt Blöcken: `set -g allow-passthrough on` in \
             der tmux.conf, dann `tmux kill-server`.)"
        );
    }
}

/// Baut die Anmelde-URI, die im QR-Code steckt.
///
/// Eigenes Schema statt https, damit Android die App direkt zuordnen kann und
/// der Wert nicht versehentlich in einem Browser landet -- ein Einladungscode
/// in einer Browserhistorie wäre genau das, was er nicht sein soll.
pub fn enrollment_uri(url: &str, server_pub: &str, code: &str) -> String {
    format!(
        "snus://enroll?url={}&key={}&code={}",
        escape(url),
        escape(server_pub),
        escape(code)
    )
}

/// Prozentkodierung. base64 enthält `+`, `/` und `=`, die als Trennzeichen in
/// einer Query gelesen würden.
fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_survives_base64_padding_and_slashes() {
        let uri = enrollment_uri(
            "https://tracker.liforra.de",
            "TboovuTQXv7OpSDxDZ9SHaXzaiqemIPEXnBAozCmYUQ=",
            "5SX44X1GDS",
        );
        // Ohne Kodierung würde das '=' die Query zerreißen und '/' den Pfad.
        assert!(!uri.split("key=").nth(1).unwrap().starts_with("Tboo/"));
        assert!(uri.contains("%3D"), "Padding muss kodiert sein: {uri}");
        assert!(uri.starts_with("snus://enroll?url=https%3A%2F%2F"));
    }

    #[test]
    fn matrix_is_square_and_has_quiet_zone() {
        let qr = Qr::encode("snus://enroll?code=TEST").unwrap();
        let (w, h, buf) = qr.to_rgba(4, 4);
        assert_eq!(w, h);
        assert_eq!(buf.len(), w * h * 4);
        // Die obere linke Ecke liegt in der Ruhezone und muss hell sein.
        assert_eq!(&buf[0..4], &[0xFF, 0xFF, 0xFF, 0xFF]);
    }
}
