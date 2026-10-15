# Deployment

Zwei Hälften: der Server läuft auf alhena in Docker, der Tray-Client läuft lokal als
User-Unit.

## Server (alhena)

Liegt in `/opt/services/services/snus-tracker/` — nach der dortigen Konvention ein
Ordner mit `docker-compose.yaml` und `Caddyfile`. Der Caddyfile wird aus
`/opt/services/*/*` eingelesen, es ist also nichts zusätzlich zu registrieren.

    cd /opt/services/services/snus-tracker
    docker compose build          # baut das Binary im Image, dauert einmalig ein paar Minuten
    docker compose run --rm snus-tracker bootstrap
    docker compose up -d

`bootstrap` gibt zwei Dinge aus, beide werden gebraucht:

- **Tunnel key** — der Fingerprint des Server-Schlüssels. Den pinnt jeder Client. Ihn
  über das Netz zu holen beweist nichts, ein Angreifer würde einfach seinen eigenen
  liefern. Deshalb steht er hier auf der Konsole und wird von Hand verglichen.
- **Invite code** — 10 Minuten gültig, für das erste Gerät.

Der Container schreibt ausschließlich nach `./data/tracker-server.db`. Diese eine Datei
ist der gesamte Zustand: versiegelte Blobs, Geräte-Pubkeys, DEK-Wraps, Audit-Log. Ein
Backup davon ist unbedenklich — ohne den RootKey eines lebenden Geräts ist nichts
davon lesbar.

### Warum der Port offen auf `8747` liegt

Nach der Konvention der anderen Services. Bei einem normalen Dienst wäre eine Bindung
auf `127.0.0.1` besser, hier ist der Unterschied klein: mit `TRACKER_REQUIRE_TUNNEL=1`
sind die Klartext-Routen gar nicht gemountet, jeder Request muss also durch den
Applikations-Tunnel. Wer den Port direkt anspricht, bekommt Bytes, die er nicht
entschlüsseln kann.

Wenn Caddy im Host-Netz läuft, kann man in `docker-compose.yaml` auf
`"127.0.0.1:8747:8747"` verengen.

## Tray-Client (Workstation)

    install -Dm755 target/release/snus ~/.local/bin/snus
    install -Dm644 deploy/snus-tray.service ~/.config/systemd/user/snus-tray.service
    systemctl --user daemon-reload
    systemctl --user enable --now snus-tray

Enrollment einmalig, mit den beiden Werten aus `bootstrap`:

    snus enroll https://tracker.liforra.de <tunnel-key> <invite-code> laptop
