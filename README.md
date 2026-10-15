> **Warning: the entire code in this repository is AI generated.**
> It has not been audited. Review it yourself before trusting it with anything that matters.

# Snus Tracker

A privacy-focused tracker for snus use, with end-to-end encrypted sync. The server only ever
stores sealed blobs; it cannot read your data.

## Components

| Directory | What | Artifact |
|---|---|---|
| `core/` | Shared Rust library: crypto, storage, sync, pharmacokinetic model | – |
| `server/` | Sync server (`tracker-server`, axum + SQLite) | `tracker-server-linux-x86_64` |
| `linux-x86/` | Linux tray client and GUI (`snus`) | `snus-linux-x86_64` |
| `android-arm64/` | Android app (Compose UI on the Rust core via JNI) | `snus-tracker-android-arm64.apk` |

See [`deploy/README.md`](deploy/README.md) for server and tray deployment and
[`android-arm64/README.md`](android-arm64/README.md) for the Android build.

## Building

```sh
cargo build --release -p tracker-server   # server
cargo build --release -p snus-tray        # Linux client
cargo test --workspace
```

The server also ships as a Docker image (`docker compose up -d`).

## Releases

Every push to `main` creates a GitHub release named after the short commit hash. Each
artifact is uploaded to that release as soon as its own build finishes; builds do not wait
for each other, so a release may be incomplete for a few minutes. Android APKs are
debug-signed.

## License

[AGPL-3.0-or-later](LICENSE).
