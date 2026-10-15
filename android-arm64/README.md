# Android-Client

Compose-App auf dem gemeinsamen Rust-Core. Die App zeigt beim Start sofort die Sorten
und, falls gerade ein Pouch drin ist, wie lange schon — beides direkt antippbar.

## Was hier nicht gebaut werden konnte

Auf dieser Maschine fehlt die Android-Toolchain vollständig. Der Kotlin- und Rust-Code
ist geschrieben und der JNI-Layer kompiliert für den Host (`cargo build -p tracker-jni`),
aber ein APK ist hier nicht entstanden. Konkret fehlt:

| Was | Status | Warum nötig |
|---|---|---|
| `rustup` | fehlt (Rust kommt aus den Arch-Paketen) | Ohne rustup kein `aarch64-linux-android`-Target |
| Android NDK | fehlt (`/opt/android-sdk/ndk` existiert nicht) | Cross-Compiler und Sysroot für ARM64 |
| SDK-Platform | fehlt (nur `build-tools/37.0.0` vorhanden) | `compileSdk 35` |

Java 26 und Gradle 9.6.1 sind vorhanden.

## Einrichten

```sh
# 1. Rust-Toolchain mit Cross-Target
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add aarch64-linux-android
cargo install cargo-ndk

# 2. SDK-Komponenten
sdkmanager "platforms;android-35" "ndk;27.2.12479018" "platform-tools"
export ANDROID_HOME=/opt/android-sdk
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/27.2.12479018
```

## Bauen

Der Rust-Core muss vor Gradle laufen — Gradle packt nur ein, was schon da ist:

```sh
cd android-arm64/rust
cargo ndk -t arm64-v8a -o ../app/src/main/jniLibs build --release

cd ..
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

## Anmelden

Auf dem Server:

```sh
tracker-server bootstrap     # gibt Tunnel-Fingerprint und Einladungscode aus
```

In der App Server-Adresse, Server-Schlüssel und Code eintragen. Den Schlüssel bewusst
von Hand — ihn über das Netz zu holen würde nichts beweisen, weil ein Angreifer in der
Mitte einfach seinen eigenen ausliefern würde. Der Vergleich mit dem ausgegebenen
Fingerprint ist der einzige Grund, warum der Tunnel überhaupt etwas wert ist.

Ist das Handy nicht das erste Gerät, danach auf einem bereits angemeldeten Gerät
`snus approve` ausführen. Der Server kann keinen Datenschlüssel herausgeben, den er nicht
hat — genau das ist der Punkt der Konstruktion.

## Aufbau

```
rust/src/bridge.rs   Reines Rust, JSON rein und raus — auf dem Host testbar
rust/src/lib.rs      Die einzige Datei, die JNI kennt
app/…/NativeBridge   Die Gegenseite in Kotlin
app/…/TrackerRepository  Identität im Android Keystore, Lease-Cache
app/…/ui/HomeScreen  Sorten-Grid, laufende Session mit lokal tickender Uhr
```

Der Geräteschlüssel liegt in `EncryptedSharedPreferences`, deren Master-Key im
hardwaregestützten Keystore steckt. Das ist der Grund, warum das Handy hier die stärkere
der beiden Plattformen ist: die Gerätehälfte des Speicherschlüssels lässt sich nicht
extrahieren. Auf einem Linux-Rechner ohne TPM ist dieselbe Hälfte eine Datei mit 0600.
