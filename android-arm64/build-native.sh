#!/usr/bin/env bash
# Builds the Rust core for arm64 Android and drops the .so where Gradle looks for it.
#
# This does by hand what `cargo ndk` would do: point cargo at the NDK's clang for both
# linking and for the C compilation that rusqlite's bundled SQLite needs. Doing it
# explicitly means one less tool to install and no guessing about which NDK it picked.
set -euo pipefail

NDK="${ANDROID_NDK_HOME:-$HOME/android-sdk/ndk/27.2.12479018}"
API=26   # must match minSdk in app/build.gradle.kts
TARGET=aarch64-linux-android
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
[ -d "$BIN" ] || { echo "NDK not found at $NDK" >&2; exit 1; }

export CC_aarch64_linux_android="$BIN/${TARGET}${API}-clang"
export AR_aarch64_linux_android="$BIN/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$BIN/${TARGET}${API}-clang"

cargo build --release -p tracker-jni --target "$TARGET"

DEST="$ROOT/app/src/main/jniLibs/arm64-v8a"
mkdir -p "$DEST"
cp "$ROOT/../target/$TARGET/release/libtracker_jni.so" "$DEST/"
echo "-> $DEST/libtracker_jni.so"
ls -la "$DEST/libtracker_jni.so"
