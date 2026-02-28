#!/usr/bin/env bash
# Build libvpn_ffi.a for iOS (aarch64) and generate Swift bindings.
#
# Prerequisites:
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#
# Usage:
#   ./ios/build-rust.sh            # release build (default)
#   ./ios/build-rust.sh debug      # debug build

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$SCRIPT_DIR/Generated"

PROFILE="${1:-release}"
if [ "$PROFILE" = "debug" ]; then
    CARGO_FLAGS=""
    TARGET_SUBDIR="debug"
else
    CARGO_FLAGS="--release"
    TARGET_SUBDIR="release"
fi

echo "==> Building vpn-ffi for iOS targets ($PROFILE)..."

# Build for physical devices (arm64)
cargo build -p vpn-ffi $CARGO_FLAGS --target aarch64-apple-ios

# Build for the iOS Simulator (arm64, Apple Silicon)
cargo build -p vpn-ffi $CARGO_FLAGS --target aarch64-apple-ios-sim

echo "==> Creating XCFramework..."

DEVICE_LIB="$ROOT_DIR/target/aarch64-apple-ios/$TARGET_SUBDIR/libvpn_ffi.a"
SIM_LIB="$ROOT_DIR/target/aarch64-apple-ios-sim/$TARGET_SUBDIR/libvpn_ffi.a"

FRAMEWORK_DIR="$SCRIPT_DIR/Frameworks/VPNCore.xcframework"
rm -rf "$FRAMEWORK_DIR"

xcodebuild -create-xcframework \
    -library "$DEVICE_LIB" \
    -library "$SIM_LIB" \
    -output "$FRAMEWORK_DIR"

echo "==> Generating Swift bindings..."

mkdir -p "$OUT_DIR"

cargo run -p vpn-ffi --bin uniffi-bindgen generate \
    --library "$DEVICE_LIB" \
    --language swift \
    --out-dir "$OUT_DIR"

echo "==> Done."
echo "    XCFramework: $FRAMEWORK_DIR"
echo "    Swift files:  $OUT_DIR/"
ls -la "$OUT_DIR"/*.swift 2>/dev/null || echo "    (no Swift files generated)"
