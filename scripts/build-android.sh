#!/bin/bash
set -euo pipefail

TARGETS=(
    "aarch64-linux-android:arm64-v8a"
    "armv7-linux-androideabi:armeabi-v7a"
    "x86_64-linux-android:x86_64"
)

echo "=== Building vpn-android for Android ==="

for pair in "${TARGETS[@]}"; do
    IFS=":" read -r target abi <<< "$pair"
    echo "→ Building for $abi ($target)..."
    cargo build --release \
        --target "$target" \
        --package vpn-android \
        2>&1 | tail -5

    mkdir -p "/out/jniLibs/$abi"
    cp "target/$target/release/libvpn_android.so" "/out/jniLibs/$abi/"
    echo "  ✓ /out/jniLibs/$abi/libvpn_android.so ($(du -h "target/$target/release/libvpn_android.so" | cut -f1))"
done

echo ""
echo "=== Done! Output in /out/jniLibs/ ==="
find /out/jniLibs -name "*.so" -exec ls -lh {} \;
