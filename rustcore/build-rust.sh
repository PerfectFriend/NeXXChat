#!/bin/bash
# Сборка libnexxrust.so для Android ABI через NDK clang.
# Вызывается gradle-таской :rustcore:buildRustNeXX перед preBuild.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
NDK=${ANDROID_NDK_HOME:-/home/thomas/build/android-sdk/ndk/27.3.13750724}
LLVM="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
API=26

# cargo из ~/build (не полагаемся на PATH вызывающего)
[ -f /home/thomas/build/env.sh ] && source /home/thomas/build/env.sh
export CARGO_TARGET_DIR="$HERE/target-android"

build_one() {
    local triple=$1 abi=$2
    local linker
    case "$triple" in
        aarch64-linux-android)   linker="$LLVM/aarch64-linux-android${API}-clang" ;;
        armv7-linux-androideabi) linker="$LLVM/armv7a-linux-androideabi${API}-clang" ;;
        x86_64-linux-android)    linker="$LLVM/x86_64-linux-android${API}-clang" ;;
        *) echo "unknown triple $triple" >&2; return 1 ;;
    esac
    local env_name
    env_name="CARGO_TARGET_$(echo "$triple" | tr 'a-z-' 'A-Z_')_LINKER"
    export "$env_name=$linker"
    export "CC_${triple//-/_}=$linker"
    export "CXX_${triple//-/_}=$linker++"
    echo "== cargo build --release --target $triple (linker=$linker)"
    cargo build --release --target "$triple"
    local so="$CARGO_TARGET_DIR/$triple/release/libnexxrust.so"
    [ -f "$so" ] || { echo "missing $so" >&2; return 1; }
    mkdir -p "$HERE/src/main/jniLibs/$abi"
    cp "$so" "$HERE/src/main/jniLibs/$abi/libnexxrust.so"
    echo "== installed -> src/main/jniLibs/$abi/libnexxrust.so ($(stat -c%s "$so") bytes)"
}

build_one aarch64-linux-android arm64-v8a
build_one armv7-linux-androideabi armeabi-v7a
build_one x86_64-linux-android x86_64
echo "ALL ABIs OK"
