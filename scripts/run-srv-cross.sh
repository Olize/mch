#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
cd "$(dirname "$0")/.."
[[ "$(uname -sm)" == "Linux x86_64" ]]
[[ -z "$(git status --porcelain --untracked-files=all)" ]]
sha=$(git rev-parse HEAD)
echo "MCH_CROSS_SOURCE $sha"
: "${ANDROID_NDK_HOME:?Set the NDK path for the API 24 build}"
ndk="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER=qemu-aarch64
export QEMU_LD_PREFIX="${QEMU_LD_PREFIX:-/usr/aarch64-linux-gnu}"
out=$(cargo metadata --offline --locked --format-version=1 --no-deps | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
cargo test --locked --all-targets --target aarch64-unknown-linux-gnu -- --include-ignored
cargo build --release --locked --target aarch64-unknown-linux-gnu
arm="$out/aarch64-unknown-linux-gnu/release/mch"
readelf -h "$arm" | grep -E 'Machine:[[:space:]]+AArch64'
qemu-aarch64 "$arm" --version
echo "MCH_ARM64_QEMU_PASS"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$ndk/aarch64-linux-android24-clang"
export CC_aarch64_linux_android="$CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"
export AR_aarch64_linux_android="$ndk/llvm-ar"
cargo build --release --locked --target aarch64-linux-android
android="$out/aarch64-linux-android/release/mch"
readelf -h "$android" | grep -E 'Machine:[[:space:]]+AArch64'
readelf -l "$android" | grep -F '/system/bin/linker64'
needed=$(readelf -d "$android")
grep -F 'Shared library: [libc.so]' <<<"$needed"
if grep -Eq 'libc\.so\.6|ld-linux' <<<"$needed"; then exit 1; fi
sha256sum "$android"
[[ "$(git rev-parse HEAD)" == "$sha" && -z "$(git status --porcelain --untracked-files=all)" ]]
echo "MCH_ANDROID_API24_BUILD_PASS"
