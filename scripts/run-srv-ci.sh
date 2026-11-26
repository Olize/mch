#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Run public Linux CI checks on SRV without GitHub Actions.
set -Eeuo pipefail

root="$(cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"

[[ "$(uname -sm)" == "Linux x86_64" ]]
[[ -z "$(git status --porcelain --untracked-files=all)" ]]
sha=$(git rev-parse HEAD)
echo "[srv-ci] Repository: $root"
echo "[srv-ci] Revision: $sha"
echo "[srv-ci] Rust: $(rustc --version)"
echo "[srv-ci] Format"
cargo fmt --all -- --check
echo "[srv-ci] Clippy"
cargo clippy --locked --all-targets -- -D warnings
echo "[srv-ci] Rust unit and CLI integration tests"
cargo test --locked --all-targets -- --include-ignored
echo "[srv-ci] Optimized public binary"
cargo build --release --locked
out=$(cargo metadata --locked --offline --no-deps --format-version=1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
bin="$out/release/mch"
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
head -c 1048576 /dev/urandom > "$scratch/src"
"$bin" -q "$scratch/src" "$scratch/copied"
cmp "$scratch/src" "$scratch/copied"
"$bin" -q -m "$scratch/copied" "$scratch/moved"
cmp "$scratch/src" "$scratch/moved"
test ! -e "$scratch/copied"
"$bin" -q --resume "$scratch/src" "$scratch/resumed"
cmp "$scratch/src" "$scratch/resumed"
if "$bin" -q "$scratch/src" "$scratch/resumed"; then exit 1; fi
cmp "$scratch/src" "$scratch/resumed"
printf 'previous' > "$scratch/resumed"
"$bin" -q --resume --overwrite "$scratch/src" "$scratch/resumed"
cmp "$scratch/src" "$scratch/resumed"
[[ "$(git rev-parse HEAD)" == "$sha" && -z "$(git status --porcelain --untracked-files=all)" ]]
echo "MCH_LINUX_SMOKE_PASS"
echo "[srv-ci] PASS: native Linux checks only."
echo "[srv-ci] Windows/macOS execution and filesystem tests remain separate."
