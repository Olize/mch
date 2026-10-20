# Technical specification — MCH 0.1.0

Status: implementation contract, not a formal safety proof. The original January 2026 plan could not be completely recovered, so undocumented future features are not presented as original requirements.

## Goal and interface

MCH is a Rust CLI for local copy/move with optional post-copy hash verification. Invocation:

mch [OPTIONS] SOURCE... DESTINATION

Supports regular files, directory trees and Unix symlinks; does not copy sockets, devices or FIFOs. Multiple source paths are supported. For a directory source, the copied directory is created as DESTINATION/source-basename; -O copies only the contents of one directory. For a single file, an existing destination directory receives its source basename; otherwise the destination is interpreted as its file path.

## Options

- -m, --move: remove original sources after all copy and verification tasks succeed.
- -N, --no-hash: skip content verification.
- --hash: BLAKE3 (default), SHA256, SHA512, SHA3-256, SHA3-512, BLAKE2B, BLAKE2S, XXH3.
- --count N: 1–256 parallel file workers (default 1); individual large files are not split into chunks.
- -O: copy only directory contents.
- --overwrite: allow replacement of existing files or links, never a directory with a file.
- --dry-run: preflight and print proposed operations, no changes.
- -q: quiet output.
- --no-color: disable ANSI colors.
- -v: version, -h: help.

## Copy/verification process

1. Normalize source and target paths, enumerate source trees, check targets and detect collisions and self-recursive copies.
2. Create missing destination directories without traversing existing symlink parents.
3. Copy regular files into temporary files alongside their destinations. When enabled, independently hash the original and staged copy and compare them. Symlinks are recreated, not dereferenced, and link text is compared.
4. Publish staged files with rename. On Unix this gives per-file atomic replacement on the destination filesystem. On Windows replacement may require moving the original aside first.
5. Restore permissions on new directory objects and delete original sources only after all copy tasks complete successfully.

Preflight errors must leave originals untouched. Failures in the copy phase retain originals but may leave successfully copied destination files behind. Errors during final source deletion can leave some originals intact and some removed. MCH is NOT an all-or-nothing transaction.

## Limitations and security boundaries

- No filesystem snapshots: sources should remain unchanged while MCH runs.
- Concurrency with a hostile filesystem actor creates race conditions (TOCTOU), and is not defended against.
- No durability guarantees on power loss; no explicit fsync.
- No preservation guarantee for owner, ACL, xattrs, timestamps, sparse extents or hard-link relationships. Basic file permissions and newly created directory permissions are handled.
- Unix symlinks are preserved as links; Windows symlink copying is unsupported.
- Destination paths with preexisting symlink ancestors are refused intentionally.
- Non-local/cloud file systems can have unusual rename behavior.
- With -N, the integrity checks are explicitly disabled.
- Temporary files may remain if the process is killed or power fails.

## Release gates

cargo fmt --check; cargo clippy --locked --all-targets -- -D warnings; cargo test --locked; cargo build --release --locked. Test matrix: Linux, macOS, Windows. The integration tests verify both successful workflows and safety refusals.
