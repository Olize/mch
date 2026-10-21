# Technical specification — MCH 0.2.0

Status: implementation contract, not a formal safety proof.

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
- --progress auto|always|never: no-ANSI line-oriented status to stderr; auto only with a terminal, quiet and dry-run suppress progress.
- --preserve-times: opt-in snapshot and restoration of access/modified timestamps for copied files and newly created destination directories; Unix symlink timestamps are preserved on the link itself.
- --resume: opt-in Unix single-regular-file resume with prefix checking and compulsory full hash verification. Refuses no-hash (-N), --count other than 1, -O, multiple sources and non-regular inputs; not yet available on Windows.
- -v: version, -h: help.

## Copy/verification process

1. Normalize source and target paths, enumerate source trees, check targets and detect collisions and self-recursive copies. If --preserve-times is enabled, snapshot timestamps of all source files and links during planning, before processing any data.
2. Create missing destination directories without traversing existing symlink parents. Sum planned regular-file sizes for progress; this is an estimate if source files are modified by another process.
3. Copy regular files into temporary files alongside their destinations. When progress is displayed, read and write in 1 MiB blocks and count bytes; otherwise use platform-optimized fs::copy for speed. When enabled, independently hash the original and staged copy and compare them. Symlinks are recreated, not dereferenced, and link text is compared.
4. With --preserve-times, apply original timestamps to the staged file/link only after copying and hashing succeed; restore timestamps of newly created directories after all children are written. Pre-existing target directories keep their own timestamps aside from normal filesystem updates. Publish staged files with rename. On Unix this gives per-file atomic replacement on the destination filesystem. On Windows replacement may require moving the original aside first.
5. Restore permissions on new directory objects and delete original sources only after all copy tasks complete successfully.

Preflight errors must leave originals untouched. Failures in the copy phase retain originals but may leave successfully copied destination files behind. Errors during final source deletion can leave some originals intact and some removed. MCH is NOT an all-or-nothing transaction.

## Unix resume protocol v1 (opt-in, supported scope)

- The source/destination path pair determines three separate hidden sibling files: a persistent `.part` staging file, a `.meta` record of source dev/inode/length/mtime, and a permanent `.lock` file. The lock is advisory OS-level `flock` and intentionally retained across runs to avoid lock-inode replacement races.
- Persistent resume objects are opened without following the final path component, with private owner permissions and a single hardlink. Conflicts or suspicious files are refused rather than deleted.
- A partial prefix is independently compared byte-for-byte against current source bytes. The original file must retain its identity, length and modification time. Before publishing, the entire source and completed staged copy are independently hashed and compared. Resume never disables hashing.
- The progress reporter separates already verified/reused bytes from new transfer bytes; copy ETA only estimates transfer.
- After successful independent verification and metadata application, the stage is renamed to its destination. The source is removed only after success when --move is selected.
- A kill/power interruption can leave incomplete staging and metadata. A mismatched or missing metadata pair is a deliberate hard error, not silently reset. The source/destination filesystem must provide safe regular-file and rename semantics.
- This does **not** defend against hostile races or a same-inode/same-size/same-mtime content mutation, cannot guarantee directory durability on power loss, and does not resume directory trees, multiple files or Windows copies.

## Limitations and security boundaries

- No filesystem snapshots: sources should remain unchanged while MCH runs.
- Concurrency with a hostile filesystem actor creates race conditions (TOCTOU), and is not defended against.
- No absolute durability guarantees after power loss. Unix moves sync staged regular files and affected destination directories before deleting source files. Unix resume synchronizes the stage and, for resume moves, the final destination directory before source deletion; noncooperating filesystems/controllers remain outside the guarantee.
- No preservation guarantee for owner, ACL, xattrs, creation times, sparse extents or hard-link relationships. Basic file permissions and newly created directory permissions are handled. Access and modification timestamps are an explicit opt-in; filesystem precision and time metadata support vary.
- Unix symlinks are preserved as links; Windows symlink copying is unsupported.
- Destination paths with preexisting symlink ancestors are refused intentionally, except verified macOS system roots `/var`, `/tmp` and `/etc`, which are normalized to `/private` before checking.
- Non-local/cloud file systems can have unusual rename behavior.
- With -N, the integrity checks are explicitly disabled.
- Progress estimates only the data-transfer phase; verification, metadata application and deleting sources are not included in the copy ETA. Progress "COPY VERIFIED" refers to hashed/copied files, not the entire move operation. With -N, the final progress state is explicitly "COPY COMPLETE (NO HASH VERIFICATION)".
- Line-based output is intended for screen readers; automatic progress is enabled only if stderr is connected to a terminal.
- Temporary files may remain if the process is killed or power fails.

## Release gates

cargo fmt --check; cargo clippy --locked --all-targets -- -D warnings; cargo test --locked; cargo build --release --locked. Test matrix: Linux, macOS, Windows. The integration tests verify both successful workflows and safety refusals.
