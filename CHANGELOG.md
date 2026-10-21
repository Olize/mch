# Changelog

## 0.2.0 — 2026-10-21

- Resume staging remains owner-private (0600) until the rename publishes it; final permissions are set on the published inode to keep interruptions resumable.
- Hardened the resume-move path: sync destination parent before deleting a source, recheck original file identity, and refuse newly created target parents for moves.
- Resume staging-state errors now name both relevant hidden file paths; added identity and missing-parent regression tests.
- Opt-in Unix-only `--resume` mode for one regular file; persistent private staging, source-state manifest, advisory lock, verified prefix and full-file hashing, source retention on errors. Tested SIGKILL/restart on 256 MiB in Termux and 320 MiB on Fedora vm01; not a transactional backup.
- Hardened `--move` source-directory identity checks: a replaced empty source directory is not deleted even when no files were planned. Windows adds a creation-time comparison.
- Clarified OS page-cache hash limitations, filesystem-dependent move durability, and metadata limitations on partial destination directories.

- Audit hardening: move no longer recursively deletes source directory trees; unexpected newly created entries or changed file identities abort source deletion.
- Move path now syncs staged file data and, on Unix, affected destination directories before source deletion. Windows directory durability remains a limitation.
- Staging files are created with owner-only permissions on Unix; accidental `-v` with file arguments fails rather than silently doing nothing.
- Added independent fail-closed public-release surface check (with explicit reviewed Unix resume opt-in), guard regression tests, and restricted CI token permissions.

- Snapshot all source timestamps before any copying to preserve shared hardlink atime consistently.
- Added opt-in `--preserve-times` for file/dir access and modification times (Unix symlinks supported); defaults stay unchanged.
- Added five cross-platform/Unix metadata regression tests covering existing target directories, parallel copies, move/overwrite, dry run and symlink targets.

- Do not claim "COPY VERIFIED" in progress output when `-N` disables integrity verification.
- Keep the platform-optimized fast copy path when progress is disabled; preserve performance and basic permissions.
- First milestone: live byte-counted transfer progress (`--progress auto|always|never`).
- Line-based plain-text status with throughput, copy ETA, files finished and copied bytes; designed for Termux, logs and screen readers.
- Explicit `--progress always` also reports to redirected stderr; `--quiet` and `--dry-run` suppress it.
- Added regression tests, cross-platform CI and data-loss hardening.

## 0.1.0 — 2026-10-20

- Turned the old --count placeholder into bounded parallel file-worker processing.
- Introduced verified temporary-file staging before writing final destinations.
- Existing destination files are now protected unless --overwrite is specified.
- Reject source/destination collisions, self-recursive directory copies and unexpected destination symlink parents.
- Move deletes sources only after the entire copy plan has succeeded.
- Implemented --dry-run, --quiet and --no-color.
- Preserved the eight hash algorithms and the existing basic CLI flags.
- Added integration tests, complete documentation and GitHub Actions CI.
- Updated the Rust package version to 0.1.0.

### Behavioral change

MCH 0.1.0 intentionally refuses overwriting an existing file by default. Use --overwrite to replace existing regular files or symbolic links. This protects data compared with earlier alpha versions.
