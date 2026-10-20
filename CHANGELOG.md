# Changelog

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
