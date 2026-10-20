# Roadmap

## v0.1.0 — Implemented

- Copy/move files, directories and Unix symlinks.
- BLAKE3 default and seven selectable alternatives.
- Full source/staging file verification.
- Multiple sources and copy-contents (-O) mode.
- --count parallel file workers (previously a no-op).
- --dry-run, --overwrite, quiet/no-color modes.
- Preflight collision and self-copy checks.
- Deferred deletion after verified copy.
- Temp-file staging and per-file atomic publish on Unix.
- Integration tests and cross-platform CI/build workflow.
- README, behavior spec, changelog.

## Potential future improvements (proposals, not recovered user requirements)

- True multi-file transaction / rollback journal and crash recovery.
- Streaming progress by bytes and human-readable ETA.
- Filesystem metadata preservation (timestamps, xattrs, ACLs, ownership, hardlinks, sparse files).
- Snapshot support and safe resumable transfers of very large files.
- Performance benchmarks across storage/media.
- Native packaging for additional platforms, including Termux.
- Explicit adversarial filesystem-race defenses using directory handles.
- Security audit and fuzz testing before claiming production-grade durability.

None of these potential improvements is part of v0.1.0 implementation contract. See SPECIFICATION.md for implemented guarantees and limitations.
