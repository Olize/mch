# Technical specification — MCH 0.3.0

Status: implementation contract, not a formal safety proof.

## Goal and interface

MCH is a Rust CLI for local copy/move with optional post-copy hash verification. Invocation:

mch [OPTIONS] SOURCE... DESTINATION

Supports regular files, directory trees and Unix symlinks; does not copy sockets, devices or FIFOs. Multiple source paths are supported. For a directory source, the copied directory is created as DESTINATION/source-basename; -O copies only the contents of one directory. For a single file, an existing destination directory receives its source basename; otherwise the destination is interpreted as its file path.

## Options

- -m, --move: remove original sources after all copy and verification tasks succeed.
- -N, --no-hash: skip staged verification. Moves still check all final destinations before deletion.
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
3. Copy regular files into temporary files alongside their destinations. When progress is displayed, read and write in 1 MiB blocks and count bytes; otherwise use std::io::copy on the open source and staging handles. When enabled, independently hash the original and staged copy and compare them. Symlinks are recreated, not dereferenced, and link text is compared.
4. With --preserve-times, apply original timestamps to the staged file/link only after copying and hashing succeed; restore timestamps of newly created directories after all children are written. Pre-existing target directories keep their own timestamps aside from normal filesystem updates. Publish staged files with rename. On Unix this gives per-file atomic replacement on the destination filesystem. Existing-target overwrites use the same-directory OS rename after checking the planned entry again. A target absent at planning uses exclusive no-replace publication.
5. Restore permissions on new directory objects and delete original sources only after all copy tasks complete successfully.

Preflight errors must leave originals untouched. Failures in the copy phase retain originals but may leave successfully copied destination files behind. Errors during final source deletion can leave some originals intact and some removed. These rules describe ordinary copying and moving. Atomic Linux directory transactions are specified below.

## Unix resume protocol v1 (opt-in, supported scope)

- The source/destination path pair determines three separate hidden sibling files: a persistent `.part` staging file, a `.meta` record of source dev/inode/length/mtime, and a permanent `.lock` file. The lock is advisory OS-level `flock` and intentionally retained across runs to avoid lock-inode replacement races.
- Persistent resume objects are opened without following the final path component, with private owner permissions and a single hardlink. Conflicts or suspicious files are refused rather than deleted.
- A partial prefix is independently compared byte-for-byte against current source bytes. The original file must retain its identity, length and modification time. Before publishing, the entire source and completed staged copy are independently hashed and compared. Resume never disables hashing.
- The progress reporter separates already verified/reused bytes from new transfer bytes; copy ETA only estimates transfer.
- After successful independent verification and metadata application, the stage is renamed to its destination. The source is removed only after success when --move is selected.
- A kill/power interruption can leave incomplete staging and metadata. A mismatched or missing metadata pair is a deliberate hard error, not silently reset. The source/destination filesystem must provide safe regular-file and rename semantics.
- This does **not** defend against hostile races or a same-inode/same-size/same-mtime content mutation, cannot guarantee directory durability on power loss, and does not resume directory trees, multiple files or Windows copies.

## v0.2.1 security patch

- The preflight destination check is not the final publication decision. When overwriting is disabled, publication must be atomic no-replace: Linux/Android use renameat2(RENAME_NOREPLACE) and a fail-closed hard-link fallback where supported; other platforms use a no-replace hard link or safely refuse publication.
- Normal regular-file copying retains an open private staging file handle instead of reopening the path with fs::copy. Unix staging stays private (0600) until publication; source permissions are then applied via the open handle.
- With explicit overwrite or move, staged bytes and published metadata are synchronized. On Unix, explicit overwrites synchronize destination directories, including resume overwrite without move.
- Hash and progress reads retry Interrupted; the 1 MiB progress buffer resides on the heap.
- These changes do not defend against all hostile parent-directory races or guarantee power-loss durability on all filesystems.

## Limitations and security boundaries

- Empty-destination copies still reject planned target directories inside any source tree. Case- or NFC-equivalent planned names can be refused even on case-sensitive filesystems. With -O --move the source root is removed after its contents are moved. Newly created Unix ancestors with no source counterpart retain mode 0700.
- Directory overlap and move checks require stable, unique file identities. Network shares, nonstandard filesystem drivers and ReFS have not been validated for this release. Windows FAT32 and exFAT volume roots must be registered with Mount Manager. Cloned volumes with identical serials can cause an overlap refusal.
- Ordinary copies require a stable source. Linux copies can select a retained read-only Btrfs snapshot.
- Concurrency with a hostile filesystem actor creates race conditions (TOCTOU), and is not defended against.
- No absolute durability guarantees after power loss. Unix moves sync staged regular files and affected destination directories before deleting source files. Unix resume synchronizes the stage and, for resume moves, the final destination directory before source deletion; noncooperating filesystems/controllers remain outside the guarantee.
- For ordinary copies there is no preservation guarantee for owner, ACL, xattrs, creation times, sparse extents or hard-link relationships. Basic file permissions and newly created directory permissions are handled. Access and modification timestamps are an explicit opt-in; filesystem precision and time metadata support vary.
- Unix symlinks are preserved as links; Windows symlink copying is unsupported.
- Destination paths with preexisting symlink ancestors are refused intentionally, except verified macOS system roots `/var`, `/tmp` and `/etc`, which are normalized to `/private` before checking.
- Non-local/cloud file systems can have unusual rename behavior.
- A successful move rechecks final file contents, link targets, directory existence and destination identities even with -N. Windows refuses multi-file move with overwrite.
- macOS may explicitly opt into verified, exclusive target creation when atomic no-replace fails on an unsupported filesystem. The destination may be visible while being filled and may be incomplete after interruption or a write error. This option rejects move, overwrite, no-hash and resume.
- The copy ETA measures transfer. Verified ordinary copies also report a copy-plus-hash ETA covering the two independent hash reads. Both estimates exclude metadata application and source removal. Progress "COPY VERIFIED" refers to hashed/copied files, not the entire move operation. With -N, the final progress state is explicitly "COPY COMPLETE (NO HASH VERIFICATION)".
- Line-based output is intended for screen readers; automatic progress is enabled only if stderr is connected to a terminal.
- Temporary files may remain if the process is killed or power fails.

## Directory resume, sparse copying and transactions

`mch --resume-dir --resume-dir-state STATE SOURCE TARGET` copies one local Unix directory into an existing target using BLAKE3 and one worker. Use a dedicated, owner-private state directory (0700) outside both trees. Only regular files without additional hard links and directories are supported. Repeat the same command after interruption. Previously published files are rehashed and completed files are checked against their recorded digest before success. The final walk also requires every planned target directory, including empty directories. Preserve the state if the job refuses recovery.

On a sparse-capable volume, `--sparse` writes all-zero blocks as holes in an ordinary copy. The logical length and contents are preserved, including a trailing hole. Windows requires a target that supports setting the sparse-file attribute.

On Linux, `mch --transaction STATE SOURCE TARGET` verifies and syncs an entire directory before publishing it at TARGET. The destination parent and private state directory must exist on the same filesystem. The default requires TARGET to be absent. Add `--replace-tree` to exchange an existing target with the staged directory. The original directory remains in STATE. Repeat the same command with `--rollback` to restore the original target or its absence. The withdrawn tree, including edits after publication, is retained in STATE. MCH serializes the destination check and rename with other MCH transactions in the same parent. If the parent is busy, retry the same command. Keep the state directory while rollback may be needed.

Transactions require Linux 5.8 or later, rsync with ACL/xattr support and a filesystem with directory birth times, directory sync and the necessary atomic rename operations. They verify contents with BLAKE3 and preserve hardlinks, sparse data, numeric ownership, permissions, modification times, POSIX ACLs and extended attributes visible to rsync. Transactions preserve modification times. They reject `--preserve-times`, which also requests access times. Run with sufficient permission to reproduce the selected metadata. Use a stable source and privately controlled state and destination paths.

On Linux Btrfs, `--snapshot-in DIR` creates a read-only subvolume named after the source inside DIR. The parent must be on the same filesystem outside the source, and the snapshot name must be unused. Nested subvolumes and mount boundaries are refused. The snapshot is retained even after a later copy failure. For retries, use its path directly as the source.

## Release gates

cargo fmt --check; cargo clippy --locked --all-targets -- -D warnings; cargo test --locked; cargo build --release --locked. Test matrix: Linux, macOS, Windows. The integration tests verify both successful workflows and safety refusals.
