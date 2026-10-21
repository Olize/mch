# Mighty Copy with Hash (mch)

**MCH** is a Rust command-line tool for copying or moving local files and directory trees with optional post-copy integrity verification. Its default hash is **BLAKE3**.

Current version: **0.2.1**. Licensed under **GNU AGPL-3.0-or-later**.

## Features

- Copy and move local files, directory trees, and multiple sources.
- Verify each regular file by reading and hashing both source and staged destination **before publishing the result**.
- Hash choices: BLAKE3 (default), SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE2b, BLAKE2s, and XXH3. XXH3 is intended for speed, not cryptographic security.
- Use `--count N` to process up to N independent file operations concurrently (1-256).
- Preserve source file permissions and newly created directory permissions.
- Preserve Unix symbolic links as links, including dangling links; links are **not followed** when traversing a directory.
- Preview all changes with `--dry-run`.
- Refuse to overwrite existing files by default; use `--overwrite` explicitly.
- Enforce a safe, atomic no-replace publication when overwrite is disabled; concurrent writers cannot silently replace a late destination.
- Stage regular files privately in the destination directory and publish only after successful verification, keeping the staging file handle open throughout copying.
- With `--move`, remove only **planned source files and subsequently empty planned directories** after successful copy/verification and destination synchronization. A new file in the source tree causes a refusal rather than recursive deletion.
- Reject copying a directory into itself, duplicate destination names, destination parent symlinks, and special files (e.g. FIFOs).

## Install

Requires the Rust toolchain with Cargo.

```bash
git clone https://github.com/Olize/mch.git
cd mch
cargo build --release --locked
```

The binary is at `target/release/mch` (or `mch.exe` on Windows). Windows builds support regular files and directories, but copying symlinks is not supported.

## Examples

```bash
# Copy one file; verify with BLAKE3
mch source.iso /backup/source.iso

# Copy a directory inside /backup (=> /backup/photos)
mch photos /backup

# Copy the contents only (=> /backup/<contents of photos>)
mch -O photos /backup

# Copy multiple files in parallel
mch --count 8 first.iso second.iso third.iso /backup

# Verify with SHA-512
mch --hash sha512 source.iso /backup/source.iso

# Move only after all files have copied and verified
mch --move photos /backup

# Preview without writing anything
mch --dry-run --move photos /backup

# Explicitly allow overwriting an existing file
mch --overwrite source.iso /backup/source.iso

# Faster but without integrity verification; use carefully
mch -N source.iso /backup/source.iso

# Show version/help
mch -v
mch --help
```

### Options

| Option | Meaning |
|---|---|
| `-m, --move` | Move after all copies have succeeded |
| `-N, --no-hash` | Disable content verification |
| `--hash ALGORITHM` | Select hash algorithm; default BLAKE3 |
| `--count N` | Number of parallel file workers; default 1, max 256 |
| `--progress auto|always|never` | Screenreader-friendly transfer status; default auto (only when stderr is a terminal) |
| `--preserve-times` | Preserve original access and modification times on files and newly created directories; also symlinks on Unix |
| `--resume` | Opt-in, verified restart of a single regular file on Unix; rejects `-N`, directories, multiple files and Windows |
| `-O, --only-src-content` | Copy only the contents of one directory |
| `--overwrite` | Explicitly replace existing files or symlinks |
| `--dry-run` | Check and show plan without modifying files |
| `-q, --quiet` | Suppress normal status output |
| `--no-color` | Disable ANSI colors |
| `-v, --version` | Show version information |
| `-h, --help` | Show CLI help |

When copying a directory **without** `-O`, the source directory name is always appended to the destination. When copying one regular file, an existing destination directory (or a path ending in the platform's separator) receives the source file under its original name. Without those conditions, the destination is treated as the file path.

With `-N`, the final progress status explicitly says **COPY COMPLETE (NO HASH VERIFICATION)**; MCH must never report an unverified copy as verified.

Progress messages appear on stderr as separate, readable lines (at most once per second plus a final copy summary). They report bytes transferred, copied-file count, approximate throughput and **copy ETA**, not a guaranteed end-to-end ETA; hash verification and source deletion take additional time. `--progress always` works with redirected logs. `--quiet` and `--dry-run` suppress progress. No animated progress bars or ANSI control sequences are used in progress output.

### Verified resumable copies (Unix single-file mode)

```bash
mch --resume --progress always large.iso /backup/large.iso
# If interrupted, repeat exactly the same command and paths.
```

`--resume` supports one regular file per invocation on Unix (tested under Linux, macOS and Android/Termux). It writes a hidden owner-private `.mch-resume-v1-*.part` file alongside the destination; `.meta` binds that staging data to the initial source inode, size and modification time. A persistent `.lock` file is intentional so simultaneous resumes cannot bypass the inode lock. All previously written bytes are checked byte-for-byte against the current source on each restart; final source and staged-file hashes must match before publishing. Changing the source, altering the stage or having a conflicting destination causes a refusal, not an automatic repair. For `--resume --move`, the destination parent must already exist and support directory synchronization before the source may be deleted. The user may need to remove abandoned staging/manifest files **manually** after reviewing them. Concurrent hostile filesystem modifications, power loss and incomplete metadata/directory durability are outside the guarantees of this release. Do **not** treat this as a transactional backup, a crash-proof data store, or a safe workflow on untested network/FUSE filesystems.

## Data safety and limitations

**Important: MCH is not a transactional backup system.**

- Verification normally reads the operating-system **page cache** after writing; equal hashes do not prove that media/controller data has been durably written or will survive a power loss.
- During explicit overwrites and moves, MCH synchronizes staged regular file contents and on Unix also synchronizes affected destination directory entries. Actual power-loss durability still depends on the filesystem and hardware.
- MCH checks the planned paths before copying and performs verification before committing each file. It does not take a filesystem snapshot. If sources change during copying, verification may fail; sources must be kept stable for reliable results.
- An error partway through an operation may leave some **completed** destination files or newly created directories behind. New directories can temporarily retain default permissions/timestamps until finalization succeeds. Sources are retained if copying or verification fails. It is safe to inspect the destination and retry, using `--overwrite` if appropriate.
- For a successful `--move`, original sources are deleted after verification. Deleting originals can itself fail, in which case both copies may remain. Do not assume an all-or-nothing transaction across sources.
- `--overwrite` is atomic per regular file on Unix when source and destination are on the same mounted destination filesystem: the temporary file is created alongside its destination and renamed into place. On Windows, replacement may temporarily rename the old destination to a backup first; it is **not** an atomic replacement guarantee.
- When `--overwrite` is not specified, existing regular files and links are never replaced. Existing destination directories may be merged; conflicting files are still rejected.
- Symbolic links are preserved on Unix, but their *textual targets* are checked rather than hashing the objects they refer to. Windows symbolic-link copying is rejected.
- `--preserve-times` optionally restores file access/modification times, newly created directory times, and Unix symlink times. Existing destination directories are never assigned source timestamps. Without this option, timestamps are not preserved intentionally. Timestamp operations can fail on unsupported filesystems and are not guarantees against external changes.
- Directory ownership, hard-link relationships, extended attributes, ACLs, birth/creation times and sparse extents are **not** preserved. Do not use MCH as a metadata-perfect backup.
- Special files (devices, sockets, FIFOs) are not copied.
- Destination paths whose existing parent components are symbolic links are rejected deliberately to avoid writing through an unexpected alias. On macOS, the standard system-managed `/var`, `/tmp`, and `/etc` aliases into `/private` are normalized after verifying their expected targets; other symlink parents remain forbidden.
- MCH reads both source and staged target for a hash comparison, usually **from the operating system's page cache**. This detects mismatches visible through filesystem reads but **does not establish physical-media durability or prove that the controller stored the data correctly**.
- For `--move` on Unix, MCH syncs staged data and relevant destination directory entries before removing planned sources. Actual power-loss durability still depends on the operating system and filesystem; source-directory deletion is not itself transactionally committed. On Windows, no equivalent directory-fsync guarantee is claimed.
- If copying fails after creating destination directories, partially created directories may retain default mode/timestamps until a later successful run. Inspect partial results before retrying, especially when copying restrictive directory permissions.
- MCH does not protect against concurrent malicious filesystem mutation (TOCTOU), disk/controller faults below the filesystem, or corruption that occurs after verification.
- Using `-N` disables post-copy integrity verification, including for moves.

Return code: **0** for success, **2** for errors (argument errors from Clap may also use its own exit status).

## Development

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
```

The GitHub Actions CI checks builds and tests on Linux, macOS, and Windows.

See [Specification](docs/SPECIFICATION.md) and [Changelog](CHANGELOG.md).

## License

Copyright (C) 2026 Olize. GNU AGPL-3.0-or-later — see [LICENSE](LICENSE).

PS.: Life is short. Time is small. Take it easy and fuck it all!

---

## Support

If you find this project useful, you can support my open-source work:

[![Liberapay](https://img.shields.io/badge/Liberapay-Support-F6C915?style=for-the-badge&logo=liberapay&logoColor=000000)](https://liberapay.com/Olize/)

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=000000)](https://buymeacoffee.com/Olize)
