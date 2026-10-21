// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn mch(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mch"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .expect("run mch")
}

fn write(path: &Path, data: &str) {
    fs::write(path, data).expect("write fixture");
}

fn assert_success(output: Output) {
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_error(output: Output) {
    assert!(
        !output.status.success(),
        "unexpected success:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn help_and_version_require_no_paths() {
    assert_success(mch(&["--help"]));
    let output = mch(&["-v"]);
    assert_success(output.clone());
    assert!(String::from_utf8_lossy(&output.stdout).contains(env!("CARGO_PKG_VERSION")));
    assert_success(mch(&["--version"]));
    assert_error(mch(&[]));
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("source");
    let dst = tmp.path().join("destination");
    write(&src, "keep on accidental -v");
    let result = mch(&["-v", src.to_str().unwrap(), dst.to_str().unwrap()]);
    assert_error(result.clone());
    assert!(String::from_utf8_lossy(&result.stderr).contains("no files were copied"));
    assert!(src.exists() && !dst.exists());
}

#[test]
fn simple_copy_default_hash_and_move() {
    let t = TempDir::new().unwrap();
    let a = t.path().join("source.txt");
    let b = t.path().join("destination.txt");
    write(&a, "MCH integrity test");
    assert_success(mch(&[a.to_str().unwrap(), b.to_str().unwrap()]));
    assert_eq!(fs::read(&a).unwrap(), fs::read(&b).unwrap());
    assert_error(mch(&[a.to_str().unwrap(), b.to_str().unwrap()]));
    let c = t.path().join("moved.txt");
    assert_success(mch(&["-m", a.to_str().unwrap(), c.to_str().unwrap()]));
    assert!(!a.exists());
    assert_eq!(fs::read_to_string(c).unwrap(), "MCH integrity test");
}

#[test]
fn overwrite_is_opt_in_and_atomic_for_a_file() {
    let t = TempDir::new().unwrap();
    let a = t.path().join("a");
    let b = t.path().join("b");
    write(&a, "new");
    write(&b, "old");
    assert_error(mch(&[a.to_str().unwrap(), b.to_str().unwrap()]));
    assert_eq!(fs::read_to_string(&b).unwrap(), "old");
    assert_success(mch(&[
        "--overwrite",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
    ]));
    assert_eq!(fs::read_to_string(&b).unwrap(), "new");
    assert_eq!(fs::read_to_string(&a).unwrap(), "new");
    let leftovers: Vec<_> = fs::read_dir(t.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|s| s.to_string_lossy().contains(".mch-tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "staging files should be removed");
}

#[test]
fn self_copy_is_rejected_even_with_overwrite() {
    let t = TempDir::new().unwrap();
    let file = t.path().join("data");
    write(&file, "untouched");
    assert_error(mch(&[
        "--overwrite",
        file.to_str().unwrap(),
        file.to_str().unwrap(),
    ]));
    assert_eq!(fs::read_to_string(file).unwrap(), "untouched");
}

#[test]
fn recursive_parallel_copy_and_verify() {
    let t = TempDir::new().unwrap();
    let source = t.path().join("src");
    let output = t.path().join("out");
    fs::create_dir_all(source.join("nested/empty")).unwrap();
    for n in 0..30 {
        let file = source.join("nested").join(format!("{n}.txt"));
        write(&file, &format!("index={n}\n"));
    }
    assert_success(mch(&[
        "--count",
        "8",
        source.to_str().unwrap(),
        output.to_str().unwrap(),
    ]));
    for n in 0..30 {
        let name = format!("{n}.txt");
        assert_eq!(
            fs::read(source.join("nested").join(&name)).unwrap(),
            fs::read(output.join("src/nested").join(&name)).unwrap()
        );
    }
    assert!(output.join("src/nested/empty").is_dir());
}

#[test]
fn only_src_content_and_empty_directories() {
    let t = TempDir::new().unwrap();
    let source = t.path().join("input");
    let dest = t.path().join("other");
    fs::create_dir_all(source.join("empty")).unwrap();
    write(&source.join("one"), "1");
    assert_success(mch(&[
        "-O",
        source.to_str().unwrap(),
        dest.to_str().unwrap(),
    ]));
    assert!(dest.join("one").exists());
    assert!(dest.join("empty").is_dir());
    assert!(!dest.join("input").exists());
}

#[test]
fn no_hash_and_all_hashes_work() {
    let t = TempDir::new().unwrap();
    let a = t.path().join("src");
    write(&a, &"hello".repeat(1000));
    for alg in [
        "blake3", "sha256", "sha512", "sha3-256", "sha3-512", "blake2b", "blake2s", "xxh3",
    ] {
        let dest = t.path().join(alg);
        assert_success(mch(&[
            "--hash",
            alg,
            a.to_str().unwrap(),
            dest.to_str().unwrap(),
        ]));
        assert_eq!(fs::read(&dest).unwrap(), fs::read(&a).unwrap());
    }
    let dest = t.path().join("none");
    assert_success(mch(&["-N", a.to_str().unwrap(), dest.to_str().unwrap()]));
}

#[test]
fn dry_run_makes_no_changes() {
    let t = TempDir::new().unwrap();
    let a = t.path().join("a");
    let b = t.path().join("b");
    write(&a, "preserve");
    assert_success(mch(&[
        "--dry-run",
        "--move",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
    ]));
    assert!(a.is_file());
    assert!(!b.exists());
}

#[test]
fn nested_copy_is_rejected_before_writing() {
    let t = TempDir::new().unwrap();
    let src = t.path().join("src");
    fs::create_dir_all(&src).unwrap();
    write(&src.join("data"), "keep");
    let inner = src.join("nested");
    assert_error(mch(&[src.to_str().unwrap(), inner.to_str().unwrap()]));
    assert!(!inner.exists());
    assert_eq!(fs::read_to_string(src.join("data")).unwrap(), "keep");
}

#[test]
fn duplicate_destination_basename_is_rejected() {
    let t = TempDir::new().unwrap();
    let a = t.path().join("a");
    let b = t.path().join("b");
    fs::create_dir_all(&a).unwrap();
    fs::create_dir_all(&b).unwrap();
    write(&a.join("dup"), "a");
    write(&b.join("dup"), "b");
    let dest = t.path().join("dst");
    assert_error(mch(&[
        a.join("dup").to_str().unwrap(),
        b.join("dup").to_str().unwrap(),
        dest.to_str().unwrap(),
    ]));
    assert!(!dest.exists());
}

#[test]
fn move_does_not_remove_any_source_on_preflight_error() {
    let t = TempDir::new().unwrap();
    let a = t.path().join("a");
    let b = t.path().join("b");
    let dest = t.path().join("dst");
    fs::create_dir_all(&dest).unwrap();
    write(&a, "first");
    write(&b, "second");
    write(&dest.join("b"), "existing");
    assert_error(mch(&[
        "-m",
        a.to_str().unwrap(),
        b.to_str().unwrap(),
        dest.to_str().unwrap(),
    ]));
    assert_eq!(fs::read_to_string(a).unwrap(), "first");
    assert_eq!(fs::read_to_string(b).unwrap(), "second");
    assert!(!dest.join("a").exists());
}

#[test]
fn invalid_worker_count_fails() {
    let t = TempDir::new().unwrap();
    let a = t.path().join("a");
    write(&a, "a");
    let dest = t.path().join("b");
    assert_error(mch(&[
        "--count",
        "0",
        a.to_str().unwrap(),
        dest.to_str().unwrap(),
    ]));
    assert_error(mch(&[
        "--count",
        "257",
        a.to_str().unwrap(),
        dest.to_str().unwrap(),
    ]));
}

#[cfg(unix)]
#[test]
fn symlink_preserves_link_target_including_dangling_links() {
    use std::os::unix::fs::symlink;
    let t = TempDir::new().unwrap();
    let input = t.path().join("link");
    let dest = t.path().join("copied");
    symlink("does-not-exist", &input).unwrap();
    assert_success(mch(&[input.to_str().unwrap(), dest.to_str().unwrap()]));
    assert_eq!(fs::read_link(dest).unwrap(), Path::new("does-not-exist"));
}

#[cfg(unix)]
#[test]
fn destination_directory_symlink_is_refused() {
    use std::os::unix::fs::symlink;
    let t = TempDir::new().unwrap();
    let src = t.path().join("original");
    let safe_dir = t.path().join("safe");
    let alias = t.path().join("alias");
    fs::create_dir(&safe_dir).unwrap();
    symlink(&safe_dir, &alias).unwrap();
    write(&src, "secure");
    let output = alias.join("out");
    assert_error(mch(&[src.to_str().unwrap(), output.to_str().unwrap()]));
    assert!(!safe_dir.join("out").exists());
}

#[cfg(unix)]
#[test]
fn hard_link_self_overwrite_is_refused() {
    let t = TempDir::new().unwrap();
    let src = t.path().join("src");
    let dst = t.path().join("hard-link");
    write(&src, "precious");
    if let Err(error) = fs::hard_link(&src, &dst) {
        if matches!(
            error.kind(),
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
        ) {
            return; // Some Android filesystems disallow app-created hard links.
        }
        panic!("hard_link fixture failed: {error}");
    }
    assert_error(mch(&[
        "--overwrite",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]));
    assert_eq!(fs::read_to_string(src).unwrap(), "precious");
}

#[test]
fn move_directory_only_after_copying_everything() {
    let t = TempDir::new().unwrap();
    let src = t.path().join("src");
    fs::create_dir_all(src.join("inner")).unwrap();
    write(&src.join("inner/data"), "done");
    let dst = t.path().join("destination");
    assert_success(mch(&[
        "--move",
        "--count",
        "3",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]));
    assert!(!src.exists());
    assert_eq!(
        fs::read_to_string(dst.join("src/inner/data")).unwrap(),
        "done"
    );
}

#[test]
fn unicode_spaces_and_nonempty_name_copy() {
    let t = TempDir::new().unwrap();
    let source = t.path().join("ä Ö 🎼 test file.txt");
    let destination = t.path().join("ziel datei.txt");
    write(&source, "Äpfel ☃");
    assert_success(mch(&[
        source.to_str().unwrap(),
        destination.to_str().unwrap(),
    ]));
    assert_eq!(fs::read_to_string(destination).unwrap(), "Äpfel ☃");
}

#[test]
fn banner_contains_motto_but_help_and_version_do_not() {
    let t = TempDir::new().unwrap();
    let source = t.path().join("src");
    let destination = t.path().join("dst");
    write(&source, "sample");
    let run = mch(&[source.to_str().unwrap(), destination.to_str().unwrap()]);
    assert_success(run.clone());
    let full = String::from_utf8_lossy(&run.stdout);
    assert!(full.contains("Life is short. Time is small."));
    assert!(full.contains("Copyright (C) 2026 Olize"));
    for option in ["-h", "-v", "--version"] {
        let output = mch(&[option]);
        assert_success(output.clone());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("Life is short."));
    }
}

#[test]
fn many_files_are_copied_with_parallel_workers() {
    let t = TempDir::new().unwrap();
    let src = t.path().join("many");
    let dst = t.path().join("copy");
    fs::create_dir(&src).unwrap();
    for index in 0..128 {
        write(
            &src.join(format!("file-{index:04}")),
            &format!("payload-{index}"),
        );
    }
    assert_success(mch(&[
        "--count",
        "12",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]));
    for index in 0..128 {
        let name = format!("file-{index:04}");
        assert_eq!(
            fs::read(src.join(&name)).unwrap(),
            fs::read(dst.join("many").join(&name)).unwrap()
        );
    }
}

#[cfg(unix)]
#[test]
fn copy_preserves_unix_file_mode() {
    use std::os::unix::fs::PermissionsExt;
    let t = TempDir::new().unwrap();
    let src = t.path().join("executable");
    let dst = t.path().join("copied");
    write(&src, "hello");
    fs::set_permissions(&src, fs::Permissions::from_mode(0o751)).unwrap();
    assert_success(mch(&[src.to_str().unwrap(), dst.to_str().unwrap()]));
    assert_eq!(
        fs::metadata(dst).unwrap().permissions().mode() & 0o777,
        0o751
    );
}

#[test]
fn move_retains_source_when_destination_file_conflicts() {
    let t = TempDir::new().unwrap();
    let src = t.path().join("source");
    let dst = t.path().join("target");
    write(&src, "original");
    write(&dst, "occupied");
    assert_error(mch(&["-m", src.to_str().unwrap(), dst.to_str().unwrap()]));
    assert_eq!(fs::read_to_string(&src).unwrap(), "original");
    assert_eq!(fs::read_to_string(&dst).unwrap(), "occupied");
}

#[test]
fn progress_always_reports_verified_transfer_without_terminal_control() {
    let t = TempDir::new().unwrap();
    let source = t.path().join("big.bin");
    let dest = t.path().join("copy.bin");
    fs::write(&source, vec![0x5Au8; 2 * 1024 * 1024]).unwrap();
    let out = mch(&[
        "--progress",
        "always",
        source.to_str().unwrap(),
        dest.to_str().unwrap(),
    ]);
    assert_success(out.clone());
    assert_eq!(fs::read(source).unwrap(), fs::read(dest).unwrap());
    let progress = String::from_utf8_lossy(&out.stderr);
    assert!(
        progress.contains("PROGRESS COPY VERIFIED: 100.0%"),
        "{progress}"
    );
    assert!(progress.contains("2.0 MiB / 2.0 MiB copied"), "{progress}");
    assert!(progress.contains("1/1 files"), "{progress}");
    assert!(progress.contains("copy ETA 0s"), "{progress}");
    assert!(
        !progress.contains('\r'),
        "screenreader output must use normal lines"
    );
    assert!(!progress.contains("\x1b["), "no ANSI control sequences");
}

#[test]
fn progress_auto_never_and_quiet_are_silent_in_piped_cli() {
    let t = TempDir::new().unwrap();
    let src = t.path().join("input");
    write(&src, "test");
    for (flags, name) in [
        (vec![], "auto"),
        (vec!["--progress", "never"], "never"),
        (vec!["-q", "--progress", "always"], "quiet"),
        (vec!["--progress", "always", "--dry-run"], "dry-run"),
    ] {
        let dst = t.path().join(name);
        let mut args = flags;
        args.extend([src.to_str().unwrap(), dst.to_str().unwrap()]);
        let result = mch(&args);
        assert_success(result.clone());
        assert!(
            !String::from_utf8_lossy(&result.stderr).contains("PROGRESS"),
            "unexpected progress in {name}"
        );
        assert_eq!(dst.exists(), name != "dry-run");
    }
}

#[test]
fn progress_always_with_empty_directory_and_zero_byte_file() {
    let t = TempDir::new().unwrap();
    let empty = t.path().join("dir");
    fs::create_dir(&empty).unwrap();
    let out = mch(&[
        "--progress",
        "always",
        empty.to_str().unwrap(),
        t.path().join("dest").to_str().unwrap(),
    ]);
    assert_success(out.clone());
    assert!(String::from_utf8_lossy(&out.stderr).contains("0/0 files"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("100.0%"));
    let src = t.path().join("zero.bin");
    write(&src, "");
    let target = t.path().join("zero-copy.bin");
    let out = mch(&[
        "--progress",
        "always",
        src.to_str().unwrap(),
        target.to_str().unwrap(),
    ]);
    assert_success(out.clone());
    assert!(String::from_utf8_lossy(&out.stderr).contains("1/1 files"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("0 B / 0 B copied"));
}

#[test]
fn progress_parallel_move_matches_source_and_removes_it() {
    let t = TempDir::new().unwrap();
    let source = t.path().join("folder");
    fs::create_dir(&source).unwrap();
    for i in 0..20 {
        fs::write(source.join(format!("{i}.bin")), vec![i as u8; 4096]).unwrap();
    }
    let target = t.path().join("dest");
    let out = mch(&[
        "--progress",
        "always",
        "--count",
        "4",
        "-m",
        source.to_str().unwrap(),
        target.to_str().unwrap(),
    ]);
    assert_success(out.clone());
    assert!(String::from_utf8_lossy(&out.stderr).contains("20/20 files"));
    assert!(!source.exists());
    for i in 0..20 {
        assert_eq!(
            fs::read(target.join("folder").join(format!("{i}.bin"))).unwrap(),
            vec![i as u8; 4096]
        );
    }
}

#[test]
fn progress_invalid_value_and_preflight_conflict_cannot_modify_source() {
    let t = TempDir::new().unwrap();
    let src = t.path().join("src");
    let dest = t.path().join("dest");
    write(&src, "retain");
    write(&dest, "existing");
    assert_error(mch(&[
        "--progress",
        "invalid",
        src.to_str().unwrap(),
        dest.to_str().unwrap(),
    ]));
    let failure = mch(&[
        "--progress",
        "always",
        "--move",
        src.to_str().unwrap(),
        dest.to_str().unwrap(),
    ]);
    assert_error(failure.clone());
    assert!(!String::from_utf8_lossy(&failure.stderr).contains("COPY VERIFIED"));
    assert_eq!(fs::read_to_string(&src).unwrap(), "retain");
    assert_eq!(fs::read_to_string(&dest).unwrap(), "existing");
}

#[cfg(unix)]
#[test]
fn progress_always_preserves_unix_file_mode() {
    use std::os::unix::fs::PermissionsExt;
    let t = TempDir::new().unwrap();
    let source = t.path().join("executable");
    let dest = t.path().join("copy");
    write(&source, "binary content");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o751)).unwrap();
    assert_success(mch(&[
        "--progress",
        "always",
        source.to_str().unwrap(),
        dest.to_str().unwrap(),
    ]));
    assert_eq!(
        fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
        0o751
    );
    assert_eq!(fs::read(source).unwrap(), fs::read(dest).unwrap());
}

#[test]
fn preserve_times_for_file_with_and_without_progress() {
    use filetime::{FileTime, set_file_times};
    let t = TempDir::new().unwrap();
    let src = t.path().join("original.bin");
    write(&src, "mtime and atime test data");
    let access = FileTime::from_unix_time(1_600_000_000, 0);
    let modified = FileTime::from_unix_time(1_640_000_000, 0);
    set_file_times(&src, access, modified).unwrap();
    for (index, extra) in [Vec::<&str>::new(), vec!["--progress", "always"]]
        .into_iter()
        .enumerate()
    {
        let dst = t.path().join(format!("output-{index}.bin"));
        let mut args = vec!["--preserve-times"];
        args.extend(extra);
        args.extend([src.to_str().unwrap(), dst.to_str().unwrap()]);
        assert_success(mch(&args));
        let metadata = fs::metadata(&dst).unwrap();
        assert_eq!(
            FileTime::from_last_modification_time(&metadata).unix_seconds(),
            modified.unix_seconds()
        );
        assert_eq!(
            FileTime::from_last_access_time(&metadata).unix_seconds(),
            access.unix_seconds()
        );
        assert_eq!(fs::read(&src).unwrap(), fs::read(&dst).unwrap());
        set_file_times(&src, access, modified).unwrap();
    }
}

#[test]
fn preserve_times_of_new_nested_directories_after_copying_children() {
    use filetime::{FileTime, set_file_times};
    let t = TempDir::new().unwrap();
    let src = t.path().join("photos");
    fs::create_dir_all(src.join("nested/empty")).unwrap();
    write(&src.join("nested/picture"), "content");
    let access = FileTime::from_unix_time(1_600_000_000, 0);
    let modified = FileTime::from_unix_time(1_640_000_000, 0);
    for directory in [src.join("nested/empty"), src.join("nested"), src.clone()] {
        set_file_times(directory, access, modified).unwrap();
    }
    let out = t.path().join("archive");
    assert_success(mch(&[
        "--preserve-times",
        "--count",
        "4",
        src.to_str().unwrap(),
        out.to_str().unwrap(),
    ]));
    for directory in [
        out.join("photos"),
        out.join("photos/nested"),
        out.join("photos/nested/empty"),
    ] {
        let meta = fs::metadata(&directory).unwrap();
        assert_eq!(
            FileTime::from_last_modification_time(&meta).unix_seconds(),
            modified.unix_seconds(),
            "mtime of {}",
            directory.display()
        );
        assert_eq!(
            FileTime::from_last_access_time(&meta).unix_seconds(),
            access.unix_seconds(),
            "atime of {}",
            directory.display()
        );
    }
}

#[test]
fn preserve_times_does_not_apply_source_dir_times_to_existing_destination_dir() {
    use filetime::{FileTime, set_file_times};
    let t = TempDir::new().unwrap();
    let src = t.path().join("photos");
    let dest = t.path().join("archive");
    let already_there = dest.join("photos");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&already_there).unwrap();
    write(&src.join("new"), "new content");
    let old = FileTime::from_unix_time(1_600_000_000, 0);
    let newer = FileTime::from_unix_time(1_700_000_000, 0);
    set_file_times(&src, old, old).unwrap();
    set_file_times(&already_there, newer, newer).unwrap();
    assert_success(mch(&[
        "--preserve-times",
        src.to_str().unwrap(),
        dest.to_str().unwrap(),
    ]));
    assert!(already_there.join("new").exists());
    let result = FileTime::from_last_modification_time(&fs::metadata(&already_there).unwrap());
    assert_ne!(
        result.unix_seconds(),
        old.unix_seconds(),
        "existing destination directories must not inherit source timestamps"
    );
}

#[cfg(unix)]
#[test]
fn preserve_symlink_times_without_touching_link_target() {
    use filetime::{FileTime, set_file_times, set_symlink_file_times};
    use std::os::unix::fs::symlink;
    let t = TempDir::new().unwrap();
    let target = t.path().join("target");
    let link = t.path().join("link");
    let copied = t.path().join("copied-link");
    write(&target, "target bytes");
    symlink("target", &link).unwrap();
    let target_time = FileTime::from_unix_time(1_700_000_000, 0);
    let link_time = FileTime::from_unix_time(1_600_000_000, 0);
    set_file_times(&target, target_time, target_time).unwrap();
    set_symlink_file_times(&link, link_time, link_time).unwrap();
    assert_success(mch(&[
        "--preserve-times",
        link.to_str().unwrap(),
        copied.to_str().unwrap(),
    ]));
    assert_eq!(fs::read_link(&copied).unwrap(), Path::new("target"));
    let copy_times = fs::symlink_metadata(&copied).unwrap();
    assert_eq!(
        FileTime::from_last_modification_time(&copy_times).unix_seconds(),
        link_time.unix_seconds()
    );
    let target_times = fs::metadata(&target).unwrap();
    assert_eq!(
        FileTime::from_last_modification_time(&target_times).unix_seconds(),
        target_time.unix_seconds(),
        "link time preservation must not change the target timestamp"
    );
}

#[test]
fn preserve_times_on_overwrite_and_move_and_dry_run() {
    use filetime::{FileTime, set_file_times};
    let t = TempDir::new().unwrap();
    let src = t.path().join("src");
    let dst = t.path().join("existing");
    write(&src, "replace me");
    write(&dst, "old");
    let mtime = FileTime::from_unix_time(1_600_000_000, 0);
    set_file_times(&src, mtime, mtime).unwrap();
    assert_success(mch(&[
        "--dry-run",
        "--preserve-times",
        "--overwrite",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]));
    assert_eq!(fs::read_to_string(&dst).unwrap(), "old");
    assert_success(mch(&[
        "--preserve-times",
        "--overwrite",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]));
    assert_eq!(
        FileTime::from_last_modification_time(&fs::metadata(&dst).unwrap()).unix_seconds(),
        mtime.unix_seconds()
    );
    let moved = t.path().join("moved");
    assert_success(mch(&[
        "--move",
        "--preserve-times",
        src.to_str().unwrap(),
        moved.to_str().unwrap(),
    ]));
    assert!(!src.exists());
    assert_eq!(
        FileTime::from_last_modification_time(&fs::metadata(&moved).unwrap()).unix_seconds(),
        mtime.unix_seconds()
    );
}

#[cfg(unix)]
#[test]
fn preserve_original_atime_for_several_hardlink_sources() {
    use filetime::{FileTime, set_file_times};
    let t = TempDir::new().unwrap();
    let input = t.path().join("hardlinks");
    let out = t.path().join("out");
    fs::create_dir_all(&input).unwrap();
    let first = input.join("a");
    let second = input.join("b");
    write(&first, "same inode must keep pre-copy access time");
    // Some Android/Termux installations deny hardlink creation even inside
    // their own temporary directory. Keep the full test mandatory on Unix
    // CI (Linux/macOS), but skip this unsupported fixture on Android only.
    if let Err(error) = fs::hard_link(&first, &second) {
        #[cfg(target_os = "android")]
        if matches!(
            error.kind(),
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
        ) {
            eprintln!("Android filesystem does not permit hardlinks: {error}");
            return;
        }
        panic!("create hardlink test fixture: {error}");
    }
    // atime older than mtime triggers relatime updates on Linux.
    let old_access = FileTime::from_unix_time(1_600_000_000, 0);
    let newer_mtime = FileTime::from_unix_time(1_700_000_000, 0);
    set_file_times(&first, old_access, newer_mtime).unwrap();
    assert_success(mch(&[
        "--preserve-times",
        "--count",
        "1",
        input.to_str().unwrap(),
        out.to_str().unwrap(),
    ]));
    for output in [out.join("hardlinks/a"), out.join("hardlinks/b")] {
        let meta = fs::metadata(&output).unwrap();
        assert_eq!(
            FileTime::from_last_access_time(&meta).unix_seconds(),
            old_access.unix_seconds(),
            "must preserve the original pre-copy atime for {}",
            output.display()
        );
        assert_eq!(
            FileTime::from_last_modification_time(&meta).unix_seconds(),
            newer_mtime.unix_seconds()
        );
    }
}

#[test]
fn progress_without_hash_must_never_claim_verification() {
    let t = TempDir::new().unwrap();
    let src = t.path().join("data");
    let dst = t.path().join("copy");
    write(&src, "no-hash intentionally bypasses verification");
    let output = mch(&[
        "--progress",
        "always",
        "-N",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]);
    assert_success(output.clone());
    let status = String::from_utf8_lossy(&output.stderr);
    assert!(
        status.contains("PROGRESS COPY COMPLETE (NO HASH VERIFICATION): 100.0%"),
        "{status}"
    );
    assert!(!status.contains("COPY VERIFIED"), "{status}");
    assert_eq!(fs::read(&src).unwrap(), fs::read(&dst).unwrap());
}

#[cfg(unix)]
fn resume_fixture_paths(
    source: &Path,
    dest: &Path,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    use std::os::unix::ffi::OsStrExt;
    let resolved = fs::canonicalize(source).unwrap();
    // macOS TempDir names commonly start with /var, which is a symlink
    // into /private/var. Engine planning normalizes the destination parent,
    // so fixtures must hash that *same physical destination*.
    let resolved_destination = fs::canonicalize(dest.parent().unwrap())
        .unwrap()
        .join(dest.file_name().unwrap());
    let mut hash = blake3::Hasher::new();
    hash.update(b"MCH-resume-v1\0");
    for part in [resolved.as_os_str(), resolved_destination.as_os_str()] {
        let bytes = part.as_bytes();
        hash.update(&(bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    let base = format!(".mch-resume-v1-{}", hash.finalize().to_hex());
    (
        dest.parent().unwrap().join(format!("{base}.part")),
        dest.parent().unwrap().join(format!("{base}.lock")),
        dest.parent().unwrap().join(format!("{base}.meta")),
    )
}

#[cfg(unix)]
fn seed_resume_partial(source: &Path, dest: &Path, bytes: usize) -> std::path::PathBuf {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let (part, _, manifest) = resume_fixture_paths(source, dest);
    let meta = fs::metadata(source).unwrap();
    let body = fs::read(source).unwrap();
    assert!(bytes <= body.len());
    fs::write(&part, &body[..bytes]).unwrap();
    fs::set_permissions(&part, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(
        &manifest,
        format!(
            "MCH-RESUME-1\n{}:{}:{}:{}:{}\n",
            meta.dev(),
            meta.ino(),
            meta.len(),
            meta.mtime(),
            meta.mtime_nsec()
        ),
    )
    .unwrap();
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600)).unwrap();
    part
}

#[cfg(unix)]
#[test]
fn resume_fresh_and_empty_files_are_verified() {
    let t = TempDir::new().unwrap();
    for length in [0, 20, 2 * 1024 * 1024 + 19] {
        let src = t.path().join(format!("source-{length}"));
        let dst = t.path().join(format!("target-{length}"));
        fs::write(&src, vec![0xA5; length]).unwrap();
        let out = mch(&[
            "--resume",
            "--progress",
            "always",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ]);
        assert_success(out.clone());
        assert_eq!(fs::read(&src).unwrap(), fs::read(&dst).unwrap());
        let status = String::from_utf8_lossy(&out.stderr);
        assert!(status.contains("RESUME HASH VERIFIED"), "{status}");
        assert!(status.contains("RESUME COPIED"), "{status}");
        let (partial, _, manifest) = resume_fixture_paths(&src, &dst);
        assert!(!partial.exists());
        assert!(!manifest.exists());
    }
}

#[cfg(unix)]
#[test]
fn resume_valid_prefix_and_persists_source_file_times() {
    use filetime::{FileTime, set_file_times};
    let t = TempDir::new().unwrap();
    let src = t.path().join("somé input file");
    let dst = t.path().join("output file");
    let data = vec![0x5F; 3 * 1024 * 1024 + 37];
    fs::write(&src, &data).unwrap();
    let atime = FileTime::from_unix_time(1_600_000_000, 0);
    let mtime = FileTime::from_unix_time(1_650_000_000, 0);
    set_file_times(&src, atime, mtime).unwrap();
    let partial = seed_resume_partial(&src, &dst, 2 * 1024 * 1024);
    let out = mch(&[
        "--resume",
        "--preserve-times",
        "--progress",
        "always",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]);
    assert_success(out.clone());
    let log = String::from_utf8_lossy(&out.stdout);
    assert!(log.contains("2097152 existing bytes"), "{log}");
    let progress = String::from_utf8_lossy(&out.stderr);
    assert!(
        progress.contains("2097152 B existing verified"),
        "{progress}"
    );
    assert!(progress.contains("1048613 B newly copied"), "{progress}");
    assert_eq!(fs::read(&dst).unwrap(), data);
    assert!(!partial.exists());
    assert_eq!(
        FileTime::from_last_modification_time(&fs::metadata(&dst).unwrap()).unix_seconds(),
        mtime.unix_seconds()
    );
}

#[cfg(unix)]
#[test]
fn resume_corrupted_prefix_and_oversized_partial_fail_without_data_loss() {
    use std::os::unix::fs::PermissionsExt;
    let t = TempDir::new().unwrap();
    let src = t.path().join("source");
    let dst = t.path().join("destination");
    fs::write(&src, b"this is the immutable original content").unwrap();
    let partial = seed_resume_partial(&src, &dst, 20);
    fs::write(&partial, b"CHANGED CONTENT HERE").unwrap();
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o600)).unwrap();
    let before = fs::read(&partial).unwrap();
    assert_error(mch(&[
        "--resume",
        "--move",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]));
    assert_eq!(
        fs::read(&src).unwrap(),
        b"this is the immutable original content"
    );
    assert_eq!(fs::read(&partial).unwrap(), before);
    assert!(!dst.exists());
    fs::write(&partial, vec![1; 512]).unwrap();
    fs::set_permissions(&partial, fs::Permissions::from_mode(0o600)).unwrap();
    assert_error(mch(&[
        "--resume",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]));
    assert_eq!(
        fs::read(&src).unwrap(),
        b"this is the immutable original content"
    );
    assert!(!dst.exists());
}

#[cfg(unix)]
#[test]
fn resume_source_changed_after_partial_is_rejected() {
    use filetime::{FileTime, set_file_times};
    let t = TempDir::new().unwrap();
    let src = t.path().join("source");
    let dst = t.path().join("destination");
    fs::write(&src, b"same initial prefix, original tail content").unwrap();
    let partial = seed_resume_partial(&src, &dst, 11);
    // Change only the tail while keeping the source size and prefix intact.
    let mut modified = fs::read(&src).unwrap();
    let last = modified.len() - 1;
    modified[last] ^= 1;
    fs::write(&src, modified).unwrap();
    set_file_times(
        &src,
        FileTime::from_unix_time(1_600_000_000, 0),
        FileTime::from_unix_time(1_700_000_000, 0),
    )
    .unwrap();
    let outcome = mch(&["--resume", src.to_str().unwrap(), dst.to_str().unwrap()]);
    assert_error(outcome.clone());
    assert!(
        String::from_utf8_lossy(&outcome.stderr).contains("identity, size or modification time")
    );
    assert!(partial.exists());
    assert!(!dst.exists());
}

#[cfg(unix)]
#[test]
fn resume_rejects_symlink_staging_hardlinks_and_malformed_manifest() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let t = TempDir::new().unwrap();
    let src = t.path().join("source");
    let dst = t.path().join("destination");
    fs::write(&src, b"still present").unwrap();
    let part = seed_resume_partial(&src, &dst, 3);
    let (part_path, _, manifest) = resume_fixture_paths(&src, &dst);
    assert_eq!(part, part_path);
    fs::remove_file(&part).unwrap();
    symlink(&src, &part).unwrap();
    assert_error(mch(&[
        "--resume",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]));
    assert_eq!(fs::read(&src).unwrap(), b"still present");
    fs::remove_file(&part).unwrap();
    fs::write(&part, b"sti").unwrap();
    fs::set_permissions(&part, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&manifest, b"invalid-state").unwrap();
    assert_error(mch(&[
        "--resume",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]));
    assert!(!dst.exists());
    assert_eq!(fs::read(&src).unwrap(), b"still present");
}

#[cfg(unix)]
#[test]
fn resume_existing_destination_needs_overwrite_and_move_removes_only_after_hash() {
    let t = TempDir::new().unwrap();
    let src = t.path().join("source");
    let dst = t.path().join("destination");
    fs::write(&src, b"verified copied content").unwrap();
    fs::write(&dst, b"preserve existing content").unwrap();
    let out = mch(&["--resume", src.to_str().unwrap(), dst.to_str().unwrap()]);
    assert_error(out);
    assert_eq!(fs::read(&dst).unwrap(), b"preserve existing content");
    assert!(src.exists());
    let stage = seed_resume_partial(&src, &dst, 14);
    assert_success(mch(&[
        "--resume",
        "--move",
        "--overwrite",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]));
    assert!(!src.exists());
    assert!(!stage.exists());
    assert_eq!(fs::read(&dst).unwrap(), b"verified copied content");
}

#[cfg(unix)]
#[test]
fn resume_overwrite_without_move_keeps_source_and_replaces_target() {
    let t = TempDir::new().unwrap();
    let src = t.path().join("source");
    let dst = t.path().join("destination");
    fs::write(&src, b"verified replacement for resume overwrite").unwrap();
    fs::write(&dst, b"old target must be replaced").unwrap();
    let part = seed_resume_partial(&src, &dst, 12);
    assert_success(mch(&[
        "--resume",
        "--overwrite",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]));
    assert!(!part.exists());
    assert_eq!(fs::read(&src).unwrap(), fs::read(&dst).unwrap());
    assert!(src.exists(), "non-move overwrite must never delete source");
}

#[test]
fn resume_rejects_unsupported_flags_and_dry_run_does_not_write() {
    let t = TempDir::new().unwrap();
    let src = t.path().join("source");
    let dst = t.path().join("destination");
    write(&src, "contents");
    assert_error(mch(&[
        "--resume",
        "-N",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]));
    assert_error(mch(&[
        "--resume",
        "--count",
        "2",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]));
    assert_error(mch(&[
        "--resume",
        "-O",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]));
    assert_error(mch(&[
        "--resume",
        src.to_str().unwrap(),
        src.to_str().unwrap(),
    ]));
    #[cfg(unix)]
    {
        assert_success(mch(&[
            "--resume",
            "--dry-run",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ]));
        assert!(!dst.exists());
        let (stage, lock, manifest) = resume_fixture_paths(&src, &dst);
        assert!(!stage.exists() && !lock.exists() && !manifest.exists());
    }
    assert_eq!(fs::read(&src).unwrap(), b"contents");
}

#[cfg(unix)]
#[test]
fn resume_rejects_locked_transfer_and_does_not_publish() {
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let t = TempDir::new().unwrap();
    let src = t.path().join("source");
    let dst = t.path().join("destination");
    fs::write(&src, b"concurrency conflict").unwrap();
    let (_, lock_path, _) = resume_fixture_paths(&src, &dst);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&lock_path)
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let out = mch(&["--resume", src.to_str().unwrap(), dst.to_str().unwrap()]);
    assert_error(out.clone());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("another MCH --resume is active"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!dst.exists());
    assert_eq!(fs::read(&src).unwrap(), b"concurrency conflict");
}

#[cfg(unix)]
#[test]
fn resume_rejects_missing_manifest_and_lockfile_symlink() {
    use std::os::unix::fs::symlink;
    let t = TempDir::new().unwrap();
    let src = t.path().join("src");
    let dst = t.path().join("dst");
    fs::write(&src, b"source").unwrap();
    let (part, lock, manifest) = resume_fixture_paths(&src, &dst);
    fs::write(&part, b"source").unwrap();
    // An abandoned/incomplete pair must NOT be automatically trusted.
    let out = mch(&["--resume", src.to_str().unwrap(), dst.to_str().unwrap()]);
    assert_error(out.clone());
    let diagnostic = String::from_utf8_lossy(&out.stderr);
    assert!(
        diagnostic.contains("incomplete resume staging/manifest"),
        "{diagnostic}"
    );
    assert!(
        diagnostic.contains(&part.display().to_string()),
        "{diagnostic}"
    );
    assert!(
        diagnostic.contains(&manifest.display().to_string()),
        "{diagnostic}"
    );
    assert!(!manifest.exists());
    fs::remove_file(&lock).unwrap();
    symlink(&src, &lock).unwrap();
    let out = mch(&["--resume", src.to_str().unwrap(), dst.to_str().unwrap()]);
    assert_error(out);
    assert_eq!(fs::read(&src).unwrap(), b"source");
    assert!(!dst.exists());
}

#[cfg(unix)]
#[test]
fn resume_rejects_hardlinked_partial_instead_of_modifying_linked_source() {
    use std::os::unix::fs::MetadataExt;
    let t = TempDir::new().unwrap();
    let src = t.path().join("source");
    let dst = t.path().join("dst");
    fs::write(&src, b"important source content").unwrap();
    let stage = seed_resume_partial(&src, &dst, 5);
    fs::remove_file(&stage).unwrap();
    // Android may block creating hardlinks at the OS level.
    if let Err(err) = fs::hard_link(&src, &stage) {
        #[cfg(target_os = "android")]
        if matches!(
            err.kind(),
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::Unsupported
        ) {
            return;
        }
        panic!("unexpected hardlink fixture error: {err}");
    }
    assert!(fs::metadata(&stage).unwrap().nlink() >= 2);
    let result = mch(&[
        "--resume",
        "--move",
        src.to_str().unwrap(),
        dst.to_str().unwrap(),
    ]);
    assert_error(result);
    assert_eq!(fs::read(&src).unwrap(), b"important source content");
    assert!(!dst.exists());
}

#[cfg(unix)]
#[test]
fn resume_refuses_directory_and_symlink_source_even_on_dry_run() {
    use std::os::unix::fs::symlink;
    let t = TempDir::new().unwrap();
    let src = t.path().join("src");
    let dir = t.path().join("dir");
    let link = t.path().join("link");
    let out = t.path().join("out");
    fs::write(&src, b"keep").unwrap();
    fs::create_dir(&dir).unwrap();
    symlink(&src, &link).unwrap();
    assert_error(mch(&[
        "--resume",
        "--dry-run",
        dir.to_str().unwrap(),
        out.to_str().unwrap(),
    ]));
    assert_error(mch(&[
        "--resume",
        link.to_str().unwrap(),
        out.to_str().unwrap(),
    ]));
    assert_eq!(fs::read(&src).unwrap(), b"keep");
    assert!(!out.exists());
}

#[test]
fn move_empty_tree_with_new_parent_directories_succeeds() {
    let t = TempDir::new().unwrap();
    let source = t.path().join("empty-src");
    fs::create_dir_all(source.join("sub/empty")).unwrap();
    let dest = t.path().join("not-yet-created/level/toplevel");
    let result = mch(&["--move", source.to_str().unwrap(), dest.to_str().unwrap()]);
    assert_success(result);
    assert!(!source.exists());
    assert!(dest.join("empty-src/sub/empty").is_dir());
}

#[cfg(unix)]
#[test]
fn resume_move_rejects_new_destination_parent_and_keeps_source() {
    let t = TempDir::new().unwrap();
    let source = t.path().join("only-source");
    let parent = t.path().join("missing/directory");
    let destination = parent.join("copy");
    fs::write(&source, b"never remove this without durable destination").unwrap();
    let output = mch(&[
        "--resume",
        "--move",
        source.to_str().unwrap(),
        destination.to_str().unwrap(),
    ]);
    assert_error(output.clone());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("--resume --move requires an existing destination parent"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(source).unwrap(),
        b"never remove this without durable destination"
    );
    assert!(!parent.exists());
}

#[cfg(unix)]
#[test]
fn resume_publishes_original_unix_permissions_after_private_staging() {
    use std::os::unix::fs::PermissionsExt;
    let t = TempDir::new().unwrap();
    let source = t.path().join("source");
    let destination = t.path().join("destination");
    fs::write(&source, b"permission preservation with resumed copy").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
    let partial = seed_resume_partial(&source, &destination, 10);
    assert_eq!(
        fs::metadata(&partial).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_success(mch(&[
        "--resume",
        source.to_str().unwrap(),
        destination.to_str().unwrap(),
    ]));
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert_eq!(fs::read(&source).unwrap(), fs::read(&destination).unwrap());
    assert!(!partial.exists());
}
