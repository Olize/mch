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
    assert!(String::from_utf8_lossy(&output.stdout).contains("0.1.0"));
    assert_success(mch(&["--version"]));
    assert_error(mch(&[]));
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
