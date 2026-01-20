// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const COLOR_OK: &str = "\x1b[32;1m";
const COLOR_BAD: &str = "\x1b[31;1m";
const COLOR_RESET: &str = "\x1b[0m";

#[derive(Copy, Clone, Debug, ValueEnum)]
enum HashAlg {
    Blake3,
    Sha256,
    Sha512,
    Sha3_256,
    Sha3_512,
    Blake2b,
    Blake2s,
    Xxh3,
}

impl HashAlg {
    fn as_str(self) -> &'static str {
        match self {
            HashAlg::Blake3 => "BLAKE3",
            HashAlg::Sha256 => "SHA256",
            HashAlg::Sha512 => "SHA512",
            HashAlg::Sha3_256 => "SHA3-256",
            HashAlg::Sha3_512 => "SHA3-512",
            HashAlg::Blake2b => "BLAKE2B",
            HashAlg::Blake2s => "BLAKE2S",
            HashAlg::Xxh3 => "XXH3",
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "mch",
    disable_help_subcommand = true,
    disable_version_flag = true,
    version = VERSION,
    about = concat!("Mighty Copy with Hash
Copyright (C) 2026 Olize
", env!("CARGO_PKG_VERSION")),
    long_about = None
)]
struct Cli {
    /// Print version information (custom header)
    #[arg(short = 'v', long = "version")]
    version: bool,
    /// Print version information

    #[arg(short = 'm', long = "move")]
    move_mode: bool,

    #[arg(short = 'N', long = "no-hash")]
    no_hash: bool,

    #[arg(
        long = "hash",
        value_enum,
        default_value = "blake3",
        ignore_case = true
    )]
    hash: HashAlg,

    #[arg(long = "count", default_value_t = 1)]
    count: u32,

    #[arg(short = 'O', long = "only-src-content")]
    only_src_content: bool,

    #[arg(required = true)]
    sources: Vec<String>,

    #[arg(required = true)]
    destination: String,
}

fn ensure_parent_dir(dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir: {}", parent.display()))?;
    }
    Ok(())
}

fn file_name_of(p: &Path) -> Result<&OsStr> {
    p.file_name()
        .ok_or_else(|| anyhow!("cannot determine filename for {}", p.display()))
}

fn is_dir(p: &Path) -> bool {
    fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

fn hash_file(path: &Path, alg: HashAlg) -> Result<String> {
    let mut f =
        fs::File::open(path).with_context(|| format!("open for hashing: {}", path.display()))?;
    let mut buf = vec![0u8; 1024 * 1024];

    match alg {
        HashAlg::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hasher.finalize().to_hex().to_string())
        }
        HashAlg::Sha256 => {
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        HashAlg::Sha512 => {
            use sha2::Digest;
            let mut hasher = sha2::Sha512::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        HashAlg::Sha3_256 => {
            use sha3::Digest;
            let mut hasher = sha3::Sha3_256::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        HashAlg::Sha3_512 => {
            use sha3::Digest;
            let mut hasher = sha3::Sha3_512::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        HashAlg::Blake2b => {
            use blake2::digest::Digest;
            let mut hasher = blake2::Blake2b512::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        HashAlg::Blake2s => {
            use blake2::digest::Digest;
            let mut hasher = blake2::Blake2s256::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(hex::encode(hasher.finalize()))
        }
        HashAlg::Xxh3 => {
            use xxhash_rust::xxh3::Xxh3;
            let mut hasher = Xxh3::new();
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(format!("{:016x}", hasher.digest()))
        }
    }
}

fn print_verify(ok: bool, label: &str, alg: HashAlg) {
    if ok {
        println!("{COLOR_OK}{label} {} SRC ≙ DEST{COLOR_RESET}", alg.as_str());
    } else {
        println!(
            "{COLOR_BAD}{label} {} SRC ≠ DEST{COLOR_RESET}",
            alg.as_str()
        );
    }
}

#[cfg(unix)]
fn copy_symlink(src: &Path, dst: &Path, cli: &Cli) -> Result<()> {
    use std::os::unix::fs as unixfs;

    ensure_parent_dir(dst)?;
    let target = fs::read_link(src).with_context(|| format!("read symlink: {}", src.display()))?;

    let _ = fs::remove_file(dst);
    unixfs::symlink(&target, dst)
        .with_context(|| format!("create symlink: {} -> {}", dst.display(), target.display()))?;

    if !cli.no_hash {
        let dst_target =
            fs::read_link(dst).with_context(|| format!("read symlink: {}", dst.display()))?;
        let ok = target == dst_target;
        print_verify(ok, &format!("SYMLINK {}", src.display()), cli.hash);
        if !ok {
            return Err(anyhow!(
                "symlink target mismatch: {} -> {:?} vs {:?}",
                src.display(),
                target,
                dst_target
            ));
        }
    }

    Ok(())
}

fn copy_regular_file(src: &Path, dst: &Path, cli: &Cli) -> Result<()> {
    ensure_parent_dir(dst)?;
    fs::copy(src, dst)
        .with_context(|| format!("copy file: {} -> {}", src.display(), dst.display()))?;

    if !cli.no_hash {
        let h1 =
            hash_file(src, cli.hash).with_context(|| format!("hash src: {}", src.display()))?;
        let h2 =
            hash_file(dst, cli.hash).with_context(|| format!("hash dst: {}", dst.display()))?;
        let ok = h1 == h2;
        print_verify(ok, &src.display().to_string(), cli.hash);
        if !ok {
            return Err(anyhow!(
                "hash mismatch: {} ({} != {})",
                src.display(),
                h1,
                h2
            ));
        }
    }

    Ok(())
}

fn copy_dir_recursive(src_dir: &Path, dst_dir: &Path, cli: &Cli) -> Result<()> {
    fs::create_dir_all(dst_dir).with_context(|| format!("create dir: {}", dst_dir.display()))?;

    for entry in
        fs::read_dir(src_dir).with_context(|| format!("read dir: {}", src_dir.display()))?
    {
        let entry = entry?;
        let src_path = entry.path();
        let meta = fs::symlink_metadata(&src_path)
            .with_context(|| format!("stat: {}", src_path.display()))?;
        let dst_path = dst_dir.join(entry.file_name());

        if meta.file_type().is_dir() {
            copy_dir_recursive(&src_path, &dst_path, cli)?;
        } else if meta.file_type().is_symlink() {
            #[cfg(unix)]
            {
                copy_symlink(&src_path, &dst_path, cli)?;
            }
            #[cfg(not(unix))]
            {
                return Err(anyhow!(
                    "symlink not supported on this platform: {}",
                    src_path.display()
                ));
            }
        } else if meta.file_type().is_file() {
            copy_regular_file(&src_path, &dst_path, cli)?;
        } else {
            return Err(anyhow!("unsupported file type: {}", src_path.display()));
        }
    }

    Ok(())
}

fn compute_target_path_for_source(cli: &Cli, src: &Path, dest: &Path) -> Result<PathBuf> {
    if cli.sources.len() > 1 || is_dir(dest) {
        Ok(dest.join(file_name_of(src)?))
    } else {
        Ok(dest.to_path_buf())
    }
}

fn run(cli: Cli) -> Result<()> {
    // Custom version output for -v/--version
    if cli.version {
        println!("Mighty Copy with Hash");
        println!("Copyright (C) 2026 Olize");
        println!("{}", VERSION);
        return Ok(());
    }

    println!("Mighty Copy with Hash Version {}", VERSION);
    println!("Copyright (C) 2026 Olize");
    println!("PS.: Life is short. Time is small. Take it easy and fuck it all!");
    println!();

    if cli.count != 1 {
        eprintln!("Note: --count is accepted, but will be implemented in alpha.3. Using 1.");
    }

    let dest = PathBuf::from(&cli.destination);

    if cli.sources.len() > 1 {
        fs::create_dir_all(&dest)
            .with_context(|| format!("create destination dir: {}", dest.display()))?;
        if !is_dir(&dest) {
            return Err(anyhow!(
                "destination must be a directory when multiple sources are provided: {}",
                dest.display()
            ));
        }
    } else if cli.destination.ends_with('/') {
        fs::create_dir_all(&dest)
            .with_context(|| format!("create destination dir: {}", dest.display()))?;
    }

    let mut did_anything = false;

    for src_s in &cli.sources {
        let src = PathBuf::from(src_s);
        let meta = fs::symlink_metadata(&src)
            .with_context(|| format!("stat source: {}", src.display()))?;

        if meta.file_type().is_symlink() {
            let target_dst = compute_target_path_for_source(&cli, &src, &dest)?;
            #[cfg(unix)]
            {
                copy_symlink(&src, &target_dst, &cli)?;
            }
            #[cfg(not(unix))]
            {
                return Err(anyhow!(
                    "symlink not supported on this platform: {}",
                    src.display()
                ));
            }

            did_anything = true;
            if cli.move_mode {
                fs::remove_file(&src)
                    .with_context(|| format!("remove source symlink: {}", src.display()))?;
            }
        } else if meta.file_type().is_file() {
            let target_dst = compute_target_path_for_source(&cli, &src, &dest)?;
            copy_regular_file(&src, &target_dst, &cli)?;

            did_anything = true;
            if cli.move_mode {
                fs::remove_file(&src)
                    .with_context(|| format!("remove source file: {}", src.display()))?;
            }
        } else if meta.file_type().is_dir() {
            if cli.only_src_content {
                fs::create_dir_all(&dest)
                    .with_context(|| format!("create destination dir: {}", dest.display()))?;
                if !is_dir(&dest) {
                    return Err(anyhow!(
                        "destination must be a directory when using -O: {}",
                        dest.display()
                    ));
                }
                copy_dir_recursive(&src, &dest, &cli)?;
                did_anything = true;

                if cli.move_mode {
                    fs::remove_dir_all(&src)
                        .with_context(|| format!("remove source dir: {}", src.display()))?;
                }
            } else {
                fs::create_dir_all(&dest)
                    .with_context(|| format!("create destination dir: {}", dest.display()))?;
                if !is_dir(&dest) {
                    return Err(anyhow!(
                        "destination must be a directory when copying a directory: {}",
                        dest.display()
                    ));
                }
                let dst_dir = dest.join(file_name_of(&src)?);
                copy_dir_recursive(&src, &dst_dir, &cli)?;
                did_anything = true;

                if cli.move_mode {
                    fs::remove_dir_all(&src)
                        .with_context(|| format!("remove source dir: {}", src.display()))?;
                }
            }
        } else {
            return Err(anyhow!("unsupported file type: {}", src.display()));
        }
    }

    if !did_anything {
        return Err(anyhow!("nothing copied"));
    }

    Ok(())
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("ERROR: {:#}", e);
        std::process::exit(2);
    }
}
