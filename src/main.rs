// SPDX-License-Identifier: AGPL-3.0-or-later

#[cfg(unix)]
mod batch_fault;
#[cfg(unix)]
mod batch_journal;
#[cfg(unix)]
mod batch_mkdir;
#[cfg(unix)]
mod batch_plan;
#[cfg(unix)]
mod batch_runtime;
#[cfg(unix)]
mod batch_store;
#[cfg(unix)]
mod batch_verify;
#[cfg(unix)]
mod batch_walk;
#[cfg(unix)]
mod batch_writer;
mod engine;
mod hashing;
#[cfg(target_os = "linux")]
mod linux_tree;
mod progress;
mod resume;
#[cfg(target_os = "linux")]
mod snapshot;
mod sparse;
#[cfg(target_os = "linux")]
mod tree_transaction;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use std::io::IsTerminal;
use std::path::PathBuf;

#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
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
    fn label(self) -> &'static str {
        match self {
            Self::Blake3 => "BLAKE3",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_512 => "SHA3-512",
            Self::Blake2b => "BLAKE2B",
            Self::Blake2s => "BLAKE2S",
            Self::Xxh3 => "XXH3",
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum, Eq, PartialEq)]
enum ProgressMode {
    Auto,
    Always,
    Never,
}

#[derive(Parser, Debug)]
#[command(
    name = "mch",
    about = "Mighty Copy with Hash — verified file copying and moving",
    long_about = None,
    disable_version_flag = true,
    version
)]
struct Cli {
    /// Print the MCH version and exit
    #[arg(short = 'v', long = "version")]
    version: bool,

    /// Move sources (remove them only after all copies succeed)
    #[arg(short = 'm', long = "move")]
    move_mode: bool,

    /// Skip source/destination verification (less safe, faster)
    #[arg(short = 'N', long = "no-hash")]
    no_hash: bool,

    /// Select the verification hash
    #[arg(long = "hash", value_enum, default_value_t = HashAlg::Blake3, ignore_case = true)]
    hash: HashAlg,

    /// Parallel file workers (1-256; 1 is the default)
    #[arg(long = "count", default_value_t = 1)]
    count: usize,

    /// Copy only the contents of one source directory
    #[arg(short = 'O', long = "only-src-content")]
    only_src_content: bool,

    /// Allow replacing existing regular files or symlinks
    #[arg(long = "overwrite")]
    overwrite: bool,

    /// macOS only: explicitly permit non-atomic verified copy on unsupported filesystems.
    /// A crash can leave a partial destination; never replaces an existing target.
    #[arg(long = "allow-nonatomic-publish")]
    allow_nonatomic_publish: bool,

    /// Display planned operations without writing or deleting anything
    #[arg(long = "dry-run")]
    dry_run: bool,

    /// Suppress per-file verification output
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// Never emit ANSI color sequences
    #[arg(long = "no-color")]
    no_color: bool,

    /// Line-based transfer progress: auto (TTY), always, or never
    #[arg(long = "progress", value_enum, default_value_t = ProgressMode::Auto)]
    progress: ProgressMode,

    /// Progress reporting interval in milliseconds (default 1000)
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(50..=3600000))]
    progress_interval_ms: u64,

    /// Copy runs of zero bytes as holes in ordinary files (requires sparse-file support)
    #[arg(long, conflicts_with_all = ["resume","resume_dir","transaction","allow_nonatomic_publish"])]
    sparse: bool,

    /// Preserve access and modification times on copied items (opt-in)
    #[arg(long = "preserve-times")]
    preserve_times: bool,

    /// Restart a partially copied single regular file (Unix only; experimental)
    #[arg(long = "resume")]
    resume: bool,

    /// Experimental opt-in: resume copying all regular files in one directory tree (Unix)
    #[arg(long = "resume-dir", conflicts_with_all = ["resume", "allow_nonatomic_publish"])]
    resume_dir: bool,

    /// Existing, private 0700 state directory for --resume-dir, outside both trees
    #[arg(long = "resume-dir-state", requires = "resume_dir")]
    resume_dir_state: Option<PathBuf>,

    /// Atomically publish one Linux directory tree with hardlinks, sparse data, ACLs, xattrs and ownership
    #[arg(long, value_name = "PRIVATE_STATE_DIR", conflicts_with_all = ["resume", "resume_dir", "move_mode", "overwrite", "no_hash", "dry_run", "allow_nonatomic_publish", "only_src_content", "preserve_times"])]
    transaction: Option<PathBuf>,

    /// Atomically exchange an existing destination directory and retain its previous contents
    #[arg(long, requires = "transaction")]
    replace_tree: bool,

    /// Withdraw a transaction, retaining the whole tree in its private state directory
    #[arg(long, requires = "transaction", conflicts_with = "snapshot_in")]
    rollback: bool,

    /// Create a retained read-only Btrfs snapshot in this existing directory before copying
    #[arg(long, value_name = "DIRECTORY", conflicts_with_all = ["move_mode", "dry_run", "resume"])]
    snapshot_in: Option<PathBuf>,

    /// One or more source files/directories
    #[arg(required = true, num_args = 1..)]
    sources: Vec<PathBuf>,

    /// Target file or directory
    #[arg(required = true)]
    destination: PathBuf,
}

impl Cli {
    fn color(&self) -> bool {
        !self.no_color && std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
    }

    fn show_progress(&self) -> bool {
        !self.quiet
            && !self.dry_run
            && match self.progress {
                ProgressMode::Auto => std::io::stderr().is_terminal(),
                ProgressMode::Always => true,
                ProgressMode::Never => false,
            }
    }

    fn report(&self, line: &str, ok: bool) {
        if self.quiet {
            return;
        }
        if self.color() {
            let color = if ok { "\x1b[32;1m" } else { "\x1b[31;1m" };
            println!("{color}{line}\x1b[0m");
        } else {
            println!("{line}");
        }
    }
}

fn run() -> Result<()> {
    let only_version = std::env::args_os()
        .nth(1)
        .is_some_and(|a| (a == "-v" || a == "--version") && std::env::args_os().count() == 2);
    if only_version {
        println!("Mighty Copy with Hash");
        println!("Copyright (C) 2026 Olize");
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let cli = Cli::parse();
    #[cfg(target_os = "linux")]
    let mut cli = cli;
    if cli.version {
        anyhow::bail!("-v/--version must be used alone; no files were copied");
    }

    if !cli.quiet {
        println!(
            "Mighty Copy with Hash Version {}",
            env!("CARGO_PKG_VERSION")
        );
        println!("Copyright (C) 2026 Olize");
        println!("PS.: Life is short. Time is small. Take it easy and fuck it all!");
        println!();
    }

    if !(1..=256).contains(&cli.count) {
        anyhow::bail!("--count must be between 1 and 256");
    }
    if cli.only_src_content && cli.sources.len() != 1 {
        anyhow::bail!("-O/--only-src-content requires exactly one source directory");
    }
    #[cfg(not(target_os = "macos"))]
    if cli.allow_nonatomic_publish {
        anyhow::bail!("--allow-nonatomic-publish is supported only on macOS");
    }
    if cli.allow_nonatomic_publish && (cli.move_mode || cli.overwrite || cli.no_hash || cli.resume)
    {
        anyhow::bail!(
            "--allow-nonatomic-publish requires verified ordinary copy (no --move, --overwrite, --no-hash, or --resume)"
        );
    }
    if (cli.snapshot_in.is_some() || cli.transaction.is_some()) && cli.sources.len() != 1 {
        anyhow::bail!("snapshot and transaction modes require exactly one source directory");
    }
    if cli.transaction.is_some() && (cli.hash != HashAlg::Blake3 || cli.count != 1) {
        anyhow::bail!("transaction mode requires BLAKE3 and one worker");
    }
    #[cfg(not(target_os = "linux"))]
    if cli.snapshot_in.is_some() || cli.transaction.is_some() {
        anyhow::bail!("tree transactions and Btrfs snapshot creation require Linux");
    }
    if cli.resume {
        if cli.no_hash {
            anyhow::bail!("--resume requires hash verification; remove -N/--no-hash");
        }
        if cli.sources.len() != 1 || cli.only_src_content || cli.count != 1 {
            anyhow::bail!(
                "--resume currently supports exactly one regular source file, --count 1, without -O"
            );
        }
        #[cfg(not(unix))]
        anyhow::bail!("--resume is not yet supported on this platform");
    }
    if cli.resume_dir {
        if cli.sources.len() != 1
            || cli.resume_dir_state.is_none()
            || cli.count != 1
            || cli.move_mode
            || cli.overwrite
            || cli.only_src_content
            || cli.no_hash
            || cli.dry_run
            || cli.preserve_times
            || cli.hash != HashAlg::Blake3
        {
            anyhow::bail!(
                "--resume-dir requires one source directory, --resume-dir-state PATH, --count 1, BLAKE3; no --move, --overwrite, -O, -N, --dry-run, or --preserve-times"
            );
        }
        #[cfg(not(unix))]
        anyhow::bail!("--resume-dir is currently supported only on Unix");
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(parent) = &cli.snapshot_in {
            cli.sources[0] = snapshot::capture(
                &cli.sources[0],
                parent,
                &cli.destination,
                cli.transaction
                    .as_deref()
                    .or(cli.resume_dir_state.as_deref()),
            )?;
        }
        if let Some(state) = &cli.transaction {
            return tree_transaction::run(
                &cli.sources[0],
                &cli.destination,
                state,
                cli.rollback,
                cli.replace_tree,
            );
        }
    }
    #[cfg(unix)]
    if cli.resume_dir {
        return batch_runtime::run(&cli);
    }
    let plan = engine::build_plan(&cli, &cli.destination)?;
    engine::execute(&cli, &plan)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ERROR: {error:#}");
        std::process::exit(2);
    }
}
