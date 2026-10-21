// SPDX-License-Identifier: AGPL-3.0-or-later

mod engine;
mod hashing;
mod progress;
mod resume;

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

    /// Preserve access and modification times on copied items (opt-in)
    #[arg(long = "preserve-times")]
    preserve_times: bool,

    /// Restart a partially copied single regular file (Unix only; experimental)
    #[arg(long = "resume")]
    resume: bool,

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
    let plan = engine::build_plan(&cli, &cli.destination)?;
    engine::execute(&cli, &plan)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ERROR: {error:#}");
        std::process::exit(2);
    }
}
