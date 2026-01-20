// SPDX-License-Identifier: AGPL-3.0-or-later

use clap::{Parser, ValueEnum};

const VERSION: &str = "0.0.1-alpha.1";

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

#[derive(Parser, Debug)]
#[command(
    name = "mch",
    disable_help_subcommand = true,
    version = VERSION,
    about = "Mighty Copy with Hash",
    long_about = None
)]
struct Cli {
    /// Copy mode is default. Use -m/--move to delete source after successful verify.
    #[arg(short = 'm', long = "move")]
    move_mode: bool,

    /// Do not perform hash verification.
    #[arg(short = 'N', long = "no-hash")]
    no_hash: bool,

    /// Hash algorithm (case-insensitive).
    #[arg(long = "hash", value_enum, default_value = "blake3", ignore_case = true)]
    hash: HashAlg,

    /// Number of files processed in parallel (positive integer). (TODO: implement)
    #[arg(long = "count", default_value_t = 1)]
    count: u32,

    /// Copy only the content of a source directory (without the top-level folder).
    #[arg(short = 'O', long = "only-src-content")]
    only_src_content: bool,

    /// Sources (files and/or directories).
    #[arg(required = true)]
    sources: Vec<String>,

    /// Destination path (last argument).
    #[arg(required = true)]
    destination: String,
}

fn main() {
    let cli = Cli::parse();

    println!("Mighty Copy with Hash Version {}", VERSION);
    println!("Copyright (C) 2026 Olize");
    println!("PS.: Life is short. Time is small. Take it easy and fuck it all!");
    println!();
    println!("Parsed args (scaffold):");
    println!("  move_mode: {}", cli.move_mode);
    println!("  no_hash: {}", cli.no_hash);
    println!("  hash: {:?}", cli.hash);
    println!("  count: {}", cli.count);
    println!("  only_src_content: {}", cli.only_src_content);
    println!("  sources: {:?}", cli.sources);
    println!("  destination: {}", cli.destination);
}
