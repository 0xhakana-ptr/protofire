//! tools/xtask/src/main.rs
//!
//! The command line, and the three things it can ask for.
//!
//! ## The files
//!
//! | File | What it holds |
//! |---|---|
//! | [`mod@machine`] | the triple, the emulator, the arguments that describe a machine |
//! | [`mod@build`] | building an image and booting it |
//! | [`mod@gate`] | what a boot must print, and the matchers that decide it |
//! | this file | the CLI and the dispatch |
//!
//! The split is by subject, and the subject that made it necessary is the
//! gate's: a list of every line a machine's boot must print is six hundred
//! lines of its own, and a reader asking how an image is built should not have
//! to scroll past it.
//!
//! ## Why this is Rust and not a script
//!
//! Thirty-odd `scripts/check-*.sh`, each the same shape, build, start QEMU,
//! capture the log, grep for a line, has a fine shape and the wrong medium.  An
//! assertion written as a `grep` is a string in a shell, and the only way to
//! know whether it can fail is to break the kernel and boot it.

mod build;
mod gate;
mod machine;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;

use crate::build::build;
use crate::build::run;
use crate::gate::check;
use crate::machine::Machine;

#[derive(Parser)]
#[command(about = "Build, boot and check the Protofire images")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Build one machine's image.
    Build {
        #[arg(long, value_enum, default_value = "x86_64")]
        machine: Machine,
        #[arg(long, default_value = "debug")]
        profile: String,
    },
    /// Boot one machine's image and keep its serial output.
    Run {
        #[arg(long, value_enum, default_value = "x86_64")]
        machine: Machine,
        #[arg(long, default_value = "debug")]
        profile: String,
        /// How long to let the machine run, in seconds.
        #[arg(long, default_value_t = 15)]
        timeout: u64,
        /// Keep the serial log at this path instead of a temporary file.
        #[arg(long)]
        log: Option<PathBuf>,
    },
    /// Boot one machine's image and require its first console line.
    Check {
        #[arg(long, value_enum, default_value = "x86_64")]
        machine: Machine,
        #[arg(long, default_value = "debug")]
        profile: String,
        #[arg(long, default_value_t = 15)]
        timeout: u64,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Build { machine, profile } => build(machine, &profile),
        Commands::Run {
            machine,
            profile,
            timeout,
            log,
        } => run(machine, &profile, timeout, log.as_deref()).map(|_| ()),
        Commands::Check {
            machine,
            profile,
            timeout,
        } => check(machine, &profile, timeout),
    }
}
