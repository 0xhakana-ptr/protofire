//! tools/xtask/src/main.rs
//!
//! The build, boot and check commands, written in Rust so their assertions can
//! be tested.
//!
//! ## Why this exists
//!
//! The previous tree had thirty-odd `scripts/check-*.sh`, and each one was the
//! same shape: build the image, start QEMU, capture the serial log, grep for a
//! line.  The shape is fine; the medium is not.  An assertion written as a
//! `grep` is a string in a shell, and the only way to know whether it can fail
//! is to break the kernel and run a boot — so the gates accumulate as copies of
//! each other, and the logic that decides pass from fail is the part nobody
//! tests.
//!
//! Here the decision is a function.  `expect_line` takes a log's text and the
//! line it wants and returns what is wrong with them; a unit test calls it with
//! a log that does not contain the line, and the failure path is exercised
//! without an emulator.  The QEMU invocation stays, because that is genuinely
//! an external process — but it is one implementation, spelled once, and every
//! check is a short argument list over it.
//!
//! ## What does not live here
//!
//! `cargo` and `rustfmt` are not shell scripts either, and a `just` recipe that
//! runs one command is already thin enough.  This tool is for the workflows
//! that would otherwise be a script: anything with a boot in it, and anything
//! that has to decide whether a log means success.

use std::fmt::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;
use clap::Parser;

/// The machines this tree knows how to build for.
///
/// The target triple is the whole of the selection: `arch` names its
/// implementation in a `cfg(target_arch)` table, so a triple that no crate has
/// an implementation for fails to build rather than picking one silently.
///
/// The accepted spellings are the ones the target triples use — `x86_64`, not
/// `x8664` — because a caller reads them from `rustc --print target-list` and
/// from every other command in this tree.  An alias that disagreed with the
/// thing it names is a papercut the previous tree's `Makefile` had in the other
/// direction (`run-x8664` beside `x86_64-unknown-none`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Machine {
    #[value(name = "x86_64", alias = "x8664")]
    X8664,
    Aarch64,
    Riscv64,
}

impl Machine {
    /// The Rust target triple.
    const fn triple(self) -> &'static str {
        match self {
            Self::X8664 => "x86_64-unknown-none",
            Self::Aarch64 => "aarch64-unknown-none",
            Self::Riscv64 => "riscv64gc-unknown-none-elf",
        }
    }

    /// The emulator that boots this machine's image.
    const fn qemu(self) -> &'static str {
        match self {
            Self::X8664 => "qemu-system-x86_64",
            Self::Aarch64 => "qemu-system-aarch64",
            Self::Riscv64 => "qemu-system-riscv64",
        }
    }

    /// The emulator arguments that describe the machine, without the kernel.
    ///
    /// Only x86_64 has one today, because only x86_64 has an image this tree
    /// can boot.  The other two return their arguments as an empty list rather
    /// than a guess: a machine whose boot has not been written is not a machine
    /// whose boot can be asserted, and inventing arguments for it would be a
    /// gate that passes because it never ran anything.
    fn qemu_arguments(self) -> &'static [&'static str] {
        match self {
            Self::X8664 => &["-machine", "q35", "-cpu", "max", "-m", "512M"],
            Self::Aarch64 => &[],
            Self::Riscv64 => &[],
        }
    }

    /// The lines this machine's boot has to print, in order.
    ///
    /// The first names the loader: a PVH boot and a multiboot2 boot are
    /// different code paths through the same function, so a mismatch is a real
    /// difference rather than a wording preference.
    ///
    /// The second is the heap's own bounds.  It is here rather than treated as
    /// a log line because reaching it means `bounds()` ran, which is what makes
    /// the allocator lay out its free lists — a boot that printed the first
    /// line and stopped before the second has a loader but no heap.  The
    /// address itself is not asserted: it moves with the image, and the gate
    /// is that the line is there, not where it points.
    fn required_lines(self) -> &'static [(&'static str, bool)] {
        match self {
            Self::X8664 => &[
                (
                    "protofire 0.1.0: entered via pvh, console up, stage 1",
                    true,
                ),
                ("protofire: heap at ", false),
            ],
            Self::Aarch64 => &[],
            Self::Riscv64 => &[],
        }
    }
}

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

/// Where cargo puts the image for a target and profile.
fn image_path(machine: Machine, profile: &str) -> PathBuf {
    PathBuf::from("target")
        .join(machine.triple())
        .join(profile)
        .join("bootloader")
}

/// Build the image for one machine.
fn build(machine: Machine, profile: &str) -> Result<()> {
    let mut command = Command::new("cargo");
    command
        .args(["build", "--offline", "-p", "bootloader", "--target"])
        .arg(machine.triple());
    if profile == "release" {
        command.arg("--release");
    }
    let status = command
        .status()
        .context("running cargo build for the bootloader")?;
    if !status.success() {
        bail!("cargo build failed for {}", machine.triple());
    }

    let image = image_path(machine, profile);
    if !image.exists() {
        bail!("the build succeeded but no image is at {}", image.display());
    }
    Ok(())
}

/// Boot one machine's image, returning the serial log's text.
///
/// The timeout is not a failure: this kernel halts rather than exiting, so a
/// machine that is still running when the clock expires is the expected
/// outcome.  What the caller does with the log is where success is decided.
fn run(machine: Machine, profile: &str, timeout: u64, log: Option<&Path>) -> Result<String> {
    build(machine, profile)?;

    let image = image_path(machine, profile);
    let machine_arguments = machine.qemu_arguments();
    if machine_arguments.is_empty() {
        bail!(
            "{} has no boot arguments yet: its image cannot be booted, so there is \
             nothing to assert about it",
            machine.triple()
        );
    }

    // The log is a file rather than a pipe: QEMU writes to it until it is
    // killed, and reading a pipe to end-of-file would block on a guest that
    // never exits.
    let log_path = match log {
        Some(path) => path.to_path_buf(),
        None => std::env::temp_dir().join(format!(
            "protofire-{}-{}.log",
            machine.triple(),
            std::process::id()
        )),
    };
    if log_path.exists() {
        std::fs::remove_file(&log_path).ok();
    }

    let mut command = Command::new(machine.qemu());
    command
        .args(machine_arguments)
        .arg("-kernel")
        .arg(&image)
        .args(["-display", "none", "-no-reboot", "-no-shutdown"])
        .arg("-serial")
        .arg(format!("file:{}", log_path.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let mut child = command
        .spawn()
        .with_context(|| format!("starting {}", machine.qemu()))?;

    // Sleep in small steps rather than one long one, so a machine that exits
    // early — a crash, a bad image — is noticed without waiting the whole
    // budget.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
    loop {
        if let Some(status) = child.try_wait().context("waiting for qemu")? {
            // A non-zero status is QEMU refusing the image.  That is a real
            // failure and the log is empty, which the caller would otherwise
            // read as "the boot printed nothing".
            if !status.success() {
                let text = std::fs::read_to_string(&log_path).unwrap_or_default();
                bail!(
                    "{} exited with {status} before the timeout; serial log:\n{text}",
                    machine.qemu()
                );
            }
            break;
        }
        if std::time::Instant::now() >= deadline {
            // The expected path: the kernel halted and QEMU is still running.
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let text = std::fs::read_to_string(&log_path)
        .with_context(|| format!("reading the serial log at {}", log_path.display()))?;
    if log.is_none() {
        // A temporary log is this run's only copy; a caller that wants to read
        // it after a failure has to ask for a path.
        let _ = std::fs::remove_file(&log_path);
    }
    Ok(text)
}

/// Boot one machine and require the lines its console prints.
fn check(machine: Machine, profile: &str, timeout: u64) -> Result<()> {
    let required = machine.required_lines();
    if required.is_empty() {
        bail!(
            "{} has no expected console lines yet: there is no boot to check",
            machine.triple()
        );
    }

    let log = run(machine, profile, timeout, None)?;
    for (expected, exact) in required {
        let outcome = if *exact {
            expect_line(&log, expected)
        } else {
            expect_line_prefix(&log, expected)
        };
        if let Err(problem) = outcome {
            let mut message = String::new();
            writeln!(message, "check failed: {problem}")?;
            writeln!(message, "  serial log ({} bytes):", log.len())?;
            for line in log.lines() {
                writeln!(message, "    {line}")?;
            }
            bail!("{message}");
        }
    }

    println!(
        "check passed: {} printed {} required line(s) and reached its heap",
        machine.triple(),
        required.len()
    );
    Ok(())
}

/// Whether a serial log contains a line, exactly.
///
/// The comparison is against whole lines with trailing carriage returns
/// removed.  The serial writer emits `\r\n` because the reader is a terminal,
/// and a check that required the `\r` would fail the moment the sink changed —
/// the byte is not what the gate is about.  Whole-line equality rather than a
/// substring, on the other hand, is: `<expected>` inside a longer line is a
/// different line, and a log that printed `garbage <expected>` has not printed
/// `<expected>`.
fn expect_line(log: &str, expected: &str) -> std::result::Result<(), String> {
    if log
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .any(|line| line == expected)
    {
        return Ok(());
    }
    if log.trim().is_empty() {
        return Err(format!(
            "the serial log is empty: the boot died before the console was up \
             (expected {expected:?})"
        ));
    }
    Err(format!("the serial log has no line {expected:?}"))
}

/// Whether a serial log has a line starting with `prefix`.
///
/// The counterpart to [`expect_line`] for lines whose tail is a value the build
/// chose — an address moves with the image, and asserting one would make the
/// gate fail for a correct kernel.  The prefix is what names the fact; the tail
/// is what the log reports about it.
fn expect_line_prefix(log: &str, prefix: &str) -> std::result::Result<(), String> {
    if log
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .any(|line| line.starts_with(prefix))
    {
        return Ok(());
    }
    if log.trim().is_empty() {
        return Err(format!(
            "the serial log is empty: the boot died before the console was up \
             (expected a line starting with {prefix:?})"
        ));
    }
    Err(format!(
        "the serial log has no line starting with {prefix:?}"
    ))
}

#[cfg(test)]
mod tests {
    use super::expect_line;
    use super::expect_line_prefix;

    /// The line the boot prints is found when it is there.
    #[test]
    fn an_exact_line_is_accepted() {
        let log = "first\nprotofire 0.1.0: entered via pvh, console up, stage 1\nlast\n";
        assert_eq!(
            expect_line(log, "protofire 0.1.0: entered via pvh, console up, stage 1"),
            Ok(())
        );
    }

    /// A log that ends in CRLF still matches: the trailing `\r` is what a
    /// terminal sink adds, and it is not part of the claim.
    #[test]
    fn a_carriage_return_is_ignored() {
        let log = "protofire 0.1.0: entered via pvh, console up, stage 1\r\n";
        assert_eq!(
            expect_line(log, "protofire 0.1.0: entered via pvh, console up, stage 1"),
            Ok(())
        );
    }

    /// The failure path is the one that has to work: a log without the line is
    /// refused.  This is the assertion a boot gate exists for, and it is
    /// exercised here without an emulator.
    #[test]
    fn a_missing_line_is_refused() {
        let log = "first\nsomething else\n";
        assert!(expect_line(log, "protofire 0.1.0: entered via pvh, console up, stage 1").is_err());
    }

    /// A line that merely contains the expected text is not the expected line.
    /// Substring matching is how a gate goes green on a log that printed the
    /// failure message this check was looking for.
    #[test]
    fn a_longer_line_that_contains_it_is_refused() {
        let log = "not a boot: protofire 0.1.0: entered via pvh, console up, stage 1\n";
        assert!(expect_line(log, "protofire 0.1.0: entered via pvh, console up, stage 1").is_err());
    }

    /// An empty log is a different failure from a wrong one, and the message
    /// says so: it is the difference between a boot that died before its
    /// console and one that printed the wrong thing.
    #[test]
    fn an_empty_log_says_the_console_never_came_up() {
        let error = expect_line("", "anything").unwrap_err();
        assert!(error.contains("empty"), "{error}");
    }

    /// A line whose tail is a value the build chose matches on its prefix.
    ///
    /// The heap's bounds move with the image, so the gate asserts the line's
    /// shape rather than its value: a check that named an address would fail
    /// for a correct kernel the first time a symbol moved.
    #[test]
    fn a_prefix_match_accepts_a_varying_tail() {
        let log = "protofire: heap at 0x11d790..0x411d790\n";
        assert_eq!(expect_line_prefix(log, "protofire: heap at "), Ok(()));
    }

    /// The prefix is required, not merely present somewhere: a log that printed
    /// the words in another line is not a boot that reached the heap.
    #[test]
    fn a_prefix_that_is_absent_is_refused() {
        let log = "protofire 0.1.0: entered via pvh, console up, stage 1\n";
        assert!(expect_line_prefix(log, "protofire: heap at ").is_err());
    }

    /// An empty log says so, the same way `expect_line` does.
    #[test]
    fn an_empty_log_says_the_console_never_came_up_for_a_prefix() {
        let error = expect_line_prefix("", "anything").unwrap_err();
        assert!(error.contains("empty"), "{error}");
    }

    /// The CR stripping is at the end only: a `\r` in the middle of a line is
    /// part of that line's content.
    #[test]
    fn only_the_trailing_carriage_return_is_stripped() {
        let log = "a\rb\r\n";
        assert!(expect_line(log, "a\rb").is_ok());
        assert!(expect_line(log, "ab").is_err());
    }
}
