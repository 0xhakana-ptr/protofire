//! tools/xtask/src/build.rs
//!
//! Building an image and booting it: the whole of this tool's contact with the
//! outside world.
//!
//! Two external processes and no third.  `cargo` builds the kernel and
//! `qemu-system-*` runs it, and both are here rather than in `main` because
//! everything that shells out is something a unit test cannot call, and the
//! split is what leaves the decision half testable.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use anyhow::Context;
use anyhow::Result;
use anyhow::bail;

use crate::machine::Machine;

/// The disk a boot is given: 1 MiB, which is more than the boot reads and
/// enough that the driver's first writes cannot fail for want of space.
const DISK_BYTES: usize = 1024 * 1024;

/// Where cargo puts the image for a target and profile.
fn image_path(machine: Machine, profile: &str) -> PathBuf {
    PathBuf::from("target")
        .join(machine.triple())
        .join(profile)
        .join("bootloader")
}

/// Build the image for one machine.
pub(crate) fn build(machine: Machine, profile: &str) -> Result<()> {
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
pub(crate) fn run(
    machine: Machine,
    profile: &str,
    timeout: u64,
    log: Option<&Path>,
) -> Result<String> {
    build(machine, profile)?;

    let image = image_path(machine, profile);

    // The disk the machine boots with.  A file rather than a constant buffer:
    // the driver writes to it, and QEMU refuses a `raw` drive over a file that
    // does not exist unless it is told to create one, so the file is created
    // here, sized to what a boot's writes can reach.
    let disk = std::env::temp_dir().join(format!(
        "protofire-{}-{}.disk",
        machine.triple(),
        std::process::id()
    ));
    let _ = std::fs::remove_file(&disk);
    std::fs::write(&disk, vec![0u8; DISK_BYTES])
        .with_context(|| format!("creating the disk at {}", disk.display()))?;
    let machine_arguments = machine.qemu_arguments(&disk);
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
        .args(&machine_arguments)
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
    // early, a crash, a bad image, is noticed without waiting the whole
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
