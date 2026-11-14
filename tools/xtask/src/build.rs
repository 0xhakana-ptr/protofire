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

use anyhow::anyhow;

use crate::machine::Machine;

/// The disk a boot is given: 1 MiB, which is more than the boot reads and
/// enough that the driver's first writes cannot fail for want of space.
const DISK_BYTES: usize = 1024 * 1024;

/// The volume's label and the greeting file, as the kernel's own constants
/// name them.
///
/// Two copies of each string, here and in `kernel/src/volume.rs`, because
/// the disk is formatted **here**, before the machine runs, and the kernel's
/// self-check reads back the constant it carries.  The boot's read-back line
/// is what polices the pairing: drift and the gate goes red.
const VOLUME_LABEL: &str = "protofire";
const GREETING_PATH: &str = "/greeting.txt";
const GREETING_CONTENT: &[u8] = b"the quick brown pyrofox";
const INIT_PATH: &str = "/bin/init";
const SHELL_PATH: &str = "/bin/shell";

/// The profile every boot's `init` is built in.
///
/// One constant because the build and the read have to name the same
/// directory: the first version built the default profile and read the
/// release one, which a tree that had never built it by hand could not
/// satisfy, the gate failed with "no such file" on a clean clone and only
/// passed on a machine where an earlier manual build had left the file.
const INIT_PROFILE: &str = "release";

/// The linker script every machine's `init` is linked with.
///
/// One constant, and not a per-machine table: the script carries no machine
/// fact.  It fixes the base the kernel's user window computes and lets the
/// target triple choose the container, which is why `arch/<machine>/`, where
/// the kernel's scripts live, because their load addresses *are* their
/// machines' loader conventions, is the wrong home for this one.
const INIT_LINKER_SCRIPT: &str = "apps/init/linker.ld";

/// Build one program crate for `machine`'s target, answering the ELF's bytes.
///
/// The program's own linker script fixes its base, and its Rust flags are
/// named here rather than in a config so the kernel's are not inherited: a
/// program links as PIC, because its window base is far past the absolute
/// relocations a static build would emit, and the precompiled core the
/// sysroot carries is built with the default code model, which the program's
/// own CGUs must not contradict.  Every shipped program goes through here
/// `init` and, since the tree carried two, `shell`, so their images share
/// one construction and one set of flags rather than two.
fn build_program(machine: Machine, package: &str) -> Result<Vec<u8>> {
    // The image is a PIE container with `relocation-model=pic` alone, and a
    // PIE's calls to its own library symbols go through a GOT whose slots
    // are filled by `R_X86_64_RELATIVE` relocations the kernel's loader does
    // not apply, measured: the first program big enough to make the linker
    // route a `bcmp` through the GOT died on its first comparison, at
    // address 0.  `-no-pie` resolves those slots at link time, which is
    // honest for an image whose load address the linker script fixes anyway;
    // the kernel's own build, which does relocate, is a different command
    // and does not inherit this one's flags.
    let rustflags = format!(
        "-C link-arg=-T{INIT_LINKER_SCRIPT} -C link-arg=--strip-debug \
         -C relocation-model=pic -C link-arg=-no-pie"
    );
    let mut command = Command::new("cargo");
    command
        .args(["build", "--offline", "-p"])
        .arg(package)
        .arg("--target")
        .arg(machine.triple())
        .args(["--profile", INIT_PROFILE])
        .env("RUSTFLAGS", &rustflags);
    if !command
        .status()
        .context("running cargo build for apps/init")?
        .success()
    {
        bail!("cargo build failed for {} on {}", package, machine.triple());
    }
    let elf = PathBuf::from("target")
        .join(machine.triple())
        .join(INIT_PROFILE)
        .join(package);
    std::fs::read(&elf)
        .with_context(|| format!("reading the built {} at {}", package, elf.display()))
}

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

    // The volume, formatted **here**: the greeting the boot's self-check reads
    // back, and `/bin/init`, the compiled program the kernel execs from its
    // own filesystem.  A PyroFS image built on the host from the same crate
    // the kernel mounts, the disk file is the delivery channel, and the
    // kernel's `format_if_empty` finds it already a volume.
    let init = build_program(machine, "init")?;
    let shell = build_program(machine, "shell")?;
    let volume = fs::pyrofs::PyroFs::build_image(
        VOLUME_LABEL,
        &[
            fs::pyrofs::ImageEntry {
                path: GREETING_PATH,
                data: GREETING_CONTENT,
            },
            fs::pyrofs::ImageEntry {
                path: INIT_PATH,
                data: &init,
            },
            fs::pyrofs::ImageEntry {
                path: SHELL_PATH,
                data: &shell,
            },
        ],
    )
    .map_err(|error| anyhow!("building the PyroFS volume failed: {error:?}"))?;
    let mut disk_bytes = vec![0u8; DISK_BYTES];
    let volume_len = volume.len().min(DISK_BYTES);
    disk_bytes[..volume_len].copy_from_slice(&volume[..volume_len]);
    std::fs::write(&disk, disk_bytes.as_slice())
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
