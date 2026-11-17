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

/// The volume the NVMe namespace carries, and the file the boot reads back.
///
/// Two copies of each, here and in `kernel/src/volume.rs`, for the same reason
/// the boot volume's label is two copies: the disk is formatted **here** and
/// the read-back line is what polices the pairing.
const NVME_VOLUME_LABEL: &str = "nvme";
const NVME_NOTE_PATH: &str = "/note.txt";
const NVME_NOTE_CONTENT: &[u8] = b"written by the host, read over nvme";

/// The disk the NVMe controller is given: 16 MiB.
///
/// A namespace's block count is what the probe reads back, so the number has to
/// be large enough that the size in the Identify answer is unambiguous, and
/// small enough that creating the file costs nothing.  16 MiB is 32768 blocks
/// of 512 bytes, which is not a power of two in the answer's low bytes and so
/// cannot be confused with the zeroed memory around it.
const NVME_DISK_BYTES: usize = 16 * 1024 * 1024;

/// The disk the SATA controller is given: 32 MiB.
///
/// A different size from the NVMe disk on purpose: two disks whose capacities
/// read the same would make the boot's two identify lines indistinguishable,
/// and a reader checking one against the other would be guessing.
const SATA_DISK_BYTES: usize = 32 * 1024 * 1024;

/// The SATA disk's far block, as the kernel's probe expects to find it.
///
/// Two copies of one constant, here and in `kernel/src/ahci.rs`, for the same
/// reason the NVMe disk's magic is two copies: a read the driver could
/// satisfy from its own memory is not evidence.  Drift and the read answers
/// garbage and the gate goes red.
const SATA_DISK_MAGIC: &[u8; 8] = b"PFATAH01";

/// The disk the USB storage device is given: 8 MiB.
///
/// A third size, so the MSC driver's geometry line names a number the other
/// two disks' lines cannot be confused with.
const USB_DISK_BYTES: usize = 8 * 1024 * 1024;

/// The disk's first block, as the kernel's probe expects to find it.
///
/// Two copies of one constant, here and in `kernel/src/nvme.rs`, for the same
/// reason the volume's label is two copies: a read the kernel could satisfy
/// from its own memory is not evidence, so the disk says something only the
/// **host** wrote, and the boot's line is what polices the pairing.  Drift and
/// the read answers garbage and the gate goes red.
const NVME_DISK_MAGIC: &[u8; 8] = b"PFNVME01";

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

    // The NVMe controller's own disk.  Separate from the one above for the
    // reason the machine's arguments give: the virtio driver mounts that one,
    // and the NVMe probe reads this one to prove the controller rather than to
    // mount a second volume.  It is left empty, so what the probe reads back is
    // whatever the device holds rather than something this tool wrote, and it
    // is only created for the machine that has the controller.
    let nvme_disk = std::env::temp_dir().join(format!(
        "protofire-{}-{}.nvme",
        machine.triple(),
        std::process::id()
    ));
    let _ = std::fs::remove_file(&nvme_disk);
    let sata_disk = std::env::temp_dir().join(format!(
        "protofire-{}-{}.sata",
        machine.triple(),
        std::process::id()
    ));
    let _ = std::fs::remove_file(&sata_disk);
    let usb_disk = std::env::temp_dir().join(format!(
        "protofire-{}-{}.usb",
        machine.triple(),
        std::process::id()
    ));
    let _ = std::fs::remove_file(&usb_disk);
    if machine.has_xhci() {
        std::fs::write(&usb_disk, vec![0u8; USB_DISK_BYTES])
            .with_context(|| format!("creating the USB disk at {}", usb_disk.display()))?;
    }

    if machine.has_ahci() {
        // The far block is the magic the kernel's probe reads back, and the
        // rest is left as the device holds it: nothing mounts this disk yet,
        // and a probe that read a volume it built itself would prove nothing.
        let mut sata_bytes = vec![0u8; SATA_DISK_BYTES];
        let magic_at = SATA_DISK_BYTES - 512;
        sata_bytes[magic_at..magic_at + SATA_DISK_MAGIC.len()].copy_from_slice(SATA_DISK_MAGIC);
        std::fs::write(&sata_disk, sata_bytes)
            .with_context(|| format!("creating the SATA disk at {}", sata_disk.display()))?;
    }

    if machine.has_nvme() {
        // A real volume at the front, so the namespace the boot mounts over
        // this controller has something in it to read; and the magic at the
        // far block, because block zero of a filesystem is its superblock.
        // The kernel reads the magic back from the last block and reads the
        // file through the mount, and each line polices one pairing.
        let nvme_volume = fs::pyrofs::PyroFs::build_image(
            NVME_VOLUME_LABEL,
            &[fs::pyrofs::ImageEntry {
                path: NVME_NOTE_PATH,
                data: NVME_NOTE_CONTENT,
            }],
        )
        .map_err(|error| anyhow!("building the NVMe volume failed: {error:?}"))?;
        let mut nvme_bytes = vec![0u8; NVME_DISK_BYTES];
        let volume_len = nvme_volume.len().min(NVME_DISK_BYTES);
        nvme_bytes[..volume_len].copy_from_slice(&nvme_volume[..volume_len]);
        let magic_at = NVME_DISK_BYTES - 512;
        nvme_bytes[magic_at..magic_at + NVME_DISK_MAGIC.len()].copy_from_slice(NVME_DISK_MAGIC);
        std::fs::write(&nvme_disk, nvme_bytes)
            .with_context(|| format!("creating the NVMe disk at {}", nvme_disk.display()))?;
    }

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
    let machine_arguments = machine.qemu_arguments(&disk, &nvme_disk, &sata_disk, &usb_disk);
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
    // The QMP socket the virtio keyboard's key is typed through.
    //
    // The monitor's `sendkey` names no console, so it reaches the first
    // console-less input handler -- the USB keyboard.  `input-send-event` is
    // the one that names a console, and its `device` argument is the console
    // the machine bound that keyboard to; the two keyboards are therefore
    // typed through two different channels, each one addressed to its own.
    let qmp_path = std::env::temp_dir().join(format!(
        "protofire-{}-{}.qmp",
        machine.triple(),
        std::process::id()
    ));
    if machine.has_xhci() {
        let _ = std::fs::remove_file(&qmp_path);
        command.arg("-qmp");
        command.arg(format!(
            "unix:path={},server=on,wait=off",
            qmp_path.display()
        ));
    }
    command
        .args(&machine_arguments)
        .arg("-kernel")
        .arg(&image)
        .args(["-display", "none", "-no-reboot", "-no-shutdown"])
        .arg("-serial")
        .arg(format!("file:{}", log_path.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // The keyboard's report, typed by the **monitor**: a gate that waited for
    // a human to press a key would never run twice the same way, and the
    // monitor's `sendkey` is what makes a key arrive on a machine nobody is
    // touching.  The monitor rides stdio (the serial console rides its file),
    // the keys are sent once the boot is well past the program exercise that
    // reads the console -- a report still in the queue then would be bytes
    // that exercise's `ReadConsole` check did not expect -- and the two keys
    // are `a` then `b`, so a reader can tell the reports apart.  A machine
    // with no keyboard is not given a monitor at all.
    if machine.has_xhci() {
        command.args(["-monitor", "stdio"]);
        command.stdin(Stdio::piped());
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("starting {}", machine.qemu()))?;

    if machine.has_xhci() {
        // SAFETY: irrelevant -- this is a host side, not a guest one.
        let mut stdin = child.stdin.take().expect("the monitor's stdin");
        let log_for_keys = log_path.clone();
        let qmp_for_keys = qmp_path.clone();
        std::thread::spawn(move || {
            // The keys go in **after** the boot's own program exercise reads
            // the console: that check asserts nothing was typed, and a report
            // still in the queue when it runs is bytes the check did not
            // expect -- measured, exit 255.  The log is the signal, and the
            // line is the program's device-list call, which runs *after* that
            // check and *before* the boot halts: typing earlier risks the
            // check, typing later risks a machine that has already stopped.
            // A boot that never gets there is a boot the keys were never for.
            for _ in 0..600 {
                if std::fs::read_to_string(&log_for_keys)
                    .map(|text| text.contains("protofire: process 1 listed block device 0"))
                    .unwrap_or(false)
                {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            // The USB keyboard hears the monitor's key, and the virtio one
            // hears the key QMP addresses to the console it is bound to.
            // `a` and `b` so a reader can tell the two reports apart.
            {
                use std::io::Write as _;
                let _ = writeln!(stdin, "sendkey a");
                let _ = stdin.flush();
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            send_key_over_qmp(&qmp_for_keys, "b");
            // The monitor stays open; QEMU owns the pipe from here.
            std::mem::forget(stdin);
        });
    }

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
    let _ = std::fs::remove_file(&qmp_path);
    Ok(text)
}

/// Type one key at the virtio keyboard, through QMP.
///
/// The monitor's `sendkey` reaches the first input handler that named no
/// console, and that is the USB keyboard.  This path is the other half: QEMU's
/// input layer has exactly one handler per event, and `input-send-event` names
/// the **console** whose handler takes it, so the key arrives at the virtio
/// keyboard the machine bound to that console and at nothing else.
///
/// A failure here is silent on purpose: the machine's log is what says whether
/// the key arrived, and a thread that printed its own error would be a second
/// account of one fact.  A key that never arrives leaves the gate's line
/// missing, which is the failure this caller wants seen.
fn send_key_over_qmp(qmp_path: &std::path::Path, qcode: &str) {
    use std::io::Read as _;
    use std::io::Write as _;

    // QEMU creates the socket at startup, so a connect that fails is a machine
    // that has not got there yet.
    let mut connected = None;
    for _ in 0..100 {
        match std::os::unix::net::UnixStream::connect(qmp_path) {
            Ok(stream) => {
                connected = Some(stream);
                break;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    }
    let Some(mut stream) = connected else {
        return;
    };

    // QMP greets, and wants the capability handshake before anything else.
    // The replies are read rather than parsed: this caller asks one question
    // and the machine's log is the answer it can check.
    let mut reply = [0u8; 4096];
    let _ = stream.read(&mut reply);
    let _ = writeln!(stream, "{{\"execute\":\"qmp_capabilities\"}}");
    let _ = stream.read(&mut reply);

    // A press and the release that follows it, the pair a real key sends.
    for down in [true, false] {
        let event = format!(
            "{{\"execute\":\"input-send-event\",\"arguments\":{{\"device\":\"{VGA_CONSOLE_ID}\",\
             \"events\":[{{\"type\":\"key\",\"data\":{{\"down\":{down},\
             \"key\":{{\"type\":\"qcode\",\"data\":\"{qcode}\"}}}}}}]}}}}"
        );
        let _ = writeln!(stream, "{event}");
        let _ = stream.read(&mut reply);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// The console the virtio keyboard is bound to, as the machine's arguments
/// name it.
///
/// Two copies of one name, here and in `machine.rs`, because the device is
/// created there and addressed here: a drift would be a key typed at a
/// console no keyboard is bound to, which QEMU refuses with "not bound to a
/// QemuConsole" rather than delivering it anywhere.
const VGA_CONSOLE_ID: &str = "disp0";
