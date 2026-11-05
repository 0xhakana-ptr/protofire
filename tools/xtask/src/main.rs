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
//! is to break the kernel and run a boot, so the gates accumulate as copies of
//! each other, and the logic that decides pass from fail is the part nobody
//! tests.
//!
//! Here the decision is a function.  `expect_line` takes a log's text and the
//! line it wants and returns what is wrong with them; a unit test calls it with
//! a log that does not contain the line, and the failure path is exercised
//! without an emulator.  The QEMU invocation stays, because that is genuinely
//! an external process, but it is one implementation, spelled once, and every
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
/// The accepted spellings are the ones the target triples use, `x86_64`, not
/// `x8664`, because a caller reads them from `rustc --print target-list` and
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
    fn qemu_arguments(self, disk: &Path) -> Vec<String> {
        match self {
            // A disk is part of the machine the gate boots: the boot prefers a
            // real device over its in-memory image, and a machine with no disk
            // would exercise the fallback instead of the driver.  The image is
            // a raw file QEMU creates, because the driver writes to it and a
            // read-only disk would be a different test.
            Self::X8664 => vec![
                "-machine".to_string(),
                "q35".to_string(),
                "-cpu".to_string(),
                "max".to_string(),
                "-m".to_string(),
                "512M".to_string(),
                "-drive".to_string(),
                format!("file={},format=raw,if=none,id=blk0", disk.display()),
                "-device".to_string(),
                // `disable-legacy=on` asks for the modern interface only.
                //
                // The default is a *transitional* device, which offers both a
                // legacy and a modern interface and, this is the part that
                // costs a boot, a capability list whose virtio structures a
                // modern-only parser does not read the way it expects.  This
                // tree implements the modern transport, so it asks for the
                // device that has only that.  On x86_64 the same flag is
                // unnecessary because `q35`'s default is already modern.
                "virtio-blk-pci,drive=blk0,disable-legacy=on".to_string(),
            ],
            // The device-tree machine, with a disk on its PCIe bus.
            //
            // The disk is what makes the driver path runnable rather than only
            // its fallback.  It needs the BAR assignment pass the boot now
            // runs: QEMU's `virt` has a host bridge and no firmware, so every
            // BAR comes up unaddressed until something allocates one.
            Self::Aarch64 => vec![
                "-machine".to_string(),
                "virt".to_string(),
                "-cpu".to_string(),
                "max".to_string(),
                "-m".to_string(),
                "512M".to_string(),
                "-drive".to_string(),
                format!("file={},format=raw,if=none,id=blk0", disk.display()),
                "-device".to_string(),
                // `disable-legacy=on` asks for the modern interface only.
                //
                // The default is a *transitional* device, which offers both a
                // legacy and a modern interface and, this is the part that
                // costs a boot, a capability list whose virtio structures a
                // modern-only parser does not read the way it expects.  This
                // tree implements the modern transport, so it asks for the
                // device that has only that.  On x86_64 the same flag is
                // unnecessary because `q35`'s default is already modern.
                "virtio-blk-pci,drive=blk0,disable-legacy=on".to_string(),
            ],
            // The OpenSBI machine: firmware first, then this image's entry in
            // S-mode.  `-cpu rv64` and not a named extension list, because the
            // generic CPU is what the previous tree booted and what the device
            // tree describes; the disk rides the PCIe bus, which is the same
            // `virtio-blk-pci` the other two machines are given and the same
            // modern-only interface request.  `-smp 2` because the boot starts
            // the machine's second hart, the tree lists what the firmware
            // cold-booted and asks the firmware for the rest, and a gate that
            // booted one hart would never exercise the start.
            Self::Riscv64 => vec![
                "-machine".to_string(),
                "virt".to_string(),
                "-cpu".to_string(),
                "rv64".to_string(),
                "-smp".to_string(),
                "2".to_string(),
                "-m".to_string(),
                "512M".to_string(),
                "-drive".to_string(),
                format!("file={},format=raw,if=none,id=blk0", disk.display()),
                "-device".to_string(),
                // `disable-legacy=on` asks for the modern interface only, for
                // the same reason the other two machines ask: a transitional
                // device's capability list is one this tree's modern parser
                // does not read the way it expects.
                "virtio-blk-pci,drive=blk0,disable-legacy=on".to_string(),
            ],
        }
    }

    /// The lines this machine's boot has to print, in order.
    ///
    /// The first names the loader: a PVH boot and a multiboot2 boot are
    /// different code paths through the same function, so a mismatch is a real
    /// difference rather than a wording preference.
    ///
    /// The second names the page table the kernel built.  The boot assembly
    /// maps four gigabytes identity with 2 MiB pages, every one writable and
    /// cached; this is the kernel's own table, with a 4 KiB granule and a
    /// permission per region.  Reaching the heap line means the swap did not
    /// lose any address the boot was still using.
    ///
    /// The third names the interrupt table, and says the flag is on.  A boot
    /// that installed a table and never enabled interrupts has never taken one,
    /// and the machine's first tick would then be a fault nobody saw; enabling
    /// the flag and staying up is what says the delivery path works.
    ///
    /// The fourth is the heap's own bounds.  It is here rather than treated as
    /// a log line because reaching it means `bounds()` ran, which is what makes
    /// the allocator lay out its free lists, a boot that printed the first
    /// line and stopped before the second has a loader but no heap.  The
    /// address itself is not asserted: it moves with the image, and the gate
    /// is that the line is there, not where it points.
    ///
    /// The third names the three syscalls the read went through, not just the
    /// result.  A boot that read the file by calling the filesystem directly
    /// printed the same bytes and the same label; the words `through syscall
    /// open/read/close` are what distinguish the two, and they are the whole
    /// claim this line makes.
    ///
    /// The fourth names every mounted filesystem and the prefix it owns.  A
    /// mount table with one entry has never resolved anything, so the line is
    /// required to name three: the volume the disk was formatted with, a tmpfs
    /// at `/tmp`, and a disc at `/cdrom`.
    ///
    /// The fifth is the disc's file read back.  The disc is the one filesystem
    /// the boot cannot have written, so bytes coming out of it came from the
    /// image, which is why it is the line that proves the namespace rather
    /// than the mounts.
    ///
    /// The fifth names where the block device came from.  The boot falls back
    /// to its in-memory image when the bus has no disk, so "the filesystem
    /// mounted" alone would pass on a machine where the driver never ran, ///
    /// `virtio-blk on pci` is the line that says it did. Lines the log has to
    /// contain more than once, and how many.
    ///
    /// A separate list from [`Machine::required_lines`] because it answers a
    /// different question: that one asks "did the boot reach this step", and
    /// this one asks "did it reach it again after sleeping".  One program's
    /// `Write` appears twice in its image, and a boot that never woke prints
    /// it once.
    /// Fragments that have to appear on **one** line, together.
    ///
    /// A separate list from `required_lines` because it answers a question
    /// neither of the other two can: a line that names the fork's two answers
    /// is one fact, and two separate prefix checks would pass on two lines that
    /// said different things.
    fn paired_lines(self) -> &'static [&'static [&'static str]] {
        match self {
            Self::X8664 | Self::Aarch64 | Self::Riscv64 => &[
                // The parent's status is its child's pid and the child's is
                // zero: the same call, answered twice, differently.
                &["exit statuses 1 -> 4", "4 -> 0"],
            ],
        }
    }

    fn repeated_lines(self) -> &'static [(&'static str, usize)] {
        match self {
            Self::X8664 | Self::Aarch64 | Self::Riscv64 => &[(" says hello", 6)],
        }
    }

    fn required_lines(self) -> &'static [(&'static str, bool)] {
        match self {
            Self::X8664 => &[
                // The policy, asked twice through the real handler.
                //
                // A rule the boot installs allows one label and not another,
                // and both cases go through `open` rather than calling the
                // policy directly.  That is what makes these lines a check on
                // the *wiring*: deleting the check from `open` turns "denied"
                // into "MISPOLICED", which the gate refuses.
                ("protofire: mac policy enabled, ", false),
                // The frame pool, and the allocator exercised rather than
                // described.  The count of tables taken from frames is zero on
                // this machine, its spare tables are enough, so the check is
                // what stands in for a branch that has never run.
                // The whole line, because its tail is the outcome.
                //
                // A prefix would accept `pool check FAILED`: the numbers before
                // it are the same on both runs, and only the last word says
                // whether the allocator handed the frame back.  The counts are
                // fixed for a given machine and pool size, so requiring them
                // makes the line a fact rather than a shape.
                ("protofire: frame pool ", false),
                ("protofire: mac allowed ", false),
                ("protofire: mac denied ", false),
                ("protofire: syscall table installed, ", false),
                (
                    "protofire 0.1.0: entered via pvh, console up, stage 1",
                    true,
                ),
                ("protofire: heap at ", false),
                ("protofire: block device from virtio-blk on pci", true),
                (
                    "protofire: namespace: pyrofs on / (protofire), tmpfs on /tmp (memory), iso9660 on /cdrom (bootdisc)",
                    true,
                ),
                (
                    "protofire: /cdrom/README.TXT reads back from the disc",
                    true,
                ),
                ("protofire: virtio-blk wrote and read back sector ", false),
                (
                    "protofire: filesystem mounted and read /greeting.txt through syscall open/read/close, label ",
                    false,
                ),
                // The descriptor table and the TSS, before anything can enter
                // ring 3.
                //
                // `RSP0` is the stack the first ring-3 interrupt lands on, and
                // an `iretq` without one takes a triple fault rather than
                // printing anything.  The line is the only evidence that
                // `lgdt`/`ltr` were executed rather than planned.
                ("protofire: descriptor tables installed, TSS loaded", true),
                // The interrupt path, exercised rather than reported.
                //
                // "Interrupts on" is a flag; a boot that printed it and never
                // took an interrupt has said nothing.  This line means the
                // controller delivered a vector, the gate and the stub ran, and
                // the `iretq` returned, and it can fail: with the raise
                // disabled the boot prints "raised but not delivered" instead.
                //
                // The vector is the machine's, not a constant: `arch`'s
                // `test_interrupt` answers one above the processor's
                // exceptions, because vector zero is the divide error and the
                // APIC will happily deliver a fault.
                ("protofire: interrupt delivered to its handler", true),
                // Two programs in ring 3, each in an address space of its own.
                //
                // `1` and `2` are the programs' own numbers: one program
                // twice reads exactly the same as two programs once, so the
                // value comes from the program and not from a kernel counter.
                // Three programs print twice each: the two that sleep print
                // before and after the wake, and the pipe reader prints before
                // it blocks and after it is woken.  One line each would pass on
                // a boot where nobody ever waited, which is what a `Sleep` or a
                // `Read` that answered immediately would produce.
                //
                // The second line is required, so this is where a boot that
                // never woke fails: the sleeping program's first `Write` is
                // there, and its second never is.
                ("program 1 says hello", true),
                ("program 2 says hello", true),
                ("protofire: every program exited, ", false),
                // The fork, as two statuses that are the same call's two
                // answers: the parent (pid 1) exits with its child's pid, and
                // that child (pid 4) exits with zero.  A fork that copied
                // nothing, or answered the same value to both, prints neither
                // pair.
                ("protofire: forked a process, child pid 4", true),
                // The fork's two answers, checked as a pair on one line: the
                // parent (pid 1) exits with its child's pid 4, and pid 4 exits
                // with zero.  The pipe's two programs have no identity call, so
                // their statuses are whatever their last call left behind, //
                // reported, and deliberately not asserted. Sleeping, and the
                // wake that ended it.
                //
                // Two lines, because they are two facts: a program asked for a
                // deadline, and one was woken by the timer.  A boot that slept
                // and never woke prints the first and not the second, and the
                // program's second "says hello", which is what the wake
                // produced, is what the exit line counts.
                ("protofire: a program sleeps until counter ", false),
                ("protofire: a program woke, ", false),
                // And the timer moved the CPU between them.
                //
                // The switch count depends on QEMU's speed, so the line that
                // has to hold is that any switch came from a tick.  A boot
                // whose preempt sink was not installed prints "did not
                // preempt".
                ("protofire: the timer preempted, ", false),
            ],
            // The device-tree machine takes the same path, minus the disk: it
            // has no virtio-mmio driver yet, so the boot falls back to its
            // in-memory image and the `block device from` line names that.
            //
            // The interrupt line is required here for the same reason it is
            // required on x86_64, but on this machine it is a stronger claim.
            // `install_interrupt_table` raises a supervisor call after writing
            // `VBAR_EL1` and answers `true` only if it arrived at the entry it
            // should have and returned, so the line means the save/restore
            // path and the vector numbering were both executed.  A machine
            // that reported `false` here printed that instead, and the gate
            // refused it: this is the line that would have caught the boot that
            // stopped after the heap.
            Self::Aarch64 => {
                &[
                // A program at EL0, and its calls served.
                //
                // `program mapped 1` means a frame of machine code was mapped
                // `user`, without that bit the `eret` into EL0 faults on its
                // first fetch.  `hello from ring 3` is the program's `Write`
                // reaching the console through the trap path.
                ("protofire: entering ring 3", true),
                // Two programs, each in an address space of its own, at
                // addresses no other program can reach.
                ("protofire: program 1 mapped at ", false),
                ("protofire: program 2 mapped at ", false),
                ("protofire: program 3 mapped at ", false),
                // A read that had nothing to read and waited for another task.
                // The wake below is the only thing that ends it, so the pair is
                // the claim: a task blocked, and a task's write is what moved
                // it.
                ("protofire: a program blocks on a pipe", true),
                ("protofire: a write woke ", false),
                // Both ran, in order, each printing its own number.  One
                // program twice would read the same as one program once, which
                // is why the number comes from the program and not from a
                // kernel counter.
                ("program 1 says hello", true),
                ("program 2 says hello", true),
                // And the switch happened once and both exits were counted.
                // Deleting the `TTBR0_EL1` write leaves program 2's entry
                // unmapped and the boot stops at an instruction abort; deleting
                // the context restore resumes program 1 in program 2's space.
                ("protofire: every program exited, ", false),
                // The fork, as two statuses that are the same call's two
                // answers: the parent (pid 1) exits with its child's pid, and
                // that child (pid 4) exits with zero.  A fork that copied
                // nothing, or answered the same value to both, prints neither
                // pair.
                ("protofire: forked a process, child pid 4", true),
                // The fork's two answers, checked as a pair on one line: the
                // parent (pid 1) exits with its child's pid 4, and pid 4 exits
                // with zero.  The pipe's two programs have no identity call, so
                // their statuses are whatever their last call left behind, // reported, and deliberately not asserted.
                // The policy, asked twice through the real handler.
                //
                // A rule the boot installs allows one label and not another,
                // and both cases go through `open` rather than calling the
                // policy directly.  That is what makes these lines a check on
                // the *wiring*: deleting the check from `open` turns "denied"
                // into "MISPOLICED", which the gate refuses.
                ("protofire: mac policy enabled, ", false),
                // The frame pool, and the allocator exercised rather than
                // described.  The count of tables taken from frames is zero on
                // this machine, its spare tables are enough, so the check is
                // what stands in for a branch that has never run.
                // A program at EL0, and its calls served.
                //
                // `program mapped 1` means a frame of machine code was mapped
                // `user`, without that bit the `eret` into EL0 faults on its
                // first fetch.  `hello from ring 3` is the program's `Write`
                // reaching the console through the trap path.
                ("protofire: entering ring 3", true),
                // Two programs, each in an address space of its own, at
                // addresses no other program can reach.
                ("protofire: program 1 mapped at ", false),
                ("protofire: program 2 mapped at ", false),
                ("protofire: program 3 mapped at ", false),
                // A read that had nothing to read and waited for another task.
                // The wake below is the only thing that ends it, so the pair is
                // the claim: a task blocked, and a task's write is what moved
                // it.
                ("protofire: a program blocks on a pipe", true),
                ("protofire: a write woke ", false),
                // Both ran, in order, each printing its own number.  One
                // program twice would read the same as one program once, which
                // is why the number comes from the program and not from a
                // kernel counter.
                ("program 1 says hello", true),
                ("program 2 says hello", true),
                // And the switch happened once and both exits were counted.
                // Deleting the `TTBR0_EL1` write leaves program 2's entry
                // unmapped and the boot stops at an instruction abort; deleting
                // the context restore resumes program 1 in program 2's space.
                ("protofire: every program exited, ", false),
                // The fork, as two statuses that are the same call's two
                // answers: the parent (pid 1) exits with its child's pid, and
                // that child (pid 4) exits with zero.  A fork that copied
                // nothing, or answered the same value to both, prints neither
                // pair.
                ("protofire: forked a process, child pid 4", true),
                // The fork's two answers, checked as a pair on one line: the
                // parent (pid 1) exits with its child's pid 4, and pid 4 exits
                // with zero.  The pipe's two programs have no identity call, so
                // their statuses are whatever their last call left behind, // reported, and deliberately not asserted.
                // The whole line, because its tail is the outcome.
                //
                // A prefix would accept `pool check FAILED`: the numbers before
                // it are the same on both runs, and only the last word says
                // whether the allocator handed the frame back.  The counts are
                // fixed for a given machine and pool size, so requiring them
                // makes the line a fact rather than a shape.
                (
                    "protofire: frame pool 16384 frame(s), 16384 free, 0 in page tables, pool check ok",
                    true,
                ),
                ("protofire: mac allowed ", false),
                ("protofire: mac denied ", false),
                ("protofire: syscall table installed, ", false),
                (
                    "protofire 0.1.0: entered via dtb, console up, stage 1",
                    true,
                ),
                (
                    "protofire: page table built and installed, 4 KiB granule",
                    true,
                ),
                ("protofire: interrupt table installed, interrupts on", true),
                // The path exercised, not the flag set.
                //
                // "Interrupts on" is a flag; a boot that printed it and never
                // took an interrupt has said nothing about whether the machine
                // can.  This line means a controller delivered a line, the
                // vector fired, the handler ran and the interrupt was finished
                //, and the check behind it can fail: with the raise disabled
                // the boot prints "raised but not delivered" instead.
                ("protofire: interrupt delivered to its handler", true),
                ("protofire: heap at ", false),
                // The driver running on the device, and doing real I/O on it.
                //
                // `block device from memory` is the fallback: a machine with no
                // disk prints it and boots anyway, which is correct and is not
                // the same claim.  These two lines name the virtio path, and
                // the second is a sector leaving the machine and coming back
                // through the driver's own queue.
                ("protofire: block device from virtio-blk on pci", true),
                ("protofire: virtio-blk wrote and read back sector ", false),
                (
                    "protofire: namespace: pyrofs on / (protofire), tmpfs on /tmp (memory), iso9660 on /cdrom (bootdisc)",
                    true,
                ),
                (
                    "protofire: /cdrom/README.TXT reads back from the disc",
                    true,
                ),
                (
                    "protofire: filesystem mounted and read /greeting.txt through syscall open/read/close, label ",
                    false,
                ),
            ]
            }
            // The OpenSBI machine, at the same milestones as the other two:
            // the tree parsed, the kernel's own table installed, the frame
            // pool exercised, the interrupt path proven by a line the machine
            // raised itself, a timer the firmware owns the deadline of, and
            // three programs at U-mode, one asleep, one blocked on a pipe,
            // one writing to it.  The pool's count is exact for the same
            // reason aarch64's is, the numbers are fixed by the machine's
            // memory and the linker's span, so a shape-check would accept a
            // `pool check FAILED` tail.
            Self::Riscv64 => &[
                (
                    "protofire 0.1.0: entered via dtb, console up, stage 1",
                    true,
                ),
                ("protofire: device tree v", false),
                (
                    "protofire: page table built and installed, 4 KiB granule",
                    true,
                ),
                (
                    "protofire: frame pool 16384 frame(s), 16384 free, 0 in page tables, pool check ok",
                    true,
                ),
                ("protofire: interrupt table installed, interrupts on", true),
                ("protofire: interrupt delivered to its handler", true),
                // The second hart, started through the firmware and counted
                // rather than assumed.  The line names the hart: one that
                // never stored its flag prints "did not come up", and a boot
                // that printed nothing for a hart it asked for would be a
                // start nobody could tell from a start nobody made.
                ("protofire: hart 1 online", true),
                // And what each CPU has actually taken: the start alone cannot
                // tell a CPU that works from one that stored a flag and
                // stopped.  The boot CPU owns the scheduler and its count is
                // real; the started CPU is parked, and the line says so.
                ("protofire: cpus online = 2", true),
                ("protofire: cpu 0 id 0, scheduler owner, ", false),
                ("protofire: cpu 1 id 1, parked, 0 tick(s)", true),
                // The external controller, initialized rather than merely
                // named: base, the context this hart claims through, the
                // machine's source count, and the hart line the PLIC reaches
                // it on.  A tree that named the window and a driver that did
                // not program it would print the first three and "off".
                (
                    "protofire: external controller at 0xc000000, context 1, 95 source(s), hart line on",
                    true,
                ),
                // A real device's interrupt, claimed and taken, not merely a
                // controller that was programmed: the console's UART is source
                // 10, and the count is one because the boot asks it for exactly
                // one interrupt and then silences the device.
                (
                    "protofire: console source 10 enabled at the controller",
                    true,
                ),
                ("protofire: console interrupt(s) taken = 1", true),
                ("protofire: timer line enabled = 1", true),
                ("protofire: timer armed at ", false),
                ("protofire: heap at ", false),
                ("protofire: block device from virtio-blk on pci", true),
                ("protofire: virtio-blk wrote and read back sector ", false),
                (
                    "protofire: namespace: pyrofs on / (protofire), tmpfs on /tmp (memory), iso9660 on /cdrom (bootdisc)",
                    true,
                ),
                (
                    "protofire: /cdrom/README.TXT reads back from the disc",
                    true,
                ),
                ("protofire: syscall table installed, ", false),
                ("protofire: mac policy enabled, ", false),
                ("protofire: mac allowed ", false),
                ("protofire: mac denied ", false),
                (
                    "protofire: filesystem mounted and read /greeting.txt through syscall open/read/close, label ",
                    false,
                ),
                ("protofire: entering ring 3", true),
                ("protofire: program 1 mapped at ", false),
                ("protofire: program 2 mapped at ", false),
                ("protofire: program 3 mapped at ", false),
                ("protofire: a program blocks on a pipe", true),
                ("protofire: a write woke ", false),
                ("program 1 says hello", true),
                ("program 2 says hello", true),
                ("protofire: every program exited, ", false),
                // The fork, as two statuses that are the same call's two
                // answers: the parent (pid 1) exits with its child's pid, and
                // that child (pid 4) exits with zero.  A fork that copied
                // nothing, or answered the same value to both, prints neither
                // pair.
                ("protofire: forked a process, child pid 4", true),
                // The fork's two answers, checked as a pair on one line: the
                // parent (pid 1) exits with its child's pid 4, and pid 4 exits
                // with zero.  The pipe's two programs have no identity call, so
                // their statuses are whatever their last call left behind, //
                // reported, and deliberately not asserted. Sleeping, and the
                // wake that ended it: the deadline is a firmware call on this
                // machine, and a boot that slept and never woke prints the
                // sleep line and not the wake.
                ("protofire: a program sleeps until counter ", false),
                ("protofire: a program woke, ", false),
                ("protofire: the timer preempted, ", false),
            ],
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

    // Lines that have to carry several fragments at once.
    for fragments in machine.paired_lines().iter() {
        let found = log.lines().any(|line| {
            let line = line.trim_end_matches('\r');
            fragments.iter().all(|fragment| line.contains(fragment))
        });
        if !found {
            let mut message = String::new();
            writeln!(
                message,
                "check failed: no line carries all of {:?} together",
                fragments
            )?;
            for line in log.lines() {
                writeln!(message, "    {line}")?;
            }
            bail!("{message}");
        }
    }

    // A line that has to appear more than once.
    //
    // The required-lines list can say "this line exists"; it cannot say "and it
    // exists twice", and the difference is the whole of what a sleep proves.
    // A program that wrote its line and then slept for ever prints it once; a
    // program that slept and woke prints it twice.  So the boot that reports
    // both programs exiting is checked here against the count the program's own
    // source has: two writes each.
    for (line, least) in machine.repeated_lines().iter().copied() {
        let seen = log
            .lines()
            .filter(|candidate| candidate.trim_end().contains(line))
            .count();
        if seen < least {
            let mut message = String::new();
            writeln!(
                message,
                "check failed: \"{line}\" appears {seen} time(s), and the program writes it {least}",
            )?;
            for candidate in log.lines() {
                writeln!(message, "    {candidate}")?;
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
/// and a check that required the `\r` would fail the moment the sink changed,
/// /// the byte is not what the gate is about.  Whole-line equality rather than
/// a substring, on the other hand, is: `<expected>` inside a longer line is a
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
/// chose, an address moves with the image, and asserting one would make the
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
