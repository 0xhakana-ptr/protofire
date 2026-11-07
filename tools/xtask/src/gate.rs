//! tools/xtask/src/gate.rs
//!
//! What a machine's boot must print, and the functions that decide it.
//!
//! ## Three lists, three questions
//!
//! | List | Question it answers |
//! |---|---|
//! | [`Machine::required_lines`] | did the boot reach this step |
//! | [`Machine::paired_lines`] | do these fragments appear on **one** line, together |
//! | [`Machine::repeated_lines`] | did the boot reach this step **twice** |
//!
//! They are separate because each answers something the others cannot.  Two
//! prefix checks pass on two lines that said different things; one program's
//! line twice reads exactly like two programs' lines once.
//!
//! ## Why the decision is code
//!
//! A gate written as a `grep` in a shell is a string nothing tests: the only
//! way to know whether it can fail is to break the kernel and boot it.  Here
//! the expectations are a list and the matchers are functions, so a unit test
//! calls one with a log that does not contain the line and exercises the
//! failure path without an emulator.

use std::fmt::Write as _;

use anyhow::Result;
use anyhow::bail;

use crate::build::run;
use crate::machine::Machine;

impl Machine {
    /// Fragments that have to appear on **one** line, together.
    ///
    /// A separate list from [`Machine::required_lines`] because it answers a
    /// question neither of the other two can: a line that names the fork's two
    /// answers is one fact, and two separate prefix checks would pass on two
    /// lines that said different things.
    pub(crate) fn paired_lines(self) -> &'static [&'static [&'static str]] {
        match self {
            Self::X8664 | Self::Aarch64 => &[
                // The exec'd process exits with its own pid — the image it
                // became asks the kernel who it is and exits with the answer —
                // and the forked child exits with zero.  The pair on one line
                // is the whole of both stories: `exec` kept the task's
                // identity, and `fork` answered its two processes
                // differently.
                &["exit statuses 1 -> 1", "4 -> 0"],
                // A task was placed on a CPU other than the one it last ran
                // on.  The line names the move when there was one, and **there
                // is not always one**: placement depends on which CPU reaches
                // the queue first, and two boots in twenty never move a task at
                // all.  A gate that required the named move failed on those, so
                // the fact this checks is the count's own line — the record
                // ran — rather than that the boot happened to place a task
                // twice.  `required_lines` carries the prefix.
            ],
            Self::Riscv64 => &[
                &["exit statuses 1 -> 1", "4 -> 0"],
                // The second CPU, on one line: the slot the kernel numbered it
                // with, the hart the machine named, that it takes its own
                // interrupts, and the interrupt this boot aimed at it.
                //
                // The hart id is **not** asserted.  Which hart the firmware
                // cold-boots is the firmware's choice, and QEMU alternates
                // between 0 and 1: a boot where it chose 1 printed
                // `cpu 0 id 1` and `cpu 1 id 0`, both correct, and a gate that
                // required `id 1` failed on it once in forty.  What is
                // invariant is the slot the kernel numbered: a started CPU is
                // slot 1, and it is ticking and has taken an interrupt.
                &["cpu 1 id ", ", ticking, "],
                // The started hart said so on a line that names it and says it
                // is online.  A hart that did not come up prints `hart N did
                // not come up` on the same prefix, which carries no ` online`,
                // so the pair is what separates a start from a failure rather
                // than the prefix alone.
                &["hart ", " online"],
            ],
        }
    }

    /// Lines the log has to contain more than once, and how many.
    ///
    /// A separate list from [`Machine::required_lines`] because it answers a
    /// different question: that one asks "did the boot reach this step", and
    /// this one asks "did it reach it again after sleeping".  One program's
    /// `Write` appears twice in its image, and a boot that never woke prints
    /// it once.
    pub(crate) fn repeated_lines(self) -> &'static [(&'static str, usize)] {
        match self {
            Self::X8664 | Self::Aarch64 | Self::Riscv64 => &[(" says hello", 6)],
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
    /// the allocator lay out its free lists — a boot that printed the first
    /// line and stopped before the second has a loader but no heap.  The
    /// address itself is not asserted: it moves with the image, and the gate
    /// is that the line is there, not where it points.
    ///
    /// The fifth names where the block device came from.  The boot falls back
    /// to its in-memory image when the bus has no disk, so "the filesystem
    /// mounted" alone would pass on a machine where the driver never ran;
    /// `virtio-blk on pci` is the line that says it did.
    ///
    /// The sixth names every mounted filesystem and the prefix it owns, and
    /// the seventh is the disc's file read back.  The disc is the one
    /// filesystem the boot cannot have written, so bytes coming out of it came
    /// from the image, which is why it is the line that proves the namespace
    /// rather than the mounts.  The filesystem line also names the three
    /// syscalls the read went through: a boot that read the file by calling
    /// the filesystem directly printed the same bytes and the same label, and
    /// the words `through syscall open/read/close` are the whole claim.
    pub(crate) fn required_lines(self) -> &'static [(&'static str, bool)] {
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
                // what stands in for a branch that has never run.  The exact-
                // match form of this line, with the counts required, is the
                // other two machines': their pool sizes are fixed by the
                // machine's memory and the linker's span, and this machine's
                // is fixed by the machine's answer too, which is why the
                // reaped line below carries this boot's exact tail instead.
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
                // Two CPUs, and the same evidence aarch64 requires: the
                // INIT-SIPI start reached a CPU that came up and recorded it,
                // the interrupt the boot sent it arrived, and a program ran on
                // it to its exit.  A gate at one CPU would accept an ICR write
                // that never started anyone.
                ("protofire: hart 1 online", true),
                ("protofire: ipi to 1 other cpu(s), taken", true),
                ("protofire: cpu 1 id 1, ticking, ", false),
                ("protofire: work available, started cpus woken", true),
                ("protofire: cpu 1 runs process ", false),
                ("protofire: program ended on cpu 1", true),
                ("protofire: parallel, programs ended on ", false),
                // Every finished program's address space went back, and the
                // pool it returned to is reported beside it.  The count is the
                // boot's four spaces — the three programs plus the forked
                // child — released once the machine is finished.  Releasing at
                // each exit was tried and produced 186 page faults in six
                // boots of eight, which is why the count is here at the end
                // rather than absent.
                //
                // The line is required whole because its tail is the ratchet:
                // with the tables each mapping built reclaimed beside the
                // frames, every frame the boot took is back, and the free
                // count is the pool's whole size.  A release that leaks even
                // the walk's scaffolding — three tables per space, fifteen on
                // this boot — prints a smaller number and fails here.
                (
                    "protofire: address spaces reaped 4, 131072 frame(s) free",
                    true,
                ),
                // The invalidation's own account, as a whole line: three sends,
                // three acknowledgements, no wait ran out.
                //
                // The numbers are exact because this machine's remapping is
                // deterministic: the second CPU is online before the BARs are
                // re-encoded uncached, so every window changed afterwards is a
                // change that CPU has to be told about.  Deleting the broadcast
                // turns this into `0 sent, 0 acknowledged` and the gate refuses
                // it, which a bare `0 timed out` check would have passed.
                (
                    "protofire: tlb shootdown 3 sent, 3 acknowledged, 0 timed out",
                    true,
                ),
                // The placement rule's own record.  The count is the number of
                // times a task was taken onto a CPU other than the one it last
                // ran on; it is not always above zero, because whether a task
                // moves depends on which CPU reaches the queue first, and two
                // boots in twenty move none.  What this line proves is that the
                // record ran and answered, which `assign` is the only writer
                // of.
                ("protofire: task migrations ", false),
                // Three programs in ring 3, each in an address space of its
                // own.
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
                // The fork's two faults, as the two answers they get.  The
                // fork shares the stack page read-only, so each process's
                // first write faults, and the count decides: one write finds
                // the page still shared and is **copied**, the other finds
                // itself the last holder and is handed the frame outright.
                // Either order is correct — which process runs first decides
                // which answer each gets — so the check is that both answers
                // exist, and the promote's frame is the copy's source frame,
                // which is the pair reading itself.
                ("protofire: copy-on-write copy at ", false),
                ("protofire: copy-on-write promote at ", false),
                // The exec, as a line that names both sides of the change:
                // the task that called and the image it became.  The number
                // and the image are this boot's facts — pid 1 calls, image 4
                // is what it becomes — so the line is required whole.
                //
                // The exec'd task's exit status is its own pid, reported by
                // the image it became through `GetPid`, which is the pair the
                // fragment check reads: a process that lost its identity in
                // the change could not exit as 1.
                ("protofire: process 1 exec'd image 4", true),
                // Sleeping, and the wake that ended it.
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
                    // The policy, asked twice through the real handler.
                    //
                    // A rule the boot installs allows one label and not
                    // another, and both cases go through `open` rather than
                    // calling the policy directly.  That is what makes these
                    // lines a check on the *wiring*: deleting the check from
                    // `open` turns "denied" into "MISPOLICED", which the gate
                    // refuses.
                    ("protofire: mac policy enabled, ", false),
                    // The frame pool, and the allocator exercised rather than
                    // described.  The count of tables taken from frames is zero
                    // on this machine, its spare tables are enough, so the
                    // check is what stands in for a branch that has never run.
                    // A program at EL0, and its calls served.
                    //
                    // `program mapped 1` means a frame of machine code was
                    // mapped `user`, without that bit the `eret` into EL0
                    // faults on its first fetch.  `hello from ring 3` is the
                    // program's `Write` reaching the console through the trap
                    // path.
                    ("protofire: entering ring 3", true),
                    // Two cores, and the same evidence x86_64 requires: the
                    // PSCI start reached a core that came up and recorded it,
                    // the interrupt the boot sent it arrived, and a program ran
                    // on it to its exit.  A gate at one core would accept a
                    // PSCI call that never worked.
                    ("protofire: hart 1 online", true),
                    ("protofire: ipi to 1 other cpu(s), taken", true),
                    ("protofire: cpu 1 id 1, ticking, ", false),
                    ("protofire: work available, started cpus woken", true),
                    ("protofire: cpu 1 runs process ", false),
                    ("protofire: program ended on cpu 1", true),
                    ("protofire: parallel, programs ended on ", false),
                    // Every finished program's address space went back, and the
                    // pool it returned to is reported beside it.  The count is
                    // the programs: one address space each, released once the
                    // machine is finished.  Releasing at each exit was tried
                    // and produced 186 page faults in six boots of eight, which
                    // is why the count is here at the end rather than absent.
                    (
                        "protofire: address spaces reaped 4, 16384 frame(s) free",
                        true,
                    ),
                    // One invalidation, acknowledged, and no wait ran out.
                    // This core's ECAM window is past the identity map, so the
                    // boot creates a mapping for it after the second core is
                    // up, and that one mapping is the whole broadcast this
                    // machine sends.
                    (
                        "protofire: tlb shootdown 1 sent, 1 acknowledged, 0 timed out",
                        true,
                    ),
                    // The placement rule's own record.  The count is the number
                    // of times a task was taken onto a CPU other than the one
                    // it last ran on; it is not always above zero, because
                    // whether a task moves depends on which CPU reaches the
                    // queue first, and two boots in twenty move none.  What
                    // this line proves is that the record ran and answered,
                    // which `assign` is the only writer of.
                    ("protofire: task migrations ", false),
                    // Three programs, each in an address space of its own,
                    // at addresses no other program can reach.
                    ("protofire: program 1 mapped at ", false),
                    ("protofire: program 2 mapped at ", false),
                    ("protofire: program 3 mapped at ", false),
                    // A read that had nothing to read and waited for another
                    // task. The wake below is the only thing that ends it, so
                    // the pair is the claim: a task blocked, and a task's write
                    // is what moved it.
                    ("protofire: a program blocks on a pipe", true),
                    ("protofire: a write woke ", false),
                    // Both ran, in order, each printing its own number.  One
                    // program twice would read the same as one program once,
                    // which is why the number comes from the program and not
                    // from a kernel counter.
                    ("program 1 says hello", true),
                    ("program 2 says hello", true),
                    // And the switch happened once and every exit was counted.
                    // Deleting the `TTBR0_EL1` write leaves program 2's entry
                    // unmapped and the boot stops at an instruction abort;
                    // deleting the context restore resumes program 1 in program
                    // 2's space.
                    ("protofire: every program exited, ", false),
                    // The fork, as two statuses that are the same call's two
                    // answers: the parent (pid 1) exits with its child's pid,
                    // and that child (pid 4) exits with zero.  A fork that
                    // copied nothing, or answered the same value to both,
                    // prints neither pair.
                    ("protofire: forked a process, child pid 4", true),
                    // The fork's two answers, checked as a pair on one line:
                    // the parent (pid 1) exits with its child's pid 4, and pid
                    // 4 exits with zero.  The pipe's two programs have no
                    // identity call, so their statuses are whatever their last
                    // call left behind, // reported, and deliberately not
                    // asserted. The whole line, because its tail is the
                    // outcome.
                    //
                    // A prefix would accept `pool check FAILED`: the numbers
                    // before it are the same on both runs, and only the last
                    // word says whether the allocator handed the frame back.
                    // The counts are fixed for a given machine and pool size,
                    // so requiring them makes the line a fact rather than a
                    // shape.
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
                    ("protofire: timer armed at ", false),
                    ("protofire: the timer preempted, ", false),
                    // The path exercised, not the flag set.
                    //
                    // "Interrupts on" is a flag; a boot that printed it and
                    // never took an interrupt has said nothing about whether
                    // the machine can.  This line means a controller delivered
                    // a line, the vector fired, the handler ran and the
                    // interrupt was finished, and the check behind it can fail:
                    // with the raise disabled the boot prints "raised but not
                    // delivered" instead.
                    ("protofire: interrupt delivered to its handler", true),
                    ("protofire: heap at ", false),
                    // The driver running on the device, and doing real I/O on
                    // it.
                    //
                    // `block device from memory` is the fallback: a machine
                    // with no disk prints it and boots anyway, which is correct
                    // and is not the same claim.  These two lines name the
                    // virtio path, and the second is a sector leaving the
                    // machine and coming back through the driver's own queue.
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
                // rather than assumed.  One that never stored its flag prints
                // "did not come up", and a boot that printed nothing for the
                // harts it asked for would be a start nobody could tell from a
                // start nobody made.
                //
                // The number is the machine's, not the gate's: firmware may
                // cold-boot any hart, so `hart 0 online` and `hart 1 online`
                // are both correct answers depending on which one it chose.
                // The prefix is what the line has to say; the id is the
                // machine's fact.
                ("protofire: hart ", false),
                // The interrupt the boot aimed at the started CPU, and whether
                // it arrived.  A hart that stored its flag and stopped prints
                // `not taken`: this is the line that separates "the firmware
                // accepted the start" from "a CPU ran the trap path".
                ("protofire: ipi to 1 other cpu(s), taken", true),
                // And what each CPU has actually taken: the start alone cannot
                // tell a CPU that works from one that stored a flag and
                // stopped.  The boot CPU owns the scheduler and its count is
                // real; the started CPU takes its own timer and the interrupt
                // above, and does not run a task, which the line says by
                // naming the owner on the other CPU.
                ("protofire: cpus online = 2", true),
                // The boot CPU is slot zero and owns the scheduler.  Its hart
                // id is whichever one the firmware cold-booted, so the number
                // after `id` is the machine's answer rather than the gate's.
                ("protofire: cpu 0 id ", false),
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
                // The fork's two faults, as the two answers they get: one
                // write finds the shared page still held by both and is
                // copied, the other finds its holder last and is promoted in
                // place.  Either order is correct, so the check is that both
                // answers exist.
                ("protofire: copy-on-write copy at ", false),
                ("protofire: copy-on-write promote at ", false),
                // The exec, as a line that names both sides of the change: the
                // task that called and the image it became.  This boot's facts
                // are pid 1 and image 4, so the line is required whole.
                ("protofire: process 1 exec'd image 4", true),
                // Sleeping, and the wake that ended it: the deadline is a
                // firmware call on this machine, and a boot that slept and
                // never woke prints the sleep line and not the wake.
                ("protofire: a program sleeps until counter ", false),
                ("protofire: a program woke, ", false),
                ("protofire: the timer preempted, ", false),
                // Parallel execution, as a number rather than a claim: at
                // least one program ran to its exit on a CPU other than the
                // boot one.  `cpus online = 2` says a CPU came up; this is the
                // line that says it ran a program.
                ("protofire: program ended on cpu 1", true),
                ("protofire: parallel, programs ended on ", false),
                // Every finished program's address space went back, as on the
                // other two machines.
                (
                    "protofire: address spaces reaped 4, 16384 frame(s) free",
                    true,
                ),
                // No invalidation, and that is this machine's fact rather than
                // a gap.  Its ECAM window is at `0x3000_0000`, inside the four
                // gigabyte identity map, so the boot finds it already mapped
                // and changes no shared table after the second hart is up.  The
                // line is required so the count is visible: a `0 sent` that
                // became a `3 sent` would say the machine had started remapping
                // shared tables, and a `0 timed out` with `0 sent` cannot be
                // mistaken for an invalidation that was never answered.
                (
                    "protofire: tlb shootdown 0 sent, 0 acknowledged, 0 timed out",
                    true,
                ),
                // Placement moved, as on the other two machines: a task is not
                // pinned to a hart, so one that was preempted or woken can be
                // selected here or there.  The count is the number of times a
                // task was taken onto a CPU other than the one it last ran on;
                // it is not always above zero, because whether a task moves
                // depends on which CPU reaches the queue first, and two boots
                // in twenty move none.  What this line proves is that the
                // record ran and answered, which `assign` is the only writer
                // of.
                ("protofire: task migrations ", false),
            ],
        }
    }
}

/// Boot one machine and require the lines its console prints.
pub(crate) fn check(machine: Machine, profile: &str, timeout: u64) -> Result<()> {
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
pub(crate) fn expect_line(log: &str, expected: &str) -> std::result::Result<(), String> {
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
pub(crate) fn expect_line_prefix(log: &str, prefix: &str) -> std::result::Result<(), String> {
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
