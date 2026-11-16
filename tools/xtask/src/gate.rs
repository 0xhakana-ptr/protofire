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
                // The exec'd process exits with the **first byte of the file
                // it read**, `t`, 116, of "the quick brown pyrofox", and the
                // forked child dies by its own bad write, with the kernel's
                // fault status.  The fragments carry their trailing commas on
                // purpose: `1 -> 1` is a *substring* of `1 -> 116`, and a
                // fragment check that matched prefixes would have passed this
                // pair on the old status unchanged.  The comma is the value's
                // boundary.
                // The reader waits for the writer **by pid** and exits with
                // that process's status.  `3 -> 0` is the writer's, so a wait
                // that answered about another process prints a different
                // number here, which is what the unnamed `WaitProcess` could
                // do, answering with the forked child's `139`.
                &["exit statuses 1 -> 116,", "2 -> 0,", "3 -> 0,", "4 -> 139"],
                // A task was placed on a CPU other than the one it last ran
                // on.  The line names the move when there was one, and **there
                // is not always one**: placement depends on which CPU reaches
                // the queue first, and two boots in twenty never move a task at
                // all.  A gate that required the named move failed on those, so
                // the fact this checks is the count's own line, the record
                // ran, rather than that the boot happened to place a task
                // twice.  `required_lines` carries the prefix.
            ],
            Self::Riscv64 => &[
                // The reader waits for the writer **by pid** and exits with
                // that process's status.  `3 -> 0` is the writer's, so a wait
                // that answered about another process prints a different
                // number here, which is what the unnamed `WaitProcess` could
                // do, answering with the forked child's `139`.
                &["exit statuses 1 -> 116,", "2 -> 0,", "3 -> 0,", "4 -> 139"],
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
                // The external controller, programmed rather than named: the
                // context this hart claims through, the tree's source count the
                // driver used, and the hart line it reaches this hart on.  The
                // context **number** is the consumer's position in the tree and
                // follows the hart firmware cold-booted, so it is not asserted
                //, see `required_lines`.  What the pair holds still is that
                // the count is the tree's and the line is on: a boot whose PLIC
                // was named and never programmed prints `hart line off`, and a
                // driver that read the wrong node prints a different count.
                &[
                    "external controller at 0xc000000, context ",
                    ", 95 source(s), hart line on",
                ],
            ],
            // The AIA machine: the same kernel on a tree that names an APLIC
            // and an IMSIC.  The first three pairs are the same facts as the
            // PLIC machine's, the programs, the second CPU and the hart, and
            // the rest is what only this machine prints.
            Self::Riscv64Aia => &[
                &["exit statuses 1 -> 116,", "2 -> 0,", "3 -> 0,", "4 -> 139"],
                &["cpu 1 id ", ", ticking, "],
                &["hart ", " online"],
                // The controller is the **IMSIC**, because that is what claims
                // a message: an APLIC in message mode delivers into a hart's
                // file, and the file's claim is the one that answers.  The
                // count is the tree's `riscv,num-ids`; the base and the hart's
                // file index follow the firmware's cold-boot choice, for the
                // reason the PLIC machine's context number is not asserted.
                &[", 255 source(s), hart line on"],
                // The IMSIC's geometry and its self-test, together: the stride
                // is the tree's own arithmetic, the window divided by the
                // `interrupts-extended` pairs, and the identity proves the
                // message path with no device attached.
                // The failure branch prints ` NOT delivered and claimed`,
                // which **contains** `delivered and claimed`, so this pair
                // alone cannot tell the two apart, and `absent_lines` is what
                // refuses the failure text on this machine.
                &[
                    "imsic at 0x28000000, stride ",
                    "hart file ",
                    " identit(ies), self-test identity ",
                    " delivered and claimed",
                ],
                // The APLIC's domain is locked in message mode, so the
                // console's wired source is an identity in the file.
                &[
                    "the aplic is in message mode; wired source ",
                    " delivers as its own imsic identity",
                ],
                // A device's queue mapped to a message, on a machine that can
                // take one.  The page follows the cold-boot hart; the identity
                // and the vector are the boot's choice and are read back from
                // the device before this line is printed.
                &[
                    "block message wired to imsic page ",
                    ", identity ",
                    ", vector ",
                ],
            ],
        }
    }

    /// The rows a riscv64 machine's **own tree** produces.
    ///
    /// Everything above this is shared: both machines hand off through the same
    /// firmware, build the same table, start the same second hart and run the
    /// same programs.  What differs is the controller their trees name, and
    /// that is what these two lists hold, the PLIC machine's window and the
    /// one console interrupt a line delivers, or the AIA machine's IMSIC, its
    /// message-mode APLIC and the device message it takes.
    pub(crate) fn controller_rows(self) -> &'static [(&'static str, bool)] {
        match self {
            Self::Riscv64Aia => &[
                // The IMSIC, enabled and **self-tested**: the geometry the tree
                // states, and a message written to this hart's own page and
                // claimed back.  The hart-file index and the identity follow
                // the firmware's choice of cold-boot hart, so neither is
                // asserted, `paired_lines` holds the shape.
                ("protofire: imsic at 0x28000000, stride ", false),
                // The APLIC is locked in message mode here, so a wired source
                // becomes an identity in the file rather than a line.  This is
                // the line that says the kernel noticed which mode it has,
                // instead of programming a direct-delivery domain that does not
                // exist on this machine.
                (
                    "protofire: the aplic is in message mode; wired source ",
                    false,
                ),
                // A real device's message, wired end to end: the page, the
                // identity and the vector.  The page follows the hart the
                // firmware cold-booted, so it is a prefix.
                ("protofire: block message wired to imsic page ", false),
                // The console's own message, delivered through the APLIC and
                // claimed as its source's identity.  This is the end of the
                // message path: a source the tree named, an APLIC that turned
                // its wire into a message, a file that delivered it, and a
                // trap that acknowledged the UART and counted it.
                //
                // The count is one because the boot asks for exactly one
                // transmit interrupt and then silences the device, the same
                // shape the PLIC machine's line has, reached by a different
                // mechanism.  A boot whose `sourcecfg`/`target` writes are off
                // by one source delivers identity 9 to a kernel waiting on 10
                // and prints zero here; measured, that is what this machine did
                // before the fix.
                ("protofire: console interrupt(s) taken = 1", true),
            ],
            Self::Riscv64 => &[
                // The external controller, initialized rather than merely
                // named: base, the context this hart claims through, the
                // machine's source count, and the hart line the PLIC reaches
                // it on.  A tree that named the window and a driver that did
                // not program it would print the first three and "off".
                //
                // The context number is **not** asserted, for the reason the
                // hart id is not: it is the consumer's position in the tree's
                // `interrupts-extended`, S-mode on hart N is context `2N+1`,
                // and which hart firmware cold-boots is the firmware's choice.
                // A boot whose firmware picked hart 1 printed `context 3`, and
                // a gate requiring `context 1` failed on it, three boots in
                // fifteen, with the controller programmed and the line taken.
                // What is invariant is the shape, and `paired_lines` carries
                // it.
                (
                    "protofire: external controller at 0xc000000, context ",
                    false,
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
            ],
            _ => &[],
        }
    }

    /// Text that must **not** appear anywhere in the log.
    ///
    /// The complement of a required line, and it exists because a failure text
    /// can contain its own success text: the IMSIC self-test prints
    /// ` delivered and claimed` when it worked and ` NOT delivered and claimed`
    /// when it did not, so a required fragment cannot tell them apart.
    /// Measured, deleting the claim from the success path left the required
    /// pair matching the failure line, and the gate stayed green.
    pub(crate) fn absent_lines(self) -> &'static [&'static str] {
        match self {
            Self::X8664 | Self::Aarch64 | Self::Riscv64 => &[],
            Self::Riscv64Aia => &[
                "NOT delivered and claimed",
                // A delivery nobody claimed is silenced by the trap path, and
                // on this machine that means a wired source or a message
                // identity the boot did not expect.  The line is not fatal, so
                // only a check keeps it out of a green boot.
                "unhandled external interrupt",
            ],
        }
    }

    /// Lines whose tail is a count that has to be **above zero**.
    ///
    /// A fourth question, and the one this tree's device messages needed: "the
    /// line appeared with a number" passes on `= 0`, which is exactly what a
    /// wiring that armed every register and took nothing prints.  The count
    /// itself cannot be asserted, an IMSIC file holds one pending bit per
    /// identity, so completions arriving before the first is claimed collapse
    /// into one trap, so the claim is the one the mechanism makes: at least
    /// one device message reached a handler.
    pub(crate) fn nonzero_lines(self) -> &'static [&'static str] {
        match self {
            Self::X8664 | Self::Aarch64 | Self::Riscv64 => &[],
            // The two devices' messages.  The block device's line is the one a
            // boot whose wiring ran before the driver's reset prints as `= 0`,
            // which is the defect this gate exists to catch.  The card's is
            // the second identity in the same table: two devices, two bits in
            // the file, two handlers, and each count is its own, a boot that
            // took one device's message and not the other's fails here rather
            // than passing on a total.
            Self::Riscv64Aia => &[
                "protofire: block completion message(s) taken = ",
                "protofire: network message(s) taken = ",
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
            Self::X8664 | Self::Aarch64 | Self::Riscv64 | Self::Riscv64Aia => &[(" says hello", 6)],
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
                // The clock the time calls read: the counter's origin and the
                // rate it counts at, both read from the machine.  A boot that
                // recorded neither answers every `GetTimeOfDay` with
                // `Unsupported`, which reads the same as a machine whose timer
                // never came up, so the line is what separates the two.
                ("protofire: time origin ", false),
                // The generator, and a measurement of it: two 8-byte reads have
                // to differ.  An exact line rather than a prefix, because
                // "the same" is the failure this line exists to catch and a
                // prefix check would pass on it.
                ("protofire: random seeded, two reads differ", true),
                (
                    "protofire 0.1.0: entered via pvh, console up, stage 1",
                    true,
                ),
                ("protofire: heap at ", false),
                // The heap walked by the allocator's own invariant after the
                // mount, reporting that the walk saw a carved heap.  The line
                // exists because a check that reads an allocator nothing
                // allocates from passes forever: this tree shipped
                // `verify_kernel_heap` reaching a second
                // `KernelGlobalAllocator` whose free lists still said "one free
                // block" while the kernel's `#[global_allocator]` carved the
                // arena, and the check called the used block damage.
                //
                // A prefix, not the whole line, because the byte count moves
                // with the allocation sequence and a gate requiring it would
                // report an unrelated refactor as a defect.  The boot refuses
                // an untouched arena itself and prints a line that does not
                // begin with this prefix, so the regression cannot satisfy the
                // gate.
                ("protofire: heap checked after mount, carved ", false),
                ("protofire: block device from virtio-blk on pci", true),
                // The network card, and the ARP exchange that proves both
                // queues.  The first line is the bring-up, the second is a
                // frame leaving and the reply coming back, the only evidence
                // this tree has that the frame path runs on a machine.
                //
                // The reply's own fields are on the line, and the driver
                // returns false when they are not the answer to the question it
                // asked.  So requiring the line at all is requiring that the
                // card sent a frame, received one, and that the one it received
                // was addressed back to it.
                // The service table, and one service reached through it.  The
                // first line is the boot installing what it offers and closing
                // the table; the second is a request submitted by **name**,
                // driven through the trait, and answered with the machine's own
                // counter.  A boot that printed the first without the second
                // would have a table nothing could use.
                ("protofire: services installed = ", false),
                ("protofire: clock service answered ", false),
                // The memory calls, answered by the kernel because a program
                // cannot print a value.  `67` is `Mmap` and `92` is `Brk`; the
                // numbers are the ABI's, so the line is also a check that the
                // program's own constants reached the calls they name.
                //
                // Both addresses have to be inside the program's window, and
                // the mapping's is **not** an error code: a kernel that refused
                // the call would print an encoding whose high bit is set, and
                // the two lines would still be there.
                ("protofire: program memory call 67 answered 0x80", false),
                ("protofire: program memory call 92 answered 0x80", false),
                // The filesystem interface, exercised by the program the
                // boot execs: a file written and read back, a directory
                // made and listed, a rename and a remove, and the `*At`
                // calls resolving a relative name against a descriptor the
                // program opened.  The two `wrote` lines are exact, the
                // counts are the program's own constants, and the anchored
                // lines are prefixes because the descriptor number is the
                // table's to hand out, not the gate's to pin.
                ("protofire: process 1 wrote 19 byte(s) to a file", true),
                ("protofire: process 1 wrote 4 byte(s) to a file", true),
                (
                    "protofire: process 1 stat'd /tmp/kept.txt, kind file, size 19",
                    true,
                ),
                ("protofire: process 1 read /tmp/notes entry 0", true),
                (
                    "protofire: process 1 created directory notes via descriptor ",
                    false,
                ),
                ("protofire: process 1 stat'd at.txt via descriptor ", false),
                // The truncate, on the descriptor the program opened for
                // writing.  A prefix because the descriptor is the table's to
                // hand out; the size check beside it is the program's own, so a
                // handler that answered zero without reaching the node would
                // leave the file long and end the program at its stat.
                ("protofire: process 1 set descriptor ", false),
                // The two readings asked of a descriptor rather than a name.  A
                // prefix because neither line carries anything but the number
                // the table handed out; the record and the entry beside them
                // are the program's own comparisons, so a call that answered
                // the wrong anchor ends the program instead.
                ("protofire: process 1 stat'd descriptor ", false),
                ("protofire: process 1 listed descriptor ", false),
                // The seek, twice: from the end and backwards from where it
                // landed. A prefix because the position is the answer and the
                // number is the file's; what the program does with it, a read
                // of one byte compared against `fi`, is what turns the line
                // into evidence that the position moved rather than being
                // reported.
                ("protofire: process 1 seeked descriptor ", false),
                // The two flushes.  Their answer is zero whether the node was
                // reached or not, so the line naming which one ran is the only
                // thing this boot can say about them; whether the bytes left
                // the machine is not a fact ring 3 can observe.
                ("protofire: process 1 flushed descriptor ", false),
                (
                    "protofire: process 1 flushed the data of descriptor ",
                    false,
                ),
                // The punch and the two data-reduction flags.  The punch is
                // the refusal this boot expects, because the root is PyroFS
                // and only the NTFS volume makes holes; the flags round trip,
                // and their lines carry the word the program read back.
                (
                    "protofire: process 1 asked for the flags of descriptor ",
                    false,
                ),
                (
                    "protofire: process 1 was refused a call on descriptor ",
                    false,
                ),
                (
                    "protofire: process 1 renamed note.txt via descriptor ",
                    false,
                ),
                (
                    "protofire: process 1 removed scratch.txt via descriptor ",
                    false,
                ),
                // The process model: a program starts another program and
                // waits for it by pid, and the signal exchange between them
                // runs both ways, the child's cooperative send, the
                // parent's delivery to the child's own handler, and the
                // queued record a suspend answers.  The pids are the
                // table's, so prefixes.
                ("protofire: process 1 spawned /bin/shell as pid ", false),
                ("protofire: a wait answered status 23 for process ", false),
                (
                    "protofire: a signal wait answered signal 10 from process ",
                    false,
                ),
                (
                    "protofire: a suspend answered signal 10 from process ",
                    false,
                ),
                // The time and the information calls, reached from ring 3 and
                // answered by the registry.  Two lines each for the clock and
                // the generator because the program calls each twice, the
                // clock to check it does not go backwards, the generator to
                // check two draws differ, and one line each for the two
                // records.  The length on the line is the program's own buffer
                // size, which is a fact about the program and not about the
                // kernel.
                ("protofire: process 1 read the clock, 16 byte(s)", true),
                ("protofire: process 1 drew random bytes, 16 byte(s)", true),
                ("protofire: process 1 asked the ABI, 24 byte(s)", true),
                ("protofire: process 1 asked the system, 64 byte(s)", true),
                ("protofire: process 1 asked the network, 24 byte(s)", true),
                ("protofire: virtio-net up, address ", false),
                ("protofire: virtio-net arp reply ", false),
                // The IPv6 side, over the same card and the same receive
                // path: a neighbour solicitation this stack answered, the
                // line names the address asked about and the peer's MAC it
                // took out of the solicitation's own option, and an echo
                // request it replied to, with the identifier and sequence
                // the request carried.
                //
                // Both are loopbacks through `demux_ipv6`, which is the
                // path a frame off the wire takes.  QEMU's user-mode network
                // was measured and refused for this: `ipv6=on` makes slirp
                // stop answering IPv4 ARP, so enabling it costs four
                // working IPv4 exchanges to reach a neighbour that does not
                // answer NDP anyway.
                ("protofire: ipv6 neighbour answered for fe80:", false),
                ("protofire: ipv6 echo reply to fe80:", false),
                // And the ring-3 half: a program reads the IPv6 record and
                // checks the link-local address against the MAC it was told
                // about, `fe80::` plus the modified EUI-64, the one fact a
                // program can verify without the wire.
                ("protofire: process 1 asked the ipv6 side, 56 byte(s)", true),
                // And the two transports over IPv6: a datagram and a stream,
                // both to this machine's own link-local address, both
                // through the receive path.  The lines above prove the
                // answering paths; these prove a datagram and a segment
                // carry over IPv6 at all, which nothing else here does.
                (
                    "protofire: ipv6 udp received 10 byte(s) from this machine",
                    true,
                ),
                // And the reassembly: a datagram split the way a shrinking
                // path splits one, put back together through the demux, and
                // read whole.  Without it a fragment is a datagram dropped in
                // pieces, which no line here shows.
                ("protofire: fragments reassembled 20 byte(s), intact", true),
                // What a server says this machine is, and an address a
                // router's prefix configured for itself.  Two protocols, and
                // neither restates the other: DHCP asks a server, stateless
                // configuration only listens to a router.
                //
                // The name lookup is deliberately not required here: it needs
                // a network with a resolver behind it, and a gate that fails
                // because CI has no internet is a gate nobody can fix.
                ("protofire: dhcp leased ", false),
                ("protofire: slaac configured ", false),
                // The other half of the same advertisement: its source is a
                // default router, and an address off this link is asked for
                // through it rather than sent to its own solicited-node group.
                (
                    "protofire: ipv6 route via fe80:0000:0000:0000:5055:0aff:fe00:0202, ",
                    false,
                ),
                (
                    "protofire: ipv6 tcp echoed 2 byte(s) of 2, round trip",
                    true,
                ),
                // The answer the reply left behind: the cache holding it, and
                // the same question answered from the table without a second
                // frame on the wire.  The second line is exact because its
                // tail is the one fact a lookup could not vary.
                ("protofire: arp cache holds ", false),
                (
                    "protofire: arp cache answered 10.0.2.2 again without the wire",
                    true,
                ),
                // The ping: the echo reply is a packet QEMU's user-mode
                // network built, matched against the identifier, sequence and
                // data the request sent, the round trip IPv4 can carry, on
                // every machine this gate boots.
                ("protofire: icmp echo reply from 10.0.2.2, ", false),
                // The datagram: one UDP send to a port nothing owns, and
                // the port-unreachable refusal that comes back carrying the
                // original, the peer's proof that a datagram this stack
                // built arrived with its header intact.
                ("protofire: udp sent from port 40000, refused by ", false),
                // The datagram exchange, from ring 3: a bind, a fork, the
                // child's send, and the receive that answers it.  The send's
                // and receive's lines are exact, the lengths are the
                // program's own constant and the sender record is what the
                // kernel filled, and the bind is a prefix because the
                // descriptor number is the table's to hand out.
                ("protofire: process 1 bound port 8612 as descriptor ", false),
                (
                    "protofire: process 7 sent 9 byte(s) to 10.0.2.15 port 8612",
                    true,
                ),
                (
                    "protofire: process 1 received 9 byte(s) from 10.0.2.15 port 8613",
                    true,
                ),
                // The stream: a listener, a client, an echo, and the close
                // that ends both ends, on loopback, the whole of a TCP
                // exchange, run by the boot on every machine this gate
                // boots.  The ids are the table's, so the connect line is a
                // prefix; the echo's length beside the send's is exact,
                // because a round trip that dropped a byte could not say 9.
                ("protofire: tcp connected, listener ", false),
                ("protofire: tcp echoed 9 byte(s) of 9, round trip", true),
                // The close is over and the four-tuple is still held: the
                // hold is what lets a retransmitted finish be answered
                // instead of reset, and it is why this is not "gone".
                ("protofire: tcp closed, both ends held in time wait", true),
                // The recovery: a segment the probe refuses to deliver, and
                // the retransmission that puts it back.  No wire this gate
                // boots loses a frame, so this is the only line that can tell
                // a stack with a queue from one without: the attempt count is
                // the schedule's, and the byte count is the peer's own inbox
                // after the copy that was lost arrived again.
                (
                    "protofire: tcp recovered 1 attempt(s), 12 byte(s), intact",
                    true,
                ),
                // A program setting and reading back the machine's name, from
                // ring 3: the pair of calls a program can make about this
                // machine and cannot see any other way.  The status is exact,
                // because the call answering anything else is the one that says
                // it was not wired.
                ("protofire: process 1 set the machine's name, 0", true),
                // A socket's two ends, read back by the program that owns it.
                // The own end is exact: the port it listened on and the address
                // the boot's lease gave.  The peer's port is the table's to
                // choose, so that line is a prefix.
                ("protofire: process 1 socket is 10.0.2.15:9003", true),
                ("protofire: process 1 peer is 10.0.2.15:", false),
                // The reordering: a stream's two halves delivered the wrong way
                // round, which no wire this gate boots does on its own.  The
                // held count is the cache taking the early half; the byte count
                // is the peer's own inbox once the gap closed.
                (
                    "protofire: tcp reordered 1 held, 19 byte(s), in order",
                    true,
                ),
                // The path's size: a fragmentation-needed report the probe
                // builds, because no wire this gate boots sends one, handed to
                // the demux a received frame goes through.  The two numbers are
                // the stream's segment size before and after, so a stack that
                // read the report and did nothing with it prints the same
                // number twice.
                (
                    "protofire: path mtu 1460 -> 536, the report reached the stream",
                    true,
                ),
                // The IPv6 half, and the layout difference that makes it a
                // separate exchange: a packet-too-big report's MTU word takes
                // the four bytes an IPv4 error leaves unused, so the quotation
                // starts eight bytes in.
                (
                    "protofire: path mtu6 1460 -> 1220, the report reached the stream",
                    true,
                ),
                // The window: a stream's buffer filled with one segment and a
                // byte past it refused.  No exchange this gate runs carries
                // enough bytes for a shrinking window to differ from a constant
                // one, which is why this is its own exchange.
                (
                    "protofire: window 8192 -> 0, and a byte past it was refused",
                    true,
                ),
                // The window the peer advertises: a bare acknowledgement
                // states a full buffer, a write carries nothing, and the same
                // write carries nine bytes once the peer reopens.  A sender
                // that parsed the field and ignored it would print the same
                // number three times.
                (
                    "protofire: peer window 8192 -> 0 -> 9, the peer's window bounded the write",
                    true,
                ),
                // The socket options, from ring 3: a number set, the same
                // number read back at its own width, and an option this
                // stack does not serve refused.  The width is the word a size
                // is, and the refusal is what stops a program believing it
                // set something the kernel has no implementation of.
                ("protofire: process 1 set socket option 5 answered 0", true),
                ("protofire: process 1 read socket option 5 answered 8", true),
                ("protofire: process 1 set socket option 1 refused", true),
                // The same two options, read back where they act: a receive
                // buffer is the window the connection advertises next, and a
                // send buffer is the congestion window it will not exceed.
                (
                    "protofire: options window 8192 -> 1000, congestion 14600 -> 4380, both options moved what they govern",
                    true,
                ),
                // The local-domain socket, in the kernel's own exchange: a
                // name bound, connected to, accepted, and bytes both ways.  A
                // one-pipe connection would answer one direction and print
                // zero for the other.
                (
                    "protofire: local socket 5 byte(s) forward, 6 back, both ways through one name",
                    true,
                ),
                // The raw socket, in the kernel's own exchange: a protocol
                // number instead of a port, and a packet this machine sends
                // itself, composed by the stack and parsed back out of the
                // frame it built.  The source address on what it receives is
                // what says the header was not the caller's.
                (
                    "protofire: raw socket sent 10 byte(s) as protocol 253, and received 10 from this machine",
                    true,
                ),
                // The packet filter: a rule installed, the datagram it names
                // **not delivered**, and the same datagram delivered once the
                // rule is removed.  Both halves are required, because a filter
                // that always drops and one that never does each pass one of
                // them, and a filter whose rules nothing consults passes
                // neither while its four calls report success.
                (
                    "protofire: filter dropped the datagram under a rule: yes, delivered it once removed: yes, and an outbound rule kept a frame off the card: yes",
                    true,
                ),
                // Multicast forwarding, in the kernel's own exchange: a frame
                // through the demux, an entry naming it, and what the card was
                // told.  The three numbers are the arriving hop count, what
                // the copy left with, and whether the payload is the
                // sender's, because a forwarding path is broken three ways and
                // each looks right through a different window.
                (
                    "protofire: multicast forwarded 1 frame(s), ttl 5 -> 4, payload intact",
                    true,
                ),
                // IPsec's ESP, in one exchange: the wire carried ciphertext,
                // the demux recovered the bytes, and a repeat of the same frame
                // did not arrive twice.  A protocol number with the plaintext
                // still inside passes a counter and not this.
                (
                    "protofire: esp sealed 1, opened 1, the wire carried ciphertext, and the replay 0 byte(s)",
                    true,
                ),
                // DCCP's whole connection, driven through the function the
                // demux calls: a Request, a Response, the client opening, and
                // the first datagram arriving on the server.  A state machine
                // that stored no states passes none of it.
                ("protofire: dccp client open, carried 4 byte(s)", true),
                (
                    "protofire: tls handshake finished verified yes, and carried 5 byte(s) under the application keys",
                    true,
                ),
                // The frame path's data offset: two TCP segments through the
                // demux, one carrying an option and one not, and a stream
                // holding their data and neither header.  Every other exchange
                // runs on the loopback, which hands a connection the payload
                // it built and never a frame, so this is the only line that
                // can tell a demux which slices the segment from one that
                // passes the packet.
                (
                    "protofire: frame data 8 byte(s) sent, 8 held, the headers stayed out of the stream",
                    true,
                ),
                // The timeout, measured: two exchanges, the second later than
                // the first, and an estimate that moved.  The numbers are the
                // machine's clock and change every boot, so the line is
                // required by its **second** line, which is the verdict and
                // not a number.
                // The route table: a second, more specific route, and the
                // frame following it rather than the default gateway.
                (
                    "protofire: routes 1 -> 2, and the longer prefix chose 2",
                    true,
                ),
                ("protofire: round trip ", false),
                ("protofire: the estimate moved with the measurement", true),
                // And the same exchange between two ring-3 processes, which is
                // the claim a probe cannot make: a bind, a connect, an accept,
                // and a read and a write each way.
                //
                // The three lines required are the ones that do not depend on
                // an interleaving.  Whether a read parks or finds its bytes
                // already there is the scheduler's choice, and requiring
                // `a program blocks on a local socket` made this gate fail on a
                // boot where the child's write landed first: the exit statuses
                // were identical, so nothing was broken.  The park and its wake
                // are still printed and still read by a human; they are not a
                // gate line, because a gate that depends on a race is a gate
                // that fails for the wrong reason.
                (
                    "protofire: process 1 bound the local name, descriptor ",
                    false,
                ),
                (
                    "protofire: process 9 connected to the local name, descriptor ",
                    false,
                ),
                // The wake the connect makes.  Its count is zero when the
                // accept had not parked yet, so it is a prefix: what the line
                // proves is that the call answered a descriptor and woke
                // whatever was waiting.
                ("protofire: a local connect woke ", false),
                (
                    "protofire: process 1 accepted a local connection as descriptor ",
                    false,
                ),
                // The congestion window, on an exchange long enough to see it
                // move: ten acknowledgements grow it and a timeout collapses
                // it.  Every other boot exchange finishes before the window
                // matters.
                (
                    "protofire: congestion 14600 -> 15240 -> 1460, grew and then collapsed",
                    true,
                ),
                // The third of the lease's three states: a broadcast request
                // with no server named, which a server answers.  A boot never
                // reaches it on its own because a server's default lease is a
                // day.
                ("protofire: rebind sent, the wire answered", true),
                // The stream exchange, from ring 3: the same two programs
                // the datagram exchange used.  The listen and the accept
                // are prefixes, the descriptor number is the table's, and
                // the connect, the two writes and the two reads are exact:
                // the lengths are the program's own constant, and the
                // child's exit status is the echo's first byte, which only
                // a completed round trip could have carried.
                (
                    "protofire: process 1 listening on port 9003 as descriptor ",
                    false,
                ),
                (
                    "protofire: process 8 connected to 10.0.2.15 port 9003 as stream ",
                    false,
                ),
                ("protofire: process 8 wrote 9 byte(s) to a stream", true),
                (
                    "protofire: process 1 accepted a stream as descriptor ",
                    false,
                ),
                ("protofire: process 1 read 9 byte(s) from a stream", true),
                ("protofire: process 1 wrote 9 byte(s) to a stream", true),
                ("protofire: process 8 read 9 byte(s) from a stream", true),
                (
                    "protofire: namespace: pyrofs on / (protofire), tmpfs on /tmp (memory), iso9660 on /cdrom (bootdisc)",
                    true,
                ),
                (
                    "protofire: /cdrom/README.TXT reads back from the disc",
                    true,
                ),
                ("protofire: virtio-blk wrote and read back sector ", false),
                // The negotiated flush bit.  Its absence was invisible until a
                // `Fsync` took seconds and failed, so the line is what turns
                // "the driver asked" into "the device answered".
                ("protofire: virtio-blk negotiated flush=", false),
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
                // boot's four spaces, the three programs plus the forked
                // child, released once the machine is finished.  Releasing at
                // each exit was tried and produced 186 page faults in six
                // boots of eight, which is why the count is here at the end
                // rather than absent.
                //
                // The line is required whole because its tail is the ratchet:
                // with the tables each mapping built reclaimed beside the
                // frames, every frame the boot took is back, and the free
                // count is the pool's whole size.  A release that leaks even
                // the walk's scaffolding, three tables per space, fifteen on
                // this boot, prints a smaller number and fails here.
                (
                    "protofire: address spaces reaped 9, 131072 frame(s) free",
                    true,
                ),
                // Nine and not eight: the local-domain exchange forks once
                // more than the stream exchange did, so the boot runs nine
                // programs.  The number is the programs, which is why it is
                // exact.
                //
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
                // The placement rule's preferred half: a switch put a task back
                // on the CPU it last ran on.  Required because a rule that
                // never preferred anything still printed the migration line
                // above, the two numbers are what a reader compares, and a
                // boot whose home count was zero moved every task it placed.
                ("protofire: task placings home ", false),
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
                // The pipe's reader waited for a process to end, and the
                // kernel answered, the same claim the other machines carry,
                // and the line rather than an exit status because
                // `WaitProcess` names no particular child.
                ("protofire: a wait answered status ", false),
                // And the writer's end was closed by its **exit**, not by a
                // `Close` it never makes: the pipe's writer exits with its
                // write end open, so this line is the release running.  A
                // release that did not run would leave the reader parked and
                // the boot unfinished, and the wait's line above would never
                // print either.
                ("protofire: process 2 released ", false),
                // The program answered its own fault, as on the other two:
                // the reader installs a handler, stores into its own
                // read-execute code page, and the kernel resumes it at the
                // handler instead of killing it.  `vector 14` is this
                // machine's page fault.
                ("protofire: process 3 installed a fault handler at ", false),
                ("protofire: process 3 handled its own fault at ", false),
                // The child inherited its parent's descriptors: the announcing
                // program makes a pipe before it forks, and both ends are
                // copied to the child, owned by it.  Without the copy the child
                // would find every inherited number refused, because the table
                // checks the owner.
                ("protofire: forked process 4 inherited ", false),
                // The program took a fault **it answered itself**: the
                // reader installs a handler, stores into its own code
                // page (a write no resolver answers), and the kernel
                // resumes it at the handler instead of killing it.  The
                // `program 64 says hello` line below is the handler's own
                ("protofire: forked a process, child pid 4", true),
                // The fork's two faults, as the two answers they get.  The
                // fork shares the stack page read-only, so each process's
                // first write faults, and the count decides: one write finds
                // the page still shared and is **copied**, the other finds
                // itself the last holder and is handed the frame outright.
                // Either order is correct, which process runs first decides
                // which answer each gets, so the check is that both answers
                // exist, and the promote's frame is the copy's source frame,
                // which is the pair reading itself.
                ("protofire: copy-on-write copy at ", false),
                ("protofire: copy-on-write promote at ", false),
                // The exec, as a line that names both sides of the change:
                // the task that called and the image it became.  The number
                // and the image are this boot's facts, pid 1 calls, image 4
                // is what it becomes, so the line is required whole.
                //
                // And the opened line under it is the identity claim's new
                // home: the exec'd image opens the boot's file, and the
                // kernel prints **which process** opened it, read from the
                // scheduler's own record.  A process that lost its identity
                // in the change would open it under some other number.
                // The loader's own line, required as a prefix: the segment
                // count and the entry are the compiled image's facts, and the
                // line is what separates "the loader ran" from "a program ran".
                ("protofire: loaded /bin/init, ", false),
                ("protofire: process 1 exec'd /bin/init", true),
                ("protofire: process 1 opened /greeting.txt", true),
                // The child's death, as the kernel reports it: which process,
                // the address its write named, and the status the pair reads.
                // A prefix, because the address is the program's own code page
                // and the vector is the machine's answer.
                ("protofire: process 4 died from a fault at ", false),
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
                        "protofire: address spaces reaped 9, 16384 frame(s) free",
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
                    // The placement rule's preferred half: a switch put a task
                    // back on the CPU it last ran on.  Required because a rule
                    // that never preferred anything still printed the migration
                    // line above, the two numbers are what a reader compares,
                    // and a boot whose home count was zero moved every task it
                    // placed.
                    ("protofire: task placings home ", false),
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
                    // And the reader waited for a process to end, on the
                    // same boot.  The **line** is the assertion rather than
                    // an exit status: `WaitProcess` promises "some process
                    // finished", not "the one you meant", so a status a
                    // reader reported could be another process's.  Which of
                    // the answer's two spellings appears is the race the
                    // program cannot control; both mean the call returned.
                    ("protofire: a wait answered status ", false),
                    ("protofire: process 2 released ", false),
                    // The program took a fault **it answered itself**: the
                    // reader installs a handler, stores into its own code
                    // page (a write no resolver answers), and the kernel
                    // resumes it at the handler instead of killing it.  The
                    // `program 64 says hello` line below is the handler's own
                    // and the status is 0, which only a program that came back
                    // can print.
                    ("protofire: process 3 installed a fault handler at ", false),
                    ("protofire: process 3 handled its own fault at ", false),
                    // The child inherited its parent's descriptors: the
                    // announcing program makes a pipe before it forks, and both
                    // ends are copied to the child, owned by it.  Without the
                    // copy the child would find every inherited number refused,
                    // because the table checks the owner.
                    ("protofire: forked process 4 inherited ", false),
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
                    // The fork's two faults, as the two answers they get.  The
                    // fork shares the stack page read-only, so each process's
                    // first write faults, and the count decides: one write
                    // finds the page still shared and is **copied**, the other
                    // finds itself the last holder and is handed the frame
                    // outright.  Either order is correct, so the check is that
                    // both answers exist.
                    ("protofire: copy-on-write copy at ", false),
                    ("protofire: copy-on-write promote at ", false),
                    // The exec, as a line that names both sides of the change:
                    // the task that called and the image it became.  This
                    // boot's facts are pid 1 and image 4, so the line is
                    // required whole.  The opened line under it is the
                    // identity claim: the kernel names the process that opened
                    // the boot's file, read from the scheduler's own record.
                    // The loader's own line, required as a prefix: the segment
                    // count and the entry are the compiled image's facts, and
                    // the line is what separates "the loader ran" from "a
                    // program ran".
                    ("protofire: loaded /bin/init, ", false),
                    ("protofire: process 1 exec'd /bin/init", true),
                    ("protofire: process 1 opened /greeting.txt", true),
                    // The child's death, as the kernel reports it: which
                    // process, the address its write named, and the status
                    // the pair reads.  A prefix, because the address is the
                    // program's own code page and the vector is the machine's
                    // answer.
                    ("protofire: process 4 died from a fault at ", false),
                    // The frame pool, and the allocator exercised rather than
                    // described.  The whole line, because its tail is the
                    // outcome: a prefix would accept `pool check FAILED`, the
                    // numbers before it being the same on both runs, and only
                    // the last word says whether the allocator handed the
                    // frame back.
                    (
                        "protofire: frame pool 16384 frame(s), 16384 free, 0 in page tables, pool check ok",
                        true,
                    ),
                    ("protofire: mac allowed ", false),
                    ("protofire: mac denied ", false),
                    ("protofire: syscall table installed, ", false),
                    ("protofire: time origin ", false),
                    ("protofire: random seeded, two reads differ", true),
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
                    // The heap walked by the allocator's own invariant after
                    // the mount, reporting that the walk saw a carved heap.  A
                    // prefix rather than the whole line, because the byte count
                    // moves with the allocation sequence; the boot refuses an
                    // untouched arena itself and prints a line this prefix does
                    // not match.
                    ("protofire: heap checked after mount, carved ", false),
                    // The driver running on the device, and doing real I/O on
                    // it.
                    //
                    // `block device from memory` is the fallback: a machine
                    // with no disk prints it and boots anyway, which is correct
                    // and is not the same claim.  These two lines name the
                    // virtio path, and the second is a sector leaving the
                    // machine and coming back through the driver's own queue.
                    ("protofire: block device from virtio-blk on pci", true),
                    // The network card, and the ARP exchange that proves both
                    // queues.  The first line is the bring-up, the second is a
                    // frame leaving and the reply coming back, the only
                    // evidence this tree has that the frame path runs on a
                    // machine.
                    //
                    // The reply's own fields are on the line, and the driver
                    // returns false when they are not the answer to the
                    // question it asked.  So requiring the line at all is
                    // requiring that the card sent a frame, received one, and
                    // that the one it received was addressed back to it.
                    // The service table, and one service reached through it.
                    // The first line is the boot installing what it offers and
                    // closing the table; the second is a request submitted by
                    // **name**, driven through the trait, and answered with the
                    // machine's own counter.  A boot that printed the first
                    // without the second would have a table nothing could use.
                    ("protofire: services installed = ", false),
                    ("protofire: clock service answered ", false),
                    // The memory calls, answered by the kernel because a
                    // program cannot print a value.  `67` is `Mmap` and `92` is
                    // `Brk`; the numbers are the ABI's, so the line is also a
                    // check that the program's own constants reached the calls
                    // they name.
                    //
                    // Both addresses have to be inside the program's window,
                    // and the mapping's is **not** an error code: a kernel that
                    // refused the call would print an encoding whose high bit
                    // is set, and the two lines would still be there.
                    ("protofire: program memory call 67 answered 0x80", false),
                    ("protofire: program memory call 92 answered 0x80", false),
                    // The filesystem interface, exercised by the program the
                    // boot execs: a file written and read back, a directory
                    // made and listed, a rename and a remove, and the `*At`
                    // calls resolving a relative name against a descriptor
                    // the program opened.  The two `wrote` lines are exact
                    // the counts are the program's own constants, and the
                    // anchored lines are prefixes because the descriptor
                    // number is the table's to hand out, not the gate's to
                    // pin.
                    ("protofire: process 1 wrote 19 byte(s) to a file", true),
                    ("protofire: process 1 wrote 4 byte(s) to a file", true),
                    (
                        "protofire: process 1 stat'd /tmp/kept.txt, kind file, size 19",
                        true,
                    ),
                    ("protofire: process 1 read /tmp/notes entry 0", true),
                    (
                        "protofire: process 1 created directory notes via descriptor ",
                        false,
                    ),
                    ("protofire: process 1 stat'd at.txt via descriptor ", false),
                    // The truncate, on the descriptor the program opened for
                    // writing.  A prefix because the descriptor is the table's
                    // to hand out; the size check beside it is the program's
                    // own, so a handler that answered zero without reaching the
                    // node would leave the file long and end the program at its
                    // stat.
                    ("protofire: process 1 set descriptor ", false),
                    // The two readings asked of a descriptor rather than a
                    // name.  A prefix because neither line carries anything but
                    // the number the table handed out; the record and the entry
                    // beside them are the program's own comparisons, so a call
                    // that answered the wrong anchor ends the program instead.
                    ("protofire: process 1 stat'd descriptor ", false),
                    ("protofire: process 1 listed descriptor ", false),
                    // The seek, twice: from the end and backwards from where it
                    // landed. A prefix because the position is the answer and
                    // the number is the file's; what the program does with it,
                    // a read of one byte compared against `fi`, is what turns
                    // the line into evidence that the position moved rather
                    // than being reported.
                    ("protofire: process 1 seeked descriptor ", false),
                    // The two flushes.  Their answer is zero whether the node
                    // was reached or not, so the line naming which one ran is
                    // the only thing this boot can say about them; whether the
                    // bytes left the machine is not a fact ring 3 can observe.
                    ("protofire: process 1 flushed descriptor ", false),
                    (
                        "protofire: process 1 flushed the data of descriptor ",
                        false,
                    ),
                    // The punch and the two data-reduction flags.  The punch
                    // is the refusal this boot expects, because the root is
                    // PyroFS and only the NTFS volume makes holes; the flags
                    // round trip, and their lines carry the word the program
                    // read back.
                    (
                        "protofire: process 1 asked for the flags of descriptor ",
                        false,
                    ),
                    (
                        "protofire: process 1 was refused a call on descriptor ",
                        false,
                    ),
                    (
                        "protofire: process 1 renamed note.txt via descriptor ",
                        false,
                    ),
                    (
                        "protofire: process 1 removed scratch.txt via descriptor ",
                        false,
                    ),
                    // The process model: a program starts another program
                    // and waits for it by pid, and the signal exchange
                    // between them runs both ways, the child's cooperative
                    // send, the parent's delivery to the child's own
                    // handler, and the queued record a suspend answers.  The
                    // pids are the table's, so prefixes.
                    ("protofire: process 1 spawned /bin/shell as pid ", false),
                    ("protofire: a wait answered status 23 for process ", false),
                    (
                        "protofire: a signal wait answered signal 10 from process ",
                        false,
                    ),
                    (
                        "protofire: a suspend answered signal 10 from process ",
                        false,
                    ),
                    // The time and the information calls, reached from ring 3
                    // and answered by the registry.  Two lines each for the
                    // clock and the generator because the program calls each
                    // twice, the clock to check it does not go backwards, the
                    // generator to check two draws differ, and one line each
                    // for the two records.  The length on the line is the
                    // program's own buffer size, which is a fact about the
                    // program and not about the kernel.
                    ("protofire: process 1 read the clock, 16 byte(s)", true),
                    ("protofire: process 1 drew random bytes, 16 byte(s)", true),
                    ("protofire: process 1 asked the ABI, 24 byte(s)", true),
                    ("protofire: process 1 asked the system, 64 byte(s)", true),
                    ("protofire: process 1 asked the network, 24 byte(s)", true),
                    ("protofire: virtio-net up, address ", false),
                    ("protofire: virtio-net arp reply ", false),
                    // The IPv6 side, over the same card and the same receive
                    // path: a neighbour solicitation this stack answered, the
                    // line names the address asked about and the peer's MAC it
                    // took out of the solicitation's own option, and an echo
                    // request it replied to, with the identifier and sequence
                    // the request carried.
                    //
                    // Both are loopbacks through `demux_ipv6`, which is the
                    // path a frame off the wire takes.  QEMU's user-mode
                    // network was measured and refused for this: `ipv6=on`
                    // makes slirp stop answering IPv4 ARP, so enabling it costs
                    // four working IPv4 exchanges to reach a neighbour that
                    // does not answer NDP anyway.
                    ("protofire: ipv6 neighbour answered for fe80:", false),
                    ("protofire: ipv6 echo reply to fe80:", false),
                    // And the ring-3 half: a program reads the IPv6 record and
                    // checks the link-local address against the MAC it was told
                    // about, `fe80::` plus the modified EUI-64, the one fact a
                    // program can verify without the wire.
                    ("protofire: process 1 asked the ipv6 side, 56 byte(s)", true),
                    // And the two transports over IPv6: a datagram and a
                    // stream, both to this machine's own link-local address,
                    // both through the receive path.  The lines above prove the
                    // answering paths; these prove a datagram and a segment
                    // carry over IPv6 at all, which nothing else here does.
                    (
                        "protofire: ipv6 udp received 10 byte(s) from this machine",
                        true,
                    ),
                    // And the reassembly: a datagram split the way a
                    // shrinking path splits one, put back together through the
                    // demux, and read whole.  Without it a fragment is a
                    // datagram dropped in pieces, which no line here shows.
                    ("protofire: fragments reassembled 20 byte(s), intact", true),
                    ("protofire: dhcp leased ", false),
                    ("protofire: slaac configured ", false),
                    // The other half of the same advertisement: its source is a
                    // default router, and an address off this link is asked for
                    // through it rather than sent to its own solicited-node
                    // group.
                    (
                        "protofire: ipv6 route via fe80:0000:0000:0000:5055:0aff:fe00:0202, ",
                        false,
                    ),
                    (
                        "protofire: ipv6 tcp echoed 2 byte(s) of 2, round trip",
                        true,
                    ),
                    // The cache, for the reason the x86_64 list states: the
                    // answer is kept, and the second ask reads it back.
                    ("protofire: arp cache holds ", false),
                    (
                        "protofire: arp cache answered 10.0.2.2 again without the wire",
                        true,
                    ),
                    // The ping, for the reason the x86_64 list states: the
                    // reply is a packet another machine built, matched
                    // against what the request sent.
                    ("protofire: icmp echo reply from 10.0.2.2, ", false),
                    // The datagram, for the same reason: the refusal names
                    // the port this stack sent from, out of the original
                    // datagram the error carries.
                    ("protofire: udp sent from port 40000, refused by ", false),
                    // The exchange, for the reason the x86_64 list states:
                    // the bind, the fork, the child's send, and the receive
                    // that answers it, each line naming what only a
                    // delivered datagram could have carried.
                    ("protofire: process 1 bound port 8612 as descriptor ", false),
                    (
                        "protofire: process 7 sent 9 byte(s) to 10.0.2.15 port 8612",
                        true,
                    ),
                    (
                        "protofire: process 1 received 9 byte(s) from 10.0.2.15 port 8613",
                        true,
                    ),
                    // The stream, for the reason the x86_64 list states:
                    // the exchange is loopback, and the echo's exact length
                    // is what a dropped byte could not say.
                    ("protofire: tcp connected, listener ", false),
                    ("protofire: tcp echoed 9 byte(s) of 9, round trip", true),
                    ("protofire: tcp closed, both ends held in time wait", true),
                    // The recovery: a segment the probe refuses to deliver,
                    // and the retransmission that puts it back.  The same line
                    // the other machines gate on, for the same reason: no wire
                    // this gate boots loses a frame, so this is the only one
                    // that can tell a stack with a queue from one without.
                    (
                        "protofire: tcp recovered 1 attempt(s), 12 byte(s), intact",
                        true,
                    ),
                    // A program setting and reading back the machine's name,
                    // from ring 3: the pair of calls a program can make about
                    // this machine and cannot see any other way.  The status is
                    // exact, because the call answering anything else is the
                    // one that says it was not wired.
                    ("protofire: process 1 set the machine's name, 0", true),
                    // A socket's two ends, read back by the program that owns
                    // it.  The own end is exact: the port it listened on and
                    // the address the boot's lease gave.  The peer's port is
                    // the table's to choose, so that line is a prefix.
                    ("protofire: process 1 socket is 10.0.2.15:9003", true),
                    ("protofire: process 1 peer is 10.0.2.15:", false),
                    // The reordering: a stream's two halves delivered the wrong
                    // way round, which no wire this gate boots does on its own.
                    // The held count is the cache taking the early half; the
                    // byte count is the peer's own inbox once the gap closed.
                    (
                        "protofire: tcp reordered 1 held, 19 byte(s), in order",
                        true,
                    ),
                    // The path's size: a fragmentation-needed report the probe
                    // builds, because no wire this gate boots sends one, handed
                    // to the demux a received frame goes through.  The two
                    // numbers are the stream's segment size before and after,
                    // so a stack that read the report and did nothing with it
                    // prints the same number twice.
                    (
                        "protofire: path mtu 1460 -> 536, the report reached the stream",
                        true,
                    ),
                    // The IPv6 half, and the layout difference that makes it a
                    // separate exchange: a packet-too-big report's MTU word
                    // takes the four bytes an IPv4 error leaves unused, so the
                    // quotation starts eight bytes in.
                    (
                        "protofire: path mtu6 1460 -> 1220, the report reached the stream",
                        true,
                    ),
                    // The window: a stream's buffer filled with one segment and
                    // a byte past it refused.  No exchange this gate runs
                    // carries enough bytes for a shrinking window to differ
                    // from a constant one, which is why this is its own
                    // exchange.
                    (
                        "protofire: window 8192 -> 0, and a byte past it was refused",
                        true,
                    ),
                    // The window the peer advertises: a bare acknowledgement
                    // states a full buffer, a write carries nothing, and the
                    // same write carries nine bytes once the peer reopens.
                    (
                        "protofire: peer window 8192 -> 0 -> 9, the peer's window bounded the write",
                        true,
                    ),
                    // The socket options, from ring 3.
                    ("protofire: process 1 set socket option 5 answered 0", true),
                    ("protofire: process 1 read socket option 5 answered 8", true),
                    ("protofire: process 1 set socket option 1 refused", true),
                    (
                        "protofire: options window 8192 -> 1000, congestion 14600 -> 4380, both options moved what they govern",
                        true,
                    ),
                    (
                        "protofire: local socket 5 byte(s) forward, 6 back, both ways through one name",
                        true,
                    ),
                    (
                        "protofire: raw socket sent 10 byte(s) as protocol 253, and received 10 from this machine",
                        true,
                    ),
                    (
                        "protofire: filter dropped the datagram under a rule: yes, delivered it once removed: yes, and an outbound rule kept a frame off the card: yes",
                        true,
                    ),
                    (
                        "protofire: multicast forwarded 1 frame(s), ttl 5 -> 4, payload intact",
                        true,
                    ),
                    (
                        "protofire: esp sealed 1, opened 1, the wire carried ciphertext, and the replay 0 byte(s)",
                        true,
                    ),
                    ("protofire: dccp client open, carried 4 byte(s)", true),
                    (
                        "protofire: tls handshake finished verified yes, and carried 5 byte(s) under the application keys",
                        true,
                    ),
                    (
                        "protofire: frame data 8 byte(s) sent, 8 held, the headers stayed out of the stream",
                        true,
                    ),
                    (
                        "protofire: routes 1 -> 2, and the longer prefix chose 2",
                        true,
                    ),
                    ("protofire: round trip ", false),
                    ("protofire: the estimate moved with the measurement", true),
                    (
                        "protofire: process 1 bound the local name, descriptor ",
                        false,
                    ),
                    (
                        "protofire: process 9 connected to the local name, descriptor ",
                        false,
                    ),
                    ("protofire: a local connect woke ", false),
                    (
                        "protofire: process 1 accepted a local connection as descriptor ",
                        false,
                    ),
                    // The same two options, read back where they act: a receive
                    // buffer is the window the connection advertises next, and
                    // a send buffer is the congestion window it will not
                    // exceed.
                    (
                        "protofire: options window 8192 -> 1000, congestion 14600 -> 4380, both options moved what they govern",
                        true,
                    ),
                    (
                        "protofire: local socket 5 byte(s) forward, 6 back, both ways through one name",
                        true,
                    ),
                    (
                        "protofire: raw socket sent 10 byte(s) as protocol 253, and received 10 from this machine",
                        true,
                    ),
                    (
                        "protofire: filter dropped the datagram under a rule: yes, delivered it once removed: yes, and an outbound rule kept a frame off the card: yes",
                        true,
                    ),
                    (
                        "protofire: multicast forwarded 1 frame(s), ttl 5 -> 4, payload intact",
                        true,
                    ),
                    (
                        "protofire: esp sealed 1, opened 1, the wire carried ciphertext, and the replay 0 byte(s)",
                        true,
                    ),
                    ("protofire: dccp client open, carried 4 byte(s)", true),
                    (
                        "protofire: tls handshake finished verified yes, and carried 5 byte(s) under the application keys",
                        true,
                    ),
                    (
                        "protofire: frame data 8 byte(s) sent, 8 held, the headers stayed out of the stream",
                        true,
                    ),
                    ("protofire: round trip ", false),
                    ("protofire: the estimate moved with the measurement", true),
                    (
                        "protofire: process 1 bound the local name, descriptor ",
                        false,
                    ),
                    (
                        "protofire: process 9 connected to the local name, descriptor ",
                        false,
                    ),
                    ("protofire: a local connect woke ", false),
                    (
                        "protofire: process 1 accepted a local connection as descriptor ",
                        false,
                    ),
                    // The congestion window, on an exchange long enough to see
                    // it move: ten acknowledgements grow it and a timeout
                    // collapses it.  Every other boot exchange finishes before
                    // the window matters.
                    (
                        "protofire: congestion 14600 -> 15240 -> 1460, grew and then collapsed",
                        true,
                    ),
                    // The third of the lease's three states: a broadcast
                    // request with no server named, which a server answers.  A
                    // boot never reaches it on its own because a server's
                    // default lease is a day.
                    ("protofire: rebind sent, the wire answered", true),
                    // The exchange, for the reason the x86_64 list states:
                    // the child's exit status is the echo's first byte.
                    (
                        "protofire: process 1 listening on port 9003 as descriptor ",
                        false,
                    ),
                    (
                        "protofire: process 8 connected to 10.0.2.15 port 9003 as stream ",
                        false,
                    ),
                    ("protofire: process 8 wrote 9 byte(s) to a stream", true),
                    (
                        "protofire: process 1 accepted a stream as descriptor ",
                        false,
                    ),
                    ("protofire: process 1 read 9 byte(s) from a stream", true),
                    ("protofire: process 1 wrote 9 byte(s) to a stream", true),
                    ("protofire: process 8 read 9 byte(s) from a stream", true),
                    // The stream exchange, from ring 3: the same two programs
                    // the datagram exchange used.  The listen and the accept
                    // are prefixes, the descriptor number is the table's, and
                    // the connect, the two writes and the two reads are exact:
                    // the lengths are the program's own constant, and the
                    // child's exit status is the echo's first byte, which only
                    // a completed round trip could have carried.
                    (
                        "protofire: process 1 listening on port 9003 as descriptor ",
                        false,
                    ),
                    (
                        "protofire: process 8 connected to 10.0.2.15 port 9003 as stream ",
                        false,
                    ),
                    ("protofire: process 8 wrote 9 byte(s) to a stream", true),
                    (
                        "protofire: process 1 accepted a stream as descriptor ",
                        false,
                    ),
                    ("protofire: process 1 read 9 byte(s) from a stream", true),
                    ("protofire: process 1 wrote 9 byte(s) to a stream", true),
                    ("protofire: process 8 read 9 byte(s) from a stream", true),
                    ("protofire: virtio-blk wrote and read back sector ", false),
                    // The negotiated flush bit.  Its absence was invisible
                    // until a `Fsync` took seconds and failed, so the line is
                    // what turns "the driver asked" into "the device answered".
                    ("protofire: virtio-blk negotiated flush=", false),
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
            // Both riscv64 machines, and the list is the rows **both** print.
            // What each machine's tree names is in `controller_rows`, which the
            // check walks after this one: a slice cannot be appended at compile
            // time, and a second copy of sixty rows would be two lists that
            // have to agree.
            Self::Riscv64 | Self::Riscv64Aia => &[
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
                ("protofire: timer line enabled = 1", true),
                ("protofire: timer armed at ", false),
                ("protofire: heap at ", false),
                // The heap walked by the allocator's own invariant after the
                // mount, reporting that the walk saw a carved heap.  A prefix
                // rather than the whole line, because the byte count moves with
                // the allocation sequence; the boot refuses an untouched arena
                // itself and prints a line this prefix does not match.
                ("protofire: heap checked after mount, carved ", false),
                ("protofire: block device from virtio-blk on pci", true),
                // The network card, and the ARP exchange that proves both
                // queues.  The first line is the bring-up, the second is a
                // frame leaving and the reply coming back, the only evidence
                // this tree has that the frame path runs on a machine.
                //
                // The reply's own fields are on the line, and the driver
                // returns false when they are not the answer to the question it
                // asked.  So requiring the line at all is requiring that the
                // card sent a frame, received one, and that the one it received
                // was addressed back to it.
                // The service table, and one service reached through it.  The
                // first line is the boot installing what it offers and closing
                // the table; the second is a request submitted by **name**,
                // driven through the trait, and answered with the machine's own
                // counter.  A boot that printed the first without the second
                // would have a table nothing could use.
                ("protofire: services installed = ", false),
                ("protofire: clock service answered ", false),
                // The memory calls, answered by the kernel because a program
                // cannot print a value.  `67` is `Mmap` and `92` is `Brk`; the
                // numbers are the ABI's, so the line is also a check that the
                // program's own constants reached the calls they name.
                //
                // Both addresses have to be inside the program's window, and
                // the mapping's is **not** an error code: a kernel that refused
                // the call would print an encoding whose high bit is set, and
                // the two lines would still be there.
                ("protofire: program memory call 67 answered 0x80", false),
                ("protofire: program memory call 92 answered 0x80", false),
                // The filesystem interface, exercised by the program the
                // boot execs: a file written and read back, a directory
                // made and listed, a rename and a remove, and the `*At`
                // calls resolving a relative name against a descriptor the
                // program opened.  The two `wrote` lines are exact, the
                // counts are the program's own constants, and the anchored
                // lines are prefixes because the descriptor number is the
                // table's to hand out, not the gate's to pin.
                ("protofire: process 1 wrote 19 byte(s) to a file", true),
                ("protofire: process 1 wrote 4 byte(s) to a file", true),
                (
                    "protofire: process 1 stat'd /tmp/kept.txt, kind file, size 19",
                    true,
                ),
                ("protofire: process 1 read /tmp/notes entry 0", true),
                (
                    "protofire: process 1 created directory notes via descriptor ",
                    false,
                ),
                ("protofire: process 1 stat'd at.txt via descriptor ", false),
                // The truncate, on the descriptor the program opened for
                // writing.  A prefix because the descriptor is the table's to
                // hand out; the size check beside it is the program's own, so a
                // handler that answered zero without reaching the node would
                // leave the file long and end the program at its stat.
                ("protofire: process 1 set descriptor ", false),
                // The two readings asked of a descriptor rather than a name.  A
                // prefix because neither line carries anything but the number
                // the table handed out; the record and the entry beside them
                // are the program's own comparisons, so a call that answered
                // the wrong anchor ends the program instead.
                ("protofire: process 1 stat'd descriptor ", false),
                ("protofire: process 1 listed descriptor ", false),
                // The seek, twice: from the end and backwards from where it
                // landed. A prefix because the position is the answer and the
                // number is the file's; what the program does with it, a read
                // of one byte compared against `fi`, is what turns the line
                // into evidence that the position moved rather than being
                // reported.
                ("protofire: process 1 seeked descriptor ", false),
                // The two flushes.  Their answer is zero whether the node was
                // reached or not, so the line naming which one ran is the only
                // thing this boot can say about them; whether the bytes left
                // the machine is not a fact ring 3 can observe.
                ("protofire: process 1 flushed descriptor ", false),
                (
                    "protofire: process 1 flushed the data of descriptor ",
                    false,
                ),
                // The punch and the two data-reduction flags.  The punch is
                // the refusal this boot expects, because the root is PyroFS
                // and only the NTFS volume makes holes; the flags round trip,
                // and their lines carry the word the program read back.
                (
                    "protofire: process 1 asked for the flags of descriptor ",
                    false,
                ),
                (
                    "protofire: process 1 was refused a call on descriptor ",
                    false,
                ),
                (
                    "protofire: process 1 renamed note.txt via descriptor ",
                    false,
                ),
                (
                    "protofire: process 1 removed scratch.txt via descriptor ",
                    false,
                ),
                // The process model: a program starts another program and
                // waits for it by pid, and the signal exchange between them
                // runs both ways, the child's cooperative send, the
                // parent's delivery to the child's own handler, and the
                // queued record a suspend answers.  The pids are the
                // table's, so prefixes.
                ("protofire: process 1 spawned /bin/shell as pid ", false),
                ("protofire: a wait answered status 23 for process ", false),
                (
                    "protofire: a signal wait answered signal 10 from process ",
                    false,
                ),
                (
                    "protofire: a suspend answered signal 10 from process ",
                    false,
                ),
                // The time and the information calls, reached from ring 3 and
                // answered by the registry.  Two lines each for the clock and
                // the generator because the program calls each twice, the
                // clock to check it does not go backwards, the generator to
                // check two draws differ, and one line each for the two
                // records.  The length on the line is the program's own buffer
                // size, which is a fact about the program and not about the
                // kernel.
                ("protofire: process 1 read the clock, 16 byte(s)", true),
                ("protofire: process 1 drew random bytes, 16 byte(s)", true),
                ("protofire: process 1 asked the ABI, 24 byte(s)", true),
                ("protofire: process 1 asked the system, 64 byte(s)", true),
                ("protofire: process 1 asked the network, 24 byte(s)", true),
                ("protofire: virtio-net up, address ", false),
                ("protofire: virtio-net arp reply ", false),
                // The IPv6 side, over the same card and the same receive
                // path: a neighbour solicitation this stack answered, the
                // line names the address asked about and the peer's MAC it
                // took out of the solicitation's own option, and an echo
                // request it replied to, with the identifier and sequence
                // the request carried.
                //
                // Both are loopbacks through `demux_ipv6`, which is the
                // path a frame off the wire takes.  QEMU's user-mode network
                // was measured and refused for this: `ipv6=on` makes slirp
                // stop answering IPv4 ARP, so enabling it costs four
                // working IPv4 exchanges to reach a neighbour that does not
                // answer NDP anyway.
                ("protofire: ipv6 neighbour answered for fe80:", false),
                ("protofire: ipv6 echo reply to fe80:", false),
                // And the ring-3 half: a program reads the IPv6 record and
                // checks the link-local address against the MAC it was told
                // about, `fe80::` plus the modified EUI-64, the one fact a
                // program can verify without the wire.
                ("protofire: process 1 asked the ipv6 side, 56 byte(s)", true),
                // And the two transports over IPv6: a datagram and a stream,
                // both to this machine's own link-local address, both
                // through the receive path.  The lines above prove the
                // answering paths; these prove a datagram and a segment
                // carry over IPv6 at all, which nothing else here does.
                (
                    "protofire: ipv6 udp received 10 byte(s) from this machine",
                    true,
                ),
                // And the reassembly: a datagram split the way a shrinking
                // path splits one, put back together through the demux, and
                // read whole.  Without it a fragment is a datagram dropped in
                // pieces, which no line here shows.
                ("protofire: fragments reassembled 20 byte(s), intact", true),
                // What a server says this machine is, and an address a
                // router's prefix configured for itself.  Two protocols, and
                // neither restates the other: DHCP asks a server, stateless
                // configuration only listens to a router.
                //
                // The name lookup is deliberately not required here: it needs
                // a network with a resolver behind it, and a gate that fails
                // because CI has no internet is a gate nobody can fix.
                ("protofire: dhcp leased ", false),
                ("protofire: slaac configured ", false),
                // The other half of the same advertisement: its source is a
                // default router, and an address off this link is asked for
                // through it rather than sent to its own solicited-node group.
                (
                    "protofire: ipv6 route via fe80:0000:0000:0000:5055:0aff:fe00:0202, ",
                    false,
                ),
                (
                    "protofire: ipv6 tcp echoed 2 byte(s) of 2, round trip",
                    true,
                ),
                // The cache, for the reason the x86_64 list states: the
                // answer is kept, and the second ask reads it back.
                ("protofire: arp cache holds ", false),
                (
                    "protofire: arp cache answered 10.0.2.2 again without the wire",
                    true,
                ),
                // The ping: the echo reply is a packet QEMU's user-mode
                // network built, matched against the identifier, sequence and
                // data the request sent, the round trip IPv4 can carry, on
                // every machine this gate boots.
                ("protofire: icmp echo reply from 10.0.2.2, ", false),
                // The datagram: one UDP send to a port nothing owns, and
                // the port-unreachable refusal that comes back carrying the
                // original, the peer's proof that a datagram this stack
                // built arrived with its header intact.
                ("protofire: udp sent from port 40000, refused by ", false),
                // The datagram exchange, from ring 3: a bind, a fork, the
                // child's send, and the receive that answers it.  The send's
                // and receive's lines are exact, the lengths are the
                // program's own constant and the sender record is what the
                // kernel filled, and the bind is a prefix because the
                // descriptor number is the table's to hand out.
                ("protofire: process 1 bound port 8612 as descriptor ", false),
                (
                    "protofire: process 7 sent 9 byte(s) to 10.0.2.15 port 8612",
                    true,
                ),
                (
                    "protofire: process 1 received 9 byte(s) from 10.0.2.15 port 8613",
                    true,
                ),
                // The stream: a listener, a client, an echo, and the close
                // that ends both ends, on loopback, the whole of a TCP
                // exchange, run by the boot on every machine this gate
                // boots.  The ids are the table's, so the connect line is a
                // prefix; the echo's length beside the send's is exact,
                // because a round trip that dropped a byte could not say 9.
                ("protofire: tcp connected, listener ", false),
                ("protofire: tcp echoed 9 byte(s) of 9, round trip", true),
                ("protofire: tcp closed, both ends held in time wait", true),
                // The recovery: a segment the probe refuses to deliver, and
                // the retransmission that puts it back.  No wire this gate
                // boots loses a frame, so this is the only line that can tell
                // a stack with a queue from one without: the attempt count is
                // the schedule's, and the byte count is the peer's own inbox
                // after the copy that was lost arrived again.
                (
                    "protofire: tcp recovered 1 attempt(s), 12 byte(s), intact",
                    true,
                ),
                // A program setting and reading back the machine's name, from
                // ring 3: the pair of calls a program can make about this
                // machine and cannot see any other way.  The status is exact,
                // because the call answering anything else is the one that says
                // it was not wired.
                ("protofire: process 1 set the machine's name, 0", true),
                // A socket's two ends, read back by the program that owns it.
                // The own end is exact: the port it listened on and the address
                // the boot's lease gave.  The peer's port is the table's to
                // choose, so that line is a prefix.
                ("protofire: process 1 socket is 10.0.2.15:9003", true),
                ("protofire: process 1 peer is 10.0.2.15:", false),
                // The reordering: a stream's two halves delivered the wrong way
                // round, which no wire this gate boots does on its own.  The
                // held count is the cache taking the early half; the byte count
                // is the peer's own inbox once the gap closed.
                (
                    "protofire: tcp reordered 1 held, 19 byte(s), in order",
                    true,
                ),
                // The path's size: a fragmentation-needed report the probe
                // builds, because no wire this gate boots sends one, handed to
                // the demux a received frame goes through.  The two numbers are
                // the stream's segment size before and after, so a stack that
                // read the report and did nothing with it prints the same
                // number twice.
                (
                    "protofire: path mtu 1460 -> 536, the report reached the stream",
                    true,
                ),
                // The IPv6 half, and the layout difference that makes it a
                // separate exchange: a packet-too-big report's MTU word takes
                // the four bytes an IPv4 error leaves unused, so the quotation
                // starts eight bytes in.
                (
                    "protofire: path mtu6 1460 -> 1220, the report reached the stream",
                    true,
                ),
                // The window: a stream's buffer filled with one segment and a
                // byte past it refused.  No exchange this gate runs carries
                // enough bytes for a shrinking window to differ from a constant
                // one, which is why this is its own exchange.
                (
                    "protofire: window 8192 -> 0, and a byte past it was refused",
                    true,
                ),
                // The window the peer advertises: a bare acknowledgement
                // states a full buffer, a write carries nothing, and the same
                // write carries nine bytes once the peer reopens.  A sender
                // that parsed the field and ignored it would print the same
                // number three times.
                (
                    "protofire: peer window 8192 -> 0 -> 9, the peer's window bounded the write",
                    true,
                ),
                // The socket options, from ring 3: a number set, the same
                // number read back at its own width, and an option this
                // stack does not serve refused.  The width is the word a size
                // is, and the refusal is what stops a program believing it
                // set something the kernel has no implementation of.
                ("protofire: process 1 set socket option 5 answered 0", true),
                ("protofire: process 1 read socket option 5 answered 8", true),
                ("protofire: process 1 set socket option 1 refused", true),
                // The same two options, read back where they act: a receive
                // buffer is the window the connection advertises next, and a
                // send buffer is the congestion window it will not exceed.
                (
                    "protofire: options window 8192 -> 1000, congestion 14600 -> 4380, both options moved what they govern",
                    true,
                ),
                // The local-domain socket, in the kernel's own exchange: a
                // name bound, connected to, accepted, and bytes both ways.  A
                // one-pipe connection would answer one direction and print
                // zero for the other.
                (
                    "protofire: local socket 5 byte(s) forward, 6 back, both ways through one name",
                    true,
                ),
                // The raw socket, in the kernel's own exchange: a protocol
                // number instead of a port, and a packet this machine sends
                // itself, composed by the stack and parsed back out of the
                // frame it built.  The source address on what it receives is
                // what says the header was not the caller's.
                (
                    "protofire: raw socket sent 10 byte(s) as protocol 253, and received 10 from this machine",
                    true,
                ),
                // The packet filter: a rule installed, the datagram it names
                // **not delivered**, and the same datagram delivered once the
                // rule is removed.  Both halves are required, because a filter
                // that always drops and one that never does each pass one of
                // them, and a filter whose rules nothing consults passes
                // neither while its four calls report success.
                (
                    "protofire: filter dropped the datagram under a rule: yes, delivered it once removed: yes, and an outbound rule kept a frame off the card: yes",
                    true,
                ),
                // Multicast forwarding, in the kernel's own exchange: a frame
                // through the demux, an entry naming it, and what the card was
                // told.  The three numbers are the arriving hop count, what
                // the copy left with, and whether the payload is the
                // sender's, because a forwarding path is broken three ways and
                // each looks right through a different window.
                (
                    "protofire: multicast forwarded 1 frame(s), ttl 5 -> 4, payload intact",
                    true,
                ),
                // IPsec's ESP, in one exchange: the wire carried ciphertext,
                // the demux recovered the bytes, and a repeat of the same frame
                // did not arrive twice.  A protocol number with the plaintext
                // still inside passes a counter and not this.
                (
                    "protofire: esp sealed 1, opened 1, the wire carried ciphertext, and the replay 0 byte(s)",
                    true,
                ),
                // DCCP's whole connection, driven through the function the
                // demux calls: a Request, a Response, the client opening, and
                // the first datagram arriving on the server.  A state machine
                // that stored no states passes none of it.
                ("protofire: dccp client open, carried 4 byte(s)", true),
                (
                    "protofire: tls handshake finished verified yes, and carried 5 byte(s) under the application keys",
                    true,
                ),
                // The frame path's data offset: two TCP segments through the
                // demux, one carrying an option and one not, and a stream
                // holding their data and neither header.  Every other exchange
                // runs on the loopback, which hands a connection the payload
                // it built and never a frame, so this is the only line that
                // can tell a demux which slices the segment from one that
                // passes the packet.
                (
                    "protofire: frame data 8 byte(s) sent, 8 held, the headers stayed out of the stream",
                    true,
                ),
                // The timeout, measured: two exchanges, the second later than
                // the first, and an estimate that moved.  The numbers are the
                // machine's clock and change every boot, so the line is
                // required by its **second** line, which is the verdict and
                // not a number.
                ("protofire: round trip ", false),
                ("protofire: the estimate moved with the measurement", true),
                // And the same exchange between two ring-3 processes, which is
                // the claim a probe cannot make: a bind, a connect, an accept,
                // and a read and a write each way.
                //
                // The three lines required are the ones that do not depend on
                // an interleaving.  Whether a read parks or finds its bytes
                // already there is the scheduler's choice, and requiring
                // `a program blocks on a local socket` made this gate fail on a
                // boot where the child's write landed first: the exit statuses
                // were identical, so nothing was broken.  The park and its wake
                // are still printed and still read by a human; they are not a
                // gate line, because a gate that depends on a race is a gate
                // that fails for the wrong reason.
                (
                    "protofire: process 1 bound the local name, descriptor ",
                    false,
                ),
                (
                    "protofire: process 9 connected to the local name, descriptor ",
                    false,
                ),
                // The wake the connect makes.  Its count is zero when the
                // accept had not parked yet, so it is a prefix: what the line
                // proves is that the call answered a descriptor and woke
                // whatever was waiting.
                ("protofire: a local connect woke ", false),
                (
                    "protofire: process 1 accepted a local connection as descriptor ",
                    false,
                ),
                // The congestion window, on an exchange long enough to see it
                // move: ten acknowledgements grow it and a timeout collapses
                // it.  Every other boot exchange finishes before the window
                // matters.
                (
                    "protofire: congestion 14600 -> 15240 -> 1460, grew and then collapsed",
                    true,
                ),
                // The third of the lease's three states: a broadcast request
                // with no server named, which a server answers.  A boot never
                // reaches it on its own because a server's default lease is a
                // day.
                ("protofire: rebind sent, the wire answered", true),
                // The stream exchange, from ring 3: the same two programs
                // the datagram exchange used.  The listen and the accept
                // are prefixes, the descriptor number is the table's, and
                // the connect, the two writes and the two reads are exact:
                // the lengths are the program's own constant, and the
                // child's exit status is the echo's first byte, which only
                // a completed round trip could have carried.
                (
                    "protofire: process 1 listening on port 9003 as descriptor ",
                    false,
                ),
                (
                    "protofire: process 8 connected to 10.0.2.15 port 9003 as stream ",
                    false,
                ),
                ("protofire: process 8 wrote 9 byte(s) to a stream", true),
                (
                    "protofire: process 1 accepted a stream as descriptor ",
                    false,
                ),
                ("protofire: process 1 read 9 byte(s) from a stream", true),
                ("protofire: process 1 wrote 9 byte(s) to a stream", true),
                ("protofire: process 8 read 9 byte(s) from a stream", true),
                ("protofire: virtio-blk wrote and read back sector ", false),
                // The negotiated flush bit.  Its absence was invisible until a
                // `Fsync` took seconds and failed, so the line is what turns
                // "the driver asked" into "the device answered".
                ("protofire: virtio-blk negotiated flush=", false),
                // The completion-message report, which every machine prints
                // and whose **number is the machine's**: a tree that names no
                // IMSIC takes none, because no device can send it a message,
                // and the boot says `= 0`.  What the line holds still is that
                // the census ran and that the count is a number rather than
                // absent, the AIA machine's own boot is where a non-zero
                // count is evidence, and no gate machine has an IMSIC yet.
                ("protofire: block completion message(s) taken = ", false),
                // The card's own count, on its own identity.  Every machine
                // prints it; the AIA machine is where a non-zero number is
                // evidence, and it is a separate line from the block device's
                // so that one device's delivery cannot stand in for the
                // other's.
                ("protofire: network message(s) taken = ", false),
                (
                    "protofire: namespace: pyrofs on / (protofire), tmpfs on /tmp (memory), iso9660 on /cdrom (bootdisc)",
                    true,
                ),
                (
                    "protofire: /cdrom/README.TXT reads back from the disc",
                    true,
                ),
                ("protofire: syscall table installed, ", false),
                ("protofire: time origin ", false),
                ("protofire: random seeded, two reads differ", true),
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
                // The pipe's reader waited for a process to end, and the
                // kernel answered, the same claim the other machines carry,
                // and the line rather than an exit status because
                // `WaitProcess` names no particular child.
                ("protofire: a wait answered status ", false),
                ("protofire: process 2 released ", false),
                // The program answered its own fault, as on aarch64: the
                // reader installs a handler, stores into its own read-execute
                // code page, and the kernel resumes it at the handler instead
                // of killing it.  `vector 15` is this machine's store page
                // fault, which is the access the program made on purpose.
                ("protofire: process 3 installed a fault handler at ", false),
                ("protofire: process 3 handled its own fault at ", false),
                // The child inherited its parent's descriptors: the announcing
                // program makes a pipe before it forks, and both ends are
                // copied to the child, owned by it.  Without the copy the child
                // would find every inherited number refused, because the table
                // checks the owner.
                ("protofire: forked process 4 inherited ", false),
                // The program took a fault **it answered itself**: the
                // reader installs a handler, stores into its own code
                // page (a write no resolver answers), and the kernel
                // resumes it at the handler instead of killing it.  The
                // `program 64 says hello` line below is the handler's own
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
                // are pid 1 and image 4, so the line is required whole.  The
                // opened line under it is the identity claim: the kernel names
                // the process that opened the boot's file, read from the
                // scheduler's own record.
                // The loader's own line, required as a prefix: the segment
                // count and the entry are the compiled image's facts, and the
                // line is what separates "the loader ran" from "a program ran".
                ("protofire: loaded /bin/init, ", false),
                ("protofire: process 1 exec'd /bin/init", true),
                ("protofire: process 1 opened /greeting.txt", true),
                // The child's death, as the kernel reports it: which process,
                // the address its write named, and the status the pair reads.
                // A prefix, because the address is the program's own code page
                // and the vector is the machine's answer.
                ("protofire: process 4 died from a fault at ", false),
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
                    "protofire: address spaces reaped 9, 16384 frame(s) free",
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
                // The placement rule's preferred half: a switch put a task back
                // on the CPU it last ran on.  Required because a rule that
                // never preferred anything still printed the migration line
                // above, the two numbers are what a reader compares, and a
                // boot whose home count was zero moved every task it placed.
                ("protofire: task placings home ", false),
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
    // The shared rows, then the ones this machine's own tree produces.  Both
    // are required, and neither is a fallback for the other.
    let all_required = required
        .iter()
        .chain(machine.controller_rows().iter())
        .copied()
        .collect::<Vec<_>>();
    // Counted before the loop consumes the list, and it is the whole list: a
    // report that named only the shared rows would print the same number for
    // two machines with different expectations, which is how a missing tail
    // would go unnoticed.
    let required_count = all_required.len();
    for (expected, exact) in all_required {
        let outcome = if exact {
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

    // Text that must not be there at all.
    for forbidden in machine.absent_lines().iter().copied() {
        if log.contains(forbidden) {
            let mut message = String::new();
            writeln!(
                message,
                "check failed: the log contains {forbidden:?}, which it must not",
            )?;
            for line in log.lines().filter(|line| line.contains(forbidden)) {
                writeln!(message, "    {line}")?;
            }
            bail!("{message}");
        }
    }

    // Lines that have to carry a count above zero.
    //
    // Required-lines can say "this line exists", and `= 0` satisfies it.  This
    // is the question a mechanism needs answered: did the thing happen.
    for prefix in machine.nonzero_lines().iter().copied() {
        let seen = log
            .lines()
            .map(|line| line.trim_end_matches('\r'))
            .find_map(|line| line.strip_prefix(prefix))
            .and_then(|tail| tail.split_whitespace().next())
            .and_then(|number| number.parse::<usize>().ok());
        match seen {
            Some(count) if count > 0 => {}
            _ => {
                let mut message = String::new();
                writeln!(
                    message,
                    "check failed: no line starting with {prefix:?} carries a count above zero",
                )?;
                for line in log.lines() {
                    writeln!(message, "    {line}")?;
                }
                bail!("{message}");
            }
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
        "check passed: {} ({}) printed {} required line(s) and reached its heap",
        machine.label(),
        machine.triple(),
        required_count
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

#[cfg(test)]
mod tests {
    //! The tests for this file.
    //!
    //! The matchers' tests: an absent line, a varying tail, and a prefix that
    //! has to be at the start.
    //!
    //! These are why this tool is Rust.  In a shell the failure path of a gate
    //! is the one nobody runs; here it is a function call.

    use crate::gate::expect_line;
    use crate::gate::expect_line_prefix;

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
