# What has moved in, and what has not

This tree replaces a single crate of 312,000 lines.  The migration is not a
rewrite and not a copy: each subsystem moves in as a crate of its own, with its
tests, once it can be built and exercised on its own.  This document is the
count.

**The number that matters: about 18% of the previous tree is here.**  What is
here is the part that proves the architecture — a boot, a heap, a bus, a driver,
a filesystem and a syscall — and the rest is being moved a crate at a time.

## The table

| Subsystem | Previous tree | Here | What is in |
|---|---:|---:|---|
| `abi` | 4,725 | 3,479 | the whole wire format, and the syscall numbering |
| `arch` | 95,361 | 9,493 | boot, interrupts, serial, port I/O, page tables, the exception path, IDT, the 8259, the PL011, the device-tree handshake, the GIC — ten of a hundred |
| `crypto` | 4,606 | 4,850 | all of it, one module per algorithm — counted under `libs` below |
| `fs` | 68,494 | 14,683 | PyroFS, tmpfs, ISO 9660, the mount table and the VFS contract; eight filesystems are not here |
| `kernel` | 39,704 | 1,536 | the boot sequence, the syscall table, device discovery |
| `memory` | 9,649 | 1,865 | the frame pool and the region pools |
| `network` | 39,240 | 1 | nothing |
| `drivers` | 18,828 | 5,422 | PCI (ports, ECAM, BAR enumeration, MSI-X), and virtio block |
| `syscall` | 15,647 | 253 | the context, the validators, three handlers |
| `user` | 19,145 | — | nothing; `apps/` holds three skeletons |
| `libs` | — | 16,291 | allocator, audit, cell, crypto, fdt, irq, paging, profiler, rights, sync, unicode |
| **total** | **312,131** | **~56,500** | |

The `libs` crates have no previous-tree column because most of them were modules
under `src/kernel/` or `src/memory/` there; their lines are counted in those
rows.

## Filesystems

`fs` is the largest subsystem and one of its thirteen filesystems is here.

| Filesystem | Lines | Here |
|---|---:|---|
| NTFS | 14,643 | no |
| PyroFS | 7,260 | **yes** |
| ISO 9660 | 5,928 | **yes**, read-only — rewritten, not moved |
| ext4 | 3,436 | no |
| F2FS | 3,285 | no |
| FAT32 | 2,732 | no |
| exFAT | 2,345 | no |
| btrfs | 2,108 | no |
| squashfs | 1,849 | no |
| the VFS layer | 1,723 | contract only — see below |
| tmpfs | 1,072 | **yes** |
| FUSE | 876 | no |

**The VFS row has moved.**  `fs/src/vnode.rs` and `fs/src/filesystem.rs` carry
the *contract* — what a node is, what a filesystem answers — and the namespace
is now `fs/src/mount.rs` and `fs/src/path.rs`: a mount table, longest-prefix
resolution, and path normalization.  What is still not here is the *handle
table*, which arrives with the process layer because a handle belongs to a
process.

Three filesystems are mounted on a boot: PyroFS at `/`, tmpfs at `/tmp` and an
ISO 9660 disc at `/cdrom`.  The second is what proved the namespace — a table
with one entry has never resolved anything — and the third is what proved it
goes both ways, because a disc cannot be written and so what comes out of it
came from the image.

**ISO 9660 was rewritten rather than moved**, and that is the pattern for the
rest: the previous tree's 5,928 lines are 1,105 of a reader and 800 of a
*writer* — a writer for a writable ISO image, which was a requirement of that
kernel rather than of the format.  The rewrite is the reader, at 1,700 lines,
with the field offsets named and tested instead of being a packed struct cast
from a sector.  See [`fs/src/iso9660/mod.rs`](../fs/src/iso9660/mod.rs).

The order the rest come in is by what they prove rather than by size: the FAT
family next (shared structure, three formats), then the read-only formats, then
NTFS and ext4, which are where a mistake costs data.

## Network

Nothing.  `net` is a one-line crate so the layer exists and the boundary is
declared before there is code to put behind it.

The previous tree's network subsystem is 39,240 lines: TCP, TLS, SCTP, DCCP,
IPsec, WireGuard, DNS, mDNS, DHCP, NTP, PPP/PPPoE, multicast routing, a packet
filter and raw sockets.  The order it comes in is bottom-up — link, then
internet, then the transports — because each layer's tests need the one below it.

## Architecture

Eight modules out of a hundred, on each machine.  The previous tree's `arch` is
95,361 lines across `x86_64` (49 files), `aarch64` (25) and `riscv64` (22), plus
`pci`, `fdt`, `trap`, `mmu`, `percpu`, `smp`, `thread`, `user_access`,
`syscall_trap`, `ptrace` and more.

What is here is what a boot needs before anything else: the entry, the console,
the interrupt flag, the page-table encoding, the exception path, and — on
x86_64 — the port I/O the PCI bus is reached through.  What comes next is the
last hop of an MSI: the encoding is here and the frame is here, and a write to
the frame does not raise an interrupt on QEMU's `virt`.  That is an open
question, and it is written down rather than papered over.

### MSI-X: the encoding, and the hop that does not arrive

`drivers/bus/pci/src/msix.rs` is the MSI-X capability and table: the three
structures, the entry layout, and the two bits in message control that are
different — 15 enables the feature and 14 says the function must not fall back
to its INTx pin.  An entry's mask bit is set-means-masked, the opposite of every
other enable bit in PCI.  The table size register holds the count *minus one*.

Five defects were fixed while writing it, and four were in the test fake:

- The message control register is the **high half** of the dword at the
  capability's offset; its low half is `cap_id` and `cap_next`, which are
  read-only.  Writing the control into the low half corrupts the capability id
  and leaves the enable bit where the device is not looking.
- The table size register was read as a count rather than a count minus one.
- The fake's register file was too small for offset `0x98`.
- The fake wrote `1` into the size field to mean "one entry", which is two.

`arch/aarch64/src/gicv2m.rs` is the frame: `MSI_TYPER` holds two ten-bit fields
— the first interrupt and the count — and `MSI_SET_SPI` is an array where the
**address** selects which interrupt a write raises, not the payload.  The boot
reads `MSI_TYPER` and reports what it found: `msi frame raises 80 interrupt(s)
from 64`, which is `0x0050_0040` decoded and not assumed.

**A write to `MSI_SET_SPI` does not raise an interrupt on this machine.**
Reading `MSI_TYPER` works, so the window is mapped and readable.  Writing it
leaves `GICD_ISPENDR` at zero — the frame produces nothing, so this is not a
delivery problem.  Three candidate interrupt numbers were enabled (the frame's
own report of 64, and 48 and 80 from QEMU's `base-spi`/`num-spi` device
properties, which disagree with `MSI_TYPER`), and none arrived.  Writing the
same address from QEMU's monitor does not raise one either.

So the boot test was removed rather than left passing vacuously, and the two
crates stay: they are arithmetic over a specification, and the
specification-shaped half is tested.  What is not known is why QEMU's frame does
not act on the write, and the next step is to find that out rather than to build
a driver on top of it.

### The interrupt controller, and the probe that could not fail

An aarch64 boot now takes an interrupt:

```
protofire: interrupt table installed, interrupts on
protofire: interrupt delivered to its handler
```

`arch/aarch64/src/gic.rs` is the GICv2 register layer: the distributor decides
which lines exist and which CPU they go to, the CPU interface is what this core
acknowledges and finishes through, and the two are different windows.  The
arithmetic is the specification's, and the two arrays a driver must reach do not
share a divisor — `ISENABLER` holds 32 interrupts per register and `IPRIORITYR`
holds **four** — so a driver that used 32 for both enables the right line and
sets the priority of a different one.

The dispatcher now tells an IRQ from a fault: the vector is `(group * 4) +
kind`, so `vector % 4 == 1` is an IRQ whatever its group, and that path
acknowledges, hands the number to the sink, and finishes.  Returning without the
finish leaves the line active and the machine taking exactly one interrupt —
which is why the finish is not on the handler's honour.

**The probe could not fail, and that is the defect worth recording.**  The boot
raises an interrupt from the controller and a handler counts it.  The first
version raised interrupt **zero** and initialised its counter to **zero**, so a
boot that raised nothing printed exactly what a boot that raised something
printed.  Deleting the write that raises it changed no output at all.  The
counter now starts at `usize::MAX`, and deleting the write prints
`raised but not delivered`.

Two things were learned from the controller's own behaviour while doing this:

- **`GICD_SGIR` raises only interrupts 0..16.**  It has no field for a device
  line, because a device raises its own.  The first version asked it for
  interrupt 40, wrote an SGI id the distributor did not route, and then had to
  reconcile "the path works" — an unclaimed PPI arrived on its own and was
  reported — with "my interrupt never came".  The path an SGI takes is the same
  one a device's takes, so it is the right instrument and the only one.

- **A PCIe `interrupt-map` did not resolve, and was left out rather than
  guessed at.**  The entries are `key + phandle + parent specifier`, and QEMU's
  `virt` writes a parent specifier wider than the GIC's declared
  `#interrupt-cells` — five cells against three.  A parser that assumed three
  read the next entry's key as part of the controller's number.  Rather than
  ship a table that resolved one pin out of four, the function was removed; the
  number a PCI function raises is still an open question, and the answer is the
  one the map states.

### PCI enumeration, and the six defects that were hiding behind "not mapped"

QEMU's `virt` has a PCIe host bridge and no firmware, so every BAR comes up
unaddressed.  Reading a capability was possible after the device tree arrived;
reaching the device behind it needed the assignment pass a firmware would have
run — size each BAR, allocate from the bridge's `ranges` window, write it back,
verify.

The aarch64 boot now writes a sector and reads it back:

```
protofire: pci bars assigned 4, kept 0, no room 0, refused 0
protofire: block device from virtio-blk on pci
protofire: virtio-blk wrote and read back sector 63
```

Six things were wrong, and only one of them was the feature:

1. **`bar::size` treated a zero register as "no BAR".**  An unaddressed BAR
   reads zero.  On a machine with firmware that is unusual; on a device-tree
   machine it is the *normal* state, so the early return turned every device
   into no device.  The current value cannot answer whether a BAR exists — only
   the device can, and the way to ask is a sizing write.

2. **The 32-bit mask was not widened.**  A 32-bit BAR's mask came out as
   `0x0000_0000_FFFF_F000`, whose complement plus one is
   `0xFFFF_FFFF_0000_1000` — not a power of two, so every 32-bit BAR sized as
   absent.  The mechanism's answer is a 64-bit mask whatever the BAR's width.

3. **The type bits were read from the register, not the mask.**  Those bits are
   wires: they survive a sizing write and do not survive an address write.  A
   decoder that used the current value called every unassigned 64-bit BAR 32-bit
   and tried to place it below four gigabytes.

4. **Nothing above four gigabytes was mappable.**  The identity map stopped
   there, so a PCIe ECAM window at `0x40_1000_0000` had nowhere to go.
   `map_region` now creates a 2 MiB block table for a region above the limit.

5. **A mapping was made and the TLB was not told.**  `flush_translation` is now
   part of `map_region`, and each machine spells it: `tlbi vmalle1` on aarch64,
   a `cr3` rewrite on x86_64, `sfence.vma` on riscv64.

6. **The transport was built on a `PortConfig` while the scan ran over ECAM.**
   A port that does not exist answers `0xFFFF_FFFF`, so the capability walk
   visited forty-eight structures whose type was `0xFF` and reported the device
   as having no `Common` capability.  The scan and the transport must agree
   about the mechanism, and now they are handed the same one.

The sixth is the one worth keeping: it was introduced by *this* change, in the
same function that added the mechanism choice.  A diagnostic line — `the walk
saw 48 structure(s), types 255 255 …` — is what named it, and that line is now
part of the error rather than a probe.

Two smaller things fell out.  `Device::bars` returns **slots**, and a PCI
capability's `bar` field counts **registers**; a 64-bit BAR occupies one slot
and two register numbers, so indexing the slot array with a register number
reaches the wrong window.  `Device::bar_register` is the lookup that matches.
And a capability's `bar` field is at `+4`, `offset` at `+8`, `length` at `+12` —
the previous version read them one dword too far.

### The device tree, and the four bugs it exposed

`libs/fdt` is the format — header, structure block, strings block, and the walks
over them — and `arch/aarch64` is what records the pointer firmware left in
`x0`.  The split is the tree's own rule: a format is not a machine, and the same
bytes are read by a host test that has neither.

Parsing it turned four things from constants into questions, and each question
found a defect:

1. **The console's address.**  `serial` now asks the tree for
   `arm,pl011` and falls back to `0x0900_0000` for a boot whose blob did not
   parse.  The boot line says which path ran, which is how the two states are
   told apart in a log.

2. **The device windows.**  `paging::device_windows` was a constant range.  It
   now asks the tree where **memory** is and treats everything else as a
   device — the complement, not a list, because a list has to grow before the
   device it is missing can work and its failure is an intermittently stale
   register read.

3. **The PCIe ECAM window.**  `pci::EcamConfig` is a second `ConfigSpace`: the
   port mechanism is x86_64's and a device-tree machine has a memory window
   instead.  Everything above — enumeration, capability walks, BAR decoding —
   is unchanged, which is what the trait was for.

4. **`TCR_EL1.IPS`.**  `ips_for_parange` mapped `PARange` to `IPS` as if the two
   registers numbered sizes differently.  They do not: the encoding is the
   identity.  A machine reporting 40 bits was programmed with 36, and the first
   access to a PCIe ECAM window at `0x40_1000_0000` — 275 GiB — faulted with
   `DFSC = 0b000010`, *address size fault, level 2*.  The test that had been
   asserting the wrong mapping is now the table a reader can check.

Five more defects fell out of making the machine reach further, and none of them
was the device tree's:

- **`all_compatible` used a fixed stack of 32.** QEMU's tree has 51 children
  under its root, so it found 28 of the 32 `virtio,mmio` transports and every
  fixture-based test passed.  The walk is a cursor over the structure block now,
  which is the order the format already stores, with a depth stack only for the
  cell widths.
- **A node's `#address-cells` governs its children, not itself.**  Its own `reg`
  is decoded with its parent's.  The first version got this backwards and read
  the PCIe bridge's `reg` as three cells: `0x0040_1000_0000_0000`, a number, so
  nothing failed.
- **Capability structures were read one dword too far.**  `bar` is at `+4`,
  `offset` at `+8`, `length` at `+12`; the first version read them from `+4`,
  `+8` and `+12` as if `bar` were a dword of its own.
- **`(word >> (shift + 8))` overflowed at `shift = 24`**, which panicked the boot
  on a capability structure at offset `0x1C`.
- **A panic printed nothing.**  `bootloader`'s handler called `arch::halt()` and
  stopped.  A boot that ended mid-log looked identical to one that finished, and
  this cost a session: the shift-overflow panic above happened after the scan
  line with no message at all.  The handler now prints.

`qemu-virt.dtb` in the parser's test assets is firmware's own bytes, not `dtc`'s
rendering of a source file — a generator and a parser written from one reading
of a specification agree with each other, and only firmware disagrees when that
reading is wrong.  It is what caught the stack bound.

### Translation is on, and how it was found not to be

Until this change `arch_aarch64::paging::install` wrote `MAIR_EL1` and
`TTBR0_EL1` and returned `true`, and the boot printed "page table built and
installed, 4 KiB granule" about a table no access went through: `SCTLR_EL1.M`
was never set.  That is the defect this file keeps recording — written, wired,
never executed — and it was found by reading the function rather than by a
gate, because the line it printed was true about the register and false about
the machine.

Turning translation on took three fixes, and each was found by QEMU's exception
log rather than by reasoning:

1. **The table descriptors carried leaf fields.**  `encode_at` set `AF`, `AP`,
   the attribute index and `UXN`/`PXN` on every descriptor; the architecture
   calls those bits Ignored in a table descriptor.  Invisible while nothing read
   a descriptor.  A table descriptor is now its address and its type.
2. **`EntryEncoding::encode` had no level.**  aarch64 writes a 4 KiB page
   descriptor and a 1 GiB block descriptor with different low bits, so the
   implementation hard-coded `Level::Third` — and the kernel builds four
   levels, so every page became a block.  The trait takes a level in both
   directions now, and the other two machines accept and ignore it with the
   reason written down.
3. **`TCR_EL1.T0SZ` was 25.**  That is a 39-bit space, which is a three-level
   table; this kernel's root is a level 0 table and needs 16 (48 bits).  With
   25, the machine indexed `TTBR0_EL1` as a level 1 table, never read entry 0,
   and the first fetch faulted with `DFSC = 0b000101`,
   *translation fault, level 1* — the log line that named the constant.

The aarch64 boot now prints the same nine lines with the MMU on.  Setting
`TCR_T0SZ` back to 25 stops it after `protofire: page table`, so those lines are
evidence that translation is in use rather than a coincidence.  A test,
`the_address_size_matches_the_table_depth`, derives the required value from
`Level::Root::shift()` instead of restating it.

### Device windows

Turning the MMU on changes what an unruled address *means*.  With translation
off every access is device-like; with it on, an address with no rule is Normal
memory — cached and prefetchable — and the PL011's status register read from a
stale cache line is a console that prints nothing for a reason that looks like a
dead UART.

`arch::paging::device_windows()` is the machine's answer: aarch64 returns
`0x0000_0000..0x4000_0000` — everything below `virt`'s RAM — and x86_64 returns
an empty slice, because it learns its device addresses from a bus and re-maps
them one BAR at a time.  `kernel::address_space` turns that answer into a
permission, which is the division the tree already has: `arch` says what the
machine is, the kernel says what to do about it.

The aarch64 range is a constant of `qemu-system-aarch64 -machine virt`.  It is
the honest form of "this is the machine the boot gates run on", and the parse of
the device tree is what turns it into a query.

### The aarch64 boot, and what it cost

`entry.S` does four things before Rust: a stack, the bss clear, the drop from
EL2 to EL1, and `CPACR_EL1.FPEN`.  The last one is there because the boot that
did not do it **printed four lines and stopped**, and the reason took a QEMU
exception log to find: `ESR_EL1.EC` = 7 at a `0x0E01...` word, which is a NEON
instruction LLVM emitted for the `memcpy` inside `PyroFS::build_image`.  Every
line before that was scalar code, which is why the failure looked like a
filesystem problem.

The lesson is the one this file keeps recording: a machine's boot is exercised
or it is not, and building an image is not exercising it.  `scripts/verify.sh`
now boots **every** machine with an image, so the next boot that stops early is
a red gate rather than a line someone happened to notice.

The trap path is real: `entry.S` saves `x0`..`x30`, `ELR_EL1`, `SPSR_EL1`,
`ESR_EL1`, `FAR_EL1` and `q0`..`q31` into an 800-byte frame, calls
`aarch64_exception_dispatch`, and `eret`s.  `install_interrupt_table` does not
report success from writing `VBAR_EL1` — it raises a supervisor call first and
answers `true` only if the call arrived at entry 4 and returned.  A probe that
cannot fail is not evidence, so the probe was mutated (the expected vector
changed to 8) and the boot line went back to "not installed".


## Kernel

The boot sequence, the syscall table and device discovery.  Not here:

| Module | Lines | Why it is not here yet |
|---|---:|---|
| the scheduler | — | nothing to schedule; a process layer needs address spaces |
| the process layer | — | the same |
| the network stack | — | see above |
| audit, security policy, service manager, procfs, shm | — | each arrives with the subsystem it observes |

The previous tree's `kernel` is 39,704 lines.  Most of it is the process layer
and the scheduler, and they are the last to arrive because every other subsystem
has to have somewhere to put a per-process value before a process is worth
having.

## `user` and `apps`

The previous tree's `src/user/` is 19,145 lines: a user-space runtime, syscall
wrappers, a demo renderer, the shell's commands and the programs themselves.

`apps/` holds `init`, `shell` and `service_manager` as skeletons — each has the
shape a program must have and no body, because the syscall that starts a process
is served as `NotImplemented` and a body that pretended to work would be a claim
the tree cannot back.

## How a crate arrives

1. It moves in with its tests, and `cargo test -p <crate>` runs them on the host.
2. Its layer is argued in `scripts/layering.txt` before it is added to the
   workspace — a crate with no layer is the one crate nobody checks.
3. Its test count is recorded in `scripts/crate-tests-baseline.txt`, which is a
   ratchet: the count may rise freely and may not fall.
4. `docs/architecture.md` gains a paragraph if the crate's placement was a
   decision, and this table moves a row.

A filesystem has one more condition, and it is the user's: it arrives only after
a mount has been verified on a machine.
