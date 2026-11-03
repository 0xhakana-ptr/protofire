# 源火内核 Protofire Kernel

A `no_std` bare-metal kernel for x86_64, aarch64 and riscv64, written as a
workspace of crates so that every part of it can be built and tested on its own.

It is an independent kernel.  Other systems are read for what they got right and
not treated as the authority: where this tree follows a convention, the reason
is in the file that follows it.

## What works today

A boot takes this path on x86_64, and every line below is required by a gate:

```
protofire 0.1.0: entered via pvh, console up, stage 1
protofire: page table built and installed, 4 KiB granule
protofire: interrupt table installed, interrupts on
protofire: heap at 0x97a780..0x497a780
protofire: pci scan found 4 device(s) on 1 bus
protofire: block device from virtio-blk on pci
protofire: virtio-blk wrote and read back sector 63
protofire: namespace: pyrofs on / (protofire), tmpfs on /tmp (memory), iso9660 on /cdrom (bootdisc)
protofire: /cdrom/README.TXT reads back from the disc
protofire: filesystem mounted and read /greeting.txt through syscall open/read/close, label protofire
```

The same boot on aarch64, which has no PCI bus until the device tree is parsed
and so falls back to the in-memory image:

```
protofire 0.1.0: entered via dtb, console up, stage 1
protofire: page table built and installed, 4 KiB granule
protofire: interrupt table installed, interrupts on
protofire: heap at 0x408e7790..0x448e7790
protofire: pci scan found 0 device(s) on 1 bus
protofire: block device from memory (no virtio-blk on the bus)
protofire: namespace: pyrofs on / (protofire), tmpfs on /tmp (memory), iso9660 on /cdrom (bootdisc)
protofire: /cdrom/README.TXT reads back from the disc
protofire: filesystem mounted and read /greeting.txt through syscall open/read/close, label protofire
```

Two handshakes on x86_64 (PVH and multiboot2) and a device-tree boot on aarch64,
a serial console on all three machines, a TLSF heap, a PCI bus scan, a virtio
block driver over a real virtqueue, a page table with a permission per region
that aarch64 actually translates through, an exception path that saves and
restores FP/SIMD state, a mount table with three filesystems on it, and three
syscalls that read a file off the disk.

On aarch64 the interrupt line is a stronger claim than its wording suggests:
`install_interrupt_table` raises a supervisor call after writing `VBAR_EL1` and
answers `true` only if it arrived at the entry it should have and returned.  A
register written and never exercised is the recurring defect here, so the line
means the save, the restore and the `eret` all ran.

The page-table line is the same kind of claim, and for a while it was not.
`arch_aarch64` wrote `TTBR0_EL1` and never set `SCTLR_EL1.M`, so the boot said
"installed" about a table no access went through.  It now writes `TCR_EL1`,
`MAIR_EL1` and the `M` bit, reads `M` back, and every line after it — the
console, the heap, the image build, the exception path — is an access that went
through the table.  Set `TCR_T0SZ` back to its wrong value and the boot stops
after `protofire: page table`.  `docs/migration.md` has the three fixes and the
exception log that named each.

**That is roughly a seventh of the kernel this replaces.**  The rest — the other
ten filesystems, the network stack, the scheduler, the process layer, most of
the architecture modules — is being moved in a crate at a time, and a crate
arrives only when its tests arrive with it.  `docs/migration.md` counts what is
in and what is not.

| | |
|---|---|
| crates | 36 |
| source | ~51,000 lines |
| tests | 564, all runnable with `cargo test -p <crate>` |
| machines that boot | 2 of 3 (`riscv64` builds, and has no entry yet) |

## Building and running

Linux, x86_64.  One development host is supported and `rust-toolchain.toml` says
why: every measurement in the previous tree had three answers, every script had
a shell-difference branch, and a defect that only appeared on one host was found
by whoever ran the gate there.

```sh
cargo install just    # once; a distribution package is preferred where there is one
just build-x86_64     # the image, into target/x86_64-unknown-none/debug/bootloader
just run-x86_64       # boot it and keep the serial output
just check-x86_64     # boot it and require what it prints
```

`just --list` shows every recipe.  A recipe is one line naming one command;
anything with an argument or a conditional lives in `tools/xtask`, which is Rust
so that its assertions can be tested without an emulator.  Nothing in the gate
*needs* `just` — `scripts/verify.sh` is what a gate actually runs.

## The gate

```sh
sh scripts/verify.sh p3
```

`p0` is formatting, every crate's tests, and the three kernels.  `p1` adds the
boot — of every machine that has an image, not just the first one whose console
printed.  `p2` adds three censuses — the architecture gates, the dependency
layering, and the per-crate test counts.  `p3` adds clippy in every
configuration.

A census is a ratchet: it records a number, refuses growth, and refuses a
baseline row that no longer describes the tree.  Meeting one by recording a new
number is a change that argues for it in the baseline's own prose.

## Where to read next

| Question | Document |
|---|---|
| Why is the tree shaped this way, and which crate may name which? | [`docs/architecture.md`](docs/architecture.md) |
| What has been moved in, and what has not? | [`docs/migration.md`](docs/migration.md) |
| How does the asynchronous model work? | [`docs/async_io.md`](docs/async_io.md) |
| What does a change have to satisfy? | [`docs/contributing.md`](docs/contributing.md) |
| What may a contributor rely on, and what is review-only? | [`AGENTS.md`](AGENTS.md) |
| What does a gate refuse? | the gate's own header comment |

## Licence

Source code is Apache-2.0; prose is CC BY-SA 4.0.  [`LICENSES/README.md`](LICENSES/README.md)
says which files fall on which side and why the split exists.
