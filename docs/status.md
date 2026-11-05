# Status

This document is the per-machine census: for each of the three machines, what
the code does today and what it does not do yet.  It deliberately carries no
line counts, file counts, test counts, or completion percentages — those change
with every commit, and a number maintained by hand is a number that will
eventually be wrong.  The tree is the authority for how much code there is;
this document is the authority for what that code does.

Two words are used strictly below:

- **implemented** means the code path exists and is reachable.
- **verified** means a gate boots it or a test pins it.

In the tables, a dash in the *Missing* column means no gap is known and
recorded here — not that the machine has none.  Where this document and the
tree disagree, the tree is right and this document is the bug;
`scripts/check-docs.sh` enforces the part of that a machine can check: every
path named here has to exist.

Targets: **x86_64**, **AArch64** and **RISC-V 64** all build for their own
target, boot through the same gate (`scripts/verify.sh`, tier p1, one image
per machine), and run programs at ring 3 under a preempting timer.

What the machines share is one kernel and one boot narrative: the frame pool,
the heap, PyroFS with tmpfs and an ISO 9660 disc mounted by prefix, the syscall
table, the MAC policy asked both ways, and three programs — one asleep, one
blocked on a pipe, one writing to it — whose lines every machine's check
requires.  The rows below are the machine's own half.

---

## x86_64

| What | Now | Verified by | Missing |
|------|-----|-------------|---------|
| Boot | Multiboot2 or PVH handoff; the entry assembly's 2 MiB identity map | the gate's `entered via pvh` line | — |
| Console | COM1, reached through the port pair | every line the gate reads | — |
| Page table | the kernel's own 4 KiB-granule table replacing the boot's; text read-execute, read-only data read, device windows uncached | `page table built and installed, 4 KiB granule` | — |
| Interrupts | the local APIC; the 8259 masked, not remapped; the self-test raises the timer's own vector | `interrupt delivered to its handler` | — |
| Timer and clock | the APIC timer, calibrated once against the PIT; the TSC as the monotonic clock, calibrated separately — the two rates differ and the boot proves both | `timer armed at `, `timer counter  ticks apart` | — |
| Ring 3 | a GDT with DPL-3 code and data segments, a TSS whose `RSP0` names the stack every ring-3 interrupt lands on, a call gate at DPL 3, `iretq` out | `descriptor tables installed, TSS loaded`, `entering ring 3` | — |
| Scheduler | preemption, sleeping with a deadline, a read blocked on a pipe and woken by a write | `the timer preempted, `, `a write woke ` | — |
| Devices | the PCI scan over the configuration port pair, BARs assigned by the boot, virtio-blk attached | `block device from virtio-blk on pci`, `virtio-blk wrote and read back sector ` | — |
| Second CPU | the APIC can self-address, and nothing starts an application processor: a machine with more than one CPU runs one | — | the AP start and its per-CPU path |

---

## AArch64

| What | Now | Verified by | Missing |
|------|-----|-------------|---------|
| Boot | QEMU's `-kernel` raw image at EL1; the device-tree pointer recorded by the entry | the gate's `entered via dtb` line | — |
| Console | the PL011, at the address the tree names | every line the gate reads | — |
| Page table | the kernel's own 4 KiB table; `TCR_EL1` sized for the full 48-bit walk; the tree's device windows uncached | `page table built and installed, 4 KiB granule` | — |
| Interrupts | the GIC; the self-test raises a software interrupt the controller delivers | `interrupt delivered to its handler` | — |
| Timer and clock | the generic timer — one clock for both the deadline and the counter | `timer armed at ` | — |
| Ring 3 | `eret` to EL0t, `SP_EL0` carried in the trap frame, FP/SIMD saved because the compiler provably emits them | `entering ring 3` | — |
| Scheduler | preemption, sleeping with a deadline, a read blocked on a pipe and woken by a write | `the timer preempted, `, `a write woke ` | — |
| Devices | the PCIe ECAM window discovered from the tree, BARs assigned by the boot, virtio-blk attached | `block device from virtio-blk on pci` | — |
| Second CPU | the tree names the machine's cores, and nothing starts one: a machine with more than one core runs one | — | the PSCI start and its per-CPU path |

---

## RISC-V 64

| What | Now | Verified by | Missing |
|------|-----|-------------|---------|
| Boot | OpenSBI hands the entry S-mode with the device tree in `a1`; the image is an ELF at the loader's conventional address | the gate's `entered via dtb` line | — |
| Console | the NS16550A, at the emulated platform's address | every line the gate reads | — |
| Page table | Sv48 — the mode whose four-level walk is the shape the kernel's shared arithmetic defines; `satp`'s page number at the register's own bits | `page table built and installed, 4 KiB granule` | — |
| Interrupts | three lines, all bits in `sie`: the timer's, the software one the machine raises on itself, and the external one a PLIC source arrives on. The PLIC is programmed — every source's priority, this hart's context bank, the threshold — and the trap path claims a source, hands it to a sink by its number, and completes it | `interrupt delivered to its handler`, `external controller at ` | no AIA/IMSIC: the platform's message controller is not described by this machine's tree; no driver has claimed a source yet, so the claim path is exercised by construction rather than by a device |
| Timer and clock | the SBI's legacy set_timer — arming is a trap into M-mode, with every clobbered register declared; the counter's rate comes from the tree, there being no register that states it | `timer armed at 10000 ticks/ms` | — |
| Ring 3 | `sret` to U-mode, `sscratch` holding the kernel stack for the trap back, `sepc` advanced before a handler can park the frame, `SUM` granted once at the entry | `entering ring 3` | — |
| Scheduler | preemption, sleeping with a deadline — the largest duration one `addi` immediate can express — a read blocked on a pipe and woken by a write | `the timer preempted, `, `a write woke ` | — |
| Devices | the PCIe ECAM window discovered from the tree, BARs assigned by the boot, virtio-blk attached | `block device from virtio-blk on pci` | — |
| Second CPU | the tree's hart list minus the hart the firmware cold-booted, started through the HSM call; a started hart takes its own stack and the trap vector, records that it is online, and parks | `hart 1 online` | the started hart runs nothing: no ticks, no scheduler — the scheduler is a single structure, and its per-hart path is the change that grows it |
