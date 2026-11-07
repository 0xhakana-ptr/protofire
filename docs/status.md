# Status

This document is the per-machine census: for each of the three machines, what
the code does today and what it does not do yet.  It deliberately carries no
line counts, file counts, test counts, or completion percentages, those change
with every commit, and a number maintained by hand is a number that will
eventually be wrong.  The tree is the authority for how much code there is;
this document is the authority for what that code does.

Two words are used strictly below:

- **implemented** means the code path exists and is reachable.
- **verified** means a gate boots it or a test pins it.

In the tables, a dash in the *Missing* column means no gap is known and
recorded here, not that the machine has none.  Where this document and the
tree disagree, the tree is right and this document is the bug;
`scripts/check-docs.sh` enforces the part of that a machine can check: every
path named here has to exist.

Targets: **x86_64**, **AArch64** and **RISC-V 64** all build for their own
target, boot through the same gate (`scripts/verify.sh`, tier p1, one image
per machine), and run programs at ring 3 under a preempting timer.

What the machines share is one kernel and one boot narrative: the frame pool,
the heap, PyroFS with tmpfs and an ISO 9660 disc mounted by prefix, the syscall
table, the MAC policy asked both ways, and three programs, one asleep, one
blocked on a pipe, one writing to it, whose lines every machine's check
requires.  The rows below are the machine's own half.

---

## x86_64

| What | Now | Verified by | Missing |
|------|-----|-------------|---------|
| Boot | Multiboot2 or PVH handoff; the entry assembly's 2 MiB identity map | the gate's `entered via pvh` line | |
| Console | COM1, reached through the port pair | every line the gate reads | |
| Page table | the kernel's own 4 KiB-granule table replacing the boot's; text read-execute, read-only data read, device windows uncached | `page table built and installed, 4 KiB granule` | |
| Interrupts | the local APIC; the 8259 masked, not remapped; the self-test raises the inter-processor interrupt's vector, one the controller delivers and the kernel counts | `interrupt delivered to its handler` | |
| Timer and clock | the APIC timer, calibrated once against the PIT; the TSC as the monotonic clock, calibrated separately, the two rates differ and the boot proves both | `timer armed at `, `timer counter  ticks apart` | |
| Ring 3 | a GDT with DPL-3 code and data segments, a TSS whose `RSP0` names the stack every ring-3 interrupt lands on, a call gate at DPL 3, `iretq` out | `descriptor tables installed, TSS loaded`, `entering ring 3` | |
| Scheduler | preemption, sleeping with a deadline, a read blocked on a pipe and woken by a write; each task carries a pid, a parent and the status it exited with; `Fork` shares the running process's pages with its child and hands its context down, writable pages demoted read-only and copied only when a write faults, once per page that is actually written; the fault handler answers a shared page with a private copy and a page whose last holder wrote with the frame outright; `ExecProcess` rebuilds the running task around the image its argument names, in the window the task already owns, keeping its pid — the image it became opens the boot's own file through `Open`/`Read`/`Close` and exits with the first byte it read, `116`, the `t` of "the quick brown pyrofox"; pipes and files share one descriptor numbering | `the timer preempted, `, `a write woke `, `forked a process, child pid 4`, `copy-on-write copy at `, `copy-on-write promote at `, `process 1 exec'd image 4`, `process 1 opened /greeting.txt`, `exit statuses 1 -> 116` | |
| Devices | the PCI scan over the configuration port pair, BARs assigned by the boot, virtio-blk attached | `block device from virtio-blk on pci`, `virtio-blk wrote and read back sector ` | |
| Second CPU | the machine's CPU count read from `fw_cfg`, each started through INIT-SIPI into a copied-down real-mode-to-long-mode page; a started CPU loads its own GDT and TSS, its own `IDTR`, its own local APIC and its own timer, records that it is online, takes its clock, an inter-processor interrupt and a task from the shared scheduler, and enters ring 3 on it; a task is not pinned, so one preempted or woken is placed again and the boot counts and names the placement | `hart 1 online`, `ipi to 1 other cpu(s), taken`, `cpu 1 runs process `, `program ended on cpu 1`, `parallel, programs ended on `, `task migrations `, `address spaces reaped 4, `, `tlb shootdown ` | no load balancing: placement is whatever the lock decides, so a CPU with an empty queue does not take work from one that is busy. Exited programs' spaces are released at the boot's end rather than at each exit, because releasing one while the other CPU was still installed on its root faulted 186 times in six boots of eight. Shared-table changes are broadcast and acknowledged; `docs/migration.md` has the per-step cost of more CPUs |

---

## AArch64

| What | Now | Verified by | Missing |
|------|-----|-------------|---------|
| Boot | QEMU's `-kernel` raw image at EL1; the device-tree pointer recorded by the entry | the gate's `entered via dtb` line | |
| Console | the PL011, at the address the tree names | every line the gate reads | |
| Page table | the kernel's own 4 KiB table; `TCR_EL1` sized for the full 48-bit walk; the tree's device windows uncached | `page table built and installed, 4 KiB granule` | |
| Interrupts | the GIC; the self-test raises a software interrupt the controller delivers | `interrupt delivered to its handler` | |
| Timer and clock | the generic timer, one clock for both the deadline and the counter | `timer armed at ` | |
| Ring 3 | `eret` to EL0t, `SP_EL0` carried in the trap frame, FP/SIMD saved because the compiler provably emits them | `entering ring 3` | |
| Scheduler | preemption, sleeping with a deadline, a read blocked on a pipe and woken by a write; each task carries a pid, a parent and the status it exited with; `Fork` shares the running process's pages with its child and hands its context down, writable pages demoted read-only and copied only when a write faults, once per page that is actually written; the fault handler answers a shared page with a private copy and a page whose last holder wrote with the frame outright; `ExecProcess` rebuilds the running task around the image its argument names, in the window the task already owns, keeping its pid — the image it became opens the boot's own file through `Open`/`Read`/`Close` and exits with the first byte it read, `116`, the `t` of "the quick brown pyrofox"; pipes and files share one descriptor numbering | `the timer preempted, `, `a write woke `, `forked a process, child pid 4`, `copy-on-write copy at `, `copy-on-write promote at `, `process 1 exec'd image 4`, `process 1 opened /greeting.txt`, `exit statuses 1 -> 116` | |
| Devices | the PCIe ECAM window discovered from the tree, BARs assigned by the boot, virtio-blk attached | `block device from virtio-blk on pci` | |
| Second CPU | the tree's cores minus the one firmware cold-booted, started through PSCI `CPU_ON`; a started core installs its own vectors and `TTBR0_EL1`, arms its own timer, records that it is online, takes its clock, an inter-processor interrupt and a task from the shared scheduler, and enters EL0 on it; a task is not pinned, so one preempted or woken is placed again | `hart 1 online`, `ipi to 1 other cpu(s), taken`, `cpu 1 runs process `, `program ended on cpu 1`, `parallel, programs ended on `, `task migrations `, `address spaces reaped 4, `, `tlb shootdown ` | no load balancing: placement is whatever the lock decides. Exited programs' spaces are released at the boot's end rather than at each exit, because releasing one while the other core was still installed on its root faulted 186 times in six boots of eight. Shared-table changes are broadcast and acknowledged; `docs/migration.md` has the per-step cost of more cores |

---

## RISC-V 64

| What | Now | Verified by | Missing |
|------|-----|-------------|---------|
| Boot | OpenSBI hands the entry S-mode with the device tree in `a1`; the image is an ELF at the loader's conventional address | the gate's `entered via dtb` line | |
| Console | the NS16550A, at the emulated platform's address | every line the gate reads | |
| Page table | Sv48, the mode whose four-level walk is the shape the kernel's shared arithmetic defines; `satp`'s page number at the register's own bits | `page table built and installed, 4 KiB granule` | |
| Interrupts | four lines, all bits in `sie`: the timer's, the software one the machine raises on itself, and the external one a PLIC source arrives on. The PLIC is programmed, and the console's UART is claimed as a real source: enabled at the controller, asked for one transmitter interrupt, acknowledged at the device before the source is completed | `interrupt delivered to its handler`, `external controller at `, `console interrupt(s) taken = 1` | no AIA/IMSIC; one source is claimed, so a second device's interrupt has no handler |
| Timer and clock | the SBI's legacy set_timer, arming is a trap into M-mode, with every clobbered register declared; the counter's rate comes from the tree, there being no register that states it | `timer armed at 10000 ticks/ms` | |
| Ring 3 | `sret` to U-mode, `sscratch` holding the kernel stack for the trap back, `sepc` advanced before a handler can park the frame, `SUM` granted once at the entry | `entering ring 3` | |
| Scheduler | preemption, sleeping with a deadline, the largest duration one `addi` immediate can express, a read blocked on a pipe and woken by a write; each task carries a pid, a parent and the status it exited with; `Fork` shares the running process's pages with its child and hands its context down, writable pages demoted read-only and copied only when a write faults, once per page that is actually written; the fault handler answers a shared page with a private copy and a page whose last holder wrote with the frame outright; `ExecProcess` rebuilds the running task around the image its argument names, in the window the task already owns, keeping its pid — the image it became opens the boot's own file through `Open`/`Read`/`Close` and exits with the first byte it read, `116`, the `t` of "the quick brown pyrofox"; pipes and files share one descriptor numbering | `the timer preempted, `, `a write woke `, `forked a process, child pid 4`, `copy-on-write copy at `, `copy-on-write promote at `, `process 1 exec'd image 4`, `process 1 opened /greeting.txt`, `exit statuses 1 -> 116` | |
| Devices | the PCIe ECAM window discovered from the tree, BARs assigned by the boot, virtio-blk attached | `block device from virtio-blk on pci` | |
| Second CPU | the tree's hart list minus the hart the firmware cold-booted, started through the HSM call; a started hart takes its own stack, its own `satp`, its own timer and the trap vector, records that it is online, takes its clock, an inter-processor interrupt and a task from the shared scheduler, and enters U-mode on it; a task is not pinned, so one preempted or woken is placed again and the boot counts and names the placement. Which hart firmware cold-boots is the firmware's choice, so the census names the slot the kernel numbered rather than a hart id | `hart ` … ` online`, `ipi to 1 other cpu(s), taken`, `cpu 1 runs process `, `program ended on cpu 1`, `parallel, programs ended on `, `task migrations `, `address spaces reaped 4, `, `tlb shootdown ` | no load balancing: placement is whatever the lock decides. Exited programs' spaces are released at the boot's end rather than at each exit, because releasing one while the other hart was still installed on its root faulted 186 times in six boots of eight. This machine broadcasts no shared-table change, and that is a fact rather than a gap: its ECAM window is inside the identity map, so nothing is remapped after the second hart is up. `docs/migration.md` has the per-step cost of more harts |
