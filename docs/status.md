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

Where a machine's entry says nothing about a gap, no gap is known and recorded
here — which is not the same as the machine having none.  Where this document
and the tree disagree, the tree is right and this document is the bug;
`scripts/check-docs.sh` enforces the part of that a machine can check: every
path named here has to exist.

## What every machine does

The three machines are one kernel.  A boot installs the same frame pool and
heap, mounts PyroFS at `/`, tmpfs at `/tmp` and an ISO 9660 disc at `/cdrom`,
installs the syscall table, asks the MAC policy both ways, and runs three
ring-3 programs — one asleep, one blocked on a pipe, one writing to it — whose
lines every machine's check requires.  The four parts below are the same on all
three machines, so they are stated once.  A machine's own section carries only
what differs.

**Scheduler.**  Preemption, sleeping with a deadline, and a read blocked on a
pipe and woken by a write.  Each task carries a pid, a parent, and the status
it exited with.  `Fork` shares the running process's pages with its child and
hands its context down, writable pages demoted read-only and copied only when a
write faults, once per page that is actually written.  `ExecProcess` rebuilds
the running task around the **file its argument names** — a NUL-terminated path
read through the registry's namespace, parsed by the kernel's ELF64 loader, and
mapped segment by segment at the addresses the loader accepted, with a
writable-executable segment refused by name.  The task keeps its pid, and the
exec'd program opens the boot's own file through `Open`/`Read`/`Close` and
exits with the first byte it read, `116`, the `t` of "the quick brown pyrofox".
Pipes and files share one descriptor numbering.  The boot's own programs remain
machine code, and `/bin/init` is the workspace's first compiled ring-3 program.

Verified by `the timer preempted, `, `a write woke `, `forked a process, child pid 4`, `copy-on-write copy at `, `copy-on-write promote at `, `loaded /bin/init, `, `process 1 exec'd /bin/init`, `process 1 opened /greeting.txt`, and `exit statuses 1 -> 116`.

**Faults.**  A fault reaches the kernel with its direction and with the
faulting CPU's own table asked what the address is mapped as.  A write to a
page a fork demoted is the copy-on-write event the resolver answers.  A fault
no resolver answers is reported, the task goes `Finished` with the kernel's
status 139, and the next task runs.

Verified by `fault at `, `process 4 died from a fault at `, and `exit statuses ... 4 -> 139`.  Missing: a per-program fault handler — the frozen `InstallExceptionHandler` numbers — does not exist.

**Devices.**  The PCI scan, BARs assigned by the boot, and virtio-blk
attached.  Verified by `block device from virtio-blk on pci` and `virtio-blk wrote and read back sector `.

**The second CPU.**  A task is not pinned, so one that is preempted or woken
is placed again, and the boot counts and names the placement.

Verified by `hart 1 online`, `ipi to 1 other cpu(s), taken`, `cpu 1 runs process `, `program ended on cpu 1`, `parallel, programs ended on `, `task migrations `, `address spaces reaped 4, `, and `tlb shootdown `.

Missing: no load balancing — placement is whatever the lock decides, so a CPU
with an empty queue does not take work from one that is busy.  Exited programs'
spaces are released at the boot's end rather than at each exit, because
releasing one while the other CPU was still installed on its root faulted 186
times in six boots of eight.  `docs/migration.md` has the per-step cost of more
CPUs.

## x86_64

**Boot.**  Multiboot2 or PVH handoff; the entry assembly's 2 MiB identity map.
Verified by the gate's `entered via pvh` line.

**Console.**  COM1, reached through the port pair.  Every line the gate reads
comes through it.

**Page table.**  The kernel's own 4 KiB-granule table replacing the boot's;
text read-execute, read-only data read, device windows uncached.  Verified by
`page table built and installed, 4 KiB granule`.

**Interrupts.**  The local APIC; the 8259 masked rather than remapped; the
self-test raises the inter-processor interrupt's vector, which the controller
delivers and the kernel counts.  Verified by `interrupt delivered to its handler`.

**Timer and clock.**  The APIC timer, calibrated once against the PIT, and the
TSC as the monotonic clock, calibrated separately.  The two rates differ and
the boot proves both.  Verified by `timer armed at ` and `timer counter  ticks apart`.

**Ring 3.**  A GDT with DPL-3 code and data segments, a TSS whose `RSP0` names
the stack every ring-3 interrupt lands on, a call gate at DPL 3, and an `iretq`
out.  Verified by `descriptor tables installed, TSS loaded` and `entering ring 3`.

**Fault direction.**  From the page-fault error code's `W/R` bit, on vector 14
alone.

**Second CPU.**  The machine's CPU count read from `fw_cfg`, each started
through INIT-SIPI into a copied-down real-mode-to-long-mode page.  A started
CPU loads its own GDT and TSS, its own `IDTR`, its own local APIC and its own
timer, records that it is online, takes its clock, an inter-processor
interrupt and a task from the shared scheduler, and enters ring 3 on it.
Shared-table changes are broadcast and acknowledged.

## AArch64

**Boot.**  QEMU's `-kernel` raw image at EL1; the device-tree pointer recorded
by the entry.  Verified by the gate's `entered via dtb` line.

**Console.**  The PL011, at the address the tree names.

**Page table.**  The kernel's own 4 KiB table; `TCR_EL1` sized for the full
48-bit walk; the tree's device windows uncached.  Verified by `page table built and installed, 4 KiB granule`.

**Interrupts.**  The GIC; the self-test raises a software interrupt the
controller delivers.  Verified by `interrupt delivered to its handler`.

**Timer and clock.**  The generic timer, one clock for both the deadline and
the counter.  Its private interrupt is configured **level**-triggered, which is
what `CNTP_CTL_EL0.ISTATUS` staying set until reprogramming makes it, and the
started core's own clock fires from it.  Verified by `timer armed at ` and `cpu 1 id 1, ticking, `.

**Idle.**  A CPU with nothing to run spins a bounded number of turns and
re-reads its condition, rather than waiting in `wfi`.  A started core's timer
expires without its PPI ever reaching the distributor while it idles —
measured: `CNTP_CTL_EL0` 5 with `GICD_ISPENDR0` `0x3`, bit 30 absent — so a
`wfi` there never returns, and the boot ended `ended without confirmation` on
one run in ten.  Verified by the absence of that line across 240 boots.

Missing: an idle core is not parked.  This machine cannot make `wfi` wakeable
on a started core, so the power a real idle would save is not saved.  The mask
is not the cause: clearing every bit (`DAIFClr, #0xf`) and halting still left
that core's second `wfi` never returning, three failures in forty.

**Ring 3.**  `eret` to EL0t, `SP_EL0` carried in the trap frame, FP/SIMD saved
because the compiler provably emits them.  Verified by `entering ring 3`.

**Fault direction.**  From `ESR_EL1`'s WnR bit, on the two data-abort classes.

**Second CPU.**  The tree's cores minus the one firmware cold-booted, started
through PSCI `CPU_ON`.  A started core installs its own vectors and
`TTBR0_EL1`, arms its own timer, records that it is online, takes its clock, an
inter-processor interrupt and a task from the shared scheduler, and enters EL0
on it.  Shared-table changes are broadcast and acknowledged.

Missing: about two boots in a hundred end wrong, and the tree ended wrong at
the same rate before this session's changes.  The boot's last exit prints
`program ended on cpu 1` and then the machine either takes a data abort
reading one byte past the RAM's top — `fault at 0x60000000, read, mapped
read-write, supervisor`, PC in `exception_entry`'s restore (`ldp q10, q11,
[sp, #448]`), with the frame's `sp` inside the frame pool's last page — or it
wedges before `every program exited`, the reaping side waiting in
`send_ipi_to_others` for a core that halted in the unhandled path.  Measured
2 in 100 here and 1 in 60 on the pre-session baseline; a boot frozen under
the emulator's gdbstub held the boot core's `sp` at an address no kernel
stack slice names, so the standing question is what writes it.  The other
two machines never reproduce it — 80 x86_64 and 20 riscv64 boots, none —
so the question is this machine's, not the scheduler's.

A temporary trap-entry probe narrowed it one step: the first trap whose
frame is not on a kernel stack names a **frame-pool page** — `0x449a7000`
and `0x449913c0`, inside `__pool_start`..`__pool_end`, not the RAM's top —
and both catches interrupted `serial::push` printing the final `program
ended on cpu 1`, with `SPSR` at EL1h.  So a kernel-mode cpu was running
ordinary kernel code on a page the pool had handed out, the scheduler's
install path never carried a context that was not ring 3 (that probe never
fired), and every trap returns its own stack (`add sp, sp, #816` before
`eret`) — the write happens in ordinary kernel execution, which points at
a saved stack slot smashed with an address that code holding frame
addresses as locals would produce: the copy-on-write copy and the image
allocator are the suspects with the means.  The probe is removed; the
question is what wrote the slot.

## RISC-V 64

**Boot.**  OpenSBI hands the entry S-mode with the device tree in `a1`; the
image is an ELF at the loader's conventional address.  Verified by the gate's
`entered via dtb` line.

**Console.**  The NS16550A, at the emulated platform's address.

**Page table.**  Sv48, the mode whose four-level walk is the shape the kernel's
shared arithmetic defines; `satp`'s page number at the register's own bits.
Verified by `page table built and installed, 4 KiB granule`.

**Interrupts.**  Four lines, all bits in `sie`: the timer's, the software one
the machine raises on itself, and the external one a PLIC source arrives on.
The PLIC is programmed and the console's UART is claimed as a real source —
enabled at the controller, asked for one transmitter interrupt, acknowledged at
the device before the source is completed.  Verified by `interrupt delivered to its handler`, `external controller at `, and `console interrupt(s) taken = 1`.

Missing: no AIA/IMSIC.  One source is claimed, so a second device's interrupt
has no handler.

**Timer and clock.**  The SBI's legacy `set_timer`; arming is a trap into
M-mode, with every clobbered register declared.  The counter's rate comes from
the tree, there being no register that states it.  Verified by `timer armed at 10000 ticks/ms`.

**Scheduler, in addition.**  A sleep is bounded by the largest duration one
`addi` immediate can express, which is the machine's own limit rather than the
scheduler's.

**Ring 3.**  `sret` to U-mode, `sscratch` holding the kernel stack for the trap
back, `sepc` advanced before a handler can park the frame, `SUM` granted once at
the entry.  Verified by `entering ring 3`.

**Fault direction.**  From `scause`, where store and load page faults are two
different numbers.

**Second CPU.**  The tree's hart list minus the hart the firmware cold-booted,
started through the HSM call.  A started hart takes its own stack, its own
`satp`, its own timer and the trap vector, records that it is online, takes its
clock, an inter-processor interrupt and a task from the shared scheduler, and
enters U-mode on it.  Which hart the firmware cold-boots is the firmware's
choice, so the census names the slot the kernel numbered rather than a hart id.

This machine broadcasts no shared-table change, and that is a fact rather than
a gap: its ECAM window is inside the identity map, so nothing is remapped after
the second hart is up.
