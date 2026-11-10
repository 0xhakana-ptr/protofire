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
Pipes and files share one descriptor numbering, and a descriptor belongs to
the process that holds it: its exit releases every slot it owned, which for a
pipe end is the close that ends a reader's wait.  Every operation checks the
owner, so another process's number is `InvalidArgument` — the same answer as a
number that names nothing, because "denied" would tell a caller which slots
exist.  A `fork` copies the parent's descriptors to the child, owned by the
child; a pipe end copies as a **handle**, so the pipe's count rises and
end-of-file waits for both processes.  The boot's own programs remain
machine code, and `/bin/init` is the workspace's first compiled ring-3 program.

Verified by `the timer preempted, `, `a write woke `, `forked a process, child pid 4`, `copy-on-write copy at `, `copy-on-write promote at `, `loaded /bin/init, `, `process 1 exec'd /bin/init`, `process 1 opened /greeting.txt`, and `exit statuses 1 -> 116`.

The pipe's reader also calls `WaitProcess` after its end-of-file read, and the
gate requires the kernel's own `a wait answered status ` line on all three
machines: the guard, the park's retry contract and the exit's wake are on a
path every boot runs.

A park saves its resume **at the call**, not after it: a trap leaves `ELR_EL1`
past the instruction, which is what an answered call wants, and a parked call
has no answer, so resuming past it would skip the handler and leave the
program reading whatever its register held from the call before.  The rewind
lives in `block` (each machine's `arch` answers the call's width — four bytes
for `svc` and `ecall`, two for `int 0x80`), and a host test requires it.

Two things a wait cannot promise yet:

- **It answers about *some* process, not the one asked for.**  The boot has
  four, and the forked child exits first, so the status a reader receives can
  be `139`, that child's fault status, not the writer's `0`.  A per-child wait
  needs a pid argument the ABI does not have, and until it has one a program
  must not report the wait's answer as its own status — which is why the
  boot's reader exits with a constant of its own.
- **The reader's payload and its end-of-file are one call apart.**  The first
  read blocks and a retry returns the writer's four bytes; only the read after
  that sees the closed end.  That is a short read working as the contract says,
  but an image that wants both in one call needs a loop, and this one has none.

A wake reports its count whether or not it woke anyone, because zero is a fact
— a reader already awake is still a reader the bytes reached — and a line that
printed only the non-zero case made the gate depend on an interleaving.
Measured: 120 aarch64 boots with the wake line required, and 60 more with the
wait line required as well, all clean.

**Faults.**  A fault reaches the kernel with its direction and with the
faulting CPU's own table asked what the address is mapped as.  A write to a
page a fork demoted is the copy-on-write event the resolver answers.  A fault
no resolver answers is reported, the task goes `Finished` with the kernel's
status 139, and the next task runs.

A program may answer its own faults: `InstallExceptionHandler` records an
address in the task, a fault is then resumed there with the vector, the
address and the direction in the argument registers, and
`ReturnFromException` resumes the **instruction after the one that faulted**
with the handler's value as the call's answer.  The resume position is held in
the task rather than the frame, because entering the handler replaces the
frame that described the fault.

Verified by `fault at `, `process 4 died from a fault at `,
`exit statuses ... 4 -> 139`, and on every machine `process 3 installed a
fault handler at ` and `process 3 handled its own fault at `: the pipe's reader
stores into its own read-execute code page and the kernel resumes it at the
handler rather than killing it.

The handler receives the faulting instruction's address in the **fifth**
argument register, not the fourth: x86_64's fourth is `rcx`, which `int 0x80`
uses for its return address.  It answers `ReturnFromException(resume, value)`
with the address to continue at, because an instruction's length is the
program's fact and not the kernel's — x86_64's vary.

**Devices.**  The PCI scan, BARs assigned by the boot, and virtio-blk
attached.  Verified by `block device from virtio-blk on pci` and `virtio-blk wrote and read back sector `.

**The second CPU.**  A task is not pinned, so one that is preempted or woken
is placed again, and the boot counts and names the placement.  Placement
follows a rule rather than the rotation: a task the asking CPU last ran is
offered back to it first, a task no CPU has run comes next, and a task another
CPU ran is taken only when neither exists — the **steal**, which is the one
placement that migrates.  Measured on the same image: `task migrations` read 6,
9, 9, 7, 7 and 16 on six boots before the rule, and 1, 1, 2, 3, 3 and 3 after
it, against 12 to 16 `task placings home` — which is the rule's preferred arm
running, not merely a lower number.

Verified by `hart 1 online`, `ipi to 1 other cpu(s), taken`, `cpu 1 runs process `, `program ended on cpu 1`, `parallel, programs ended on `, `task migrations `, `task placings home `, `address spaces reaped 4, `, and `tlb shootdown `.

Missing: no queue per CPU, so the offer of work is still the lock's — an idle
CPU takes a free task because every CPU scans the same list, not because a
queue sharded work toward it.  A CPU with nothing to do and work belonging to
another CPU steals it, which is the migration the rule prefers to avoid but
will not refuse: leaving a core idle with work in the queue is the worse
answer.  Exited programs' spaces are released at the boot's end rather than at
each exit, because releasing one while the other CPU was still installed on its
root faulted 186 times in six boots of eight.  `docs/migration.md` has the
per-step cost of more CPUs.

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

**Idle.**  A CPU with nothing to run parks in `wfe` and is woken by the event
the kernel's inter-CPU wake issues.  The mechanism is the **event**, not the
interrupt, because a started core's timer expires without its PPI ever
reaching the distributor while it idles — measured: `CNTP_CTL_EL0` 5 with
`GICD_ISPENDR0` `0x3`, bit 30 absent — so a `wfi` there never returns.  Re-
measured for this change: a `wfi` in the idle left a started core parked in
**22 boots of 40**, and the boot ended `ended without confirmation`; `wfe`
beside a `sev` from `send_ipi_to_others` ended clean in **100 of 100**, and in
40 more with the bounded spin behind the hint removed, which is what shows the
event — not the spin — is what ends the wait.  Verified by the absence of the
confirmation line across those 100 boots and by the started core's own record
(`cpu 1 id 1, ticking, ` with a non-zero tick count).

The mask is not the cause and was ruled out: clearing every bit
(`DAIFClr, #0xf`) and halting still left that core's second `wfi` never
returning.  With `wfe` there is no bound behind it: a core whose event never
comes stays parked, and the boot's own reaping side reports the CPUs that never
confirmed rather than waiting for ever.

**Ring 3.**  `eret` to EL0t, `SP_EL0` carried in the trap frame, FP/SIMD saved
because the compiler provably emits them.  Verified by `entering ring 3`.

**Fault direction.**  From `ESR_EL1`'s WnR bit, on the two data-abort classes.

**Second CPU.**  The tree's cores minus the one firmware cold-booted, started
through PSCI `CPU_ON`.  A started core installs its own vectors and
`TTBR0_EL1`, arms its own timer, records that it is online, takes its clock, an
inter-processor interrupt and a task from the shared scheduler, and enters EL0
on it.  Shared-table changes are broadcast and acknowledged.

Missing: about two boots in a hundred used to end wrong; fixed by masking the
trap entry's restore.  The boot's last exit printed `program ended on cpu 1`
and then the machine either took a data abort one byte past the RAM's top —
`fault at 0x60000000, read, mapped read-write, supervisor`, PC in
`exception_entry`'s first `ldp` of a restore — or wedged before `every
program exited`, the reaping side waiting in `send_ipi_to_others` for a core
that halted in the unhandled path.  Measured 2 in 100 and 1 in 60 on the
pre-session baseline, never on x86_64 (80 boots) or riscv64 (20).

The cause was a trap taken during the restore.  The handler **deliberately
unmasks** — a park or a wait clears `I` so the wake can arrive — and returned
with `I` clear, so the restore that writes `ELR_EL1`/`SPSR_EL1`/`SP_EL0` and
reloads 32 SIMD registers ran interruptible.  An IRQ taken there entered the
vector with `SP_EL1` still at the frame, built a second frame over the first
one's, and its `eret` resumed the first restore with a `sp` that a temporary
trap-entry probe showed landing on a **frame-pool page** (`0x449a7000`,
`0x449913c0`) rather than the RAM's top — a saved slot the second frame had
overwritten.  Masking the entry alone was not enough and measured 3 in 200;
masking again after the dispatch, before the restore, measured **200 of 200
clean**.  `eret` reloads `DAIF` from `SPSR_EL1`, so neither mask needs an
unmask.

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

**A delivery the device does not own is not counted as an interrupt.**  The
controller can hand this source over once more after the handler silenced the
UART: the line was asserted when the source became pending, and the controller
delivers what it latched although the device has nothing to say by the time it
is read.  Measured on both the PLIC and the APLIC, six boots each: exactly one
delivery whose `IIR` read says "mine" and exactly one whose read says "not
mine", every time.  The trap path completes the second and returns without
handing it to the sink, so the count describes interrupts rather than
deliveries.  A probe is what found it — without one, the same boot printed
`taken = 1` or `taken = 2` depending on where the print landed.

The AIA's APLIC is driven in **direct delivery mode**: the machine is
described with `riscv,numsource` and `riscv,aplic`, its sources are configured
level-high with a per-source target, and a hart's delivery block claims and
completes.  The boot finds the APLIC before the PLIC, because a machine that
describes one is an AIA machine and the older node beside it is the one the
firmware left for a kernel that does not know the new one.  Measured on
`-machine virt,aia=aplic`: `external controller at 0xd000000, context 0, 96
source(s)` and `console interrupt(s) taken = 2`, with the boot completing in
4 of 4 runs.

**The IMSIC is driven, and the boot walks its message path.**  When the tree
names a supervisor IMSIC — the node whose `interrupts-extended` pairs carry
cause 9; the one carrying 11 is machine mode and is not this kernel's — the boot
reads the group's base, stride and `riscv,num-ids`, enables this hart's file
(`eithreshold` zero, `eidelivery` on), and then proves the path with no device
attached: it enables the file's **highest** identity — one past any a device
could be given — writes that identity into **this hart's own MSI page** exactly
as an MSI-X table entry would, and reads it back with the `stopei` claim.

    protofire: imsic at 0x28000000, hart file 0, 255 identit(ies), self-test identity 254 delivered and claimed

That line is the evidence: the page's address, the bare-identity data word, the
pending bit, the enable bit and the claim were all executed. QEMU's `virt` with
`-machine virt,aia=aplic-imsic` is where it runs; the default machine and
`virt,aia=aplic` print no such line because their trees name no IMSIC, and the
code that would touch `siselect`/`sireg` is not reached — which is load-bearing
rather than tidy, because on those machines the pair is an **illegal
instruction**.  Measured: `virt` and `virt,aia=aplic` both stop with
`unhandled exception 2 (illegal instruction), address 0x15051073` if the CSRs are
read unconditionally, and both boot to completion when the read is gated on the
tree as it now is.

**The APLIC's message mode delivers to the IMSIC, and each source's message
carries its own number.**  On `-machine virt,aia=aplic-imsic` the APLIC is
locked in message mode (`domaincfg` reads `0x80000104`, `DM` set and
read-only), so a wired source becomes a message into the IMSIC.  Each source's
target word names the hart and **the source's own number as the identity** —
measured, a constant there put every wired source's message onto identity 1,
which is also the firmware's inter-processor identity (`eie` reads `0x2` at hart
start, set by the firmware), and a trap that claimed identity 1 could not tell
the console's level wire from an IPI: the wire stayed high and the APLIC
re-sent for ever, 16,052 claims in six seconds.  With the identity as the
source's own, the file's enable is the **filter** — only the sources a driver
claims get one, because enabling the whole range turned every wired line with
nobody to answer it into a storm (41,201 deliveries in ten seconds from one
source, silenced at its controller once the trap path stopped re-arming it).
Those boots finish, with `console interrupt(s) taken = 0` — the console's own
message is held pending in the file, and the trap that would take it is a later
change.

Two limits remain, both measured:

- **A PCI device's MSI-X does not yet reach the file.**  The wiring exists —
  the block device's queue vector mapped, its table entry written and read
  back, MSI-X enabled — and one boot of this session saw the device's
  completion claimed and counted; the cleanup's boots did not reproduce it
  (0 of 4).  A claim without a reproducible measurement is not a mechanism, so
  the wiring is not in this tree, and the block device completes through its
  driver's polling as every other machine's does.  What the session did pin:
  the file's identity space on this machine does not deliver identity 128
  (written, read back enabled, never taken) while identity 20 does — QEMU's own
  MSI write path refuses a value past a bound the tree does not name.
- **Only one source is claimed**, so a second device's interrupt has no
  handler.  The controller can name every source the tree declares and the
  claim path completes whichever one arrives; what is missing is a driver per
  device, not a controller.

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
