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
here, which is not the same as the machine having none.  Where this document
and the tree disagree, the tree is right and this document is the bug;
`scripts/check-docs.sh` enforces the part of that a machine can check: every
path named here has to exist.

## What every machine does

The three machines are one kernel.  A boot installs the same frame pool and
heap, mounts PyroFS at `/`, tmpfs at `/tmp` and an ISO 9660 disc at `/cdrom`,
installs the syscall table, asks the MAC policy both ways, and starts three
ring-3 programs: one that sleeps and maps memory, one blocked on a pipe, and one
writing to it.  The sleeping one is `/bin/init`, which then does the rest of the
boot's demonstration itself, it forks, spawns `/bin/shell` twice, exchanges
signals with each child, and reads the clock and two ABI records, so the boot's
`every program exited` counts **six** exits from the three tasks it started.
The four parts below are the same on all three machines, so they are stated
once.  A machine's own section carries only what differs.

**Scheduler.**  Preemption, sleeping with a deadline, and a read blocked on a
pipe and woken by a write.  Each task carries a pid, a parent, and the status
it exited with.  `Fork` shares the running process's pages with its child and
hands its context down, writable pages demoted read-only and copied only when a
write faults, once per page that is actually written.  `ExecProcess` rebuilds
the running task around the **file its argument names**, a NUL-terminated path
read through the registry's namespace, parsed by the kernel's ELF64 loader, and
mapped segment by segment at the addresses the loader accepted, with a
writable-executable segment refused by name.  The task keeps its pid, and the
exec'd program opens the boot's own file through `Open`/`Read`/`Close` and
exits with the first byte it read, `116`, the `t` of "the quick brown pyrofox".
Pipes and files share one descriptor numbering, and a descriptor belongs to
the process that holds it: its exit releases every slot it owned, which for a
pipe end is the close that ends a reader's wait.  Every operation checks the
owner, so another process's number is `InvalidArgument`, the same answer as a
number that names nothing, because "denied" would tell a caller which slots
exist.  A `fork` copies the parent's descriptors to the child, owned by the
child; a pipe end copies as a **handle**, so the pipe's count rises and
end-of-file waits for both processes.  The boot's own programs remain
machine code, and `/bin/init` is the workspace's first compiled ring-3 program.

Verified by `the timer preempted, `, `a write woke `,
`forked a process, child pid 4`, `copy-on-write copy at `,
`copy-on-write promote at `, `loaded /bin/init, `, `process 1 exec'd /bin/init`,
`process 1 opened /greeting.txt`, and `exit statuses 1 -> 116`.

**Descriptor duplication** is served, `Dup` and `Dup2`, and the pair is what a
program uses to give one handle to a child and keep reading through another.
`Dup` answers the lowest free slot, which is also the answer to "is this number
in use": a program that wants the next free descriptor asks by duplicating one.
`Dup2` places the copy on a number the caller names and closes whatever that
number held first, which is what makes it succeed on a full table -- the slot
the target occupied is the one the copy takes -- and what lets a program put a
file on standard output without a window in which the number is free.  A target
equal to the source answers the source and changes nothing, because the caller
asking "is this number mine" must not lose the descriptor it asked about.

The copy is a **handle**, not an alias: for a file it shares the node and keeps
its own offset, and for a pipe it raises the end's count, so a reader sees
end-of-file only after the last handle goes.  Both properties are exercised
from ring 3, and the gate asserts the two numbers the boot printed:

```
protofire: process 1 duplicated descriptor 6 as 7
protofire: process 1 placed descriptor 6 on 12
```

The lines are exact rather than prefixes, because `as 6` is the defect a
duplicate that answered its own source would print.  Measured, making
`duplicate_for` answer the source's number failed the boot: the program's own
`duplicate == held` check exited 251 and the log stopped short of the lines
after it.

The pipe's reader also calls `WaitProcess` after its end-of-file read, and the
gate requires the kernel's own `a wait answered status ` line on all three
machines: the guard, the park's retry contract and the exit's wake are on a
path every boot runs.

A park saves its resume **at the call**, not after it: a trap leaves `ELR_EL1`
past the instruction, which is what an answered call wants, and a parked call
has no answer, so resuming past it would skip the handler and leave the
program reading whatever its register held from the call before.  The rewind
lives in `block` (each machine's `arch` answers the call's width, four bytes
for `svc` and `ecall`, two for `int 0x80`), and a host test requires it.

Two things a wait does not promise, one of which is now answered:

- **`WaitProcess` answers about *some* process, not the one asked for.**  The
  boot has four, and the forked child exits first, so the status that call
  receives can be `139`, that child's fault status, not the writer's `0`.
  `WaitProcessOf(pid)` (#196) is the answer and the boot's programs use it now:
  it names the process, parks a caller whose pid has not exited, wakes it from
  that exit, and answers `NotFound` for a pid no task has.  `WaitProcess`
  remains for the caller that genuinely wants "whichever finished first".
- **The reader's payload and its end-of-file are one call apart.**  The first
  read blocks and a retry returns the writer's four bytes; only the read after
  that sees the closed end.  That is a short read working as the contract says,
  but an image that wants both in one call needs a loop, and this one has none.

A wake reports its count whether or not it woke anyone, because zero is a fact
, a reader already awake is still a reader the bytes reached, and a line that
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
program's fact and not the kernel's, x86_64's vary.

**Devices.**  The PCI scan, BARs assigned by the boot, a bochs-display found
and given a mode, and virtio-blk attached.  The display is x86_64's alone: the
other two machines' QEMU trees carry no display controller, so a required line
on them would be a requirement the machine cannot meet.  Verified by `block device from virtio-blk on pci`,
`virtio-blk wrote and read back sector `, `virtio-blk negotiated flush=yes`, and,
on x86_64, `display answered VBE ` with `display mode 1024x768 at 32 bpp`.
The last is the flush capability: the driver asks for `VIRTIO_BLK_F_FLUSH`, and
without the line there is no way to tell a device that has it from one that
ignores a flush request, because the second fails by timing out rather than by
answering.

The NVMe controller is also up, its namespace is a block device, and the
namespace is **mounted**: the controller is found on the bus, BAR0 is mapped,
it resets and enables, an admin pair identifies it and the namespace, an I/O
pair is created, `NvmeBlockDevice` carries the namespace through the block
interface, and `volume::mount_nvme` mounts that device at `/data` as the
table's fourth entry.  Its evidence is `nvme capability `,
`nvme namespace 1, 32768 block(s) of 512 byte(s)`, `nvme I/O queue pair up`,
`nvme0n1 far block answers PFNVME01` (bytes only the host wrote, at the far
block, because block zero of a filesystem is its superblock),
`nvme0n1 wrote and read back sector `, `nvme0n1 recorded as block device 0`,
the namespace line ending `, pyrofs on /data (nvme0n1)`, and
`/data/note.txt reads back over nvme` -- all required lines of the x86_64
gate, with `process 1 listed block device 1` reading the second record back
from ring 3.  A volume that does not open is skipped rather than fatal: the
boot volume is the one a machine cannot boot without, and the second disk is a
machine fact the host may have left empty.  Its formal half is
`drivers/storage/nvme`, which names nothing of this tree and is tested on a
host: the register offsets, both queue entries, the identify offsets, the ring
arithmetic and the phase walk.

The AHCI controller is also up, and its disk is a block device: found on the
bus by its class, `PI` read for the ports implemented, the first port whose
`PxSSTS.DET` reads three taken, the engine started in the order the
specification gives, and the disk identified and driven through the same
block interface.  Its evidence is `ahci ports implemented `,
`ahci disk on port 0`,
`ahci port 0, 65536 block(s) of 512 byte(s), model QEMU HARDDISK`,
`ahci0 far block answers PFATAH01`,
`ahci0 wrote and read back sector `, and
`ahci0 recorded as block device 1` -- all required lines of the x86_64 gate,
which is the one machine whose tree carries a SATA controller.  A namespace
is not mounted here either; the proof is the device, and a mount is the next
step if a filesystem is ever wanted on it.  Its formal half is
`drivers/storage/ahci`, relocated out of the previous tree's x86_64
architecture crate, which names nothing of this tree and is tested on a host:
BAR5's registers, a port's block, the command header, the PRD entry, the
Host-to-Device FIS and the ATA identify structure.

The xHCI controller is also up, with three USB devices behind it: a keyboard, a
mouse core and a mass-storage stick.  It enumerates the bus, addresses each
device, moves a real SCSI exchange over the bulk endpoints (INQUIRY, a
capacity read, a sector read), records the disk as a third block device, and
reads the keyboard's interrupt endpoint into an HID report whose bytes are a
PS/2 Set 1 scancode.  Its evidence, all required lines of the x86_64 gate:

```
protofire: xhci at 0xfeb94000, 16384 byte(s)
[xhci  ] controller initialised and running
[xhci  ] mass storage initialised at slot 1
[usbmsd] INQUIRY: vendor='QEMU' product='QEMU HARDDISK'
[usbmsd] USB mass storage: 16384 blocks x 512 bytes = 8 MiB
[usbmsd] recorded as block device 2
[xhci  ] HID keyboard ready at slot 2
[hid  ] keyboard report: modifiers=0x00 keys=[04,00,00,00,00,00]
```

The HID line is a key the host typed, not one the boot invented: `xtask` writes
`sendkey a` to QEMU's monitor after the boot's own `ReadConsole` exercise has
finished, and `04` is the HID usage for `a`.  The keyboard report does not
produce a value from the boot's own code, so the line is evidence that an
interrupt-IN transfer completed with a report the device built.  Its formal
half is `drivers/usb/xhci` at layer 0, relocated out of the previous tree's
drivers, with twenty-four host tests on the TRB layout, the descriptor walk,
the report parser and the SCSI command blocks.

**Virtio input** is up beside the USB device, and the tree now has two
keyboards whose reports are both in the log.  `drivers/virtio/input` at layer 7
holds the device: one event queue whose buffers the driver keeps posted, the
specification's eight-byte event, and a `drain` that hands the caller the event
rather than a meaning.  `kernel/src/virtio_input.rs` is where an evdev key code
becomes a scancode, through the same table `usb_hid` already uses.  Its
evidence, required lines of the x86_64 gate:
`protofire: virtio-input up, event queue posted` and
`[vioin] device event: kind=1, code=48, value=1`.

That second key arrives through a **different channel** from the first, and the
reason is a property of the emulator worth recording.  QEMU's input layer
delivers an event to one handler, not to every device that takes input:
`qemu_input_find_handler` returns the first match and
`qemu_input_event_send_impl` calls exactly that one.  Measured, adding the
virtio keyboard made the USB keyboard's `[hid  ]` line vanish while the virtio
one's arrived, which is the same unicast seen from the other side.  So the two
keyboards are routed apart: the virtio one is bound to its own console
(`VGA,id=disp0`, with `-vga none` so the machine still has exactly one display
for the kernel's probe), the monitor's `sendkey` names no console and reaches
the USB keyboard, and QMP's `input-send-event` names that console and reaches
this one.  `input-send-event`'s `device` argument is a **console** and not a
device: a version that passed a keyboard's id made QEMU abort with
`Property 'qemu-fixed-text-console.device' not found`.

The virtio GPU is also up, and its scanout is **visible from outside the
guest**.  `drivers/display/virtio_gpu` at layer 0 holds the wire format: the
24-byte control header, the command and response numbers, the 2D and 3D bodies,
and the display-info answer, with twenty-three host tests.  The machine's half
is `kernel/src/virtio_gpu.rs`: it finds the function, walks the status
sequence, queries `GET_DISPLAY_INFO`, creates a 2D resource in
`B8G8R8X8_UNORM`, attaches a page-aligned backing of its own, points scanout
zero at it, and then transfers and flushes.  Its evidence, required lines of
the x86_64 gate:

```
protofire: virtio-gpu display 1280x800 at 0,0, resource 1 on scanout 0
protofire: virtio-gpu scanout 1280x800, 16 row(s) of 0x2080e0 presented
```

The mode is the **device's** answer rather than a constant, and the size the
resource was made is that answer's.  The second line is the driver's claim; the
gate's screen check is the other half, and it is what makes this different from
every other device here.  `xtask` asks QEMU for a `screendump` over QMP once
the presented line appears, which is the **host's** image of the scanout, parses
the PPM, and requires every pixel of the band's sixteen rows to be the colour
the boot named and row sixteen not to be.  Both halves were measured to fail on
their own: a changed proof colour failed the serial line, and a gate expecting
twelve rows where the guest painted sixteen failed with
`the band runs past its 12 rows; the pixel at row 12 reads [32, 128, 224]` --
the real pixel the device was showing.

The crate exists because of six wire errors the previous tree carried, and each
would have made its 3D path silently useless.  `CTX_CREATE` was `0x0201` where
the enum makes it `0x0200`, `CTX_DESTROY` was `0x0202` where it is `0x0201`,
`SUBMIT_3D` was `0x0208` where it is `0x0207`; `RESOURCE_CREATE_3D` named its
last three words `levels`, `num_samples` and `stride` where the specification
has `last_level`, `nr_samples` and `flags`, and dropped its padding;
`TRANSFER_HOST_3D` put the resource id before the box so the device read the
box's `x` as the id; and `RESOURCE_CREATE_2D` and `RESOURCE_FLUSH` were sized
from a reader's count of their words rather than from their structs.  Every one
of them is asserted by a host test now.

The nine GPU syscalls (`181..=189`, VIRGL 3D) are **not** landed, and the
reason is the machine rather than the tree: they need a guest-owned resource
table, a DMA path from a user buffer, and `VIRTIO_GPU_F_VIRGL`, which QEMU's
`virtio-gpu-pci` does not offer and `virtio-gpu-gl-pci` will not start without
an OpenGL display backend this host cannot give it.

The PC speaker is the one driver whose value a serial port cannot carry: the
boot plays 1000 Hz and silences it, and
`protofire: pcspkr played 1000 Hz, then silenced` is the required line.  What a
listener hears is out of band, so the check is QEMU's traces -- the command
word `0xB6`, the divisor `0xa9`/`0x04` (1193, which is 1000 Hz), and a gate
transition on port 0x61 -- landing on the hardware the specification names.
The driver is `kernel/src/pcspkr.rs`; there is no formal half because the
whole of it is one divisor and two gate bits, and the ports are the machine's.

The virtio network card is **attached on all four boots**.  `virtio_net` brings
a card up, the same status sequence the block device runs, the address read
from the configuration region under `VIRTIO_NET_F_MAC`, and both queues,
receive 0 and transmit 1, and then moves a frame in each direction.  The
exchange is an ARP request for QEMU's user-mode gateway and the reply:
`qemu_arguments` gives every bootable machine `-netdev user` and a
`virtio-net-pci`, and the gate requires `protofire: virtio-net arp reply ` on
all four.  Measured on x86_64:

```
protofire: virtio-net up, address 52:54:00:12:34:56, receive queue 256, transmit queue 256
protofire: virtio-net arp reply 52:55:0a:00:02:02 holds 10.0.2.2, asked by 52:54:00:12:34:56 for 10.0.2.15
protofire: arp cache holds 10.0.2.2 at 52:55:0a:00:02:02, the wire asked 1 time(s)
protofire: arp cache answered 10.0.2.2 again without the wire
protofire: icmp echo reply from 10.0.2.2, 17 byte(s), waited 1 time(s)
protofire: udp sent from port 40000, refused by 127.0.0.1: port unreachable, waited 1 time(s)
```

The driver's reads of the reply are checked against the request it sent, the
reply has to name this card's address and the address this boot asked about
so the line is evidence that a frame left, a frame arrived, and the frame that
arrived answers the question.  The two lines after it are the answer's second
half: the reply goes into `net`'s ARP cache, and the same question read back
answers from the table, which is why every later consumer of the gateway's
address resolves there first and the wire's ask count stays at one for the
whole boot.  The gate requires both lines on all four machines, the second
exact, because its tail is the one fact a lookup could not vary.

The last line is the ping: an echo request to the gateway, and a reply QEMU's
user-mode network built.  The boot matches the reply's identifier, sequence
and echoed bytes against the request it sent, so the line is evidence that a
packet another machine built parsed through `net`'s IPv4 and ICMP layers
checksum verified on the way in, which a packet this boot had written itself
could never prove.  A frame that is not the reply is skipped rather than
matched, because the wire carries strangers' frames and a match that could
not refuse one would claim the first thing that parsed.  The gate requires
the line on all four machines.

The last line is the datagram: one UDP send to a port on the gateway nothing
owns, and the refusal that comes back.  A port nothing listens on is the one
datagram a peer is guaranteed to answer, ICMP's port unreachable, carrying
the original datagram's first bytes.  The boot parses the embedded original
and reads its UDP header, so the port on the line came out of what the peer
echoed, not out of this boot's own constants: a datagram this stack built
was received, its header parsed, and its source port named back.  The
refusal's source address is `127.0.0.1`, which is the gateway's host side
QEMU's user-mode network speaking as the host it proxies to.  The gate
requires the line on all four machines.

Three defects were found by booting, and all three are recorded where they were
found because each was invisible to a host test and to every register read-back:

- **The notify region's multiplier was read from its `length`.**  Section
  4.1.4.4.1 makes the multiplier the dword appended *after* the capability
  structure; `length` is the region's size, as it is for the other two.  With
  the multiplier taken from `length` (0x1000 on QEMU's card) a doorbell landed
  at `off * 0x1000`, past the mapped BAR, and the boot died with
  `write past the mapped BAR` on its first transmit.
- **The header is twelve bytes, not ten.**  A probe that filled the frame with
  its own byte indices had the wire carry `2, 3, 4, …`: the card skipped twelve
  bytes of a buffer whose header the driver wrote as ten.  Two more probes
  pinned the number, a header descriptor declaring eight bytes shifted the
  frame to `4, 5, 6, …`, and a single buffer with twelve leading zeros
  delivered it whole.  The driver writes twelve now, and
  `drivers/virtio/net/src/header.rs` records which measurement decided it.
- **The receive path stripped the wrong header.**  With the card writing twelve
  bytes and the driver reading ten, the reply was on the wire, captured with
  QEMU's `filter-dump`, while the driver parsed the frame four bytes into its
  own ARP message and reported it as not an ARP.

**The card's receive queue has its own message, and it is the second identity in
the same table.**  On `riscv64-aia` both devices wire a queue to an IMSIC
identity, the block device's transmit queue to 200, the card's receive queue to
201, and the boot reports each device's count on its own line:

```
protofire: block message wired to imsic page 0x28000000, identity 200, vector 2, queue 0
protofire: net message wired to imsic page 0x28000000, identity 201, vector 2, queue 0
protofire: block completion message(s) taken = 2
protofire: network message(s) taken = 1
```

Two counts rather than one total is the claim: a sum would say a message
arrived without saying which device sent it.  The gate requires both lines
non-zero on this machine, so a boot that took one device's message and not the
other's fails rather than passing on a total.

**The wiring is one function for both devices now.**  It was a block-device
function that named identity 200, vector 2 and queue 0 in its body; the card
would have been a second copy of the table arithmetic, and a second copy is a
second place the same bug can hide.  `MessagePlan` carries the three numbers and
a name, `wire_device_message` carries the mechanism, and each device names its
own handler, a function pointer, because the registry stores one and the trap
path hands it the identity.  The compile-time assertions moved onto the list of
plans, which is also the only place a **pair** of devices can be checked for
sharing an identity: a per-device pair of assertions could not see the
collision.

**The independence was measured, not assumed.**  With the card's queue vector
left unset, a control that leaves the block device's wiring untouched, the
boot printed `net message wiring refused: ..., queue vector cleared, identity
enabled` and `network message(s) taken = 0`, while `block completion message(s)
taken = 2` did not move.  That is the evidence that the card's 1 is its own
queue's message, and not the block device's count reaching a second counter by
accident.  A first attempt at this control moved the card's *vector number*
instead of failing the write, and the count stayed at 1, a vector a device is
told about is a vector it sends to, whatever number it is, so the control had
not disconnected anything.

**The receive wait is bounded by the timer, and the wait itself has never run.**
The ARP exchange used to spin: a `spin_loop` poll with a turn count.  It now
checks the ring and, when it is empty, arms the machine's timer for a slice and
stops the core until an interrupt arrives, the card's message is one of the two
that can end it, and the timer's is the other.

Two things were measured about that loop, and only two:

- **The bound is real.**  With no receive buffer posted, the card has nowhere to
  put the reply and the loop exhausts its turns: the boot prints `virtio-net
  arp request went unanswered after 41 turn(s)` and **continues**, rather than
  stopping in a wait.  That is the difference between a bound and a count that
  can never be reached, the first version of this change counted turns and was
  killed by the checker's timeout instead, because `wait_for_a_wakeup` does not
  return without an interrupt.
- **The wait branch does not execute on this machine.**  The boot prints
  `virtio-net waited 0 time(s) for the reply`: QEMU puts the reply in the
  receive ring inside the doorbell write, so the ring is already populated when
  the loop first looks.  A frame's arrival does not depend on the message at
  all, measured by removing the card's queue vector, after which the reply
  still arrived and `network message(s) taken` read 0.

So the card's message is **delivered and counted, and the driver does not yet
wait on it in any boot this gate runs**.  That is "implemented", not "verified",
and it stays a gap rather than a claim: making the wait execute needs a machine
whose device completes asynchronously, which QEMU's user-mode network is not.
The count is what the message's own mechanism has for evidence, and it is
required non-zero on the AIA machine.

**The network's first call is served.**  `NetworkStatus` (37) answers from the
interface the boot's exercise installed, the card up, the hardware address
it published, the protocol address this boot claims, and the gateway, and a
program reads the record back through `user_abi`'s wrapper:

```
protofire: process 1 asked the network, 24 byte(s)
```

The boot installs the interface where the card comes up, so the call answers
from state rather than from constants; a machine with no card installed
nothing, and that is the one case the call answers `NotFound` for.  Verified
by the line above on every machine, and by `init`'s own read-back, which
checks the state word and that none of the three addresses is the zeros a
boot with no card would have left.

**The datagram calls are served, and the receive parks.**  `BindUdp` (58) and
`SendToUdp` (59) answer through the registry; `RecvFromUdp` (60) is served by
the trap path, because it parks, the pipe reader's shape, with the same
re-check under the scheduler's lock.  `init` proves the whole of it with a
fork: the parent binds port 8612 and receives, the child binds 8613, sends
one datagram to the parent's port, and exits with the length it sent as its
status.  Measured on x86_64:

```
protofire: process 1 bound port 8612 as descriptor 6
protofire: a program blocks on a datagram socket
protofire: a datagram for port 8612 woke 1 blocked task(s)
protofire: process 7 sent 9 byte(s) to 10.0.2.15 port 8612
protofire: process 1 received 9 byte(s) from 10.0.2.15 port 8613
```

The datagram never touched the card: its destination is this machine's own
address, which is what loopback is, the sender's call and the receiver's
answer meet at the kernel's port table, so the exchange runs identically on
every machine the gate boots.  The wake line's count is a fact about the
interleaving, the way a pipe write's is: the parent parked before the child
sent in this boot, and a child that ran first would have found the datagram
already in its queue, parked nothing, and printed `woke 0`.  The two lines
the gate requires exact are the send's and the receive's, the lengths are
the program's own constant, and the sender record's port came out of the
datagram the kernel delivered, which only a delivered datagram could have
carried.

**The stream is whole, on loopback.**  TCP's state machine lives in `net`
the handshake, the segments, the acknowledgements, and the orderly close
and the boot runs the whole of an exchange through it: a listener on this
machine, a client whose connect completes inside the call, the client's
bytes echoed through the accepted end, and the close that leaves both ends
gone from the table.  Measured on x86_64:

```
protofire: tcp connected, listener 1, stream 2
protofire: tcp echoed 9 byte(s) of 9, round trip
protofire: tcp closed, both ends done
```

The exchange never touches the card: both ends are connections in the
kernel's own table, and a segment for this machine is delivered to the
peer's state machine inside the same exchange that carried it, which is
what loopback is, and why the exchange runs identically on every machine
the gate boots.

**A lost segment is sent again.**  The stack used to have no queue at all: a
sent segment was forgotten, so the first loss on a real wire hung the stream
for the rest of the boot, and every exchange above ran on a wire that loses
nothing so nothing noticed.  `net::tcp::Connection` now keeps what it sent and
the peer has not acknowledged, and a segment that waits past its timeout is
handed back to the caller to send again, with the timeout doubled, which is
[RFC 6298]'s backoff.  Five attempts, then the stream is abandoned and a
caller's next read answers end of file rather than nothing forever.

The clock is the caller's and the unit is microseconds.  That is not tidiness:
the first version of the reassembly timeout was written as a count of ticks
against a comment describing a hundred-hertz clock, and this kernel's slice is
a hundred **microseconds**, so a thirty-second window was three hundred
milliseconds and the sentence beside it was wrong by a factor of a hundred.
A duration written as a count of ticks moves whenever the slice does, so a
constant that means a duration is now a duration.

No wire this gate boots loses a frame, so a probe makes the loss rather than
waiting for one: it queues a segment without delivering it, walks the
schedule, and delivers what the table says is due.  Measured on x86_64:

```
protofire: tcp recovered 1 attempt(s), 12 byte(s), intact
```

The attempt count is the schedule's and the byte count is the peer's own
inbox, which only a retransmitted copy could have filled.

**A segment that arrives early is held, not dropped.**  The receive path used
to require the peer's position to be exactly the one it expected, so a wire
that reordered made the peer send each early segment again; the stream's speed
became the round trip's.  A segment ahead of the gap is now held, answered with
the duplicate acknowledgement that names the hole, and delivered in sequence
order the moment the gap closes.  A cache filled backwards lands as a whole
stream in one call, which is the assertion that separates "held and delivered"
from "held forever".

Two defects were found by the tests that describe that behaviour, and both
were the sequence arithmetic's.  `trim_held` measured how much of a held
segment the inbox had covered with `inbox_end - sequence`, which wraps to a
huge number for a segment that starts *after* the inbox, so a segment that had
not been delivered at all was deleted as "already covered"; and the direction
test for "is this segment ahead" was the same subtraction, so a straddling
retransmission was read as "far ahead" and held instead of trimmed.  Both are
`seq_before` now, and reverting either fails exactly the test that names it.

A straddling segment is trimmed rather than dropped: it starts before the
expected position and runs past it, which is what a peer's retransmission after
a partial loss looks like, and the bytes past the position are new.

[RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298

**The lease is kept, and its clock is the boot's own.**  `Interface` holds the
`Lease` a server granted, `pump` asks `Lease::duty` what the clocks say, and a
lease at `Renew` sends [RFC 2131]'s unicast `REQUEST` to the server that
granted it.  A failure leaves the lease in place: one unanswered datagram is
not the clock, and tearing down an address to renew it turns a late reply into
an outage.  An expired lease releases the address, because keeping it would put
two machines on one.

The conversion was wrong and this change is what found it.  `lease_from` takes
the caller's unit, and the caller passed `1` while its clock counted
microseconds: an hour's lease was read as expired eighty-six milliseconds
after it was granted, so `duty` would have said `Expired` on the first pump and
the address would have been released before the boot finished printing its
lease line.  Nothing could see it because nothing called `duty`.  The scale is
`MICROS_PER_SECOND` now, and the kernel test goes through `lease_from` rather
than building a `Lease` by hand, because a hand-built one passes whatever scale
the caller used.

**The lease's third state is a broadcast, and it is verified.**  A lease moves
through `Bound`, `Renew` and `Rebind`: a renewal asks the one server that
granted it, and a rebinding asks every server on the link, because the one that
granted it has stopped answering.  The difference is one option's absence, so
`write_request` takes `None` for the server and the frame goes to the broadcast
address from this machine's own address.  Measured on all four boots:

```
protofire: dhcp rebound 10.0.2.15 for 86400 second(s) more
protofire: rebind sent, the wire answered
```

QEMU's user-mode DHCP answers a rebinding, which is what makes this the one of
the lease's three states a gate can prove end to end.  The probe runs it once
after the boot's own grant, and the line reports the server's answer rather
than the request having left.

**What is still not verified.**  A *renewal* is due at half the lease's life
and a server's default is a day, so no boot reaches `Renew` and that path is
"implemented" rather than "verified".  It shares everything it executes with the
rebinding above and with the grant the boot runs: the same `write_request`, the
same `parse_reply`, the same bounded wait.  The difference the gate does not see
is the destination, one address for a renewal and the broadcast for a
rebinding.

[RFC 2131]: https://www.rfc-editor.org/rfc/rfc2131

**A path that shrinks now tells the stream.**  Two gaps were the same gap: a
write went out as **one** segment, so a write larger than a frame built a frame
the card could not carry; and `demux` had no branch for ICMP at all, so a
router's report about this machine's packet was dropped unread.  Together they
made the failure this tree could not have explained: a sender whose packets are
too large gets silence, retransmits into the same silence five times, and
abandons the stream half a minute later.

A write is now a run of segments no larger than the path's payload, and a
fragmentation-needed report shrinks every stream the four-tuple it quotes
names, so one lost oversized segment fixes every later write.  Measured on
x86_64:

```
protofire: path mtu 1460 -> 536, the report reached the stream
```

The probe builds the report, because no wire this gate boots sends one: the
loopback is one machine and QEMU's user-mode network is a proxy with no router
on the path.  It hands the frame to **the same `demux` a received frame goes
through**, and the two numbers are the stream's segment size before and after.

The probe found three of this change's own defects, and all three were about
which end of a quotation is whose.  The reported MTU was applied with the two
ports swapped, so a loopback exchange shrank the peer's end and the probe read
the sender's unchanged size; the check for "was this packet ours" compared the
quoted packet's **destination**, which is right for a packet sent *to* us and
wrong for the one an error quotes; and the probe itself wrote this machine's
address in both fields, which no real report does and which let the wrong check
pass its own test.  The first two are host tests now, and the third is why the
probe writes the shape a router does.

An ICMP port or host unreachable mid-stream ends the stream it names, because a
party on the path has said the path does not exist; a report about a packet
that did not leave from this machine is refused, because a four-tuple match
alone would let a stranger end a connection by guessing a port.

**The IPv6 side of the same answer.**  `demux_ipv6` dropped every ICMPv6 error
unread, so [RFC 8201]'s packet-too-big had no consumer.  It reads them now, and
the reader is a second function rather than the IPv4 one with a flag, because
the layouts differ in the place the reading starts: an IPv4 error leaves four
bytes unused after its header word and quotes from eight, and IPv6's MTU word
**takes** those four, so its quotation starts at eight for a different reason
and its message ends four bytes later.

```
protofire: path mtu6 1460 -> 1220, the report reached the stream
```

1220 is 1280 less both headers, and 1280 is the floor [RFC 8200] guarantees, so
the number is checkable rather than measured.  The probe's first version
reported no change at all, and the reason was the same one the IPv4 probe had:
the quoted header's payload length claimed twenty bytes of transport while the
quotation carried eight, and a reader that takes the sender's word for a
length reads past what it was given.

**An off-link address now has somewhere to go.**  IPv6 had no default route:
`peer_hardware` answered every destination it did not have in its neighbour
cache with that destination's solicited-node group, so a frame for a machine on
another link went to a group no machine on this link answers.  A router
advertisement's **source** is a router willing to be a default, and its lifetime
says so; the interface records it when the lifetime is non-zero and the source
is link-local, and an address outside this link is now asked for through it.

The advertisement's two facts were entangled, which is why this was one change:
`learn_from_router` returned early when the advertisement carried no prefix, so
a router that offered only a default route taught nothing.  A prefix and a route
are separate, and the function reads both before it returns.

```
protofire: ipv6 route via fe80:0000:0000:0000:5055:0aff:fe00:0202, and an off-link address is asked for through it
```

The probe asks for the hardware address of an address no machine on this link
holds and asserts the answer came from the **router's** group rather than the
destination's.  Removing the route makes that line print `MISMATCH` and the
boot fail, which is the mutation this was checked with.

**Five network numbers moved out of `NotImplemented`.**  They are the frozen
range's own, and the ABI already fixed their contracts, so none of them is a new
decision: `GetHostName` (71) and `SetHostName` (72) are a name this
machine holds, `GetSockName` (73) and `GetPeerName` (74) are a `sockaddr_in`
written from the connection's own four-tuple, and `ResolveHostname` (93) is the
lookup the boot's DNS probe already runs.

```
protofire: process 1 set the machine's name, 0
protofire: process 1 socket is 10.0.2.15:9003
protofire: process 1 peer is 10.0.2.15:49160
protofire: process 1 resolved a name to 1746147226
```

All four are printed from a program at ring 3, not from the kernel: `init` sets
a name and reads it back, asks its own accepted stream where both ends are, and
resolves `example.com`.  That last number is `104.20.23.154`, which is the
address the boot's own DNS probe reports on the line above it, so the two
independently reached the same server.

Writing them found a deadlock that would have hung any handler of this shape.
`serve` holds the registry's lock for the length of a call, and the socket
lookups beside it (`tcp_stream_for`, `udp_socket_for`) take that same lock.  A
handler that reached for the free function instead of the `&mut SyscallTable`
the dispatcher hands it would take one lock twice in one thread, and the
symptom was a boot that stopped between two lines with nothing refused.  The
handlers take the table now, and `docs/fmts/syscall-abi.md`'s handler rule is
what made the difference visible: a handler's arguments include the table for
exactly this reason.

`GetPeerName` on a datagram socket answers `Unsupported`, because a datagram
socket has no peer: it never connected to one.  A stream over IPv6 answers the
same, because the ABI's record is fourteen address bytes and a sixteen-byte
address does not fit it.

**Two more numbers: `SetSockOpt` (79) and `GetSockOpt` (80).**  Three options
are served, and each one changes what it names: `SO_RCVBUF` is the window every
outgoing segment advertises, `SO_SNDBUF` is the congestion window a write may
not exceed, and `TCP_NODELAY` is whether a small write waits for a segment's
worth.  Every other number is `InvalidArgument`, which is the point of having
three rather than fourteen: a table of fourteen stores eleven options nothing
reads, and a field nothing reads is a promise to a program that asks,
not an option.

`SO_REUSEADDR` is deliberately **not** one of the three, and its absence is the
shape of this ABI's limit rather than an oversight: `BindUdp` names a port and
nothing else, so the option would have to be set on a socket that does not exist
yet.  A version that recorded the flag per process and spent it at the next bind
existed for one afternoon and was removed in this change, because no ring-3
program could reach it without a bind to name and the state it added was kernel
memory for a flag nothing observed.

```
protofire: options window 8192 -> 1000, congestion 14600 -> 4380, both options moved what they govern
protofire: process 1 set socket option 5 answered 0
protofire: process 1 read socket option 5 answered 8
protofire: process 1 set socket option 1 refused
```

The first line is the kernel's probe, and the three that follow are printed from
ring 3: `init` narrows its stream's receive buffer, reads the same number back
at the width a size has, and is refused an option this build does not serve.  The
probe is the one that says the numbers changed the connection, which a set and
get round trip cannot show, because a field that stored and returned a number and
was read by nothing would pass it.

[RFC 8200]: https://www.rfc-editor.org/rfc/rfc8200
[RFC 8201]: https://www.rfc-editor.org/rfc/rfc8201

**The window is a fact about the buffers, not a constant.**  `WINDOW` was
carried in every segment and enforced nowhere: this stack told each peer it had
eight kilobytes of room however full its inbox was, so a peer that filled it was
entitled to send more and what stopped it was the connection's memory growing.
The number a segment advertises is now the room the connection has left, the
inbox and the runs held ahead of a gap both counted, and bytes past it are
dropped rather than grown into.  A reader taking bytes reopens it, which is the
half that matters: a window that only ever shrank would close the stream for
good.

```
protofire: window 8192 -> 0, and a byte past it was refused
```

That line needed a probe of its own, because every exchange this gate runs
carries nine bytes or nineteen: a connection holding either advertises the same
number whether or not anything enforces it.  The probe fills the whole buffer
with one segment and reads the number back.

**A deadlock that happened once in seven boots, and the lock order that made
it.**  `ConnectLocal` woke a parked accept from inside its handler, and a
handler runs with the registry's lock held: `serve` takes it for the length of
the call.  So that path was `registry -> scheduler`.  `AcceptLocal`'s park
re-checks the queue from inside the scheduler's lock, which its own comment
argues is what closes the race between a fact and a park, and the re-check
attaches the accepted end, which takes the registry's lock: `scheduler ->
registry`.  One CPU could not do both at once, but two could, and did.

The symptom was a boot that stopped after `forked a process, child pid 9` with
nothing refused, no fault and no line after it, which is a deadlock's shape
rather than a failure's.

The measurement is a controlled pair: the two trees differ by this one patch,
on one machine, with one profile, forty boots each.

| tree | complete boots |
|---|---|
| before the fix, `64f6c138` | 38 of 40 |
| after it, `484b77ab` | **40 of 40** |

Both failures stopped on the same three lines, the last of them the fork the
child is about to connect from.  That is the pair of calls whose locks were
reversed, reached from the two CPUs the boot starts.

What replaced the wake is a flag.  A handler that makes something a parked task waits
for says so (`Dispatch::completing`) instead of waking, and the caller of
`serve` wakes **after** the registry's lock is released.  A handler cannot
arrange that itself, which is why the flag is the mechanism: the order is the
whole point.

```
protofire: a local connect woke 0 blocked task(s), descriptor 12
```

The line is a gate line again, with the descriptor the last field.  It was not
one before because whether a read parks or finds its bytes already there is the
scheduler's choice; the wake itself is not, and it is now printed on every
boot.

**A route table, and the longest match decides.**  The stack had one IPv4
gateway and one IPv6 default router, both fields on the interface: a table with
one entry, which is enough for a machine on one link with one way out and
stops being enough the moment there are two.  `net::route::Table` is the same
arithmetic at every size: a route is a prefix, a length and an optional next
hop, a destination goes to the longest match, and no match is `NotFound`
rather than a guess.

A route with **no** gateway is a destination on the link, which is a case a
single gateway could not express: the frame goes to the destination's own
hardware address instead of a router's.  A `/0` route is a default and needs no
special case, because it loses to every other match by being the shortest.

```
protofire: routes 1 -> 2, and the longer prefix chose 2
```

The probe adds a route to a prefix the default also covers and reads which
hardware address the frame is addressed to.  Searching for the **first** match
instead of the longest prints `chose 1, MISMATCH`, which is the defect the probe
exists for: a stack that never looked at the destination.

A connected subnet is deliberately **not** seeded from the address's class.
The first version did that, and a `/8` guessed from `10.x` made every host in a
private cloud "on the link" and sent frames to addresses no neighbour answers
for.  What adds a connected route is a lease carrying a subnet mask or an
advertisement carrying a prefix, and both state the length rather than guessing.

**The packet filter, and the four calls above the frozen range.**  The ABI
named `FilterAddRule` (122), `FilterRemoveRule` (123),
`FilterSetDefaultAction` (124) and `FilterGetStats` (125) and this build served
none of them, so a program that wanted a policy had numbers to call and
`NotImplemented` to read.  The four are served now, and the mechanism behind
them is `net::filter`'s: an ordered rule list, the first match deciding, a
prefix and a port range in each rule, and a flow table the stateful rules fill
so a reply finds the answer its request already got.

**A filter with an `enabled` flag has a shape that is the bug.**  Such a filter
starts with it `false`, and if no call among its four sets it, every packet takes
the `if !enabled { allow }` path, so the rules a program installed are consulted
by nothing while each call answers success.  There is no flag here to leave off.
A filter with no rules is one
whose default action decides everything, the boot installs one that allows, and
what a call can change is the rules and the default, which are the two things
that decide.

```
protofire: filter dropped the datagram under a rule: yes, delivered it once removed: yes, and an outbound rule kept a frame off the card: yes
```

The line has three verdicts and the boot requires all three, because each half
is passed by a filter that is broken the other way.  The datagram is one this
machine sends itself through the demux; under an inbound deny rule it must
**not** reach the bound port's queue and the drop counter must move, and with
the rule removed the same frame must arrive.  The third verdict is the outbound
half, which the first two cannot cover: the frame goes through the same
`submit_filtered` the three senders call, against a card that counts what
reached it, and a refused send must leave the count at zero.  A send that
submitted the frame and then returned `PermissionDenied` would look like a
refusal from the caller's side and be a packet on the wire, which is why the
count and not the answer is what the line reports.

The filter runs in the demux **before** any transport reads a byte, so a
dropped SYN makes no stream, a dropped datagram fills no queue, and a dropped
fragment spends none of the reassembly cache.  Inbound and outbound are two
decisions because a rule names one direction or both, and the two are separate
functions so a call site cannot pass the wrong one.

`net::filter` is 19 host tests: the match order (including the case a two-rule
test cannot reach, an allow before a deny), a port rule refusing a packet whose
header carried none, a prefix matching every address under it in both families,
the canonical flow key that makes a reply and its request one entry, expiry at
each protocol's own lifetime, the sweep's rate limit, the two bounds refusing
rather than growing, the counters following the verdicts, and the record
validation that refuses a rule no packet could match.

**Multicast routing, and the forwarding it does.**  `MrtInit`, `MrtDone`,
`MrtAddVif`, `MrtDelVif`, `MrtAddMfc` and `MrtDelMfc` (169-174) were named in
the ABI and served by nothing.  All six are served now, and the part worth
saying is not the tables: it is that this stack **forwards**.  A multicast
packet is read because a cache entry names its group, and it leaves by each
interface its entry names with the hop count spent.

Tables alone are not forwarding, and this is the shape to avoid: a cache written
by the syscalls and read only by a `tick` that ages entries out describes a
stream nothing forwards.  That is the same shape as the packet filter's
`enabled` flag, and the probe is built to fail on it.

```
protofire: forwarded multicast from 167772674 to 4009820675 with ttl 4, 1 interface(s)
protofire: multicast forwarded 1 frame(s), ttl 5 -> 4, payload intact
```

Three facts on the required line, because a forwarding path breaks three ways
and each looks right through a different window.  **One frame reached the
card**: a table nothing reads sends nothing.  **The hop count fell from five to
four**: a forwarder that copied the arriving count would loop until something
else stopped it.  **The payload is the sender's**: a copy that rebuilt the frame
around its own bytes would forward a datagram nobody sent.  The probe swaps the
interface's card for one that records, hands the demux a frame a sender would
have built, and reads the frame the card was given, so all three are measured
on the bytes and not on a counter.

The two tables are `net::multicast`'s and the locks are the kernel's, the
arrangement the packet filter uses.  Three pieces of the stack had to grow for
the forwarding to be real, and each has its own test:

- `ipv4::parse` keeps the **time-to-live**, which every receiver ignored and a
  forwarder reads.
- `ipv4::is_for` takes the **groups this machine joined**.  A host that read
  every group's traffic would be a host that had joined all of them, which is
  the mistake the parameter prevents.
- `ipv4::multicast_mac` is [RFC 1112]'s mapping, `01:00:5e` and twenty-three
  bits of the group.  It is lossy on purpose, thirty-two groups to one hardware
  address, and the test asserts two groups that collide rather than pretending
  the mapping is one-to-one.

A **rate limit** is stored and not enforced, and `MrtVifDef::rate_limit` says
so in its own documentation.  A rate needs a clock and a bucket, a drop from
either is silent, and a field that claimed to act would be the `enabled` flag
again under another name.

[RFC 1112]: https://www.rfc-editor.org/rfc/rfc1112

**IPsec: ESP sealed, opened, and replayed against.**  `IpsecAddSp` (164),
`IpsecDelSp` (165), `IpsecAddSa` (166), `IpsecDelSa` (167) and `IpsecGetStats`
(168) were named in the ABI and served by nothing.  All five are served, and the
part that matters is the encapsulation: a datagram a policy protects leaves as
ESP and is recovered on the other side.

```
protofire: esp sealed 1, opened 1, the wire carried ciphertext, and the replay 0 byte(s)
```

Three facts, because ESP is broken three ways and each looks like a working
tunnel through a different window.  **The wire carried ciphertext**: a stack
that set the protocol number to 50 and sent the datagram unchanged is a stack
whose peer decrypts garbage, and a counter saying "encrypted 1" would not show
it.  **The bytes came back**: the round trip runs through `ipsec_open`, which is
the function the demux calls.  **A repeat produced nothing**: the same payload
delivered twice yields one delivery, which is what makes ESP a protocol and not
a cipher.  Mutation-tested: skipping the seal prints `sealed 0 ..., PLAINTEXT,
MISMATCH`; removing the window check prints `opened 2`; sealing with a copy
prints `PLAINTEXT, MISMATCH`.

**The loopback was a real hole, and it is closed.**  `send_datagram`'s loopback
shortcut delivered straight to the port table, so a datagram this machine sent
itself never saw a policy: a protected service was reachable in plaintext by
naming the machine's own address.  The shortcut is about the card and not about
the protocol, so a loopback send is now sealed, opened, and then delivered,
which is also what spends the sequence number a replay would be checked
against.

`net::ipsec` is 16 host tests over both AEADs.  Two of them exist because a
mutation showed the first version could not see the defect:

- the **nonce** test asserts the twelve bytes each algorithm derives.  A round
  trip cannot catch a wrong nonce, because a nonce derived wrongly on both
  sides agrees with itself; the middle word is zero for [RFC 4106] and one for
  [RFC 7634], and that difference is the whole test.
- the **failed tag** test asserts that a forged payload does not advance the
  window.  The window is consulted before the tag and advanced only after it
  verifies, so a stranger cannot burn the sequence numbers the real peer is
  about to use.

AH and tunnel mode are refused with `Unsupported` rather than served: AH needs
the mutable IPv4 fields zeroed before its sum, and tunnel mode needs a second IP
header around the ESP one.  A refusal at the call is better than a packet the
peer's policy drops in silence.

[RFC 4106]: https://www.rfc-editor.org/rfc/rfc4106
[RFC 7634]: https://www.rfc-editor.org/rfc/rfc7634

**DCCP: a second datagram transport, with a state machine that runs.**  The
seven `Dccp*` calls (157-163) were named in the ABI and served by nothing.  All
seven are served, over `net::dccp`: [RFC 4340]'s generic header, the ten packet
types, the nine states, and a connection table with a listener's backlog.

```
protofire: dccp client open, carried 4 byte(s)
```

One line and two claims, because the probe drives a whole connection through
**the function the demux calls**: a Request arrives at a listener, the accept
takes it, the Response opens the client, and the first datagram lands in the
server's inbox.  A stack that stored headers and had no states prints a table of
ports and passes nothing.  Mutation-tested: removing the transition below prints
`carried 0 byte(s), MISMATCH`, and so does delivering no data at all.

**The probe found a state-machine gap, and it is fixed.**  A server in
`ResponseSent` was refusing a `DataAck`, which is the packet a client sends when
its acknowledgement and its first datagram are one segment, so the server refused
the first thing the client ever sent.  `RESPOND -> OPEN` on an acknowledging
`DataAck` is now the transition, and `a_data_ack_opens_a_server_that_sent_its_response`
is the test.

**Three deadlocks were found the same way, and each is a rule now.**  All three
were a lock held across a call that takes it again, on a mutex that is not
reentrant:

- a guard created inside a call's **argument** lives until the whole statement
  ends, so `dccp_connect(..., INTERFACE.lock().as_ref()..., ...)` held the lock
  while `dccp_connect` took it;
- `dccp_send_segment` read the interface and then handed the segment to
  `deliver_dccp`, which reads it too;
- a reply handed back to the demux answers itself, forever, so a segment this
  stack composes for a peer never re-enters `deliver_dccp`.

The probe drives both directions through `deliver_dccp` directly rather than
through the card, and that is stated where the probe is: a frame this machine
addresses to itself comes back through QEMU's network ring, and a probe that
depended on that would be measuring the emulator's reflection rule rather than
this stack.

**The header is written extended and read both ways.**  Sixteen bytes with a
forty-eight-bit sequence number.  A short form's twenty-four bits wrap in
minutes at a stream's rate, and the reader accepts both forms because a peer may
send either.  The **redundant `X` bit** is checked: byte eight's bit 4 and byte
nine's bit 7 carry one value, and a reader that took one and ignored the other
would read a short packet's sequence number from the wrong bytes.

**No CCID**, and the module says so: congestion control is [RFC 4340]'s
pluggable part, and a connection here has what the protocol requires of every
implementation, a sequence space, a window and acknowledgements, and no
algorithm.

`net::dccp` is 28 host tests: the header's round trip for all ten types, the
short form, the reserved types, the redundant bit, a data offset inside the
header, the wrap-safe sequence comparison, and every state transition including
the one above.

[RFC 4340]: https://www.rfc-editor.org/rfc/rfc4340

**TLS 1.3: the protocol, and the call that cannot use it.**  `TlsConnect`
(121) was the last of the 23 above-frozen-range protocol numbers and the largest.
`net::tls` now has the record layer, the key schedule and the handshake
messages, and the call is served as far as this machine allows.

```
protofire: tls handshake finished verified yes, and carried 5 byte(s) under the application keys
```

**Three limits, and none of them is a defect to fix later without a peer.**

First, **there is no TLS server on this machine.**  QEMU's user-mode network
answers ARP, ICMP and UDP, and it does not terminate TLS; `ConnectTcp` refuses a
peer that is not this machine.  So `TlsConnect` opens the stream, builds a
ClientHello, sends it, and answers `Unsupported`, and the boot line says how many
bytes went so the half that ran is visible.  A call that refused without
building a hello would be a number and nothing more.

Second, **there is no X.509 parser.**  A certificate chain is DER, and reading it
is a module of its own: tagged values, an algorithm identifier, a validity
window, an extension list, and the name matching that decides whether a
certificate is for the host you meant.  The handshake here carries the chain
opaque and verifies the Finished against a key the caller supplies.  Half a
parser would be worse than none: one that read a certificate's fields and skipped
the extension that says "not for this name" would pass a chain a real client
refuses.

Third, **the boot probe proves agreement and not rejection.**  It runs both sides
of a handshake against each other, which is the strongest evidence available
without a peer: a real X25519 exchange, one schedule derived twice from one
transcript, each side's Finished accepted, and a record in each direction under
the application keys.  A mutation that removed the Finished comparison from the
probe did **not** change its line, because both sides here are right.  The
rejection half is host tests, and the mutation that made `finished_value` a
constant was caught by `a_forged_finished_does_not_verify`.

`net::tls` is 18 host tests: the record round trip for both suites, the outer
type being `application_data` whatever the inner one is, the nonce's
construction asserted byte for byte against [RFC 8446] §5.3 (a round trip cannot
catch a wrong nonce, because a nonce built wrongly on both sides agrees with
itself), a failed tag leaving the counter alone, the ClientHello's length fields
walked the way a server walks them, a ServerHello naming a group nobody offered
being refused, and an all-zero X25519 output refused as [RFC 7748] §6.1 requires.

[RFC 8446]: https://www.rfc-editor.org/rfc/rfc8446
[RFC 7748]: https://www.rfc-editor.org/rfc/rfc7748

**X.509: the certificate chain TLS was missing, on host tests.**  `net::x509`
is [RFC 5280]'s certificate: a strict DER reader, the fields a verifier reads,
the signature check that makes a chain a chain, and the name matching that
decides whether the certificate is for the host you meant.  `TrustAnchorAdd`
(194) and `TrustAnchorRemove` (195) are served too, so a program can add a root
and withdraw it.

Thirteen host tests, and the ones that matter are against **real certificates**:
a self-signed root for `example.test`, a root that signs a CA intermediate that
signs a leaf, and a root that signs a `CA:FALSE` intermediate.  Each is DER
openssl wrote, and a document built by this tree's own helper would be one
shaped by the parser's assumptions.

What the tests establish, and each was mutation-checked:

  * a real certificate parses, its **signature verifies under its own key**, and
    a self-signed certificate is its own anchor;
  * a three-hop chain verifies from the root down, and the same chain with an
    intermediate missing is `IssuerMismatch`;
  * a `CA:FALSE` intermediate that signed a leaf is
    `NotACertificateAuthority`, and both signatures in that fixture are real, so
    the refusal is attributable to the rule and not to a bad fixture;
  * the name rules: case folding, one label for a wildcard, the wildcard only
    leftmost, and **no common-name fallback**;
  * the DER reader refuses the indefinite length, a length past the document, a
    long form of more than four bytes, and a multi-valued relative name.

**A defect found in the chain check, and fixed here.**  The CA rule was written
as "every certificate except `chain.first()` must be a CA", which by identity
skipped the rule for a chain of one.  Exempting by **position** is the fix: the
leaf is index zero and nothing hangs below it, and every certificate above it
vouched for the next one down.

**A defect this exposed: ECDSA after the network exercise, found and fixed.**
On aarch64, verifying a chain faulted inside `ecdsa_p256_verify`.  On x86_64 the
same call returned the right answer, and `cargo test -p crypto` passes every one
of its 64 tests on the host.  The cause was the heap's second allocator, recorded
further down this section; the fault is gone now that the free lists are one
`static`, and the chain check after the network reports `verified yes`.

Where it happens was narrowed by measurement rather than by reading, and the
answer is not the one this entry first recorded:

- **`libs/crypto` is not the defect.**  The same source, built for
  `aarch64-unknown-none` by an out-of-tree harness with the kernel's own
  profiles (`opt-level = "s"` with LTO and one codegen unit, and `opt-level = 1`
  with debug assertions and overflow checks), verifies correctly.  So does the
  kernel itself when the call is made from `boot.rs`: `verified=1`, eight times
  in a row, with no network in between.
- **The inputs are not the defect.**  A canary at the failing site prints the
  key, hash, `r` and `s` it is about to pass, and every byte matches the
  constant.
- **The stack is not the defect.**  At the failing call `sp` is
  `0x4499b010`: sixteen-byte aligned, as the ABI requires, with 36 KiB still
  below it to the bottom of the reservation at `0x44992000`.
- **The trap path is not the defect.**  A pattern written to `v0` and read back
  at the failing site matches, so the exception entry is restoring the SIMD
  state it saved.  Masking IRQs around the chain check changed nothing.

**The heap is the defect, and the trigger is not the network.**  Walking the
allocator's own free lists with `verify_kernel_heap` says where the damage
starts: it is clean immediately after `heap::bring_up`, and it is already
damaged before `exercise_network` is called at all.  Bisecting the boot puts the
first break inside `volume::attach_device`'s call to `devices::find_virtio_block`,
and inside that, after the `Arc::new(MappedBar { .. })` that the first BAR's
mapping builds.  Nothing about the network is involved: the earlier entry's
`ping_gateway` was the first consumer big enough to trip over damage that was
already there.

The damage has one shape.  `verify_kernel_heap` panics in `scan_free_lists` with
`block 0x1 outside heap`, and the diagnostics printed around it name the chain:
the free list's head is the heap's first block at `0x4098fa40`, and the block
after it is `0x1`.  `block_next_free` reads the word at `block + 16`, which is
`FREE_NEXT_OFFSET`, and that is also where the payload of an allocated block
begins.  The allocation trace shows an `alloc` at exactly `0x4098fa50`, which is
`0x4098fa40 + 16`: a block was handed out while it was still linked into a free
list, its new owner wrote the reference count over `next_free`, and the walk
then followed `0x1` as a block address.

This is where the record stops claiming and starts asking.  The allocator
removes a block from a free list by recomputing the list from
`block_size(block)` and then scanning **that** list for the block.  If the size
word is not the one the block was inserted under, the scan is a different list,
finds nothing, and leaves the block linked.  That fits every observation above,
and it is a hypothesis rather than a finding: proving it needs a test that
allocates, writes the payload, and then walks the lists, which is the first
thing to write in `libs/allocator` and not a thing this entry did.  A host test
that does exactly that passes for every size from one to five hundred and twelve
bytes, so the allocator's arithmetic is right on the host and the defect is
something the host does not do.

What is measured is narrower, and it is enough to name the subsystem: the free
list's head is the heap's first block, the block the walk reaches next is `0x1`,
the word it read is the one an allocated block's payload begins at, and the
allocation trace records a payload at exactly that address.  The block was
handed out while it was still linked, and its new owner wrote a small integer
over the link.

**There is a write past the end of the heap, and a sentinel proves it.**  Putting
two pattern-filled arrays on either side of the heap's region, in one `repr(C)`
object beside it, and checking them at two points in the boot gives a cleaner
answer than any of the above: both are intact immediately after `heap::bring_up`,
and the one **after** the heap is scribbled before `exercise_network` is called.
So the damage is not the heap's arithmetic going wrong inside its own region.
Something writes past the region's end, and the free list's `0x1` is downstream
of that write.

That experiment is not in the tree.  It is four lines of static and a check,
it changed the heap's address when it was added, and a probe that moves the
thing it measures is not evidence a gate can keep.  It is recorded here because
its result is what the next session should start from, and because reproducing
it is cheaper than the bisect that led to it.

**What the free list holds, measured.**  `AllocatorState` sits at
`0x44989a48` when the heap ends at `0x44989a40`, which is eight bytes: only
`HEAP_TRACE_CURSOR` is between them.  Its `free_lists` array is at `state + 112`,
which is where `offsetof` puts it and not where a reader counting fields by hand
would.  The heap's first block is class 26's list head, and at two points in the
same boot its first four words read:

```text
before the mount   67108864       0  0  0      free, whole, unlinked
after the mount          65       0  1  1      used, 0x41 bytes, link is 1
```

`65` is not a block size: bit 0 is the in-use flag and `0x40` is the extent, so
the block really was handed out at 64 bytes.  The trailing `1` is the reference
count an `Arc` wrote into the payload, which is the same word `block_next_free`
reads as the link.

**And the trace that would explain it makes it go away.**  Instrumenting every
insert and removal by class, every allocation of a block in the heap's first
page, and every coalesce, produced a sequence in which each removal matched an
insert and every class agreed with every size.  It also produced a boot that ran
to the end: the same source, one diagnostic more, and no `0x1`.  That is not the
first time: `0..4` indices instead of `iter().enumerate()` moved the panic to a
data abort, `#[inline(never)]` and a wider `prod` each turned it into a wrong
answer, and the sentinel arrays moved the heap itself.  **Every attempt in this
record that changed the build changed the symptom without changing the
arithmetic**, and that is the single most useful fact about this defect: it is
layout sensitive, so a probe is the worst instrument for it and a gate that only
boots is nearly useless.

What that leaves is a defect a session cannot finish by reading.  The next one
should not add a probe inside the allocator.  It should build the same image
twice with a one-byte difference that does not touch the allocator, confirm the
fault flips, and then use a hardware watchpoint on `free_lists[672]` under
`gdb-multiarch`, which is the tool that does not perturb the layout at all.

**The reproducer is six lines and no certificate.**  Two calls to
`allocator::verify_kernel_heap` are enough with nothing else added:
one immediately after `heap::bring_up` survives, and one immediately after
`volume::mount_everything` panics with `block 0x1 outside heap`.  No `net::x509`,
no ECDSA, no network card, no virtio driver in the picture beyond the disk the
mount opens.  That is the thing to hand the next session, because every earlier
description of this defect needed a certificate and a chain and a boot that ran
long enough to reach them, and none of that is load bearing.

It also says where the search should start.  `mount_everything` builds the
PyroFS image, attaches the block device and does the rest of the mount, and an
earlier bisect in this record already put the first break inside
`volume::attach_device`'s call to `devices::find_virtio_block`, after the
`Arc::new(MappedBar ..)` that the first BAR's mapping builds.  The damage is in
that sequence and not anywhere in the network stack.  The earlier entries spent
a session and a half on the network because a certificate was the first consumer
big enough to fall over; the allocator was already broken before the first frame
was sent.

**A static audit of the allocator's own address range, and what it rules out.**
`AllocatorState` is 5752 bytes with `free_lists` at offset 112 and 704 entries,
measured on the host rather than counted by hand.  `HEAP_MODEL` was 5760 bytes
when this was measured, so the eight bytes in front of the state were
`SpinLock`'s word, and the whole object was the only static in
`[0x44989a48, 0x4498b0c8)`: the next symbol began exactly at the end.  That ruled
out the cheapest explanation, which was an unrelated static beside the allocator
overrunning into it, and it left two ways in: a store through a pointer the
allocator computed, or a store through `&mut AllocatorState` with an index out of
range.

The audit was sound and aimed at a store that never happened.  `HEAP_MODEL` is
zero-sized now: the state it used to hold is the `STATE` static, and the type
carries nothing.  The two writers it named are still the only two, and neither
was ever wrong; the array they wrote was correct for the allocator doing the
writing, and wrong only for the second one that read it.

The page tables sit immediately in front of the heap, which is worth knowing and
is not the answer.  `TABLES` spans `0x40154000..0x40986000` and the heap starts
at `0x40989a40`, so a `Tables` overrun would reach `KERNEL_HEAP` first and the
heap model 64 MiB later.  `re_encode` and `map_device_blocks` both write leaves
whose addresses came from `build`, which builds a table entry for every level
below the root; the device path taken for BARs below four gigabytes is
`re_encode`, which only rewrites an entry that already exists.  Neither reaches
the heap model.

**The checkpoints that survived a one-byte probe, and the ones that did not.**
Writing one character and walking the heap after it puts `build_image` on the
clean side and `find_virtio_block` on the damaged side, with a disk attached.
Two attempts to confirm that on a machine with no disk disagreed with each
other: one boot reported the damage and another reported none, from two
checkpoint layouts.  That is the same instability as everything else in this
record, and it is why the audit above is worth more than the checkpoints: the
address arithmetic is a fact about the image, and a checkpoint result is a fact
about one build of it.

**The gate keeps its debug assertions, so the index branch is ruled out.**  The
gate boots `--profile debug`, which is `[profile.dev]`: `opt-level = 1`,
`panic = "abort"`, and the default `debug-assertions = true`.  That was measured
rather than read off the manifest, with a `debug_assert!(false)` in the boot
that panicked.  So `list_index`'s `debug_assert!((FL_MIN..=FL_MAX).contains(&fl))`
and `debug_assert!(sl < SL_COUNT)` are live in every boot this record describes,
and an out-of-range index would panic inside `list_index` rather than leave a
list corrupted for `scan_free_lists` to find.  **What is left is the other
branch: a block address the allocator computed.**

**The word that is wrong is the first block's link, and the removal that
precedes it is clean.**  Three counters, one token each, on the list class the
heap's whole size maps to:

```text
[672I block=0x40989a40 size=0x4000000 head=0x0]   ensure_init
[672I block=0x40989a40 size=0x4000000 head=0x0]   a second insert of the same block
[672R block=0x40989a40 next=0x0]                  removal, and the head becomes 0
```

The removal sets the head to `0`, which is what a correct unlink does.  The
damage appears **after** it, and the word is not a stray pointer: reading it
back gives `word = 0x1` at `slot = 0x40989a50`, which is `state.start + 16`, the
`next_free` field of the heap's first block.  That block's header says
`size = 0x40` and `used = true`: it was handed out at sixty-four bytes, its new
owner wrote a reference count of one where the link is read, and the list head
still named it.  A sixty-four-byte block does not belong on the class a whole
64 MiB block is filed under.  The counters record one insert and one removal for
that class after `ensure_init`, so whatever put the head back did not go through
`insert_free_block`; which store did is not established, and it is the question
the next attempt should answer.

**The `protofire` reading is back, and it is reproducible.**  An earlier entry
reported `0x7269666f746f7270`, the first eight bytes of the volume label, in the
free lists; a later draft withdrew it on the strength of three runs that saw
`0x1` instead.  That withdrawal was wrong.  The same build, run four times,
reports the label four times, and a checkpoint pair puts it inside
`MemoryBlockDevice::new`: a walk immediately before it survives, and a walk
immediately after it finds `block 0x7269666f746f7270 outside heap`.

The withdrawal's argument was that every write of the label in the tree is a
`copy_from_slice` into a slice, which cannot silently run past its end.  That
argument is right and does not apply, because nothing here writes the label past
anything: the bytes in the free list are the **contents** of the `String`
`name.to_string()` builds, and the only way eight bytes of a heap-resident string
appear at `state + 112 + 5376` is for a store to have been given that address.
A `debug_assert!` in `allocate` that every returned payload lies inside the heap
never fires, so the allocator did not hand out the wrong address either.  What
ships the string's bytes to the allocator's own state is therefore not the
allocator and not PyroFS, and that is the narrowest this record has been.

**A machine with no disk fails the same way, so nothing in virtio is involved.**
Four runs with `virtio-blk-pci` attached and four with no disk at all, on one
build, each reported the damage 4 of 4.  The diskless path takes
`MemoryBlockDevice` and never touches PCI, DMA or a device queue, so the search
has no business in the driver layer.

**Three machines, one defect.**  The same two lines in `kernel_main` that walk
the heap after `mount_everything` report the damage on x86_64 and on riscv64 as
well as on aarch64, and on x86_64 they report it 3 of 3 from one build with the
heap at a fixed address.  Nothing about this is aarch64 specific, and the reason
aarch64 is where it was found is that aarch64's boot is the one whose later
consumers were large enough to fall over.

That matters for the work more than the diagnosis does.  x86_64 boots in seconds
under the gate, its heap address is the same run to run, and the failure is
deterministic there, so it is the machine to reproduce on.  Every earlier
measurement in this record was taken on the slowest of the three.

**The chain's head is valid and its first link is not.**  Reading the slot the
walk complains about, with two words either side, gives:

```text
slot 0x4a25fb8, idx 672
around: 0  0  0xa24a40  0  0
```

The slot holds `0xa24a40`, which is the heap's first block and a perfectly good
address; the words around it are zero.  So the free list is not what was
overwritten.  `0xa24a40` is a **free** block, correctly linked as the head of its
class, and the word that is wrong is the one sixteen bytes into it, which is
where `block_next_free` reads and where an allocated block's payload begins.
That word holds whatever the last writer of the block's payload left there, and
the block is free now, so either the payload was written after the block was
returned to the list or the block was never taken off it.  The counters in the
earlier entry say the removal happened and set the head to zero, which leaves
the first: a payload write that arrives after the block is free again.

**The block a list names is marked used.**  One more line, taken at the walk,
settles what the head is:

```text
free block 0xa23a40  size 0x40  used true  link 0x1
```

The head of class 26's list is a block whose own header says it is in use and
whose extent is sixty-four bytes.  `insert_free_block` beginning
`debug_assert!(!block_is_used(block))`, and that assert is live in this profile,
so the insert that put it there did not go through `insert_free_block`.  The only
other write to `free_lists` is `remove_free_block`'s
`state.free_lists[idx] = next`, and `next` comes from `block_next_free(current)`.
So the head was written from a link the walk itself read out of some block, which
means one free block's `next_free` word held the address of another block rather
than zero or a third free block's address.

That closes the loop this record has been going around, and the sentence it ends
on is a hypothesis with one measurement behind it: a free block's link word
holds payload bytes, `remove_free_block` copies that word into a list head, and
the next walk follows it to a block that is in use.  What the measurement shows
is the last step of that (a list head that is a used block) and the earlier ones
follow from where `next` comes from, but the write that puts payload bytes into a
**free** block's link is the one still to be found, and it is the only one left.

**Five explanations tested with a panic and ruled out.**  Each of these was a
`panic!` at the point where it would have happened, run on x86_64, and each left
the failure unchanged, which is what makes the list worth carrying forward:

- `initialize` runs once, so the heap's first block is linked once.
- No `allocate` returns a payload inside a block a list still names, so the
  allocator never hands out a linked block.
- No `remove_free_block` is asked to remove a block that sits on a different
  class's list, so every removal's class agreed with its block's size.
- No removal meets a block whose link names itself.
- No walk meets a free block whose link is a used block's address before the
  head that is itself a used block.

The last two deserve a note on why they are not contradictory with the head
being a used block.  The removals are all consistent and the walks that were
instrumented did not see a bad link, while the **head** of class 26 is a used
block, and by `mapping` a 64-byte block belongs to class 6, not class 26.  So the word
holding it did not come from any removal that was traced, and it did not come
from `insert_free_block` either, which asserts the block is free.  That is the
shape the next attempt has to explain, and it is narrower than "the heap is
corrupted": **one array element holds an address that belongs to a class it
could not have been filed under.**

**Two more measurements, and one assumption of mine that was wrong.**  The cells
either side of the bad one are zero:

```text
idx 672 near 0 0 a23a40 0 0
```

so this is one word written, not a run of them, and an out-of-range index into
`free_lists` is not what did it.  And a removal never leaves its block at the
head it named, which was checked by panicking in `remove_free_block` when the
slot still held the block on return; that never fired.

The assumption that was wrong is worth recording because it cost a build:
`find_suitable_block` returning a block from a **higher** class than the request
is the TLSF search working as designed, not a defect.  A search for class 48
returning the 64 MiB block of class 672 is exactly what the upward scan is for,
and a check that treats the two classes having to agree as an invariant panics on
the first large allocation:

```text
search asked class 48 got a23a40 of class 672 size 4000000
```

**Three more checks the same way, all clean.**  A block just marked in use is
reachable from no list at any position, not only at a head.  That check was first
written inside one of the three carve branches and missed the other two, which is
worth recording: the branches end at different places and only the last one had
it.  Moved after the branch, it still never fires.  `coalesce` never merges into
a block that is in use, checked at the point where it would have to.  And a
removal never leaves its own block at the head it named.

So the three functions that could put a used block into `free_lists` are each
clean by measurement, and the array element is still wrong.  That contradiction
is the whole of what is left, and it says the store happens somewhere none of
these three functions is on the stack: not the search, not the carve, not the
coalesce, not the removal.

**The instrument matters as much as the machine.**  `panic!` at a candidate
survives where `diag::write` made the fault disappear, and the difference is
that a formatted diagnostic goes through `core::fmt` and the allocator while a
panic does not.  Every earlier attempt in this record that printed a diagnostic
from inside the allocator changed the symptom; the ones that changed the
arithmetic did too.  Every measurement in this entry that is worth having was
taken with a panic on x86_64, which boots in seconds and fails at a fixed
address.

**The defect was not a regression from the restructure.**  A comparison against
the archived tree, read-only source material and not part of this one, found the
heap module there differing in comment wording, in `println!` becoming
`diag::write`, and in one compile-time assert; the allocator differs in how the
lock is spelled and in nothing else, and `MemoryBlockDevice` is byte for byte the
same.  With those files equal and the mount path equal, the defect is in code
both trees share.

What the archived tree does not have is a call to `verify_kernel_heap` anywhere
in its sources.  The function exists there, and nothing invokes it, so the
attributes below were never checked on a boot: the physical walk every boot does
was always clean, and the free lists were only ever read by code that had a
reason to follow one, which is the same asymmetry that let this defect survive
here until a walk was added.

That answers a question worth asking and does not move the search: the defect is
not new, so looking for what the restructure broke would have been looking in the
wrong place.

**The checker now looks at both structures.**  `check_invariants` walked only the
physical chain, which is the reason a walk after every allocation reported clean
on a heap whose next walk panicked: the headers and the boundaries between them
were all exactly right, and the list naming a used block was the one structure
nobody read.  It walks the free lists now, and reports the defect as
`a free list names a block marked in use` rather than leaving the next walk to
trip over an address.

`a_free_list_naming_a_used_block_is_reported` links a freshly carved block as
the head of its own class's list and asserts the walk names the used flag rather
than passing.  Removing the check makes that test fail with
`a list naming a used block walked clean`, so the test is doing the work it says.

With the checker widened, `heap_audit` was turned on for a boot: it audits after
every allocation and every release and reports the first operation that sees
damage.  It reported nothing, which is this record's contradiction stated with
the allocator's own instrument instead of a hand-written panic.  The write is not
inside an allocation or a release, and every later attempt should start from
that.

**And the boot's own check was reading one structure too.**  `verify_kernel_heap`
called `scan_free_lists` and nothing else, while `check_invariants` was reached
only from the audit and the damage report, so the widened check above would
never have run on a boot.  It runs both now, and the boot reports:

```text
a free list names a block marked in use
verify_kernel_heap: HeapDefect { address: 10631744, reason: "a free list names a block marked in use" }
```

`10631744` is `0xa23a40`, the heap's first block, named by the class a whole
64 MiB block is filed under while its own header says it is in use.  That is the
whole of what this record knows, said by the allocator's own invariant rather
than by a probe, and it is the sentence a fix has to answer.

**Its neighbours are exactly right.**  Reading the block and the one the
boundary arithmetic names gives:

```text
at 672  size 0x40  next 0xa23a80  next_size 0x40  next_used true
```

`0xa23a40 + 0x40` is `0xa23a80` and that block's own header agrees, and the one
after it is in use too.  So the heap's physical structure around the bad entry is
sound and the damage is one list entry, not a boundary arithmetic that drifted.

**The answer: there are two allocators, and the checker inspects the one nothing
uses.**  `kernel/src/lib.rs` declares the `#[global_allocator]` as its own
`KernelGlobalAllocator`, `GLOBAL_ALLOCATOR`, and `libs/allocator`'s wrapper keeps
a second one, `HEAP_MODEL`, which `HeapAllocator` and `verify_kernel_heap` go
through.  Both lay their free lists over the same `KERNEL_HEAP` array, and only
the first is ever asked for memory:

```text
model state 0x4a25a48   global state 0xa24008
model remaining 67108864
model remaining after mount 67108864
```

The second number is the whole answer.  `HEAP_MODEL` never allocates anything, so
its `free_lists` still describe the heap as one free 64 MiB block.  The global
allocator, which every `Vec` and `Box` in the kernel goes through, has been
carving that same memory for the whole boot.  So `verify_kernel_heap` walks a
bookkeeping record that stopped being true at the first allocation, and reports a
free list naming a block marked in use because the block really is in use, by the
other allocator.

Nothing was ever corrupt.  Every symptom in this record, from the ECDSA index to
the release build's silence, is what a stale second view of one heap does when
something finally reads it.

That also explains the two properties that made this so hard to chase.  It is
layout sensitive because whether the stale view's first block has been handed out
yet depends on the allocation sequence, and every diagnostic that allocated moved
that sequence.  And `heap_audit` never reported anything because it audits the
global allocator, which is the one that is right.

**The repair: one heap, reached through handles.**  The free lists were a field
of `KernelGlobalAllocator`, so two objects of that type held two views of one
arena.  They are a `static` in `libs/allocator` now, and the type is zero-sized,
so a handle is a way to reach the lists rather than a place to keep them and the
divergence is not something a caller can write down.

Two tests hold the property.  `a_second_handle_sees_the_first_handle_s_allocation`
allocates through one handle and asserts the other one's byte count moved, then
runs the check through the second; with the state put back in a field it fails
with `67108864` free before and after, which is the boot's own number.  And the
boot walks the heap after the mount and prints the verdict the walk reached:

```text
protofire: heap checked after mount, carved 0x51040 byte(s), and the free lists agree
```

The line states the **verdict** and not the byte count, and the first draft of it
got that wrong.  The count moves with the allocation sequence: it read `0x3faefd0`
as free bytes until a comment-only change moved one allocation and it read
`0x3faefc0`, which made the gate report a documentation edit as a defect.  What
does not move is whether the arena was touched at all.  A stale second view still
describes the whole range as free, so the boot compares what the walk reads
against the arena's own size, and an untouched arena prints

```text
protofire: heap check after mount saw an UNTOUCHED heap, so it is reading a second view
```

and panics.  The gate requires the `carved ` prefix, which that sentence does not
begin with, so the regression cannot satisfy the requirement with its own
failure.  Putting the state back in a field was re-run to confirm it: the boot
prints the `UNTOUCHED` line, and the gate fails.

The aarch64 fault that started this search is gone with it: the chain check
after the network exercise reports `verified yes` on four consecutive boots, and
the earlier entries' `0x5` and `0x15` data aborts do not recur.

**The trigger moved twice, and the earlier entries' answers were younger
symptoms.**  The first entry said `libs/crypto`; the second said `ping_gateway`.
Both were true statements about what failed first, and neither was the cause.
What made the difference was walking the allocator's invariant instead of the
call that crashed: the ECDSA index that reached eight, the `0x5` and `0x15` data
aborts, and the release build's silent stop are one damage seen from four
places.

**Widening `prod` changes the symptom, which is what a corrupted stack looks
like.**  Giving the product's array a sixteen-limb backing store and copying the
first eight out does not fix the arithmetic, but it does change what the fault
looks like: the panic and the data abort both go away, and the chain answers
`verified no`.  That is not evidence about `mul_256_by_256`; it is evidence that
the failure depends on the frame's layout, which is what a stack whose
neighbour has already been overwritten does when a local moves.  Reading it as
an overrun in the multiply is what the earlier entry did, and it is the reading
this entry replaces.

**The release build fails worse than the debug one.**  In the release profile the
boot does not print the panic at all: the last line is the multicast exchange and
the boot stops there.  Debug has the bounds check that names the index; release
has undefined behaviour, and a boot that stops without a word is what it looks
like.  `check --machine aarch64 --profile release` fails with the serial log
ending at that line.

**What is left is the allocator, and that is a different subsystem's change.**
The next step is not a debugger on ECDSA: it is a test that allocates a block,
writes its payload, and then walks the free lists, which is where the missing
unlink shows up without a certificate anywhere in the picture.  The repair
belongs to `libs/allocator` and to whoever writes that test, and this entry's
job is to say that the crash was never in the cipher.

Two things about the search are worth keeping.  The failure moves with the
binary: it is a bounds panic at `ecdsa.rs:492:28` in one build and a data abort
at `0x5`, `0x15`, `0x1d`, `0x25` or `0x2d` in another, and that variability is
the corruption showing through, not five defects.  And `verify_kernel_heap` is
the instrument that found it: it is what turned "a cipher crashes after the
network" into "the heap is already broken before the network starts".  It costs
a walk of every free list, it exists only under `debug_assertions`, and it is
worth calling from any boot path that has just done something the allocator has
not been asked to do before.

**This is why `net::x509` has no boot probe.**  One would make every aarch64
boot fail on a defect that is not this subsystem's, and the failure would be
attributed to X.509 by whoever read the line.  Its 13 host tests are the whole
of the evidence it has, and the paragraph above the chain check says so where
the module's status is recorded.

What is not here: **revocation** (OCSP and CRLs are a network protocol and a
distribution decision) and **validity windows** (the check needs a clock, and a
verifier that guessed one would check a certificate against a time nobody
chose).

[RFC 5280]: https://www.rfc-editor.org/rfc/rfc5280

**The timeout is measured now, not assumed.**  `RTO_INITIAL_MICROS` was the
timeout for every stream on every path, and one second is right for no path: a
machine on a fast wire retransmits a segment that was merely in flight, and one
on a slow path gives up on a segment still coming.  [RFC 6298]'s estimator is
here: the first acknowledgement that measures a round trip **is** the estimate,
each later one moves it an eighth of the way and the variance a quarter, and the
timeout is `SRTT + 4 * RTTVAR`, floored at a millisecond and capped at sixty.

Two rules make it a measurement rather than a number that moves.  A segment that
was retransmitted contributes **no sample** (Karn's rule): its acknowledgement
cannot say which copy it means, so the round trip it appears to measure may be a
measurement of the timeout.  And a measurement replaces the backoff, because a
path that just answered has said how long it takes.

```
protofire: round trip 7312 then 10910 microseconds
protofire: the estimate moved with the measurement
```

Two lines because the numbers are the machine's clock and change every boot:
the gate can require a prefix and not a suffix, so the verdict is its own line
and the numbers are read by a person.  The mutation is the estimate's: make it
never move and the second line disappears.

[RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298

**The close has its own states now, and three of them it did not have.**  The
state machine had seven, and a close used two: this side's finish was `FinWait`
and the peer's acknowledgement of it went straight to `Closed`.  That is one
state for two jobs, and it lost two facts.  A finish the peer has acknowledged
is not the same as one it has not, because the first is never retransmitted and
the second is.  And `Closed` meant the table forgot the four-tuple at once, so a
peer's retransmitted finish, arriving after the close, found no connection, and
this stack answers a segment for a port nothing owns with a reset, which is a
close the peer did not ask for.

`FinWait2` (done sending, listening for the peer's finish), `Closing` (both
finishes sent and crossed, one acknowledgement still owed) and `TimeWait` (the
close is over and the four-tuple is held) are the states [RFC 793] names for
those cases.  `TimeWait` holds for `2 * MSL`, sixty seconds, and a finish
retransmitted inside it is answered with the same acknowledgement rather than
reset.

```
protofire: tcp closed, both ends held in time wait
```

The mutation is the probe's own: asserting `Closed` prints `both ends
MISMATCH`, and so does a `prune` that drops `TimeWait` the moment it starts.

[RFC 793]: https://www.rfc-editor.org/rfc/rfc793

**The frame path had a defect the loopback could not show.**  Every TCP
exchange this tree runs is a loopback, and a loopback hands a connection the
payload it built: no frame, no header, no data offset.  A frame from a card is
the other path, and both demux functions handed `receive` the **whole packet**,
so a stream fed by a real card carried its peer's twenty-byte TCP header as the
first twenty bytes of data.  QEMU's user-mode network is a real peer, so this
would have been the first thing a non-loopback exchange saw.

The fix is one slice, and the segment says where: `Segment::payload_at` is the
data offset times four, and `payload_len` is the packet less that offset rather
than less a constant `HEADER_LEN`.  The IPv6 parser already did this; the IPv4
one did not, which is the sort of difference a second reader does not see until
a segment carries an option.

```
protofire: frame data 8 byte(s) sent, 8 held, the headers stayed out of the stream
```

The probe builds two frames the way the card would carry them, one with the MSS
option and one without, and sends both through `demux`: a reader that used a
constant header length would take the first segment's option as data and be
right about the second.  Handing `receive` the whole packet prints
`8 byte(s) sent, 52 held, MISMATCH`, which is forty extra bytes: two twenty-byte
headers and one twenty-four.

**A SYN states its MSS, and the option is read.**  The header was always five
words, so this stack never told a peer what it can receive, and never learned
what a peer can: a sender assumed `MSS_DEFAULT` and a peer using RFC 1122's
536-byte default would have discovered the difference as loss.  A SYN now
carries the option, `parse` walks the option list (walked, not searched: a value
byte of an earlier option may be the MSS kind's own number), and
`Connection::note_send_move` applies the peer's number through the same
`limit_segment` a path report uses, so it only ever shrinks.

`TCP_NODELAY` was in the options table and read by nothing, which is the exact
defect that table's own module documents.  It now decides Nagle's rule: a small
write with anything in flight is held unless the option is set.  Three tests
hold the three halves apart, and removing any one of them fails exactly one:
the rule, the option, and the "a full segment is not small" exception.

**The other window, the peer's, is a bound on sending.**  The `window` field was
in every parsed segment and read by nothing: a sender compared the congestion
window and the queue's size, so a peer that advertised less than either was sent
past what it said it would take.  The bound is now the smallest of the three, and
it is kept on the connection as [RFC 793]'s `SND.WND`, read from every segment
whose acknowledgement is in the range that section calls acceptable.

Writing that bound found a second defect, in the send loop rather than in the
window: the loop tested `carried < budget` and then appended a whole MSS, so a
3012-byte budget sent 4380, one segment past the window.  No test had seen it,
because the congestion window is ten whole segments and was the only bound that
was ever smaller; the peer's window is an arbitrary number and made it reachable
on the first write.  A segment is now clamped to what the budget has left.

```
protofire: peer window 8192 -> 0 -> 9, the peer's window bounded the write
```

The probe states a window on the peer's behalf, because both ends of every other
exchange advertise `WINDOW` and nothing in a boot makes a peer say a small
number: a bare acknowledgement carrying zero, a write that carries nothing, and
the same write carrying nine bytes once the peer reopens.  Removing the bound
prints `8192 -> 14600 -> 0, MISMATCH`.

[RFC 793]: https://www.rfc-editor.org/rfc/rfc793

**Three local-domain numbers: `BindLocal` (97), `ConnectLocal` (98),
`AcceptLocal` (99).**  A name two processes meet at, a connection made when one
connects and taken when the other accepts, and bytes in both directions.  The
name is **bytes** and not a filesystem path: nothing resolves it through a
namespace and a filesystem may hold a file of the same name, which is what makes
this a socket rather than a file a program would have to create and clean up.

The connection is **two pipes**, not one.  One pipe per local socket, the client
keeping its write end and the server its read end, is a client that cannot read
what its server answered, which is half of what a socket is.  Two pipes cost one
more buffer per connection and make the connection a connection.
The mutation is the probe's: wire both halves to one pipe and the line reads
`5 byte(s) forward, 0 back, MISMATCH`.

A pipe's counts are its hands, so both ends of both pipes exist at **connect**
and not at accept.  A pipe with no reader handle answers a write with zero, which
is the rule that stops bytes going nowhere; a server's reader made only when it
accepted would have dropped everything a client wrote in between, and the first
version of this did exactly that.

```
protofire: local socket 5 byte(s) forward, 6 back, both ways through one name
protofire: process 1 bound the local name, descriptor 6
protofire: a program waits to accept a local connection
protofire: a local connect woke 1 blocked task(s)
protofire: process 9 connected to the local name, descriptor 12
protofire: process 1 accepted a local connection as descriptor 13
protofire: a program blocks on a local socket
protofire: a local write woke 1 blocked task(s)
```

The last four lines are two ring-3 processes and not the kernel: `init` binds a
name, forks, and the child connects and asks while this process accepts and
answers.  The child's exit status is `114`, the `r` of `reply`, which only a
connection that carried bytes back could have put in its register.  The park and
its wake are printed and are **not** gate lines: whether a read parks or finds
its bytes already there is the scheduler's choice, and requiring that line made
the gate fail on a boot where the child's write landed first, with identical exit
statuses and nothing broken.

Two defects were found by writing this, and both by the exit statuses rather than
by a host test.  A connect that queued a connection and woke nobody left the
server parked for ever, so `ConnectLocal` now wakes.  And the local `Read` branch
was a copy of the pipe's, which reads `a1` and `a2`, while `sys_read` packs a
stream's slots: `a1` the offset, `a2` the buffer, `a3` its length.  Every ring-3
read of a local end was therefore refused for a range whose "buffer" was the
read-from-here sentinel `0xffff_ffff_ffff_ffff`, which is what the exit statuses
`243` and `245` were saying.

**Three more: `CreateRawSocket` (76), `SendRawPacket` (77), `RecvRawPacket`
(78).**  A socket keyed on an IP **protocol number** rather than a port, which
is what lets a program implement a protocol this stack does not have.  The
demux hands it the payload of every packet this machine accepts with that
number, after the stack's own handling has run: an ICMP error a stream acted on
is still a message a program watching ICMP may read, and a stack that deflected
a packet to a raw socket would change its own protocols' meaning when a program
opened one.

The send does **not** take a header.  A program names a protocol and a payload
and the stack composes the IP header, because a program that wrote its own would
also choose its own source address and its own length, and the fields the stack
answers for would become the program's.  A raw send over IPv6 is `Unsupported`
rather than an IPv4-shaped packet: this stack's IPv6 sender writes no extension
chain for its own transports either.

```
protofire: raw socket sent 10 byte(s) as protocol 253, and received 10 from this machine
protofire: process 1 made a raw socket for protocol 253 as descriptor 6
protofire: process 1 sent a raw packet of 3 byte(s)
protofire: process 1 received a raw packet, 3 byte(s)
```

Protocol 253 is [RFC 3692]'s experimental number, so nothing else on the machine
sends or receives it and the packet the receive finds is the one the send put
there.  The kernel's probe sends a frame this machine addresses to itself and
hands it to the **demux**, not to the queue: a loopback that delivered straight
to the socket would exercise the queue and nothing else, and the header is the
part a raw send must get right.

Writing this found two defects, and both made the receive park rather than fail.
The frame's header claimed twenty bytes more than it carried, because the length
passed to `ipv4::write_header` is the payload's and the probe passed the total,
so `parse` refused the packet for a length mismatch.  And `SendRawPacket` shared
the datagram branch, whose `a2` is the buffer's pointer where a raw send's is
the destination address's width: the call was served with the datagram handler
and the log printed the **pointer** as a byte count.  Both are why `init`'s raw
exchange is a gate line and not only the kernel's probe: the ring-3 path is the
one whose argument slots differ.

[RFC 3692]: https://www.rfc-editor.org/rfc/rfc3692

**The stream calls are served, and both halves park.**  `ConnectTcp` (38) and
`ListenTcp` (56) answer through the registry; `AcceptTcp` (57) is served by
the trap path, because it parks, and a stream's data rides the same `Read`
and `Write` a file and a pipe ride.  `init` proves the whole of it with the
same two processes the datagram exchange used: this process listens on port
9003 and accepts, the fork connects, writes nine bytes, and reads the echo
back, the child's own read parks until the echo arrives.  Measured on
x86_64:

```
protofire: process 1 listening on port 9003 as descriptor 6
protofire: a program waits to accept a stream
protofire: a stream event woke 1 blocked task(s)
protofire: process 8 connected to 10.0.2.15 port 9003 as stream 12
protofire: process 8 wrote 9 byte(s) to a stream
protofire: process 1 accepted a stream as descriptor 13
protofire: a program blocks on a stream
protofire: process 1 read 9 byte(s) from a stream
protofire: a stream event woke 1 blocked task(s)
protofire: process 1 wrote 9 byte(s) to a stream
protofire: process 8 read 9 byte(s) from a stream
```

Both parks ran, and each wake is the other process's call: the connect woke
the parked accept, and the echo's write woke the parked read.  The child's
exit status is the echo's first byte, `112`, which is `p`, a number only a
completed round trip could have carried, and the gate requires it as the
status line's own fact.  The accept and the listen are prefixes on every
machine, because the descriptor numbers are the table's to hand out; the
four lines that name lengths are exact.

A network stack above this is done as `docs/roadmap.md` Level 5 promised it:
`net` carries Ethernet, ARP with its cache, IPv4, ICMP, UDP and TCP, and the
seven numbers the level serves are reachable from ring 3.  What it did not
promise stands: the twenty-three protocol numbers beside them, routing
beyond one gateway, DNS beyond a hosts table, and a stream connect to
another machine, each its own level's decision.

**Where the connection table lives.**  The streams a machine holds, the id
per end, the port a listener reserves, the queue a completed handshake waits
in, and the counters that hand out ids and sequence numbers, are
`net::tcp_table::Table`, not `kernel/src/net/mod.rs`.  All of it is protocol
state: the four fields a segment is keyed on are the wire's, and nothing in
the table needs a card, a scheduler or a lock.  What stayed in the kernel is
the part that does: the one lock, whether an address is this machine, which
hardware address a frame goes to, and when a parked task wakes.

The split is what made the table testable off a machine.  Seven host tests
now run the lookups, the id and sequence counters, the listener's pending
queue, the prune, and the rule that only a SYN with no ACK opens a
connection, none of which a boot could isolate.  One of them found a defect
on its first run: `accept_syn` built the SYN with ACK and **dropped** it, so
a caller had no way to answer a client whose handshake it had just accepted.
The function answers the reply now, which is the same shape every other move
in that crate has, compute a value, let the caller decide its wire.

Two more pieces followed it, by the same test: does it need a card, a
scheduler or a lock?

| moved | to | why it was not the kernel's |
|---|---|---|
| a datagram socket's queue | `net::udp_socket::Queue` | the ordering, the `QUEUE_LIMIT`, and the rule that a too-small buffer is refused with the datagram **kept** are the wire's; only the `Arc`, the `Weak` port entry and the wake stayed |
| the echo reply, the advertisement, the echo request and the solicitation | `net::reply` | they are three headers stacked, and composing them in the kernel meant the kernel knew where an ICMPv6 header begins inside a frame |

The second is not tidiness.  A neighbour advertisement's checksum covers a
pseudo-header built from the addresses the answer is sent from and to, and
the first IPv6 round had already produced one wrong checksum, eight bytes of
an option the message did not contain, counted into the length.  Four host
tests now compose each frame and **verify it against the ends it names**, and
one asserts the solicitation's length difference is exactly the option's
eight bytes, which is the defect that round found.  A boot could only ever
learn that by failing.

`kernel/src/net/mod.rs` is 196 lines smaller across the three moves, and every
line that left is arithmetic a host can now run.

**The transports carry over IPv6.**  Until this change the IPv6 side answered
a neighbour and an echo and stopped: a datagram or a segment could be parsed
and never routed, because a socket and a connection were keyed on four bytes.
The state is now keyed on `net::address::Address`, which carries its family
with its bytes, and the demux routes `NEXT_UDP` and `NEXT_TCP` as well as
`NEXT_ICMPV6`.

Two lines say so, and both are asserted on all four machines:

```
protofire: ipv6 udp received 10 byte(s) from this machine
protofire: ipv6 tcp echoed 2 byte(s) of 2, round trip
```

Each is a real round trip through the receive path, not a claim about code: a
datagram written by `send_datagram` with an IPv6 address, framed for the
card's ethertype, parsed back by `demux_ipv6`, routed to the socket the
address names, and read off it, and a stream that opens, carries two bytes,
echoes them and closes, all over IPv6.  The sender the datagram answers with
is checked to be this machine, so a demux that routed by the wrong address
would print the other line and fail.

**The machine negotiates its own address.**  Until this change the protocol
address, the gateway and the name server were three constants in
`device.rs`, named because QEMU's user-mode network happens to use them.  A
machine that is not QEMU's therefore could not join a network at all.

`net::dhcp` is the four-message exchange of RFC 2131, and the boot runs it
before anything else touches the card:

```
protofire: dhcp leased 10.0.2.15 from 10.0.2.2, router 10.0.2.2
```

The address on that line is what slirp granted, not what this tree guessed: the
line is the same three numbers only because slirp's defaults happen to match
the constants that used to be here, and a different server would print
different ones.  A network with no server prints its own line and keeps the
built-in address, which is why this is a probe the boot reports rather than a
step it depends on.

The exchange found one ordering defect while it was being wired: the first
version ran before `post_receive_buffer`, so the DISCOVER went out and no
reply could arrive.  The line said "found no server", which is exactly what a
correct stack on a serverless network says, which is why the boot's own line is
the evidence rather than the absence of an error.

**Names resolve through the server a lease named.**  `net::dns` is the query
this stack builds and the answer it reads back, including the compression
pointers a response uses to spell a name once.  The boot asks a real server:

```
protofire: dns resolved example.com to 104.20.23.154
```

That address came from QEMU's resolver, which forwards to the host's, so the
line is evidence of a name resolved by a machine that is not this one.  It is
deliberately not a gate line: a CI machine may have no network, and a gate that
fails for a reason the tree cannot fix is a gate nobody can rely on.

**A router's prefix configures a global IPv6 address.**  `handle_icmpv6` had no
branch for a router advertisement at all, so the SLAAC code in `net/src/internet/ndp.rs`
had no caller and no machine could reach it.  It has a branch now, and the boot
proves it by putting an advertisement through the same receive path a real one
arrives at:

```
protofire: slaac configured 2001:0db8:0000:0000:5054:00ff:fe12:3456 from its router's prefix
```

The address is the router's prefix with this interface's own modified EUI-64,
which the boot checks against the MAC it knows: a stack that built the address
from anything else would print the other line.  Three refusals live in
`net::ndp::configure_from` rather than at the caller, each RFC 4862's: a prefix
whose autonomous flag is clear, one that is not a /64, and one with no valid
lifetime.

**A fragmented datagram is put back together.**  Both families' receive paths
used to read a piece as the whole or drop it: IPv4 had no reassembly, and IPv6
refused the fragment header outright.  `net::reassembly::Cache` holds the
pieces now, bounded in every direction a sender controls, and asserted on
every machine:

```
protofire: fragments reassembled 20 byte(s), intact
```

The boot's own exchange splits one UDP datagram at an eight-byte-aligned
offset, sends both pieces through the demux the wire uses, and reads the
payload back out of the socket.  The line names the payload's length and that
it is intact, which only a correct reassembly produces.

Two bounds are worth naming because a peer chooses them.  A payload past
sixty-five thousand five hundred and fifteen less a header is refused before
anything is held, and a piece that covers bytes another piece already covered
**and disagrees with them** takes the whole datagram with it, [RFC 5722]'s
rule, and the reason the cache keeps the bytes rather than a bitmap of what
arrived: coverage alone cannot tell a retransmission from an attack, and the
first version of this code could not either until a test failed.

[RFC 5722]: https://www.rfc-editor.org/rfc/rfc5722

**A closed port is now told, not silent.**  `deliver_udp` answers
`Delivery::Unbound` when no socket owns the port, a fact it could not report
before, because "nobody was waiting" and "nobody owns it" were the same
`Ok(0)`.  The demux turns that into [RFC 792]'s port-unreachable report: the
sender's own header and the first eight payload bytes quoted back, so the
sender can match the report to its socket.  Nothing is sent about a datagram
addressed to a group or to the broadcast address, which is [RFC 1122]'s rule.

A boot cannot check the report's contents, a report only goes to a sender
that sent something, and this stack's own senders are the loopback, so the
assertion is a host test that builds the frame `answer_port_unreachable` would
send and reads the sender's source and destination ports back out of the
quote, at the offsets the sender's own header layout puts them.

[RFC 792]: https://www.rfc-editor.org/rfc/rfc792
[RFC 1122]: https://www.rfc-editor.org/rfc/rfc1122

**Crossing the syscall boundary cost no numbers.**  `SendToUdp` (59),
`ConnectTcp` (38) and `RecvFromUdp` (60) all sit below the frozen boundary, and
all three had a reserved word that must be zero.  That word is now a flags
word, and `NETWORK_FLAG_IPV6` is the only bit: with it set, the address slot
is a pointer to sixteen bytes instead of a packed word, and the sender record
is the wider one.  A caller passing zero behaves exactly as it did before,
which is what `docs/fmts/syscall-abi.md` §3.2 permits in the frozen range
"additive *optional* behaviour is the only permitted change", and the section
there now states the flag's meaning per call.

A second number per call was the alternative.  It would have spent
experimental-range numbers to say something the flags word had room for, and
left two spellings of one operation to keep in step.

**Services, built, and deliberately parked.**  A table from a name to a
service, installed during boot and frozen before anything looks one up; a caller
asks for a name and drives what it gets through one trait, without knowing which
crate implements it.  The first
service in it is the clock, whose answer is the machine's own counter, so the
boot shows the shape working end to end rather than only in host tests:

```
protofire: services installed = 1, frozen
protofire: clock service answered 0x212ae78a through the table
```

The reading is hardware and not a constant: three boots answered `0x2167a7ec`,
`0x22a11df2` and `0x2134f3b4`.

Two defects were found building it, both in `async_io` and both by writing the
test first:

- **An interleaved submission lost its completion.**  `submit` counted only the
  completions already in the queue, not the ones pending requests would produce,
  so submitting after a poll could spend a slot twice; the transfer ran, the
  device did the work, and `poll` dropped the completion with `let _ =`.  The
  check is `completions + pending` now, and the two pushes that follow assert
  their result instead of discarding it.
- **The trait could not hand a completion back.**  `poll` answered `bool` and
  each service kept its queue in a private field, so a `&mut dyn Service` could
  be driven and never read.  `Service::take_completion` is the fourth method,
  and the test for it is written over the trait object rather than a concrete
  type, a generic bound would have passed without the trait being usable.

Two halves of one crate and one ring-3 program answer to the word "service",
and they are not the same thing:

- **`kernel/src/service/table.rs`** is the table: `install`, `lookup`, `freeze`,
  and a value type so a test can build its own.  It knows how to hold a service
  and nothing about which services exist.  It was a crate of its own (layer 7)
  until its only consumer turned out to be the kernel module beside it, which
  is why it is a module now.
- **`kernel/src/service/` around it** is what this boot installs: `install_all`
  names the clock, `clock.rs` implements it.  A kernel with a second service
  changes this directory and not the table.
- **`apps/service_manager`** is a ring-3 program, and it is where "everything is
  a service" is meant to end up: it supervises processes with lifecycle policies.
  Its own header still says it is a shell because supervising needs a restart
  policy, the spawn, wait and signal calls it was waiting on have since landed,
  so what is missing now is the policy and not the mechanism.

The first two split for a reason worth keeping: the table is a mechanism, the
list is this boot's content, the same division as `fs`'s `MountTable` and
`kernel`'s `volume` module, one the merge made a division inside the crate
rather than between crates.

What a service is **not**, yet: a device.  Every driver still submits through
`block`'s `QueuedBlockDevice`, and the clock answers in the call and has no
queue, so nothing in a boot exercises the *pending* half of the model.

**This is parked on purpose, not half-finished in the way.**  "Everything is a
service" is a direction for later, and the work above exists so the direction has
a base when it is reached, not because it is the next thing to build.  It landed
early: `async_io` was being reviewed for whether it should exist at all with no
caller, and the answer "keep it, and here is the layer it is missing" turned into
building that layer.  The reasoning was sound and the result is gate-green, but
the *timing* was not the plan.

So: nothing below is scheduled, and no further work on the service layer should
be started without deciding it is time.  In particular:

- **No driver implements `Service`.**  `VirtioBlock` stays on
  `QueuedBlockDevice`, which works and has a caller.
- **No syscall reaches the table.**  No number names a service; 197 names the
  IPv6 status call and nothing here, and the 102 numbers that are served are the
  memory, filesystem, process, time, descriptor, datagram, stream and protocol
  calls.  `ServiceDeclare` and `ServiceStartAll` are unserved, which is why
  nothing here is reachable from a program yet.
- **`apps/service_manager` stays a shell.**  It is the ring-3 half, and it is the
  half that matters when this direction is picked up.

The four items this section lists below are the prerequisites for that half, and
they are prerequisites for a userland of any shape, which is why they are worth
reading whether or not this direction is taken.

### What the user-space half needed, and what it got

"Everything is a service" is a direction, and the user side is the larger half
of it.  When this section was written it listed four prerequisites, in the order
they blocked each other.  Three have landed; this is the honest scorecard rather
than the list.

| prerequisite | state | evidence |
|---|---|---|
| the memory layer | **done**, `Mmap`, `Munmap`, `Brk`, `ReclaimPages` served | the `program memory call` lines below |
| a process a program can start | **done**, `SpawnProcess` plus the six signal calls | `process 1 spawned /bin/shell as pid 5` |
| a way to reach the table from ring 3 | **done**, 102 numbers reachable, the registry holding 81 of them | `syscall table installed, 81 number(s) served` |
| **a handle that can be given away** | **not started** | `Descriptor` still has two variants, `File` and `Pipe` |

The last one is the one that matters now, and the fourth line of the old list
explains why it waited: a service handle is a `Descriptor` variant carrying the
rights it was granted, and passing one between processes is the change that
makes the service table a thing programs use rather than a thing the boot fills.

What has **not** been done is the service layer itself.  `service_manager` is
still an entry point and a panic handler, and the reason is in its own header:
supervising needs a restart policy, and a manager of processes and a manager of
services are the same code until something needs one.

**Memory.**  A program can ask for memory and get it.  `Mmap`, `Munmap`, `Brk`
and `ReclaimPages` are served from ring 3, four numbers that had none, and the
boot shows a program using two of them:

```
protofire: program memory call 67 answered 0x807ffff000
protofire: program memory call 92 answered 0x8040003000
```

`67` is `Mmap` and `92` is `Brk`.  The mapping's base is the last page of init's
own window, reservations count **down** from the top, because the image starts
at the window's base, its stack is one page above the image, and `Brk` grows up
from the stack; growing mappings down from the top keeps the two ends apart.  The
break is one page past that stack.  Both are addresses the kernel computed from
the program's own layout, and a kernel that had mapped nothing could not name
either, which is why the two lines are the evidence and not the fact that the
call returned.

The store is the other half: init writes a byte into the page it was given, and
the boot reaches its exit status.  A mapping the kernel reported but did not make
would fault there instead.

`AddressSpace` changed to make room: the frame list was a fixed array sized by
what an **image** may weigh, and a heap has nothing to do with an image's size.
It is a `Vec` now and the bounds are two, `MAX_IMAGE_FRAMES` (65) for the
loader's budget and `MAX_OWNED_FRAMES` (4096) for what one space may hold.

**Raising that bound was not enough to raise it.**  Two stack arrays had been
sized by it while it was 65: `fork_from`'s page list (98 KiB at 4096) and the
exec path's (32 KiB).  The kernel stack has neither, and every riscv64 boot died
with a store page fault three frames below `USER_BASE`, reported as
`unhandled exception ... on cpu 4294967295`, because the fault had already
destroyed the register that names the CPU.  Both are sized by the image bound
now, which is the set of pages each actually describes.

**The file interface.**  A program can write, measure, list, move and remove.
Eleven numbers serve the filesystem now, `Write` (6), `CreateDir` (19),
`RemovePath` (21), `Stat` (27), `ReadDir` (28), `Rename` (29) and the five
`*At` forms (32–36), where a program could previously only open, read and
close, and `Write` printed a fixed line instead of writing anything.  The boot
execs a program that does the whole of it against the tmpfs and shows each
answer beside the call that produced it:

```
protofire: process 1 opened note.txt via descriptor 0
protofire: process 1 wrote 19 byte(s) to a file
protofire: process 1 opened note.txt via descriptor 0
protofire: process 1 stat'd note.txt via descriptor 0, kind file, size 19
protofire: process 1 created directory notes via descriptor 0
protofire: process 1 opened at.txt via descriptor 5
protofire: process 1 wrote 4 byte(s) to a file
protofire: process 1 stat'd at.txt via descriptor 5, kind file, size 4
protofire: process 1 read /tmp/notes entry 0
protofire: process 1 renamed note.txt via descriptor 0 to kept.txt via descriptor 0
protofire: process 1 stat'd /tmp/kept.txt, kind file, size 19
protofire: process 1 removed scratch.txt via descriptor 0
```

The descriptor number on those lines is the table's, not the program's, which
is why the gate takes them as prefixes.  The checks the program makes on its
own are stricter than the lines: it compares the read-back bytes, the stat
record's kind and size, and the listed name against what it wrote, and exits
with a status that is not the greeting's byte when any of them disagrees
so the boot's `exit statuses 1 -> 116` is the whole program's claim, and a
broken step turns the gate red rather than printing something plausible.

The rights a descriptor holds are the open's: a `writable` flag recorded
beside `readable`, refused with `PermissionDenied` on a descriptor that did
not ask.  A create is the volume's own refusal when the volume cannot create,
not the lookup's miss that prompted it.  A rename whose two names resolve to
different filesystems is refused outright, the alternative is a copy and a
delete, whose halfway failure is the one outcome a rename exists to make
impossible.

The `*At` forms anchor on a descriptor, and the anchor is the descriptor's
record: every open now records the path it resolved to, because a node knows
its own last component and nothing of the namespace above it.  An absolute
path bypasses the anchor; the `AT_FDCWD` sentinel anchors at `/`, the one
base every process shares, because there is no per-process current directory
yet; anything else resolves against the directory the descriptor was opened
from.  A file, a pipe end, or another process's descriptor is not an anchor.

Two defects the first ring-3 exercise found, both recorded because a gate
that had never called these numbers was green through both:

- The five `*At` handlers were wired but **never registered** in the boot's
  table, a silent python replacement in the change that added them skipped
  `boot.rs` and nothing in that change's gate called the numbers.  The first
  program to call one got `NotImplemented`, and the probe that found it is
  the reason the registrations carry a comment.
- A program linked as PIE routes calls to its own library symbols through a
  GOT whose slots are filled by `R_X86_64_RELATIVE` relocations the loader
  does not apply.  The first image big enough to make the linker route a
  `bcmp` that way died jumping to address 0.  init now links `-no-pie`, which
  resolves those slots at link time, honest for an image whose load address
  the linker script fixes, and the flag lives in the command that builds
  init, not in the target's config, so the kernel's own relocatable build is
  untouched.

One entry-assembly defect fell out of the same exercise, on the memory side
of the boundary: x86_64's `iretq`-into-ring-3 left the kernel's own selector,
flags and hand-over pointer in the three registers a program's arguments
travel in (`rdi`, `rdx`, `rcx`, measured), because `iretq` changes rings and
touches no general register.  Every program's first `Write` therefore carried
a length the kernel was right to refuse.  The entry zeroes the program's
registers now, the same clean slate `Context::user` builds and the trap
epilogue restores everywhere else.

The boot's policy grew the permission these calls are policed by: the system
label may read and write unlabelled files **and** the scratch zone, because
`/tmp` is not unlabelled, the layout resolves it to `MAC_TYPE_TMP`, and the
scratch zone is the one the boot mounts for its programs.  The rule's
permission field is a set, which is what makes read and write one rule per
object; two `add_rule` calls with `replace` on would have displaced each
other, and the first attempt did exactly that, the boot's own allow probe
printed `MISPOLICED`, which is what caught it.

**The process model.**  A program can start a program, and processes can
signal each other.  Seven numbers serve the level, `SpawnProcess` (25) and
the six signal calls (`SendSignal` 40, `WaitSignal` 41, `SetSignalHandler`
104, `SetSignalMask` 94, `SigReturn` 134, `SigSuspend` 135), and the boot's
`init` runs the whole of it: it starts `/bin/shell`, the child announces
itself with a signal, the parent delivers one to the child's **own handler**,
and each child exits with the greeting's length.

```
protofire: process 1 spawned /bin/shell as pid 5
protofire: process 5 sent signal 10 to process 1
protofire: a signal wait answered signal 10 from process 5
protofire: a suspend answered signal 10 from process 6, mask put back
protofire: every program exited, 6 exit(s), 429 tick(s), 32 switch(es), 2 signal delivery(ies)
```

The spawn shares one image construction with `exec`, read, parse, map,
stack, exec block, and the child inherits nothing: a fresh process opens
its own files.  The signal's ring is the target's own, eight deep, FIFO,
carrying the sender **with** the signal; a masked signal stays queued and a
wait skips it, which is what a mask means.  A handled, unmasked signal is
**delivered**, the target's context redirected to the program's handler at
the one moment the kernel owns the frame, with the whole displaced context
kept for the handler's `SigReturn`, because a delivery that is not
transparent is a corruption: the measured case was a resumed flow reading
through a base register the handler's own `ecall` had overwritten, one
instruction past an address computation the delivery's resume had skipped.

Two defects the first boot of this found, both in code the signal demo was
the first to exercise:

- The riscv64 trap path destroyed the program's `x5` and `x6` **twice
  over**, the head computed the hart id in `t0`/`t1` before saving them,
  and the epilogue spent the same registers on its own return after
  restoring them.  Every `ecall` cost the program two registers, and
  nothing noticed while the only programs were machine code that reloaded
  before every call.  The shell's compiler kept a value in `t0` across one.
- `preempt` declined to switch when no other task was runnable, and a
  delivery rode the switch, an armed child spinning as the only runnable
  task never got its delivery, and the boot hung with both processes
  waiting for each other.  The delivery now moves without a switch, which
  is what it is: the signal's arrival, not a scheduling decision.

The `user_abi` crate is the other structural fact of the level: the
wrappers every program compiles against, with the numbering derived from
the ABI's own enum, a number that moves in `abi` breaks the program
side's build rather than drifting until a host test notices.

Verified by the lines above on every machine, by the gate's required lines
for the spawn, the two waits and the suspend, and by `protofire: syscall
table installed, 81 number(s) served` with the census at **102 of 196**
reachable from ring 3.

**The clock and the generator.**  `GetTimeOfDay` (70), `GetRandom` (75),
`SystemInfo` (53) and `AbiInfo` (39) answer from three different places, and
the boot says which of them it has: the machine's counter divided by the rate
the machine reported, a ChaCha20 stream seeded from that counter, and the
scheduler's own counts.  `init` reads the clock twice, a reading, then
another after work, and the pair must not go backwards, draws two blocks of
randomness that must differ, and reads both records back against the ABI's own
constants.

```
protofire: time origin 0x22d9e808 at 2611 MHz
protofire: random seeded, two reads differ
protofire: process 1 read the clock, 16 byte(s)
protofire: process 1 drew random bytes, 16 byte(s)
protofire: process 1 asked the ABI, 24 byte(s)
protofire: process 1 asked the system, 64 byte(s)
```

The time is an interval and not a date: the origin is the reading the boot
saw, recorded once, and every answer is measured from it.  `CLOCK_REALTIME` is
defined and refused with `Unsupported`, because a real-time clock needs a
device driver this kernel does not have and a plausible timestamp nobody read
is worse than an error a caller can act on.

The generator's seed is **timing**, and `docs/roadmap.md` carries the honest
sentence: there is no `RDRAND`/`RDR` probe here, so the bytes are fit for a
nonce, a salt or a shuffle and not for a long-lived key an attacker is
motivated to recover.  Six readings with a spin between them, hashed with the
origin on the end; the stream re-keys from its own state every 1024 blocks, so
an early output does not yield the later ones.

Two defects the first ring-3 boot of this found:

- `AbiInfo` names its record in `a0`, and the intercept read the record and
  length from `a1`/`a2`, the pair every other call in the group uses because
  they have a selector in front.  The length word was validated as an address,
  the range check refused it, and the program exited 200, which is the status
  `insist` uses for a refused call: indistinguishable in the log from a kernel
  that serves nothing.  The refusal prints its own line now.
- The `crypto` dependency the generator needs was absent from `kernel`'s
  manifest, so the module compiled on the host, where `fill` is never called
  and failed only for a target.

Verified by the six lines above on every machine, by the gate's required lines
for all four calls, and by `protofire: syscall table installed, 81 number(s)
served` with the census at **102 of 196**.

**The second CPU.**  A task is not pinned, so one that is preempted or woken
is placed again, and the boot counts and names the placement.  Placement
follows a rule rather than the rotation: a task the asking CPU last ran is
offered back to it first, a task no CPU has run comes next, and a task another
CPU ran is taken only when neither exists, the **steal**, which is the one
placement that migrates.  Measured on the same image: `task migrations` read 6,
9, 9, 7, 7 and 16 on six boots before the rule, and 1, 1, 2, 3, 3 and 3 after
it, against 12 to 16 `task placings home`, which is the rule's preferred arm
running, not merely a lower number.

Verified by `hart 1 online`, `ipi to 1 other cpu(s), taken`, `cpu 1 runs process `,
`program ended on cpu 1`, `parallel, programs ended on `, `task migrations `,
`task placings home `, `address spaces reaped 6, `, and `tlb shootdown `.

**A queue per CPU is not a gap, and the measurement says so.**  The offer of
work is still the lock's: every CPU scans the same list rather than taking from
a queue a shard filled toward it.  That is a shape worth changing only if the
scan costs something, so it was measured rather than assumed.  Counting every
candidate the two rotation scans look at, over six boots of the same image:

| boot | switches | candidates scanned | steals |
|---|---|---|---|
| 1 | 23 | 155 | 3 |
| 2 | 24 | 120 | 1 |
| 3 | 29 | 124 | 2 |
| 4 | 24 | 110 | 2 |
| 5 | 28 | 147 | 2 |
| 6 | 23 | 155 | 3 |

Five to seven candidates per placement, with four tasks in the machine and a
hard ceiling of eight: the scan is two linear passes over an array that fits in
a cache line.  Sharding would move that cost, not remove it, and would add a
steal path between queues, the same migration, one indirection further away.
What would change the arithmetic is a machine with many more runnable tasks than
CPUs, and nothing here has that yet.  So the shape stays, and the number is
recorded so the next reader can see it was measured.

Exited programs' spaces are released at the boot's end rather than at each exit,
because releasing one while the other CPU was still installed on its root
faulted 186 times in six boots of eight.  `docs/migration.md` has the per-step
cost of more CPUs.

## The IPv6 side of the network

IPv6 landed as a second address family on the same card, and the boot proves
three things about it.  All three lines are quoted from one boot of the x86_64
image; the aarch64 and riscv64 machines print them too, each with its own MAC
in the EUI-64.

```
protofire: ipv6 neighbour answered for fe80:0000:0000:0000:5054:00ff:fe12:3456, peer fe80:0000:0000:0000:5055:0aff:fe00:0202 is 52:55:0a:00:02:02
protofire: ipv6 echo reply to fe80:0000:0000:0000:5055:0aff:fe00:0202, identifier 7, sequence 1, 8 byte(s)
protofire: process 1 asked the ipv6 side, 56 byte(s)
```

**What each line is evidence of.**  The first is a neighbour solicitation this
stack built, parsed by the same `demux_ipv6` a frame off the wire takes, whose
target was an address the interface holds and whose source link-layer option
carried the peer's MAC into the cache, the read-back names the peer and the
MAC, so the answer is the exchange's and not a constant.  The second is an echo
request that reached `answer_echo_request` through the same demux, with the
identifier and sequence the request carried.  The third is a ring-3 program
reading the `Ipv6Status` record and checking the link-local address against the
MAC it already knew: `fe80::` plus the modified EUI-64, which is a fact a
program can verify without the wire.

**Why these are loopbacks and not a QEMU exchange.**  `ipv6=on` was tried and
measured: with it on, slirp stops answering IPv4 ARP, and the boot's ARP
exchange, ping and datagram all went silent while the boot still exited zero.
That is a card option that costs four working exchanges to reach a neighbour
slirp does not answer NDP for either, so it is off and the reason is recorded
in `tools/xtask/src/machine.rs` beside it.

**The invariant one of the tests pins.**  Swapping a datagram's source and
destination does **not** break its IPv6 checksum: a sum of sixteen-bit words is
commutative, so the checksum proves the pair of addresses and not the direction
the datagram travelled.  What says a datagram was addressed to this machine is
the IPv6 header's destination field.  The test asserts the non-obvious half and
says why, so a later change that "fixes" the pseudo-header's order fails a test
that explains the invariant instead of silently changing the wire.

**What is not proven here.**  A router advertisement configuring a global
address: the code path is in `net/src/internet/ndp.rs` and the interface holds the
field, but nothing this tree boots on sends one, so the record's `has_global`
is read and not asserted.  Reassembly of a fragmented packet: `walk` reports a
fragment and the demux drops it, because a stack that read the first piece as
the whole packet would answer with a truncated segment that looks complete.
And UDP or TCP over IPv6 through the syscall interface: the socket calls are
frozen with IPv4 addresses in their records, so that needs a family-tagged
address form and its own number.

## The filesystems

Ten filesystems are in `fs/src/` and none of them is mounted by a boot: the
boot's three are PyroFS, tmpfs and the ISO 9660 disc, because those are the
ones a demonstration needs.  The ten are proven by the host suites and by one
harness, and the evidence is named here so a reader can re-run it rather than
take the word "ported".

**Six formats write, four read, and the FUSE client is the protocol.**  `ext4`,
`f2fs`, `fat32`, `exfat`, `iso9660` and `ntfs` implement `FileSystem` and
answer creates, removals and renames; `xfs`, `squashfs`, `erofs` and `btrfs`
refuse every mutation in their own impls; `fuse` sends each mutation to the
program on the other side, so its writes are that program's.  The division is
the old tree's: `xfs` answered `PermissionDenied` to every write there too, and
the three compressed formats have no write path in either tree.  A reader that
became a writer by being ported would be a claim this tree cannot support.

**What each suite proves.**  Every format's tests build a volume of its own
and mount it, so no test depends on an image nobody rebuilt:

- `cargo test -p fs ext4`, 15 tests, a formatter that writes the superblock
  and the group descriptors so a test needs no host tool, and the JBD2 journal
  replayed and then written.
- `cargo test -p fs f2fs`, 11 tests, the segment, node and data paths plus
  the two checkpoint copies.
- `cargo test -p fs fat32` and `exfat`, 9 and 6, including FAT12's 12-bit
  packing written into both FAT copies and exFAT's NoFatChain runs.
- `cargo test -p fs iso9660`, 92, RFC 0011's stages in the order it took
  them, with the block map, the tail rule and the two-tree refusals.
- `cargo test -p fs ntfs`, 106, over a fixture built to RFC 0012's shapes;
  two more are `#[ignore]`d and driven by the harness below.
- `cargo test -p fs xfs`, `squashfs`, `erofs`, `btrfs`, 9, 40, 17 and 12.

**The one foreign judge.**  `sh scripts/check-ntfs-image.sh` makes a volume
with `mkntfs`, injects a file with `ntfscp`, a name and bytes this tree never
wrote, hands it to the driver, and then has `ntfs-3g`'s own reader list the
names, read both files back, and `ntfsfix -n` walk the metadata of what the
driver wrote.  Its second section does the same for a compressed stream on a
volume `mkntfs -C` made.  Run here:

```
ntfs image check passed: mounted a volume mkntfs made, read the host's file, and a foreign reader accepts what the driver wrote
ntfs image check passed (compressed): the driver decoded the file the host injected back
```

A punch through the interface, the old tree's third section, needs a userspace
harness this tree does not have yet, and the script says so rather than
skipping it silently.

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
the boot proves both.  Verified by `timer armed at ` and `timer counter `.  That
second line carries a count between its two fragments
`timer counter 5395 ticks apart`, which is why the gate asserts the prefix
rather than a whole line.

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
48-bit walk; the tree's device windows uncached.  Verified by
`page table built and installed, 4 KiB granule`.

**Interrupts.**  The GIC; the self-test raises a software interrupt the
controller delivers.  Verified by `interrupt delivered to its handler`.

**Timer and clock.**  The generic timer, one clock for both the deadline and
the counter.  Its private interrupt is configured **level**-triggered, which is
what `CNTP_CTL_EL0.ISTATUS` staying set until reprogramming makes it, and the
started core's own clock fires from it.  Verified by `timer armed at ` and
`cpu 1 id 1, ticking, `.

**Idle.**  A CPU with nothing to run parks in `wfe` and is woken by the event
the kernel's inter-CPU wake issues.  The mechanism is the **event**, not the
interrupt: `wfe` returns for a `sev` from any core and is untouched by the
controller, so a park ends on a call this kernel makes rather than on a line it
hopes the controller delivers.  Measured: a `wfi` in the idle left a started
core parked in **22 boots of 40**, and the boot ended `ended without
confirmation`; `wfe` beside a `sev` from `send_ipi_to_others` ended clean in
**100 of 100**, and in 40 more with the bounded spin behind the hint removed,
which is what shows the event, not the spin, is what ends the wait.  Verified
by the absence of the confirmation line across those 100 boots and by the
started core's own record (`cpu 1 id 1, ticking, ` with a non-zero tick count).

The mask is not the cause and was ruled out: clearing every bit
(`DAIFClr, #0xf`) and halting still left that core's second `wfi` never
returning.  With `wfe` there is no bound behind it: a core whose event never
comes stays parked, and the boot's own reaping side reports the CPUs that never
confirmed rather than waiting for ever.

The reason a `wfi` there never returned was found later and is not a defect in
this wait: an SGI at the reset priority of zero outranked the timer and, once
acknowledged without a finish, blocked the core's whole interrupt path.  See the
"Fixed" entry below for the trace and the measurement.

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
and then the machine either took a data abort one byte past the RAM's top
`fault at 0x60000000, read, mapped read-write, supervisor`, PC in
`exception_entry`'s first `ldp` of a restore, or wedged before `every
program exited`, the reaping side waiting in `send_ipi_to_others` for a core
that halted in the unhandled path.  Measured 2 in 100 and 1 in 60 on the
pre-session baseline, never on x86_64 (80 boots) or riscv64 (20).

The cause was a trap taken during the restore.  The handler **deliberately
unmasks**, a park or a wait clears `I` so the wake can arrive, and returned
with `I` clear, so the restore that writes `ELR_EL1`/`SPSR_EL1`/`SP_EL0` and
reloads 32 SIMD registers ran interruptible.  An IRQ taken there entered the
vector with `SP_EL1` still at the frame, built a second frame over the first
one's, and its `eret` resumed the first restore with a `sp` that a temporary
trap-entry probe showed landing on a **frame-pool page** (`0x449a7000`,
`0x449913c0`) rather than the RAM's top, a saved slot the second frame had
overwritten.  Masking the entry alone was not enough and measured 3 in 200;
masking again after the dispatch, before the restore, measured **200 of 200
clean**.  `eret` reloads `DAIF` from `SPSR_EL1`, so neither mask needs an
unmask.

**Fixed: a boot that stopped between a signal and the wait that follows it.**
With two CPUs and the signal exchange `init` runs, `SpawnProcess`, the child's
announcement, the parent's delivery, the parent's `WaitProcessOf`, a boot
sometimes stopped after `a program waits for process N` and never reached
`every program exited`.  Measured at 4 boots in 10 on the machine the gate
boots.  The scheduler was never at fault: its state read correctly throughout.

**The cause was an interrupt priority, not a lost interrupt.**  This entry said
for two sessions that the started core's private timer line stopped arriving,
because `GICD_ISPENDR0` showed no bit 30 while `CNTP_CTL_EL0.ISTATUS` was set.
That was a symptom read as a cause.  QEMU's `-d int` exception log and its
`gic_*` trace events, from **one** stalled boot, show what actually happened:

- The started core's last acknowledge was `irq 0`, a software interrupt, and
  **no `EOIR` write for it followed**, the SGI stayed active.
- Every later `gic_update_bestirq` for that core read
  `irq 30 priority 128 cpu priority mask 255 cpu running priority 0`: the
  distributor had the timer pending and could not forward it, because a
  priority-128 line cannot preempt a running priority of 0.
- The exception log then recorded **no exception at all** on that core while
  its program kept executing in ring 3 with `IRQs` unmasked, 507 IRQs taken
  and then none, over the remaining twelve million lines of log.

A running priority of 0 is the SGI's, and nothing in this tree ever wrote one.
`GICD_IPRIORITYR` resets to **zero**, zero is the *highest* priority a GIC has,
and `enable_interrupt` never routes an SGI, its enable bits are read-only, so
every inter-processor interrupt outranked the timer's `0x80`.  One un-finished
SGI then blocked that core's entire interrupt path.

`arch/aarch64/src/gic.rs` now writes every software interrupt at
`SOFTWARE_PRIORITY` (`0xA0`, below the device priority) when the controller is
enabled, and a `const` assertion fails the build if the ordering is ever
inverted.  The fix was measured against a control rather than assumed:

| image | boots completed |
|---|---|
| before the change | 4 of 10 |
| with the priority write removed (control) | 2 of 10 |
| with the priority write | **30 of 30** |

The three repairs tried before this one all made the boot worse, which is
consistent with the cause being outside the timer path altogether:

| repair | boots completed |
|---|---|
| none (before the attempts) | 6 of 14 |
| `preempt` waits when it finds an unowned user frame | 4 of 14 |
| `CNTP_CVAL_EL0` accumulated by the handler | 4 of 14 |
| boot core pings the others on every one of its ticks | 4 of 14 |

`wait_for_a_wakeup` still waits on the `sev` **event**, and that is no longer a
workaround for a broken timer: a park should end on a call this kernel makes
rather than on a line it hopes the controller delivers.  The design those three
failed repairs pointed at, "the boot core's tick drives every core", was
never implemented, and this measurement shows it was aimed at the wrong module.

Also ruled out along the way, each by measuring rather than by argument: the
machine's CPU model (cortex-a57 7 in 10, `max` 6 in 10, the same defect); the
GIC version (`virt,gic-version=2` 6 in 10, and `gic-version=3` 0 in 10 because
this tree implements the v2 register interface only); a missing `sev` after the
exit wake (real, fixed, not the whole of it); the order of `idle_until_woken`
and `switch_without_saving` (removing the idle call made it worse, 5 in 6); and
an exit whose `running[cpu]` was already clear (the probe for it never fired);
a stalled global clock (the global `TIMER_TICKS` keeps climbing at a stopped
boot, it is the started core's own count that stops, which is why the per-CPU
census is the number to read); and the `has_runnable`-counts-blocked reading
(the scheduler's state was correct throughout).

Three measurement details are worth keeping, because each cost a wrong
conclusion:

1. An early attempt booted **one** CPU against a disk formatted by the kernel's
   own built-in image, the one that carries the greeting and no init image
   and every such boot stopped five times in five.  That stop was
   `ExecProcess` failing on a file the disk did not have.  Any future
   measurement here has to name which disk it booted.
2. Reading GIC memory through a gdb stub's `x` command **kills the
   connection** on this machine; it is device memory and the stub's translation
   does not carry it.  QEMU's monitor (`xp`) reads it and survives.
3. Four QEMU processes were once left running at the same time, one of them
   holding the gdb port, so "the stalled machine" a later session attached to
   was not the one whose log it read.  The numbers in this entry come from
   single-process runs, sampled twice with the guest executing between the
   samples.

None of this was in the level-4 calls: the same boot stopped at the same line
on the commit before them.

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
The PLIC is programmed and the console's UART is claimed as a real source
enabled at the controller, asked for one transmitter interrupt, acknowledged at
the device before the source is completed.  Verified by
`interrupt delivered to its handler`, `external controller at `, and
`console interrupt(s) taken = 1`.

**A delivery the device does not own is not counted as an interrupt.**  The
controller can hand this source over once more after the handler silenced the
UART: the line was asserted when the source became pending, and the controller
delivers what it latched although the device has nothing to say by the time it
is read.  Measured on both the PLIC and the APLIC, six boots each: exactly one
delivery whose `IIR` read says "mine" and exactly one whose read says "not
mine", every time.  The trap path completes the second and returns without
handing it to the sink, so the count describes interrupts rather than
deliveries.  A probe is what found it, without one, the same boot printed
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
names a supervisor IMSIC, the node whose `interrupts-extended` pairs carry
cause 9; the one carrying 11 is machine mode and is not this kernel's, the boot
reads the group's base, stride and `riscv,num-ids`, enables this hart's file
(`eithreshold` zero, `eidelivery` on), and then proves the path with no device
attached: it enables the file's **highest** identity, one past any a device
could be given, writes that identity into **this hart's own MSI page** exactly
as an MSI-X table entry would, and reads it back with the `stopei` claim.

    protofire: imsic at 0x28000000, hart file 0, 255 identit(ies), self-test identity 254 delivered and claimed

That line is the evidence: the page's address, the bare-identity data word, the
pending bit, the enable bit and the claim were all executed. QEMU's `virt` with
`-machine virt,aia=aplic-imsic` is where it runs, `cargo xtask check --machine
riscv64-aia`, which is part of `sh scripts/verify.sh p1` and therefore of every
tier above it.  It is a **gate machine**, not a measurement made by hand: the
same image the PLIC machine boots, on a tree that names an APLIC and an IMSIC,
with its own required lines.  The default machine and `virt,aia=aplic` print no
such line because their trees name no IMSIC, and the code that would touch
`siselect`/`sireg` is not reached, which is load-bearing rather than tidy,
because on those machines the pair is an **illegal instruction**.  Measured:
`virt` and `virt,aia=aplic` both stop with `unhandled exception 2 (illegal
instruction), address 0x15051073` if the CSRs are read unconditionally, and both
boot to completion when the read is gated on the tree as it now is.

The gate's four kinds of assertion cover what a single boot line cannot, and
each was mutation-tested by breaking the kernel it guards:

| assertion | what it refuses | what broke it |
|---|---|---|
| a required line | the boot never reached this step | an absent line fails |
| paired fragments on one line | two lines that say different things | text change on the IMSIC line fails |
| a count above zero | a wiring that armed every register and took nothing | the pre-reset wiring reads `= 0` and fails |
| text that must not appear | a failure whose words contain its own success | the self-test's failure text fails |

**The APLIC's message mode delivers to the IMSIC, and each source's message
carries its own number.**  On `-machine virt,aia=aplic-imsic` the APLIC is
locked in message mode (`domaincfg` reads `0x80000104`, `DM` set and
read-only), so a wired source becomes a message into the IMSIC.  Each source's
target word names the hart and **the source's own number as the identity**
measured, a constant there put every wired source's message onto identity 1,
which is also the firmware's inter-processor identity (`eie` reads `0x2` at hart
start, set by the firmware), and a trap that claimed identity 1 could not tell
the console's level wire from an IPI: the wire stayed high and the APLIC
re-sent for ever, 16,052 claims in six seconds.  With the identity as the
source's own, the file's enable is the **filter**, only the sources a driver
claims get one, because enabling the whole range turned every wired line with
nobody to answer it into a storm (41,201 deliveries in ten seconds from one
source, silenced at its controller once the trap path stopped re-arming it).
Those boots finish, with `console interrupt(s) taken = 1`, the console's own
message, delivered through the APLIC, claimed as its source's identity, and
acknowledged at the UART.

**That one was an off-by-one in the source arrays, and no register the driver
read could show it.**  The APLIC's `sourcecfg` and `target` arrays are indexed
by **source number, which starts at one**: source `N`'s word is at the array's
base plus `(N - 1) * 4`.  The driver wrote `number * 4`, so every word landed one
source too high.  The console's source 10 therefore carried the target written
for source 9, identity 9, and the APLIC delivered every console message to
identity 9 while the kernel had enabled and was waiting on identity 10.  Every
register read back correctly, because the driver read its own wrong offsets;
`CLRIP` showed the wire asserted at source 10, `SETIE` showed it enabled, and the
file showed identity 10 enabled.  The message was sent and claimed and simply
never recognised.

What found it was QEMU's own MMIO trace, which is external to the guest:

    qemu-system-riscv64 -trace memory_region_ops_write ...
    memory_region_ops_write ... addr 0x28000000 value 0x9 size 4 name 'riscv.imsic'

Identity **9** arriving at the file, written for a kernel waiting on 10, is the
whole of the defect in one line.  After the fix the same trace reads `value 0xa`,
and the count is one on **6 of 6** boots, the same number the PLIC machine has
reached by a different mechanism.  `check --machine riscv64-aia` requires that
one, and reverting the `- 1` makes the gate fail on exactly that line.

**A PCI device's MSI-X reaches the IMSIC, and the reason it once did not is the
order the wiring ran in.**  The block device's queue is mapped to a message: an
MSI-X table entry naming this hart's file page and the bare identity 200,
MSI-X enabled, the queue's vector set, and the identity enabled in the file
every step read back from the device, then the handler registered under the
identity.  Measured on `-machine virt,aia=aplic-imsic`: **8 of 8 boots** take
the completion message, and the census line reports it:

    protofire: block message wired to imsic page 0x28000000, identity 200, vector 2
    protofire: block completion message(s) taken = 2

The count is 2 and not one per completion because an IMSIC file holds **one
pending bit per identity**: completions that arrive before the first is claimed
share the bit, and the number is how many times the trap ran.  Twelve
`virtio_notify` events in QEMU's own trace against two trap deliveries is that
shape, and it is why the count is reported beside the programs rather than
taken to be the device's request count.

The wiring has to run **after** the driver is constructed, and that is the whole
of the defect the previous session could not reproduce: the driver's first step
is a device reset (`write_status(0)`), and a reset is the device forgetting
every queue's interrupt state.  Armed before it, the table entry and the queue
vector are both discarded and the transport drops every completion silently
QEMU's trace records the notifications, and no `virtio_pci_notify` follows
because the queue's vector is `VIRTIO_NO_VECTOR` again.  The same code at the
two positions, one variable apart: **0 of 4** boots before the reset, **8 of 8**
after, with the wiring's own line reading back identically in both runs.  The
one boot that "worked" last session was a race it won, not a mechanism.

Also corrected: the previous note that this file refuses identity 128 was a
measurement of the same defect, not of the identity range.  QEMU's
`riscv_imsic_write` accepts any identity in `1..num_irqs` (255 on this machine),
and writes 20, 128 and 200 all arrived once the wiring ran in the right place.

One limit remains, measured:

- **Only one device's message is claimed.**  The identity is the boot's to hand
  out and the handler table is per identity, so a second device is a second
  identity and a second handler rather than a controller change; what is
  missing is a driver per device, not a message path.  The APLIC's wired sources
  are claimed too, each delivers as its own identity, and the console's is
  both delivered and taken, which the line above records as `taken = 1`.

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
