# virtio-net: what it takes, in what order, and how each step is verified

A working note, not a document of record: it exists so the next session does not
re-derive the shape.  `docs/status.md` is where a step's result lands when it
lands; this file goes away when the last step does.

## Why the device, and not the queue

The framework claims to serve "a block device, a network card and a GPU" in its
own header, and only the block device exists.  A second device is what tests
that claim: the shared half (virtqueue, feature negotiation, status sequence,
transport) either serves two devices without changes, or the changes it needs
are the framework's real boundary.  The IMSIC story has the same question on the
other side — one identity, one handler today — and a network card is the second
user.

## The five steps

Each is one commit, each is gate-green on its own, and each ends with something
that can be pointed at.

### 1. Take the block device's own fields out of the shared trait

`Transport` has `capacity_sectors()`, which is a block device's question: it
reads two dwords of the device-specific configuration and concatenates them.
The PCI transport answers it by naming `block_config::CAPACITY`, which is a
block layout in a crate that is not the block crate.

The replacement is a `read_device_config_dword(offset) -> u32`, which is what
every `virtio_pci` device has: a device-specific configuration region whose
layout is the device's business.  `VirtioBlock::new` then reads its own capacity
from the block layout it already owns.

**Verified by**: `VirtioBlock`'s existing host tests, unchanged — the driver
still brings up, writes and reads, and reports the same capacity.  Plus a test
that the block crate reads offset `0x0` and `0x4` and concatenates them, so the
layout claim is in the crate that owns it.

### 2. A `virtio-net` crate that brings a device up

**Done.**  `drivers/virtio/net` holds `VirtioNet::new`: the status sequence,
feature negotiation requiring `VIRTIO_NET_F_MAC`, and both queues brought up.
The queue index parameter from step 1 turned out not to be enough on its own —
`max_queue_size` still took no index and answered for queue 0 — so that was
corrected here, in the change that has a second queue to ask about.

Modern virtio-net: device id `0x1041` (transitional `0x1000`), class code
`0x02` (network).  Two queues, receive `0` and transmit `1`, and the
`VIRTIO_NET_F_MAC` feature so the driver learns the card's address instead of
inventing one.

`VirtioNet::new(transport)` performs the same sequence `VirtioBlock::new` does,
with two queues instead of one — which is what step 0x1's index parameter made
expressible.  No packets yet: the queues are configured, the device is
`DRIVER_OK`, and the boot says so.

**Verified by**: a host test over a fake transport that records the two queues'
sizes, addresses and enables, and requires that queue 0 and queue 1 were each
programmed with their own rings.  This is the test that would have caught the
queue-selection defect.

### 3. A frame in, a frame out

**Done**, and it cost three boot-level defects that this section records because
none of them was visible to a host test.

Two virtqueue layouts:

- **receive**: a device-writable buffer holding `{ virtio_net_hdr, then the
  frame }`.  The device fills it; the driver takes the used one.
- **transmit**: the same header first, then the frame, both driver-readable.

The smallest thing that proves both directions is an **ARP request on transmit
and the reply on receive**: QEMU's user-mode network (`-netdev user`) answers an
ARP for its gateway without any configuration, and the frame is 42 bytes with
fields the driver wrote.

**The three defects, in the order they were found.**

1. **The notify region's multiplier.**  `PciTransport` read
   `notify_off_multiplier` from the notify capability's `length`, which is the
   region's *size* (section 4.1.4.4: the multiplier is the dword appended after
   the structure).  QEMU's card has a 0x1000-byte notify region, so a doorbell
   was written at `queue_notify_off * 0x1000` and the boot died with
   `write past the mapped BAR`.  Every register read back what was written,
   which is why the bring-up tests passed.

2. **The header is twelve bytes.**  With ten, a probe that filled the frame with
   its own byte indices had the wire carry `2, 3, 4, …` — the card skipped
   twelve of a buffer whose header was ten, so every frame left two bytes short
   at the front.  The confirming probes: a header descriptor declaring eight
   bytes shifted the frame to `4, 5, 6, …`; two descriptors and one descriptor
   behaved identically; and a single buffer with twelve leading zeros delivered
   the frame whole.  The driver writes twelve now, and
   `drivers/virtio/net/src/header.rs` says which measurement decided it.

3. **A short response.**  The gateway's reply was on the wire (captured with
   QEMU's `filter-dump`) while the driver reported none, because it stripped ten
   bytes instead of twelve and then read the frame four bytes into its own ARP
   message.

**Verified by** the boot line on all four machines, with the reply's fields
checked against the request:

```
protofire: virtio-net arp reply 52:55:0a:00:02:02 holds 10.0.2.2, asked by 52:54:00:12:34:56 for 10.0.2.15
```

The driver returns false unless the reply names this card's address and the
address this boot asked about, so requiring the line is requiring an answer to
the question.  A host test pins the header length and the ARP field offsets, and
three more pin the receive path's guards: a frame with an unnegotiated offload
is dropped, a completion that wrote no frame is dropped, and the device's header
is not part of the frame handed up.  Each is mutation-tested.

### 4. The interrupt, and the second identity

**Not done.**  The receive queue completes through the driver's polling, so the
box still has one device whose message the IMSIC claims — which is
`docs/status.md`'s open claim.

The card's receive queue would get an MSI-X vector and an IMSIC identity,
exactly as the block device's transmit queue did, and it would be the **second**
identity in the handler table.

The identity is the boot's to hand out: a number above the APLIC's wired range,
distinct from the block device's 200 and the IMSIC self-test's 254.

**Verified by**: `check --machine riscv64-aia` requiring the net line and the
box's existing `block completion message(s) taken` still being non-zero — two
devices, two identities, one table.

### 5. `-netdev user` in the gate, and the line that says it worked

**Done, with step 3.**  `qemu_arguments` gives every bootable machine
`-netdev user,id=net0` and a `virtio-net-pci`, and the gate requires
`protofire: virtio-net up, address ` and `protofire: virtio-net arp reply ` on
all four boots.

It landed with step 3 rather than after it because the frame path has no
evidence until a machine runs it, and a boot-level driver asserted only on a
host is the state `docs/status.md` calls "implemented", not "verified".  The
step was written last for the opposite reason — that it changes what a boot
does without a human asking — and that reason is why the gate's own two lines
are the whole of the change to a boot: a machine with no card prints nothing.

## What is deliberately not in this plan

- **A network stack.**  No IP, no UDP, no DHCP.  The ARP exchange is the
  smallest frame that proves the queue, and a stack is a different project.
- **The e1000 driver.**  `drivers/net/e1000` is a placeholder, and virtio-net is
  the device the emulated machines actually have.
- **A per-CPU queue.**  Measured and declined; the numbers are in
  `docs/status.md`.

## The open question this plan does not answer

Whether a second identity is enough, or whether the handler table needs a
registry that devices register into rather than identities the boot hard-codes.
The block device's identity is a `const` in `kernel/src/devices.rs` and the
wiring is a function that names one device.  A second device will show whether
that scales to three, and the shape to prefer is the one that needs no fourth
change.
