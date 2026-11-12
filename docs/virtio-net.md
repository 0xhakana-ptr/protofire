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

Two virtqueue layouts, both from the specification:

- **receive**: a chain of device-writable buffers, each `{ virtio_net_hdr (10
  bytes, VIRTIO_NET_HDR_LEN when no offloads are negotiated), then the frame }`.
  The device fills them; the driver takes the used ones.
- **transmit**: a chain of driver-readable buffers with the same header first.

The smallest thing that proves both directions is an **ARP request on transmit
and the reply on receive**: QEMU's user-mode network (`-netdev user`) answers an
ARP for its gateway without any configuration, and the frame is 42 bytes with
fields the driver wrote.  The boot prints the reply's sender and target.

**Verified by**: the boot line, and the frame's bytes are what the driver wrote
— the reply's target is the address the driver asked about.  A host test pins
the header length and the field offsets, because those are the specification's.

### 4. The interrupt, and the second identity

The card's receive queue gets an MSI-X vector and an IMSIC identity, exactly as
the block device's transmit queue did — but this is the **second** identity in
the handler table, which is the claim `docs/status.md` still lists as open
("only one device's message is claimed").

The identity is the boot's to hand out: a number above the APLIC's wired range,
distinct from the block device's 200 and the IMSIC self-test's 254.

**Verified by**: `check --machine riscv64-aia` requiring the net line and the
box's existing `block completion message(s) taken` still being non-zero — two
devices, two identities, one table.

### 5. `-netdev user` in the gate, and the line that says it worked

`qemu_arguments` gains a `-netdev user,id=net0` and a `-device
virtio-net-pci,netdev=net0,disable-legacy=on` for the machines that can drive
it.  The gate requires the ARP line.

This step is last because it is the only one that changes what a boot does
without a human asking, and it should land when the four before it are proven.

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
