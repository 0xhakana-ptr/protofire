# Syscall ABI Specification

> **Status:** normative. Changes to this document require maintainer review.
> **Applies to:** `abi/`, `syscall/`, `kernel/src/syscall/`.

The syscall ABI is the compatibility boundary of Protofire. A ring-3 program
talks to the kernel exclusively through this interface, and carries nothing
that could absorb a change: the boot's programs are raw machine-code images
the kernel copies into a page, there is no dynamic linker, and no shared
library sits between a program and these numbers.
A number that moves, a struct that grows, or a pointer that is validated one way
in the kernel and another way in the wrapper is a silent breakage of every
already-built program.

This document is the detailed contract.  [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
carries the short version; where the two disagree, this document wins.

---

## 1. Principles

1. **ABI stability first.** Stable slots are frozen. Correctness and
   compatibility outrank convenience, naming taste, and consolidation.
2. **One source of truth.** A syscall number is written down exactly once. The
   kernel enum and the userspace wrapper are both derived from the same
   manifest; they cannot drift because they do not hold independent copies.
3. **Append-only.** Numbers are assigned once and never change meaning, not
   even to reclaim a slot nobody uses.
4. **Validate before you touch.** A user pointer is never dereferenced on the
   strength of being non-null. Every pointer is checked against the user
   address window before the handler reads or writes it.
5. **Every change is documented and tested in the same PR.** Numbering rules are
   only real if a test fails when they are broken.

---

## 2. Where the numbers live

[`abi/src/number.rs`](../../abi/src/number.rs) is the single source of truth, and
it is in `abi` rather than in `syscall/` because of what it is: a program is
compiled against these numbers, so an implementation crate that owned them would
be one a program had to depend on to be written.

It defines two things.  `SyscallNumber` is the number of each syscall, a
`#[repr(usize)]` enum.  `PUBLIC_SYSCALL_COUNT` is how many numbers this build
serves, and the dispatch table is sized from it.

The dispatch table is `kernel/src/syscall/mod.rs`, and it is sized from
`PUBLIC_SYSCALL_COUNT` rather than from a number of its own, a variant appended
without moving the count is caught by a test in `abi/src/number.rs`.

There is no separate ring-3 copy of the numbering.  The previous tree carried
two: `src/abi/` for the kernel and a vendored copy for the user side, kept
identical below the header by a census script with a baseline of recorded
differences.  The copy existed because a payload is compiled separately and
could not `use` the kernel's crate.  A crate both sides depend on removes the
reason, and the script that compared two copies is not needed.

## 3. Numbering rules

These are hard rules. Each one exists because breaking it breaks programs that
are already shipped on the demo disk.

### 3.1 Append-only

- **Never renumber** an existing syscall.
- **Never reuse** a number whose syscall was removed. If a syscall must go,
  its number is retired permanently: remove the variant, leave the number
  absent from the enum, and note the retirement beside the count. Slots 141
  and 142 are live examples: the enum skips them, and nothing may ever take
  them.
- **Never insert** in the middle of the range to keep a group tidy. The file is
  ordered by number because numbering is historical, not thematic.
- New syscalls take the **next unused number** at the end of the defined range,
  and `PUBLIC_SYSCALL_COUNT`, derived from the last variant in
  [`abi/src/number.rs`](../../abi/src/number.rs), moves with it in the same
  edit.

### 3.2 Stability classes

`0..=120` is **Stable**, and frozen: semantics, argument order, and record
layouts do not change, and additive *optional* behaviour is the only permitted
change.  `121..=SYSCALL_COUNT - 1` is **Experimental**: behaviour, arguments,
and record layouts may still be adjusted on a **minor** version bump.

The **Experimental** line is the one that lets an argument change without a
major bump: a slot no program outside this tree is built against can be
redefined, and `SYSCALL_ABI_VERSION_MINOR` is what says it was.  A version in
the frozen range never moves that way, there the paragraph above applies as
written, and a redefinition is a major bump.

A number at or below 120 is stable by being frozen: assigned once, never
renumbered, never reused. Above it, a new number is experimental in the plain
sense that only this build's kernel and this build's programs agree on it;
there is no stability function to call, and the boundary is the frozen-range
rule itself, pinned by the tests at the bottom of `abi/src/number.rs`.

Beyond `PUBLIC_SYSCALL_COUNT` no slot exists at all: the dispatch table is
sized from the count, so an unassigned number has nothing to be empty.

---

## 4. Versioning

The version of the ABI is the numbering itself: the frozen range and the
count are what a program is compiled against, and there is no separate version
constant to bump.  A change that alters what an existing number means is a
change to a frozen contract, which the numbering rules above forbid; a change
that appends is additive by construction and needs no version.

If a version field is ever worth carrying to a program, it arrives the way
everything does here: as a number in this range, appended with its own
handler, with the tests that pin the boundary updated in the same change.

---

## 5. Adding or modifying a syscall

Work through this list in order.  Every item is part of the change, not a
follow-up.

1. **Assign the number.**  Add the variant to `SyscallNumber` in
   [`abi/src/number.rs`](../../abi/src/number.rs).  Above 120 the number may
   grow; at or below it the set is frozen and a new call goes above.

2. **Move the count.**  `PUBLIC_SYSCALL_COUNT` is derived from the last
   variant, and a test in the same file pins that.  A variant appended without
   it is a syscall the dispatch table never reaches.

3. **Write the handler** in
   [`kernel/src/syscall/handlers.rs`](../../kernel/src/syscall/handlers.rs).
   The kernel's table is where the handlers live because every slot names a
   subsystem and the `syscall` crate must not.

4. **Register it** with `table.register(SyscallNumber::YourCall, your_handler)`.
   The table is sized from `PUBLIC_SYSCALL_COUNT`; a slot nothing registers
   answers `NotImplemented`, which is the honest answer rather than an absent
   one.

5. **Bump the ABI version** if the change is not purely additive (§4).

6. **Test it**, see §9.

**Modifying an existing syscall** follows the same list, minus step 1, plus a
compatibility argument in the commit message: say which range the syscall is in
and why the change is permitted there.

---

## 6. Kernel handler conventions

A handler is `fn(&mut SyscallTable, &mut Arguments<'_>) -> Result<Dispatch>`.
The two parameters are the point:

- **`&mut SyscallTable`** is what a handler needs and a stateless one would
  not: the descriptor array lives there.  This is why the kernel names its own
  handler type rather than using `syscall::SyscallHandler`, which takes the
  context alone.

- **`&mut Arguments`** is how a handler reaches a caller's bytes.  It carries
  the context plus the address-shaped arguments already turned into borrows,
  `path: Option<&str>`, `buffer: Option<&mut [u8]>`.  A handler that did
  `from_raw_parts` on `context.arg(1)` would carry a promise it cannot show;
  taking a borrow puts that promise where the borrow was built.

Rules the shape encodes:

- **Return `Result<Dispatch>`,** never a bare `usize`.  `Dispatch` carries the
  return value *and* any control-flow action the trap path must take.

- **Use the constructors**, `Dispatch::complete(value)`, `yield_now()`,
  `exit(status)`, rather than building the struct by hand.

- **Reject unused arguments explicitly** with `validate_zeroed_args(context, n)`,
  where `n` is the first unused index.  Silent acceptance of garbage makes a
  future addition ambiguous; flag words go through `validate_known_flags`.

- **Return errors, never panic.**  `Error::InvalidArgument`, `Error::NotFound`,
  `Error::PermissionDenied` are the vocabulary.  A `panic!`/`unwrap` in a
  handler takes down the kernel because of a user's mistake.

- **No `unsafe`, and that is a testable claim.**  `kernel/src/syscall/mod.rs`
  contains no `unsafe` block.  A handler that needs one is a handler whose
  argument should have arrived as a borrow, add the borrow to `Arguments`
  rather than the `unsafe` to the handler.

---

## 7. Pointer validation

A pointer from ring 3 is a number, and this section is the rule for it.

The registry's own handlers still take borrows, `Arguments::path` and
`Arguments::buffer`, built by the kernel code that owns the buffer, and a
borrow needs no validation.  The boundary exists where programs call:
`Read` and `Write` to a pipe take a ring-3 buffer, and the handler validates
the range with `is_user_range` before it touches a byte, because an address
that arrives in a register is a number until something checks it.

The calls a ring-3 program can make today, and the slots each carries:

The calls a ring-3 program can make today, and the slots each carries.

- **`Open`**, `a0` the path, a NUL-terminated string in the caller's memory;
  `a1` the flags; `a2`-`a3` reserved zero.
- **`Read`**, `a0` the descriptor; `a1` the offset, or `READ_OFFSET_CURRENT`;
  `a2` the buffer; `a3` its length; `a4`-`a5` reserved zero.
- **`Close`**, `a0` the descriptor; `a1`-`a5` reserved zero.
- **`ExecProcess`**, `a0` the path, a NUL-terminated string in the caller's
  memory naming the file the process becomes; `a1`-`a5` reserved zero.
- **`Mmap`**, `a0` an address hint, or zero for "anywhere"; `a1` the length in
  bytes; `a2` a `PROT_*` set; `a3` a `MAP_*` set that has to name anonymous
  private memory; `a4`-`a5` reserved zero.  Answers the base address, which is
  page-aligned and inside the caller's window.
- **`Munmap`**, `a0` the address; `a1` the length in bytes; `a2`-`a5` reserved
  zero.  Both are rounded to pages, and the answer is how many were taken away.
- **`Brk`**, `a0` the new break, or zero to ask what it is; `a1`-`a5` reserved
  zero.  Answers the break the kernel now holds, so a caller that asked for more
  than it can have learns what it actually got.
- **`ReclaimPages`**, `a0` how many pages the caller would like back, or zero
  for as many as will go; `a1`-`a5` reserved zero.  Answers how many came back.
- **`Write`**, `a0` the descriptor; `a1` the buffer; `a2` its length;
  `a3`-`a5` reserved zero.  Answers the bytes accepted, starting at the
  descriptor's own position, which moves by them.  A `Write` whose `a2` is
  zero names no bytes and is the announcement, not a write.
- **`Stat`**, `a0` the path, a NUL-terminated string; `a1` the record;
  `a2` its length, at least `FILE_STAT_SIZE`; `a3`-`a5` reserved zero.
  Answers zero, with the record filled.
- **`ReadDir`**, `a0` the path; `a1` the index; `a2` the buffer; `a3` its
  length; `a4`-`a5` reserved zero.  Answers the bytes written: the ABI's
  `DirectoryEntryRecord` header with the name's UTF-8 bytes packed after it.
  An index past the end answers `NotFound`.
- **`CreateDir`**, `a0` the path; `a1`-`a5` reserved zero.  Answers zero.
- **`RemovePath`**, `a0` the path; `a1`-`a5` reserved zero.  Answers zero.
- **`Rename`**, `a0` the old path; `a1` the new path; `a2`-`a5` reserved
  zero.  Answers zero.  Both names must resolve to one filesystem.
- **`OpenAt`**, `a0` the descriptor the path is relative to, or `AT_FDCWD`;
  `a1` the path; `a2` the flags; `a3`-`a5` reserved zero.  Answers a
  descriptor, like `Open`.
- **`StatAt`**, `a0` the descriptor; `a1` the path; `a2` the record; `a3`
  its length; `a4`-`a5` reserved zero.  Answers zero, like `Stat`.
- **`RenameAt`**, `a0` the old descriptor; `a1` the old path; `a2` the new
  descriptor; `a3` the new path; `a4`-`a5` reserved zero.  Answers zero.
- **`CreateDirAt`**, `a0` the descriptor; `a1` the path; `a2`-`a5` reserved
  zero.  Answers zero.
- **`RemovePathAt`**, `a0` the descriptor; `a1` the path; `a2`-`a5` reserved
  zero.  Answers zero.
- **`SpawnProcess`**, `a0` the path of the program to run, NUL-terminated;
  `a1`-`a5` reserved zero.  Answers the child's pid; the caller is the
  parent, and the child inherits nothing.
- **`SendSignal`**, `a0` the target pid; `a1` the signal, `1..=31`; `a2` the
  payload; `a3` the flags; `a4`-`a5` reserved zero.  Answers zero, or
  `NotFound` for a pid no task carries and `Busy` for a full ring.
- **`WaitSignal`**, `a0` the record; `a1` its length, at least 24 bytes;
  `a2`-`a5` reserved zero.  Blocks until a signal the mask does not block
  answers, and fills the record, signal, sender, payload, little-endian.
- **`SetSignalMask`**, `a0` the mask, one bit per signal; `a1` the flags;
  `a2`-`a5` reserved zero.  Answers the mask the caller had.
- **`SigSuspend`**, `a0` the mask; `a1` the flags; `a2` the record; `a3` its
  length; `a4`-`a5` reserved zero.  Blocks under the mask until an unblocked
  signal answers, fills the record, and puts the caller's own mask back.
- **`SetSignalHandler`**, `a0` the signal; `a1` the action (`1` install,
  `0` withdraw); `a2` the handler's address; `a3`-`a5` reserved zero.
  Answers zero.
- **`SigReturn`**, `a0` the resume; `a1`-`a5` reserved zero.  The delivered
  handler's only exit: the kernel puts the interrupted context back and the
  interrupted flow resumes at `a0`.  Control does not come back.
- **`GetTimeOfDay`**, `a0` the clock, `0` for `CLOCK_MONOTONIC` and `1` for
  `CLOCK_REALTIME`; `a1` the record; `a2` its length, at least
  `TIME_RECORD_SIZE`; `a3`-`a5` reserved zero.  Answers zero, with the record
  filled, seconds then nanoseconds.  A clock this ABI does not define is
  `InvalidArgument`; a clock it defines and this build cannot read is
  `Unsupported`, which is what `CLOCK_REALTIME` gets until a real-time clock
  driver exists.
- **`GetRandom`**, `a0` the buffer; `a1` its length; `a2`-`a5` reserved zero.
  Answers the bytes written, which is the length asked for.  A zero length
  answers zero and writes nothing.
- **`SystemInfo`**, `a0` the selector, `0` for the scheduler; `a1` the
  record; `a2` its length, at least `SYSTEM_INFO_SIZE`; `a3`-`a5` reserved
  zero.  Answers zero, with the record filled.  A selector this build does not
  serve is `InvalidArgument` rather than a record of zeros, which would read
  as an idle machine.
- **`AbiInfo`**, `a0` the record; `a1` its length, at least `ABI_INFO_SIZE`;
  `a2`-`a5` reserved zero.  Answers zero, with the version, the slot count and
  the frozen boundary filled.  This is the one call a program can make before
  it trusts any other, and every field is a constant of the build.
- **`NetworkStatus`**, `a0` the record; `a1` its length, at least
  `NETWORK_STATUS_SIZE`; `a2`-`a5` reserved zero.  Answers zero, with the
  record filled, a state word, then the card's hardware address, its
  protocol address and the gateway, packed as the wire carries them.  A
  machine with no card answers `NotFound` rather than a record: a record
  implies addresses, and a machine with no card has none.
- **`BindUdp`**, `a0` the port; `a1`-`a5` reserved zero.  Answers the
  descriptor the datagram calls carry back.  Port zero is refused: it is the
  wire's "any port", and this kernel has no port allocator to answer it
  with.  A port another socket holds answers `AlreadyExists`, a bound port
  has one owner.  The socket is routable for exactly as long as some
  descriptor holds it, which is what a fork's copy extends and a process's
  exit ends.
- **`SendToUdp`**, `a0` the descriptor; `a1` the destination's address,
  packed by `pack_address` (`10.0.2.2` is `0x0A000202`); `a2` the buffer;
  `a3` its length; `a4` the destination's port; `a5` the flags word, zero or
  [`NETWORK_FLAG_IPV6`](../../abi/src/network.rs).  Answers the bytes
  accepted, which is all a datagram send ever promises.  A datagram addressed
  to this machine is delivered through the kernel's own demux, that is what
  loopback is, and one for another machine leaves through the gateway.
- **`ConnectTcp`**, `a0` the destination's address, packed by
  `pack_address`; `a1` the destination's port; `a2` the flags word, zero or
  [`NETWORK_FLAG_IPV6`](../../abi/src/network.rs); `a3`-`a5` reserved zero.
  Answers the descriptor the stream is read and written through.  The
  handshake runs inside the call, so the first write cannot race its own
  opening; a destination that is not this machine answers `Unsupported`,
  because a handshake that waits on the wire is a wait this build does not
  make a call do.
- **`ListenTcp`**, `a0` the port; `a1`-`a5` reserved zero.  Answers the
  descriptor an accept is called on.  Port zero is refused, and a port
  another listener holds answers `AlreadyExists`, a listening port has one
  owner, whatever number of processes hold its descriptor.
- **`AcceptTcp`**, `a0` the listener descriptor; `a1`-`a5` reserved zero.
  **Blocks** until a client's handshake opens a stream, and like
  `RecvFromUdp` it has no registry handler: the trap path serves it, parks
  the caller on the listener's pending list, and the connect's wake retries
  the call.  Answers the new stream's descriptor, whose data, if the
  client wrote before the accept ran, is already in the stream's inbox.
- **`RecvFromUdp`**, `a0` the descriptor; `a1` the buffer; `a2` its length;
  `a3` the sender record; `a4` its length, at least the record's size; `a5`
  the flags word, zero or [`NETWORK_FLAG_IPV6`](../../abi/src/network.rs).
  **Blocks** until a datagram answers, and this is why it has no registry
  handler: a handler that cannot park does not hold a number whose caller may
  have to wait, so the trap path serves it, parks the caller on the socket's
  queue, and the delivery's wake retries the call.  The sender record is two
  words, the address packed as `SendToUdp` carries it, then the port.  A
  datagram longer than the buffer is refused with the datagram kept, because
  a take that discarded the bytes would make the loss permanent.

### The IPv6 flag, and why it is a flag

`SendToUdp` (59), `ConnectTcp` (38) and `RecvFromUdp` (60) are all inside the
frozen range, so their semantics and layouts may not change.  A flag is the
shape the frozen rule permits: §3.2 names **additive optional behaviour** as
the one change allowed there, and a caller passing zero is a caller whose
behaviour did not move.

With [`NETWORK_FLAG_IPV6`](../../abi/src/network.rs) set:

- **`SendToUdp`'s `a1`** is a pointer to sixteen bytes of IPv6 address in the
  caller's own memory instead of a packed word.  The pointer is checked
  against the user window before it is read, and the address is read before
  any frame exists.
- **`ConnectTcp`'s `a0`** is the same: a pointer to sixteen bytes.
- **`RecvFromUdp`'s record** is `UDP_SENDER6_RECORD_SIZE` bytes, the sixteen
  address bytes at `UDP_SENDER6_ADDRESS_OFFSET`, then the port, and `a4`
  must be at least that, which the call checks before it writes.  A caller
  that set the flag and passed the two-word record is refused with
  `InvalidArgument` rather than having sixteen bytes written past the end of
  its buffer.

A flag bit this build does not define is refused by `validate_known_flags`,
not ignored: a program that asked for a shape the kernel silently dropped
would read a record it did not get.

**Why not a second number.**  A `SendToUdp6` beside each call would have spent
numbers from the experimental range to say something the flags word already
had room for, and left two spellings of one operation to keep in step.  The
flags word was reserved zero in each of these calls precisely so that a use
like this would not have to.  `AcceptTcp` needs no flag: an accepted stream's
family is the client's, which the connection already knows.

A handled, unmasked signal is **delivered** rather than queued: the target's
context is redirected to the handler at its next install, with the record in
the argument registers, signal, sender, payload, and the interrupted resume
as the fourth, and the whole displaced context kept by the kernel for the
handler's `SigReturn`.  The delivery is transparent or it is a corruption;
the whole context is the difference.

The `*At` anchor readings, once, because all five share them: an **absolute**
path is anchored at the root and the descriptor is bypassed; **`AT_FDCWD`**
anchors at `/`, the one base every process shares, because there is no
per-process current directory yet; anything else resolves against the
directory the descriptor was opened from.  A descriptor that names no file of
the caller's, a pipe end, or a file that is not a directory is refused before
the path is looked at.

**Streams carry data through `Read` and `Write`.**  A connected stream
descriptor is readable and writable through the same two calls a file and a
pipe are, with the slots a file read takes, `a1` the offset, `a2` the
buffer, `a3` its length.  A stream has no position to seek, so the offset
slot is refused unless it is `READ_OFFSET_CURRENT`; a write goes out as one
segment and answers the bytes it carried; a read parks on an empty stream
the way a pipe's reader parks, and answers zero, end of file, once the
stream's connection is gone, which an orderly close's last acknowledgement
is what leaves behind.

IPsec's five calls install the two databases ESP reads.  They are a manager's
interface like the multicast ones: nothing here negotiates, and IKE is the
protocol that would.

- **`IpsecAddSp`**, `a0` the record; `a1` its length, exactly
  `IPSEC_SP_DEF_SIZE`; `a2`-`a5` reserved zero.  Answers the policy's id.  The
  list is **ordered and the first match wins**, which is what makes a narrow
  rule written above a broad one decide.  A `PROTECT` policy must name an
  association that exists at the moment it is installed: one installed ahead of
  its association would match a packet and have nothing to apply, and the two
  readings of that are sending plaintext and dropping in silence.
- **`IpsecDelSp`**, `a0` the id; `a1`-`a5` reserved zero.  Answers zero, or
  `NotFound`.
- **`IpsecAddSa`**, `a0` the record; `a1` its length, exactly
  `IPSEC_SA_DEF_SIZE`; `a2`-`a5` reserved zero.  Answers the association's id.
  An SPI another association holds is `AlreadyExists`, because the SPI is what
  names an association **on the wire** and two with one SPI would make an
  arriving packet belong to both.  Transport-mode ESP with AES-128-GCM or
  ChaCha20-Poly1305 is served; **AH and tunnel mode are `Unsupported`**, which
  is a different refusal from `InvalidArgument`: the machine understood the
  request and will not, and an ESP packet sent where a tunnel was asked for is
  one the peer's endpoint drops in silence.
- **`IpsecDelSa`**, `a0` the SPI; `a1`-`a5` reserved zero.  The SPI and not the
  id, because the SPI is what a manager has: it is in every packet on the wire.
  The policies that named the association are removed with it, because a policy
  whose association is gone would match a packet and have nothing to apply.
- **`IpsecGetStats`**, `a0` the record; `a1` its length, exactly
  `IPSEC_STATS_SIZE`; `a2`-`a5` reserved zero.  Four counters and the two table
  sizes.  `integrity_failures` and `replay_drops` are separate because they are
  two failures: a tag that did not verify is a packet that was not the peer's,
  and a refused sequence is a packet that was and arrived twice.

**What the wire carries.**  An outbound datagram a policy protects is built
first and encapsulated second, so the ports a selector names are the ones in
its UDP header.  The IP header's protocol becomes ESP's 50 and the payload
becomes `SPI`, sequence, the encrypted `inner || pad || pad_len || next_header`,
and the tag; the tag covers `SPI || sequence` as associated data, which is what
stops a replayed header from being accepted with a fresh one around it.

**A loopback send is still protected.**  The shortcut in `send_datagram` is
about the card and not about the protocol: a datagram this machine sends itself
is one that would have left under a policy and arrived under one, and a
loopback that skipped both would be a machine where a protected service was
reachable in plaintext by naming its own address.  So it is sealed, opened
again, and then delivered.

The multicast routing calls, six numbers above the frozen boundary, are a
manager's interface: they install the tables a forwarding decision reads, and
they do not speak a membership protocol.  IGMP and MLD are how a link tells a
router which groups it wants, and neither is here.

- **`MrtInit`**, `a0`-`a5` reserved zero.  Answers zero.  It installs the local
  interface and one link interface, and turns forwarding on; a second call is a
  no-op rather than an error, which is what makes a restart cheap.  The link
  interface is installed **here** and not by `MrtAddVif`, because there is one
  card: a caller that had to add it would be a caller whose routing works only
  if it also knew which index this call reserved.
- **`MrtDone`**, `a0`-`a5` reserved zero.  Answers zero, or `NotFound` when
  routing was not on.  Both tables are cleared, so a later `MrtInit` starts from
  the local interface and nothing else.
- **`MrtAddVif`**, `a0` the record; `a1` its length, exactly `MRT_VIF_DEF_SIZE`;
  `a2`-`a5` reserved zero.  Answers the index.  A `vif_index` of zero asks for
  automatic numbering, which is the one reading this build chose: the record's
  comment could be read as saying zero is the local interface, and one value
  cannot be both.  The local interface is `MrtInit`'s.  A second link interface
  is `AlreadyExists`: one card, so a second name for it would be a distinction
  with no behaviour behind it.
- **`MrtDelVif`**, `a0` the index; `a1`-`a5` reserved zero.  Answers zero.  The
  local interface is `InvalidArgument`, and an index nothing holds is
  `NotFound`.
- **`MrtAddMfc`**, `a0` the record; `a1` its length, exactly `MRT_MFC_DEF_SIZE`;
  `a2`-`a5` reserved zero.  Answers zero.  A second entry for one
  `(source, group)` **replaces** the first, unlike an interface: a forwarding
  entry is a route, and a route's second statement is a manager changing its
  mind.  An outgoing set that is empty, larger than the record's four, or
  repeats an interface is `InvalidArgument`.
- **`MrtDelMfc`**, `a0` the source, packed by `pack_address`; `a1` the group,
  the same way; `a2`-`a5` reserved zero.  Answers zero, or `NotFound`.

**What forwarding does, precisely.**  A packet whose destination is a group is
**received** when a forwarding entry names that group: the entry's group is the
group this machine forwards for, and receiving it is what lets the demux see it
at all.  The packet is then forwarded to the interfaces its entry names, with
the time-to-live decremented by one, and a copy is never sent back out of the
interface it arrived on.  A packet whose remaining hops do not clear an
interface's threshold gets no copy on that interface, and the boot's log says
so rather than dropping it silently.

**A rate limit is stored and not enforced.**  `MrtVifDef::rate_limit` is here
because the record carries it and a program reading its own interface back
should learn what it set.  Nothing enforces it: a rate needs a clock and a
bucket, and a drop from either is silent.  The field's own documentation says
this rather than implying otherwise.

The packet filter's four calls, which are above the frozen boundary and so
may still change, are the one policy a program installs that changes what the
demux does with a packet:

- **`FilterAddRule`**, `a0` the record; `a1` its length, exactly
  `FILTER_RULE_DEF_SIZE`; `a2`-`a5` reserved zero.  Answers the id the rule was
  given, which is never reused.  The record carries the action, the protocol,
  the address family, the direction, the stateful flag, the two prefix lengths,
  the two port ranges and the two sixteen-byte addresses.  A record no packet
  could match is `InvalidArgument` and installs nothing: an action that is
  neither allow nor deny, a prefix longer than its family's address, a port
  past sixteen bits, a range written backwards, a direction word nothing
  defines, a reserved word that is not zero, or a prefix in a rule that names
  no family.
- **`FilterRemoveRule`**, `a0` the id; `a1`-`a5` reserved zero.  Answers zero,
  or `NotFound` when no rule had that id.  Removal does not renumber the rules
  after it: an id names one rule for as long as that rule exists.
- **`FilterSetDefaultAction`**, `a0` the action; `a1`-`a5` reserved zero.
  Answers zero.  The tracked flows are forgotten in the same call, because they
  were remembered under the rules it is changing: an entry that outlived its
  rules would allow traffic the new set was written to stop.
- **`FilterGetStats`**, `a0` the record; `a1` its length, exactly
  `FILTER_STATS_SIZE`; `a2`-`a5` reserved zero.  Answers zero, with the default
  action, the rule count, the flow count and the two sixty-four-bit counters
  filled.

**The rules are the filter.**  There is no `enabled` flag and no call that
turns the filter on: a filter with no rules is one whose default action decides
everything, and the boot installs one that allows, which is what keeps every
exchange that ran before this call existed running the same way.  The previous
tree's filter had an `enabled` word, started closed, and no call among its four
ever set it, so the rules its programs installed were consulted by nothing while
each call answered success.  A state no call can reach is a state a boot cannot
show, which is why this one has none.

**Inbound and outbound are two decisions.**  A rule names one direction or
both, and the demux asks before any transport reads a byte: a packet a rule
drops has filled no queue and opened no stream.  A send asks the same way
before the frame reaches the card, and a refused send answers
`PermissionDenied` to the program rather than dropping silently, unlike a
refused packet arriving, whose sender this machine tells nothing.

**The four memory calls take **no pointer**: every argument is a value, which is
why they are the first calls a program can make that change its own address
space without the kernel copying anything in or out.

The four information calls all write a record into the caller's memory, and
their slots are not uniform: `GetTimeOfDay` and `SystemInfo` put a selector or
a clock in `a0` and so carry the record and its length in `a1`/`a2`, while
`GetRandom` and `AbiInfo` have no selector and carry them in `a0`/`a1`.  That
difference is exactly the mistake the first ring-3 boot of these found, the
entry path read `a1`/`a2` for all four, validated the length word as an
address, and refused a call whose handler worked.

`Read`'s buffer and length travel in slots because a ring-3 caller has no
borrow to hand over; the kernel's own callers leave both zero and pass the
borrow directly, which is why the reserved check starts past them.

What is already decided, and is what a new call with an address argument does too:

- **A caller's bytes are copied, never borrowed across a wait.**  A handler
  whose operation can block must stage the caller's bytes in kernel memory
  first.  A borrow into a program's address space that survives a context
  switch is a borrow into whatever the map points at when the wait ends.

- **A zero length is not a null check.**  A zero-length buffer is valid
  whatever the pointer says, because nothing is read; a non-zero length has to
  be checked before the first dereference.  The two cases are one `if` apart
  and getting it wrong is a fault on a call that asked for nothing.

- **The window is opened in one place.**  Whatever mechanism grants the kernel
  permission to touch a program's memory belongs in one module with one
  argument beside it, and every access goes through it.  The previous tree had
  that rule and a gate for it (`check-user-access-windows`); this tree will
  need both, and the gate is the part that matters, a rule enforced only by
  review is a rule the first exception erodes.

## 8. Userspace wrappers

The previous tree carried a `shared` crate holding its user-side wrappers: number
re-exports, the raw trap instruction, and typed `sys_<name>` wrappers. This tree
carries [`user_abi/`](../../user_abi/src/lib.rs), which is that crate: the
numbering as constants, one six-argument gate per machine, and the wrappers
above it.  The conventions it landed with:

- Name them `sys_` + the syscall's name (`sys_open`, `sys_read`, `sys_stat`).
- The wrapper answers the **raw status word**, and [`is_error`](../../user_abi/src/lib.rs)
  is the one test a program needs: the ABI encodes an error as a word with its
  high bit set, so a successful answer is a small positive number and a test a
  `no_std` program can make without carrying the kernel's `Result` type.  A
  program whose next step is meaningless after a refusal uses
  [`insist`](../../user_abi/src/lib.rs), the fail-fast form.
- Take Rust types in the signature where the operation has them (`&mut [u8]`
  for a read's buffer) and do the pointer/length packing here, that is the
  whole point of the layer; a path stays an address, because a NUL-terminated
  string is what the kernel's copy reads and a slice would lie about where it
  ends.
- The wrapper must not derive a syscall number arithmetically.  Name the
  constant the crate spells once, with the ABI's own value beside it.
- The gate is **one six-argument call per machine**, plus the `exit` that does
  not return: a new architecture teaches the crate two pieces of assembly, not
  one per operation.

## 9. Tests

A syscall change is not complete without both, to the extent they apply.  The
**numbering** test is a `mod tests` in `abi/src/number.rs`, pinning the number,
the count, and the frozen boundary.  The **handler** test is a `mod tests` in
`kernel/src/syscall/mod.rs`, pinning argument validation, error cases, and the
descriptor's state.

The handler tests drive the table the way a program does, a number, six argument
words, a value or an error back, rather than calling the handler directly.  A
handler that works only when called directly is one whose registration was never
tested.

## 10. Review checklist

Before requesting review of a syscall change, confirm each line:

- [ ] The number is appended, never renumbered, never reused.
- [ ] `SyscallNumber` carries the variant, and `PUBLIC_SYSCALL_COUNT` moves
      with it.
- [ ] The handler is registered in the table
      [`kernel/src/syscall/mod.rs`](../../kernel/src/syscall/mod.rs)
      installs.
- [ ] The handler returns `Result<SyscallDispatch>`, has no `panic!`/`unwrap`
      on user-controlled input, and validates unused arguments.
- [ ] User memory is reached only through the `user_memory` helpers.
- [ ] A typed `sys_*` wrapper exists and packs pointers itself.
- [ ] The ABI version is bumped for a non-additive change, with the reason in
      the commit message.
- [ ] `cargo test -p abi` is green: the numbering, the count and the frozen
      boundary are pinned there.
- [ ] `sh scripts/verify.sh p3` is green.

---

## Related documents

- [`CONTRIBUTING.md`](../../CONTRIBUTING.md), the short-form rules
- [`docs/architecture.md`](../architecture.md), the trap, the dispatch
  table, pointer validation
- [docs/fmts/code-style.md](code-style.md), error handling and module layout
- [docs/fmts/testing.md](testing.md), where tests go and how to register them
