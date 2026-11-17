# RFC 0001: Name a memory region two processes both map

- **Status:** Implemented
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-11-17
- **Supersedes:** none

## Summary

Give `ShmGet`, `ShmAt`, `ShmDt` and `ShmCtl` their mechanism: a kernel-owned
table from an integer key to a region of frames, an attach that maps those
frames into the calling process's own window, and a detach that takes the
mapping away without taking the region with it.  A region outlives the process
that made it and every process that mapped it; it goes away when the last
attach is dropped and a control call says so, which is the one place this
design chooses and the reason it needs writing down.

## Motivation

Four numbers are frozen in [`abi/src/number.rs`](../../abi/src/number.rs) as
`ShmGet = 100`, `ShmAt = 101`, `ShmDt = 102` and `ShmCtl = 103`, and nothing
serves them: a program that calls one is told `NotImplemented`, which is the
answer for a number that was never wired.

[`docs/roadmap.md`](../roadmap.md) lists shared memory as Level 8's second row
and calls it "a decision about the address space and not wiring".  That is the
claim this document has to make good, and the reason it is true is that this
tree already has **two** ways for a frame to be in two places, and neither is
shared memory:

- `fork` makes two spaces map one frame, but it demotes the page to read-only
  and marks it for copy-on-write, so the first write gives that process a
  private copy.  That is the right answer for a fork and the wrong one here: a
  shared region whose first write silently unshares is not shared memory.
- `Mmap` maps fresh frames into **one** caller's window, and nothing can name
  them afterwards.

So the missing thing is not the frame machinery.  It is a name that survives a
process, and a mapping that stays shared after a write.

## Current state

The pieces this design has to fit into, by file.

**The frames are already refcounted.**
[`memory/src/frame.rs`](../../memory/src/frame.rs) has `add_reference` (which
refuses to wrap at `u8::MAX` and answers whether it took),
`release_reference` (which answers whether the caller was the last owner and
therefore must free), and `co_owners`.  `deallocate` refuses a frame whose
count is not zero.  The protocol is already used by `fork`.

**A space records what it owns.**
[`kernel/src/address_space/space.rs`](../../kernel/src/address_space/space.rs)
has `own(frame)`, which costs one slot against `MAX_OWNED_FRAMES = 4096` per
space, and `release`, which walks that record and frees what it was the last
owner of.  A frame in a space's record but mapped by nobody is what a `Munmap`
leaves behind until the record is released; the two are separate steps on
purpose.

**Mapping and reserving.**
`AddressSpace::reserve(hint, length)` places a range by counting down from the
window's top, and `map_page_with(va, frame, permissions)` writes one leaf.  A
page mapped writable and **not** marked copy-on-write stays writable after a
write, which is the property shared memory needs and the one `share_frame`
deliberately does not give.

**The syscall path.**
[`kernel/src/process/memory.rs`](../../kernel/src/process/memory.rs) forwards
`Mmap`, `Munmap`, `Brk` and `ReclaimPages` to the registry after
`SyscallContext` validation, and
[`kernel/src/syscall/handlers.rs`](../../kernel/src/syscall/handlers.rs) serves
them; `mmap` already refuses `PROT_WRITE | PROT_EXEC` on the one-rule argument
`SECURITY.md` makes.  [`abi/src/memory.rs`](../../abi/src/memory.rs) holds the
`PROT_*` and `MAP_*` constants.

**What does not exist.** No table of regions, no key space, no attach count, no
`Shm*` handler, no ABI record for a control request.  The four numbers are the
whole of what this tree has.

## Design

### The region

A region is a fixed-size run of frames, allocated once, never resized, and
**not owned by any address space**:

```text
struct Region {
    key: i32,             // the name ShmGet answered, or shmget's IPC_PRIVATE
    frames: Vec<usize>,   // pool frames, each with one reference per attach
    bytes: usize,         // the length every attach maps
    attaches: usize,      // how many mappings exist right now
    pending: usize,       // attaches between lookup and mapping
    marked: bool,         // ShmCtl said "destroy when the last attach goes"
}
```

The table is one `sync::Mutex<Vec<Region>>` beside the scheduler's, reached the
way the descriptor registry is: a free function in the kernel that the handler
calls, not a field a handler reaches into.  A `Vec` and not a fixed array,
because the key namespace is dynamic and has no useful fixed ceiling.  The lock
is taken for the length of one table operation, with the region-table then
frame-pool order stated at `get_or_create`.

### The four calls

**`ShmGet(key, bytes, flags)`** answers a region's identifier.

- `key = 0` means "no name, and nobody else may find it", the Unix
  `IPC_PRIVATE`.  It always makes a new region and the caller must pass its
  identifier to whoever should map it.
- Otherwise the key names a region: a region with that key is answered if
  `bytes` is not larger than its length, and made if there is none.
- The flags are the ABI's and `IPC_CREAT` must be set to make a region under a
  name, so a mistyped key answers `NotFound` rather than quietly making a
  second region.  An unknown flag bit is `InvalidArgument`, the rule every
  other call in this tree keeps.
- `bytes` is rounded up to a page, refused above `MAP_MAX_BYTES`, and refused
  at zero.
- The identifier is the key for a named region, and a **negative synthetic
  value** for an `IPC_PRIVATE` one, because the ABI's answer is one word and a
  program that hands `0` to `ShmAt` must be refused rather than taken to mean
  "the first region": zero is not an identifier in this design.

**`ShmAt(id, address, flags)`** maps the region into the calling process and
answers where.

- `address = 0` lets the kernel reserve, the same way `Mmap`'s hint does, and
  it is the only form this design admits at first.  A fixed address is
  `InvalidArgument` until something needs it, because a fixed address is a
  program asserting a number about a space it does not own.
- `address` is page-aligned when it is not zero, and a hint that is not usable
  is a reservation at the window's top, never an error.
- The permissions are the attach's: `PROT_READ` always, `PROT_WRITE` if asked,
  `PROT_EXEC` refused together with `PROT_WRITE` on the rule `mmap` already
  enforces.
- **Every page is mapped writable if the attach asked for it, and none is
  marked copy-on-write.**  That is the whole difference from `fork`: nothing
  here demotes, so nothing here unshares.  The frame is shared, not promised.
- Each attach runs `add_reference` once per frame and `own`s each frame in the
  calling space's record.  A space that refused the record has the attach
  undone.
- The region table records an attach as **pending** from the moment `ShmAt`
  finds the region until the mapping either finishes or aborts.  A pending
  attach keeps `IPC_RMID` from removing the region, and an aborted attach that
  leaves a marked region vacant is itself responsible for destroying it.
- A failed mapping removes every page it wrote and every ownership record it
  added.  The pool references are then dropped once, by the attach path.
- Every attach maps **the whole region**.  A partial attach is `ShmAt` with a
  length, and the ABI's version of this call has none; inventing one would be
  inventing an argument the frozen numbering does not have.
- `Munmap` refuses a range that overlaps a shared attachment.  A shared
  mapping leaves through `ShmDt`, because that is the operation that also
  updates the region's attach count.

**`ShmDt(address)`** unmaps an attach and drops one reference per frame.

A detach is the inverse of one attach and nothing more: `unmap_page` takes the
mapping away and the frame's `release_reference` says whether it was the last
owner.  The frame is **not** freed when another region or another attach still
holds it, and it **is** freed when this detach was the last.  A `ShmDt` of an
address with no attach answers `NotFound`, which is the answer the ABI's own
`decode_error` already defines for "nothing of that name here".

**`ShmCtl(id, command, argument)`** is the one call that changes a region's
life.

- `IPC_RMID` marks the region for destruction.  The region stays until the last
  attach goes, because a mark is a promise about the future and freeing now
  would take memory out from under a program that is using it.  When the last
  detach finds the mark set, that detach frees the frames.
- `IPC_STAT` answers the region's length and attach count into a record the
  ABI states.  It exists because "is anyone else attached" is the question a
  program with a region needs an answer to, and the alternative is a program
  counting attaches itself.
- Any other command is `InvalidArgument`, and the two commands this design does
  not implement are named in Alternatives rather than silently refused as
  unknown.

### Fork, exec and exit

A fork inherits the parent's shared mappings.  The child's pages are **not**
demoted to copy-on-write: a writable shared page stays writable and both
processes continue to see one another's writes.  The child records the same
attach ranges and raises each region's attach count, so `ShmDt`, `IPC_STAT` and
`IPC_RMID` answer about the child as well.

An `exec` replaces the image and therefore detaches every shared mapping of the
old image.  This CPU installs the new root before releasing the old space; a task
cannot be held by two CPUs, and an idle CPU installs the kernel root.  The
region count and the frame references therefore move in the same operation.

A process that exits without calling `ShmDt` follows the same rule.  Its
attachment is removed at exit, and the switch that leaves the finished task
installs the next or kernel root before releasing the address space.

### The key space, and who may name what

A key is an `i32`.  A named region's key is stored as the program gave it, and
`ShmGet` finds it by value.  Two programs that both ask for key `0x1234` get
the same region, which is the point of a key and also the whole of the
authority model: **there is none.**  This design does not ask who made a
region, and it does not care.

A named key must be positive.  The negative half of `i32` belongs to the
counter that names `IPC_PRIVATE` regions, and allowing a caller to choose a
negative name would let it collide with a later private identifier.

That is stated rather than implied because the tree already has a MAC policy and
an `AccessQuery` call, and a reader will reasonably ask why a shared region is
not an object the policy knows about.  The answer is that it is not an object in
the filesystem's sense, it has no path, and giving it a label is a decision
about identity that this tree has not made: `User` labels exist in `security`
and nothing labels a process yet.  A region is therefore as visible as its key,
which is the Unix model and a thing a program opts into by choosing a
guessable key.

### Failure

Every failure is before the first page is mapped or after the last is unmapped:

- a region out of frames answers `OutOfMemory` and leaves nothing;
- an attach that cannot record or map a frame unmaps the pages it did map,
  drops each reference, and answers `OutOfMemory`;
- an attach aborted while its region is marked removes the now-vacant region;
- a detach frees only on the `true` answer from `release_reference`, which is
  the protocol's own rule and the reason a double detach is not a double free.

## Alternatives

**A file in a filesystem, mapped through `Mmap`.**  The tree has `MAP_ANONYMOUS`
and no `MAP_SHARED`, and adding one would make every filesystem's `read` and
`write` a coherency question the page cache does not have an answer for today.
Shared memory as a file is the right destination and it is two decisions away;
the four numbers exist now and the filesystem mapping does not.

**Share a fork's frames instead of demoting them.**  This is the alternative a
reader will reach for first, because `fork` already makes two spaces map one
frame.  It is refused because the two calls mean opposite things: `fork`
promises that a child's write does not reach the parent, and shared memory
promises that it does.  Making one flag choose between them would put the
promise in a boolean at the call site and make a fork that forgot the flag a
silent unshare, which is the class of defect Level 7.5 just finished fixing.

**Let each attach choose its own length.**  A region is a run of frames and an
attach maps a page-aligned subset of it; this is what `shmat`'s `shmflg` allows
in some systems and what `ShmAt`'s two arguments cannot express.  Refused
because the frozen ABI gives `ShmAt` no length, and a design that invented one
would be changing a numbering this tree says is frozen.

**A fixed address only.**  Some systems map a shared region at an address the
program chose, so a pointer in one process is a pointer in another.  This design
admits `address = 0` first and the fixed form later, because a fixed address is
a program making an assertion about a space the kernel reserved and a wrong
assertion is a fault in the program rather than a refusal from the kernel.

**`IPC_RMID` frees immediately.**  Simpler, and wrong: a region with an attach
is memory a program has mapped, and freeing it under that program is the same
defect address-space release avoids by switching roots before it frees pages.

## Drawbacks

- The table is a second nameless namespace beside the descriptor table, with
  its own lock and its own ownership rules, and a reader has to learn both.
- A key is an authority: two processes that choose the same number share
  memory.  This is Unix's model and it is a model this tree's MAC policy does
  not see.
- Every attach costs one ownership record per page against
  `MAX_OWNED_FRAMES`, so a 16 MiB region attaches 4096 pages and fills a
  space's entire record.  `Mmap` has the same cost and the same bound, and this
  design inherits it rather than fixing it.
- The region lives in the kernel's heap, so its frames are not accounted the
  way a space's are: `free_frames` falls by the region's size and the only
  owner is the table.  A program that leaks a region leaks pool the boot's
  frame census will not attribute to a process.

## Compatibility and migration

The four numbers are frozen and are served for the first time, so there is no
old behaviour to migrate: a program that called them got `NotImplemented` and
now gets an answer or a refusal from this design.

`abi` grows the flag constants (`IPC_CREAT`, `IPC_RMID`, `IPC_STAT`), the
`ShmGet`/`ShmAt`/`ShmDt`/`ShmCtl` argument shapes, and one record for
`IPC_STAT`; `user_abi` grows four wrappers.  None of that changes the frozen
range's *numbers*, which is the part `docs/fmts/syscall-abi.md` fixes.

A machine with shared memory and one without answer the same four numbers: this
design has no per-machine part, so no `arch` change and no option.

## How this is proven

- A host test per validation rule: a zero-length region, a length above
  `MAP_MAX_BYTES`, an unknown flag, `ShmAt` of an identifier nothing names, a
  fixed address, and `PROT_WRITE | PROT_EXEC` all answer `InvalidArgument`.
  These run the handler the machine runs, which is the pattern `mmap`'s tests
  already use.
- A host test of the region table without frames: two `ShmGet`s of one key
  answer one identifier, `IPC_PRIVATE` makes a new one each time, and
  `IPC_RMID` that is not followed by a detach leaves the region visible.
- A boot exercise in `/bin/init`: make a region, fork, and have the child write
  a byte through its attach and the parent read it back unchanged through its
  own.  This is the assertion the whole design exists for, and it is the one a
  host cannot make: it needs two address spaces.
- The gate line the boot prints, in the shape this tree uses for every
  mechanism: `protofire: shared region key 4660 attached twice, one byte
  crossed`.  Required whole, with the key, so a boot that answered the calls
  but shared nothing fails on the byte rather than on the line's absence.
- The detach path is proven by the region being released and the boot's frame
  census returning to its earlier count, which the existing
  `address spaces reaped` line already prints.

## Unresolved questions

- **Should `ShmCtl` also implement `IPC_SET`?**  It would change a region's
  length and mode, and a region's length is immutable in this design.  A later
  RFC can make regions resizable; this one refuses rather than lying.
- **Should a region be labelled?**  If processes ever carry MAC labels, a
  region named by a guessable key is the obvious next thing to label, and the
  answer belongs with the RFC that gives a process an identity rather than
  here.
- **What happens to a region at boot's end?**  Today every task finishes and
  every space is reaped; a region has no such moment, so a leaked region's
  frames stay until the machine stops.  Whether the boot's end should sweep the
  table is a decision about what a boot's exit means, which this tree has not
  written down.
