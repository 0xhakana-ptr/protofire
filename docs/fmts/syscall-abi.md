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
  and `PUBLIC_SYSCALL_COUNT` — derived from the last variant in
  [`abi/src/number.rs`](../../abi/src/number.rs) — moves with it in the same
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

The registry's own handlers still take borrows — `Arguments::path` and
`Arguments::buffer`, built by the kernel code that owns the buffer — and a
borrow needs no validation.  The boundary exists where programs call:
`Read` and `Write` to a pipe take a ring-3 buffer, and the handler validates
the range with `is_user_range` before it touches a byte, because an address
that arrives in a register is a number until something checks it.

The calls a ring-3 program can make today, and the slots each carries:

The calls a ring-3 program can make today, and the slots each carries.

- **`Open`** — `a0` the path, a NUL-terminated string in the caller's memory;
  `a1` the flags; `a2`-`a3` reserved zero.
- **`Read`** — `a0` the descriptor; `a1` the offset, or `READ_OFFSET_CURRENT`;
  `a2` the buffer; `a3` its length; `a4`-`a5` reserved zero.
- **`Close`** — `a0` the descriptor; `a1`-`a5` reserved zero.
- **`ExecProcess`** — `a0` the path, a NUL-terminated string in the caller's
  memory naming the file the process becomes; `a1`-`a5` reserved zero.
- **`Mmap`** — `a0` an address hint, or zero for "anywhere"; `a1` the length in
  bytes; `a2` a `PROT_*` set; `a3` a `MAP_*` set that has to name anonymous
  private memory; `a4`-`a5` reserved zero.  Answers the base address, which is
  page-aligned and inside the caller's window.
- **`Munmap`** — `a0` the address; `a1` the length in bytes; `a2`-`a5` reserved
  zero.  Both are rounded to pages, and the answer is how many were taken away.
- **`Brk`** — `a0` the new break, or zero to ask what it is; `a1`-`a5` reserved
  zero.  Answers the break the kernel now holds, so a caller that asked for more
  than it can have learns what it actually got.
- **`ReclaimPages`** — `a0` how many pages the caller would like back, or zero
  for as many as will go; `a1`-`a5` reserved zero.  Answers how many came back.
- **`Write`** — `a0` the descriptor; `a1` the buffer; `a2` its length;
  `a3`-`a5` reserved zero.  Answers the bytes accepted, starting at the
  descriptor's own position, which moves by them.  A `Write` whose `a2` is
  zero names no bytes and is the announcement, not a write.
- **`Stat`** — `a0` the path, a NUL-terminated string; `a1` the record;
  `a2` its length, at least `FILE_STAT_SIZE`; `a3`-`a5` reserved zero.
  Answers zero, with the record filled.
- **`ReadDir`** — `a0` the path; `a1` the index; `a2` the buffer; `a3` its
  length; `a4`-`a5` reserved zero.  Answers the bytes written: the ABI's
  `DirectoryEntryRecord` header with the name's UTF-8 bytes packed after it.
  An index past the end answers `NotFound`.
- **`CreateDir`** — `a0` the path; `a1`-`a5` reserved zero.  Answers zero.
- **`RemovePath`** — `a0` the path; `a1`-`a5` reserved zero.  Answers zero.
- **`Rename`** — `a0` the old path; `a1` the new path; `a2`-`a5` reserved
  zero.  Answers zero.  Both names must resolve to one filesystem.
- **`OpenAt`** — `a0` the descriptor the path is relative to, or `AT_FDCWD`;
  `a1` the path; `a2` the flags; `a3`-`a5` reserved zero.  Answers a
  descriptor, like `Open`.
- **`StatAt`** — `a0` the descriptor; `a1` the path; `a2` the record; `a3`
  its length; `a4`-`a5` reserved zero.  Answers zero, like `Stat`.
- **`RenameAt`** — `a0` the old descriptor; `a1` the old path; `a2` the new
  descriptor; `a3` the new path; `a4`-`a5` reserved zero.  Answers zero.
- **`CreateDirAt`** — `a0` the descriptor; `a1` the path; `a2`-`a5` reserved
  zero.  Answers zero.
- **`RemovePathAt`** — `a0` the descriptor; `a1` the path; `a2`-`a5` reserved
  zero.  Answers zero.

The `*At` anchor readings, once, because all five share them: an **absolute**
path is anchored at the root and the descriptor is bypassed; **`AT_FDCWD`**
anchors at `/`, the one base every process shares, because there is no
per-process current directory yet; anything else resolves against the
directory the descriptor was opened from.  A descriptor that names no file of
the caller's, a pipe end, or a file that is not a directory is refused before
the path is looked at.

The four memory calls take **no pointer**: every argument is a value, which is
why they are the first calls a program can make that change its own address
space without the kernel copying anything in or out.

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
has no such crate yet, `apps/` holds three program skeletons, so the wrapper
conventions are recorded here for the change that adds one:

- Name them `sys_` + the syscall's name (`sys_open`, `sys_read`, `sys_stat`).
- Convert the raw status word into a typed `Result` using
  [`abi::syscall::decode_result`](../../abi/src/syscall.rs).  Do not leak raw
  register values to callers.
- Take Rust types in the signature (`&str`, `&mut [u8]`) and do the
  pointer/length packing here, that is the whole point of the layer.
- The wrapper must not derive a syscall number arithmetically.  Name the
  variant of `abi::SyscallNumber`.

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
