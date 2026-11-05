# Syscall ABI Specification

> **Status:** normative. Changes to this document require maintainer review.
> **Applies to:** `abi/`, `syscall/`, `kernel/src/syscall/`.

The syscall ABI is the compatibility boundary of Protofire. Ring-3 programs are
self-contained ELF files that talk to the kernel exclusively through this
interface; there is no dynamic linker and no shared library to absorb a change.
A number that moves, a struct that grows, or a pointer that is validated one way
in the kernel and another way in the wrapper is a silent breakage of every
already-built program.

This document is the detailed contract.  [`docs/contributing.md`](../contributing.md)
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

It defines:

| Item | Meaning |
|------|---------|
| `SyscallNumber` | The number of each syscall, a `#[repr(usize)]` enum |
| `PUBLIC_SYSCALL_COUNT` | How many numbers this build serves; the dispatch table is sized from it |

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
- **Never reuse** a number whose syscall was removed. If a syscall must go, its
  number is retired permanently, rename the constant to `SYS_RESERVED_<n>` and
  leave the slot empty. Slots 141 and 142 (`SYS_RESERVED_141`,
  `SYS_RESERVED_142`) are live examples: they are numbered, never reused, and
  still classified as Experimental "until assigned".
- **Never insert** in the middle of the range to keep a group tidy. The file is
  ordered by number because numbering is historical, not thematic.
- New syscalls take the **next unused number** at the end of the defined range,
  and `SYSCALL_COUNT` is raised to `new_number + 1` in the same edit.

### 3.2 Stability classes

| Range | Class | Contract |
|-------|-------|----------|
| `0..=120` | **Stable** | Frozen. Semantics, argument order, and record layouts do not change. Additive *optional* behaviour is the only permitted change. |
| `121..=SYSCALL_COUNT - 1` | **Experimental** | May still be adjusted. Behaviour, arguments, and record layouts may change on a **minor** version bump. |

The **Experimental** line is the one that lets an argument change without a
major bump: a slot no program outside this tree is built against can be
redefined, and `SYSCALL_ABI_VERSION_MINOR` is what says it was.  A version in
the frozen range never moves that way, there the table above applies as
written, and a redefinition is a major bump.

New syscalls are always assigned in the Experimental range until they have
matured and a maintainer graduates them. The classification is computed, not
hand-maintained: `syscall_stability(n)` returns `Stable` for `n <= 120` and
`Experimental` otherwise, and its unit test pins both boundaries. Graduating a
syscall means changing that boundary deliberately, never editing one entry in
isolation.

Beyond `SYSCALL_COUNT` and up to `MAX_SYSCALLS`, slots exist but are unassigned.
The dispatch table must leave them empty; a test asserts the first unassigned
slot is `None`.

---

## 4. Versioning

Bump the ABI version in [`abi/src/syscall.rs`](../../abi/src/syscall.rs) as part
of the same change that alters the ABI:

| Change | Bump |
|--------|------|
| New syscall appended, new flag bit, new optional field at the end of a record | `SYSCALL_ABI_VERSION_MINOR` |
| Changed semantics of an existing syscall, changed argument order, changed or reordered fields in a record, removed syscall | `SYSCALL_ABI_VERSION_MAJOR` |

A major bump is a **last resort**. If the change can be expressed additively, a new syscall alongside the old one, a new flag, a field appended to a
fixed-size record, do that instead. The existing unit test pins the current
version constants; update it in the same commit, and make sure the commit
message says why the bump is warranted.

A program reads the version at runtime through the `abi_info` syscall, so it can
detect which side of a change it is talking to.  The syscall is numbered and
served as `NotImplemented` until the field that carries the version arrives.

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

3. **Write the handler** in [`kernel/src/syscall/mod.rs`](../../kernel/src/syscall/mod.rs).
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
  the context plus the address-shaped arguments already turned into borrows, `path: Option<&str>`, `buffer: Option<&mut [u8]>`.  A handler that did
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

There are no user pointers in this tree yet, and this section says what that
means rather than what it would mean if there were.

A syscall's arguments are six words, and today the caller is the kernel: the
two address-shaped arguments arrive as borrows through `Arguments`, built by
the code that owns the buffer.  There is no address to validate because there
is no privilege boundary to validate across.

When a program can call, the boundary appears and so does this section.  What
is already decided, and is worth writing down before there is code to break:

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

The previous tree carried a `shared` crate holding its user-side wrappers: number re-exports, the raw
trap instruction, and typed `sys_<name>` wrappers.  This tree has no such crate
yet, `apps/` holds three program skeletons, so the wrapper conventions are
recorded here for the change that adds one:

- Name them `sys_` + the syscall's name (`sys_open`, `sys_read`, `sys_stat`).
- Convert the raw status word into a typed `Result` using
  [`abi::syscall::decode_result`](../../abi/src/syscall.rs).  Do not leak raw
  register values to callers.
- Take Rust types in the signature (`&str`, `&mut [u8]`) and do the
  pointer/length packing here, that is the whole point of the layer.
- The wrapper must not derive a syscall number arithmetically.  Name the
  variant of `abi::SyscallNumber`.

## 9. Tests

A syscall change is not complete without both, to the extent they apply:

| Layer | Location | What it pins |
|-------|----------|--------------|
| Numbering | `mod tests` in `abi/src/number.rs` | The number, the count, and the frozen boundary |
| Handler | `mod tests` in `kernel/src/syscall/mod.rs` | Argument validation, error cases, the descriptor's state |

The handler tests drive the table the way a program does, a number, six argument
words, a value or an error back, rather than calling the handler directly.  A
handler that works only when called directly is one whose registration was never
tested.

## 10. Review checklist

Before requesting review of a syscall change, confirm each line:

- [ ] The number is appended, never renumbered, never reused.
- [ ] `SYSCALL_COUNT` and `syscall_name` are updated.
- [ ] `SyscallNumber` derives from the manifest constant, not a literal.
- [ ] `SYSCALL_POINTER_SPECS` has an entry at the right index.
- [ ] The handler is registered in `SYSCALL_REGISTRY`.
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

- [`docs/contributing.md`](../contributing.md), the short-form rules
- [`docs/architecture.md`](../architecture.md), the trap, the dispatch
  table, pointer validation
- [docs/fmts/code-style.md](code-style.md), error handling and module layout
- [docs/fmts/testing.md](testing.md), where tests go and how to register them
