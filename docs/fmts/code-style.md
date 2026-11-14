# Code Style Specification

> **Status:** normative, except where a rule is marked *convention*.
> **Applies to:** every crate in the workspace.

The repository is a large Rust tree written over time by more than one hand, and
it keeps growing. Consistency is what keeps that readable: a contributor should
be able to open an unfamiliar module, a filesystem driver, a network protocol,
the scheduler, and recognise the shape of it without learning a new author's
habits first.

The rules below are the ones this codebase actually follows. Where a rule is
mechanical it says so, and you should let the tool do the work; where it is a
convention, it says that too, and it is on you and your reviewer.

Two rule sets, and only one of them is mechanical.  **Formatting** (§2) is
`cargo fmt` / `cargo fmt --all -- --check`, part of `sh scripts/verify.sh p0`.
**Everything else** is review.

---

## 1. Match the neighborhood

This is the rule the rest of the document elaborates, and it outranks any
stylistic preference you brought with you.

When you edit a module, follow **its** conventions, the same comment density,
the same naming, the same structure, even where this document would permit
something else. A change that is locally consistent and globally slightly
idiosyncratic is a much smaller cost than a diff that reformats a file to a new
standard while claiming to fix a bug. Do not mix a refactor into a behavioural
change; if the style of a file genuinely needs to change, that is its own PR
with its own justification.

---

## 2. Formatting

`cargo fmt` is mandatory and its output is the standard. The configuration is
[`.rustfmt.toml`](../../.rustfmt.toml); it pins `required_version = 1.10.0` and
sets `unstable_features = true`, so it needs the nightly toolchain that
[`rust-toolchain.toml`](../../rust-toolchain.toml) provides. Run `cargo fmt --all`
rather than a bare `cargo fmt` if you are unsure which toolchain is active.

```bash
cargo fmt --all   # format the tree
cargo fmt --all -- --check    # what the gate runs, must be clean
```

Settings worth knowing before you fight the formatter:

`max_width = 100`, line width, wider than the usual 80, which is why separator
rules fill to ~100.  `comment_width = 80`, comments wrap narrower than code.
`wrap_comments = true`, the formatter reflows your comment text, so write
comments as prose and let it wrap.  `imports_granularity = Item`, one `use` per
item; it will not merge them.  `binop_separator = Front`, a wrapped expression
breaks *before* the operator.  `trailing_comma = Vertical`, multi-line lists
get a trailing comma.  `merge_derives = true`, multiple `#[derive]` attributes
are merged.

Two things the formatter does **not** do, and which are therefore yours to get
right: it does not reorder `use` groups (§5), and it does not format the contents
of string literals (`format_strings = false`).

---

## 3. Naming

**Types, structs, enums and traits** are `UpperCamelCase`
`MemoryManager`, `SyscallDispatch`.  **Enum variants** are `UpperCamelCase`
`InvalidArgument`, `ReturnFromException`.  **Functions, methods and locals** are
`snake_case`, `install_global_unchecked`, `try_read_byte`.  **Constants and
statics** are `SCREAMING_SNAKE_CASE`, `SYSCALL_COUNT`, `GLOBAL_TABLE`,
`PERCPU_OFFSET_SCHEDULER`.  **Modules and files** are `snake_case`
`block_cache.rs`, `pci_transport.rs`.

Files are named after what they contain, in `snake_case`, with no camel case
anywhere in the tree. A module directory with no `mod.rs` of its own uses
`#[path = "..."]` from its parent instead, see §4.

### Established suffixes

These suffixes carry meaning, and a reader will assume them:

These suffixes carry meaning, and a reader will assume them.

- **`install_global` / `install_global_unchecked` / `global()`**, the
  global-singleton pattern, see §8.  `_unchecked` marks the variant that skips
  the lifetime requirement and is therefore `unsafe`.
- **`_locked`**, requires the caller to already hold the relevant lock.
  Almost always `pub(crate)`, and always documented as such.  Examples:
  `resolve_path_locked`, `allocate_locked`.
- **`try_*`**, a non-blocking or fallible attempt.  Returns `Option<T>`,
  `Result<T>`, or `bool`, never a bare value.  Examples: `try_read_byte`,
  `try_consume_send_nonce`.
- **`raw_*`**, hands back an underlying handle or un-wrapped object rather than
  a safe abstraction.  Examples: `raw_sockets`, `raw_socket_object`.
- **`*_count`, `*_initialized`, `*_probed`**, counter and status-flag statics.

### The `GLOBAL_*` singleton convention

Process-wide singletons are `SCREAMING_SNAKE_CASE` statics whose names read
`GLOBAL_<THING>`: `GLOBAL_TABLE`, `GLOBAL_FS`, `GLOBAL_MEMORY_MANAGER`,
`GLOBAL_STACK`, `GLOBAL_AUDIT_BUFFER`, `GLOBAL_ALLOCATOR`. Subsystems that are
not "the" global of their kind are named for what they hold instead
(`VOLUME_RECOVERY_SUMMARY`, `BOOT_REPORT`, `WORKER_REGISTRY`).

### Names the compiler dictates

A handful of symbols come from outside and must not be renamed.
`__stack_chk_guard` is the stack-canary symbol the compiler emits references to,
and it legitimately violates `SCREAMING_SNAKE_CASE`. Such cases are declared with
a targeted `#[allow(non_upper_case_globals)]` on the item rather than a
module-wide allow.

---

## 4. Module and file layout

The crate roots declare their modules alphabetically. `abi/src/lib.rs` is the
shortest example, and it also shows the shape of the tree: the filesystem, the
memory manager, the network stack, the drivers, and the syscall table are
subsystems of the crate in their own right, not submodules of `kernel`:

```rust
pub mod abi;
pub mod arch;
pub mod drivers;
pub mod fs;
pub mod kernel;
pub mod memory;
pub mod network;
pub mod syscall;
pub mod user;
pub mod util;
```

A crate root declares its modules the same way, `pub mod boot;` and onward,
alphabetically, with feature-gated modules carrying their `#[cfg]` and a note
explaining the gate.

The rest of a `mod.rs` follows this order:

1. The `//!` file header (§[comments.md](comments.md#2-the-file-header)).
2. `pub mod` declarations, alphabetical.
3. `use` imports, grouped per §5.
4. `pub use` re-exports.
5. `const` and `static` items.
6. Types, then their `impl` blocks, then free functions.
7. `#[cfg(test)] mod tests` at the end of the file.

A file that would otherwise need a `mod.rs` in a subdirectory may instead be
declared from its parent with `#[path]`, which is how `syscall/src/`
organises its handler categories:

```rust
#[path = "fs/metadata.rs"]
mod fs_metadata;
```

Use that when a directory would hold a single file and the extra `mod.rs` would
be a level of indirection with nothing in it. Where a directory genuinely has
several files (`fs/src/pyrofs/`, `net/src/transport/`), a normal
`mod.rs` is the right shape.

Re-export deliberately rather than wholesale: `pub use` in a `mod.rs` is how a
subsystem presents a flat surface (`process::HANDLE_RIGHT_READ`) while its
implementation lives in submodules. If a `pub use` exists to make a sibling
module's imports read better, say so in a comment, a bare re-export with no
consumer is hard to justify later.

### File-level `allow(dead_code)`

An item-level `#[allow(dead_code)]` silences one item; the next unused item in
the same file still reports, which is the signal that keeps a file honest. A
**file-level** `#![allow(dead_code)]` turns the lint off for everything, so it
needs a reason and an exit condition written next to it:

```rust
// Why: a field the parser does not read yet is still part of the format's
// description, and the description is what the parser is written against.
// When to remove: when every field here is read by the parser.
#![allow(dead_code)]
```

`scripts/verify.sh` p2 fails a change that adds one without both lines, through
the `dead-code` census. The two that motivated the check had outlived their
reasons: a skeleton whose comment still said "step 1b wires the consumers"
after step 1b had been done, and accessors described as having "no callers in
the kernel" that had four. Disk-format type tables and host-coverage modules
are the legitimate uses; "the compiler was complaining" is not.

---

## 5. Imports

[`.rustfmt.toml`](../../.rustfmt.toml) sets `imports_granularity = "Item"` and
`reorder_imports = true`, but `group_imports = "Preserve"`, meaning rustfmt
sorts *within* a group and leaves *which group an import is in* to you. The
grouping is therefore a convention you have to maintain by hand, and it has
three tiers separated by blank lines:

1. **External crates**, `core::`, then `alloc::`, each internally sorted.
2. **Crate-absolute paths**, `crate::…`, sorted.
3. **Parent-relative paths**, `super::…`, sorted, last.

```rust
use alloc::sync::Arc;

use crate::kernel::process::Scheduler;
use crate::kernel::process::Thread;
use crate::kernel::process::ThreadWaitOutcome;
use crate::kernel::sync::Mutex;
use crate::kernel::sync::MutexGuard;

use super::plan_timed_wait;
use super::TimedWaitPlan;
use super::WaitQueue;
use super::WaitTimeoutCleanupRef;
```

Because granularity is `Item`, a single type imported from a deep path gets its
own line rather than being nested:

```rust
use crate::fs::DirectoryEntry;
use crate::fs::FileMetadata;
use crate::fs::NodeKind;
```

Prefer `super::` over `crate::` when the item is genuinely in the parent module,
it keeps a module readable in isolation. Reach for `crate::` when crossing
subsystems. `#[cfg]`-gated imports sit in the group they belong to, on their own
line.

A small number of files place a `super::` import before the `crate::` group
(`arch/x86_64/src/interrupts.rs` is one). Follow the three-tier order in new
code; do not take those files as the model.

---

## 6. Visibility

**Start private, widen reluctantly.** The default for an internal helper is
`pub(crate)`, and `pub(super)` is for items that exist only for the parent
module, like syscall handlers.

- **`pub(crate)`**, shared across the kernel but not part of any public
  surface. This is the normal choice for a helper that another subsystem needs.
- **`pub(super)`**, visible only to the parent, typically a handler reached via
  a registry table. Syscall handlers are `pub(super)` for exactly this reason:
  they are callable through `SYSCALL_REGISTRY` and nowhere else.
- **`pub`**, reserved for the ABI (`abi/src/`), types genuinely shared between
  the kernel and ring-3 code (`abi/src/`), and the small set of kernel
  entry points. A `pub` item in `kernel/src/` should be defensible as a
  deliberate surface, not a habit.

A `pub fn` reachable from nowhere but its own module is a defect that review
should catch; there is no `dead_code` lint standing in for that judgement in
the kernel build.

The same judgement, applied to `#[allow(dead_code)]`: it says the compiler
cannot prove what you can, and it is worth less the longer it lives.  A
module-wide one has to carry **why** the item is unread and **when** the line
goes.  The two file-level allows this rule was written for had both gone
stale, one covered an unused skeleton whose consumers had existed for months,
the other a "no caller yet" set that had six callers, and nothing in the tree
said so.  Prefer the narrowest form that silences exactly what is
intentionally unread: an attribute on the item, a `#[cfg]` gate naming the
targets that do read it, or `#[cfg(test)]` for a surface only tests use.
Deleting the line and reading what the compiler names is the cheapest audit
available, so reach for it before reading the code.

---

## 7. Error handling

### The types

There is one core error type, `Error`, defined in [`abi/src/lib.rs`](../../abi/src/lib.rs)
with a companion alias:

```rust
pub type Result<T> = core::result::Result<T, Error>;
```

Use `crate::Result<T>` in signatures. Domain-specific errors are separate enums
named `<Domain>Error` (`ConfigError`, `FuseError`, `VirglCommandError`),
converted at the boundary into `Error`, they do not replace it, and they do not
leak into the syscall surface.

### Human-readable text: `as_str`, not `Display`

`Error` and the domain error enums expose `pub const fn as_str(self) -> &'static str`
rather than implementing `fmt::Display`. Follow that. `Display` in this tree is
for types that are *formatted* (`MacAddress`, `IpAddress`, `ThreadState`), not
for errors; adding a `Display` impl to an error type so it can be `{}`-printed
breaks the pattern and, in `const` contexts, is not usable where `as_str` is.

### Propagation

Use `?`. It is used thousands of times across the tree and is the expected way
to move an error up. Handlers return `Result`; syscall handlers return
`Result<SyscallDispatch>` so the dispatch value and the error travel together.

The kernel/ring-3 encoding lives in `abi/src/syscall.rs` (`encode_error` /
`decode_result`), with `Error::from_syscall_code` on the receiving side. Do not
invent a second encoding.

### When a panic is acceptable

`panic!` is rare in this tree, and the rule that keeps it rare is: **panic only
for a violated invariant that indicates the kernel is already corrupt or the
build is wrong.** It is never a way to reject input.

The legitimate cases, all of which are assertions about the code rather than
about the data:

- Layout assertions checked at startup, `PerCpuData must be exactly 64 bytes`,
  `PerCpuData.cpu_id must be at offset 0`.
- Heap-integrity checks in the TLSF allocator (corruption, misalignment,
  invalid size).
- An unreachable `match` arm on a value the type system cannot narrow.

Exhausted resources, bad arguments, and unparseable input are **errors**, not
panics. Remember that `panic = "abort"` is set for every profile in
[`Cargo.toml`](../../Cargo.toml): a panic is not a recoverable event, it is the
end of the machine.

### `unwrap` and `expect`

Production paths prefer a fallback (`unwrap_or`, `unwrap_or_default`) over a
bare `unwrap()`, and prefer an explicit error over `expect`. The large counts of
`unwrap`/`expect` in the tree are concentrated in `#[cfg(test)]` code and demo
scaffolding, where panicking is the point. `expect` with a message is a last
resort, not a substitute for propagating an error, if the compiler is telling
you a value could be `None`, the question is whether that is a bug or a case you
should handle, and the answer is only rarely "abort the kernel".

`assert!`/`assert_eq!` are used freely in tests and host-side code. In kernel
paths, prefer `debug_assert!` for expensive checks that hold by construction,
`debug_assert!` is compiled out of release builds, so it must never be load-
bearing.

---

## 8. Globals: the install pattern

Most subsystems are owned by the `Kernel` struct but must also be reachable from
interrupt handlers, worker threads, and syscall paths that hold no reference to
it. The established answer is a static slot with a fixed trio of functions:

```rust
static GLOBAL_TABLE: AtomicPtr<Table> = AtomicPtr::new(ptr::null_mut());

/// Install a `'static` table.  Prefer this whenever a `'static` reference is
/// available.
pub fn install_global(table: &'static Table) { /* store */ }

/// # Safety
///
/// The caller must guarantee `table` outlives every future `global()` access.
pub unsafe fn install_global_unchecked(table: &Table) { /* store */ }

pub fn global() -> Option<&'static Table> { /* load */ }
```

Rules that make this pattern safe to read:

- **`install_global` takes `&'static` and is safe.** `install_global_unchecked`
  takes a plain reference, ignores lifetimes, and is therefore `unsafe` with a
  `# Safety` section naming the outlives obligation. Prefer the safe one; the
  `unsafe` variant exists for the kernel's own init path, where the owner is a
  field of a `'static`-lived `Kernel` and the borrow checker cannot see it.
- **`global()` returns `Option<&'static T>`.** It can legitimately be `None`
  before initialization. Callers handle that; they do not `unwrap` it in a path
  reachable before init.
- **Implement `Drop` to clear the slot** (`compare_exchange` back to null), so a
  dropped owner does not leave a dangling pointer behind for tests or for a
  re-init.
- **Provide an `uninstall_global` when tests need one.** Test code must be able
  to tear down what it installed.
- **Every call site carries a `// SAFETY:`** when it uses the unchecked form.
  `Kernel::init` is the canonical example, and each of its installs is
  annotated with the reason the reference outlives the process.

Do not add a fourth variant or a new global without a reason the existing three
cannot express. And do not reach for a global to avoid threading a parameter,
the pattern exists for things interrupt handlers must find, not for convenience.

---

## 9. Feature gating

Features are declared in [`Cargo.toml`](../../Cargo.toml) and documented in
[README.md](../../README.md). The set today is `demo-disk`, `runtime`,
`fs_profiler`, `net_profiler`, `alloc_profiler`, `fault_profiler`, and
`educational_networking`. The default set is empty; the bare-metal kernel builds
with no features, and the demo shell and most tests are built with `demo-disk`.

There is **no central `cfg` convergence point**, gates are written at the
definition and use site. The shapes in use:

```rust
// The common demo-disk gate: the module is also available in host tests and on
// a non-bare-metal host build.
#[cfg(any(feature = "demo-disk", test, not(target_os = "none")))]
pub mod demo;

// Tightest form: bare-metal only, and only with the demo disk or under test.
#[cfg(all(target_os = "none", any(feature = "demo-disk", test)))]
```

Guidance:

- **Profiler features gate counters and recording points, not logic.** With the
  feature off the code must behave identically, that is what makes the profile
  trustworthy.
- **`target_arch` / `target_os` gates outnumber feature gates.** Architecture
  dispatch is done with `#[cfg(target_arch = "...")]` in the manifests'
  dependency tables (see `arch/Cargo.toml`), not with runtime branching.  New
  architecture-specific code goes in `arch/<machine>/`, and everything above
  names the route.
- **Register a new feature in three places:** `Cargo.toml`, the feature table in
  `README.md`, and any Makefile target that needs to pass it. An undocumented
  feature is invisible to everyone who did not write it.
- **A feature must not be required to build the kernel.** `cargo build --workspace` with no
  features has to keep working on all three targets; that is what `make
  verify-p0` checks.

---

## 10. Derives and representation

The overwhelmingly common derive set is
`#[derive(Debug, Clone, Copy, PartialEq, Eq)]`, and the guidance is simple:
derive `Debug` on everything, add `Clone`/`Copy` when the type is small and
value-like, and add `PartialEq`/`Eq` when there is a real comparison, usually
for tests.

Two types use `#[repr(usize)]` because they cross an ABI or storage boundary
whose layout is load-bearing: `Error` and `SyscallNumber`. Add a `repr` when the
numeric layout is part of a contract (ABI encoding, on-disk format, register
file, a struct whose size is asserted at startup) and document the contract in
the item's doc comment. Do not add one for ordinary in-memory types.

---

## 11. `no_std` and bare-metal constraints

The kernel is `#![no_std]` with `panic = "abort"`. Consequences that show up in
everyday code:

- **`core` and `alloc` only.** There is no `std`. `Box`, `Vec`, `Arc`, and
  `String` come from the kernel heap, which is initialized partway through
  `Kernel::init()`, so allocation is available only *after* that point, and not
  at all in the earliest boot path.
- **No floating point** in kernel paths, and no `libm`.
- **Be careful with `format!` in hot paths.** It allocates. In an interrupt
  handler, in a scheduler path, or in anything reachable from a lock, prefer
  fixed buffers and the `util::debug` helpers.
- **Do not block in an interrupt context.** Allocating, taking a `Mutex`, or
  waiting on a `Condvar` from an ISR is a deadlock waiting for a quiet moment.
  The path is easy to reach by accident: SLAAC sends its router solicitation
  from the tick handler, so a driver's transmit path is an ISR path, and a
  completion wait that parked there would hold the SLAAC lock across the park.
  A wait that can be reached that way asks `arch::interrupts::are_enabled()`
  first and polls instead of parking, the caller re-reads its ring either way.

---

## 12. Review checklist

- [ ] `cargo fmt --all -- --check` is clean.
- [ ] Naming follows §3, including the established suffixes.
- [ ] New modules are declared alphabetically; `mod.rs` follows the §4 order.
- [ ] `use` blocks keep the three-tier grouping.
- [ ] New items default to `pub(crate)` / `pub(super)` unless they are genuinely
      part of a public surface.
- [ ] Errors propagate via `Result`/`?`; any new `panic!`/`unwrap` is justified
      under §7.
- [ ] New globals follow the install pattern exactly, including `Drop` cleanup
      and `# Safety` on the unchecked variant.
- [ ] New feature flags are registered in `Cargo.toml`, `README.md`, and the
      Makefile.
- [ ] New architecture gates outside `arch/` carry the `fact:` or `gap:`
      reason §14 requires, and `sh scripts/check-arch-fanout.sh` is re-recorded
      if they move.
- [ ] `sh scripts/verify.sh p3` is green.

---

## 13. Layer dependencies

A `use crate_name::…` is not a private decision: it is an edge in the tree's
dependency graph, and the graph is checked.
[`scripts/check-layering.sh`](../../scripts/check-layering.sh) reads
[`scripts/layering.txt`](../../scripts/layering.txt) and refuses an edge that
points at the same layer or upward.  A crate may name a crate in a lower layer
and nothing else.

The layers are argued in that file rather than assumed, and the one edge that
is a decision rather than a consequence, `sync` names `arch`, because closing
a spinlock's interrupt window needs the machine's flag, is written there with
its cost.  A new edge has to be argued for in the change that adds it, not
discovered later.

Two directions are wrong by definition:

- **A driver does not name `fs`.**  A disk driver knows a controller and a
  device interface; who mounts what on top of it is not its business.  `block`
  sits below both so neither has to name the other.
- **A program does not name a crate of the kernel.**  `apps/` compiles against
  `abi` and reaches everything else through syscalls, which is why the programs
  are at the top layer with nothing depending on them.

The old rule, "the census is debt with a number attached, and a cut is
finished when its rows reach zero", described a tree where the edges were
inside one crate and could only be counted.  Here the edges are crate
dependencies, so the gate does not count them: it refuses them.

---

## 14. Architecture gates

Keeping hardware out of the kernel's own code is the same kind of budget, and
it has the same kind of check.
[`scripts/check-arch-fanout.sh`](../../scripts/check-arch-fanout.sh) counts
every `target_arch = "x86_64" | "aarch64" | "riscv64"` in a `.rs` file outside
`arch/`, per file, and compares the result with
[`scripts/arch-fanout-baseline.txt`](../../scripts/arch-fanout-baseline.txt).
A count that grows fails the gate; a count that drops has to be re-recorded in
the same change.

**The number is zero, and it stays zero.**  The census's one historical row was
`bootloader/src/main.rs`, and its reason said the entry symbol and the panic
handler are things only a binary can define.  That was true and it was not the
question: the *symbol* is a binary's, but the *instruction* it reaches for is
the machine's.  So the machine's entry assembly, its linker script and its stop
instruction moved into `arch/<machine>/`, and `bootloader` defines one neutral
symbol that every machine's assembly calls.

The number is what porting costs.  An architecture is supposed to be
`arch/<machine>/` and nothing else; every gate the census finds is a file the
fourth architecture has to be taught as well.  The way down is to move the
question behind `arch/`, where the machine answers it.
---

## 14. Architecture gates

Keeping hardware out of the kernel's own code is the same kind of budget, and
it has the same kind of check.
[`scripts/check-arch-fanout.sh`](../../scripts/check-arch-fanout.sh) counts
every `target_arch = "x86_64" | "aarch64" | "riscv64"` in a `.rs` file outside
`arch/`, per file, and compares the result with
[`scripts/arch-fanout-baseline.txt`](../../scripts/arch-fanout-baseline.txt).
A count that grows fails `sh scripts/check-arch-fanout.sh`; a count that drops
has to be re-recorded in the same change.

The number is what porting costs.  An architecture is supposed to be
`arch/<arch>/` plus its `main.rs` entry point; every gate the census finds
is a file the fourth architecture has to be taught as well.  The way down is
the same as the way down for the dependency graph: a gate that says "on this
architecture, do it this way" is a question the architecture should be
answering, so it moves behind a shim in `arch/`, `arch::thread`,
`arch::mmu`, `arch::tlb`, and the rest, and the kernel-side code asks the
question instead of naming an architecture.

Not every row can go that way, and the baseline says which is which.  Each row
carries a reason after the count, and it has to be one of two things:

- **`fact:`**, the file names an architecture because the thing it carries
  *is* that architecture's: an ABI record, a driver for its hardware, an
  instruction, a test of its page tables, or a query only its own code asks.
  A fourth architecture decides what it does here; there is no shim to write.
- **`gap:`**, the file names an architecture only because a question has not
  been moved behind `arch/` yet, and the reason says where it belongs.

`sh scripts/check-arch-fanout.sh` refuses a row that gives neither, so a new gate
outside the arch layer is either moved or argued for in that change.  A row
whose count *grows* fails with its own reason printed, because a reason that
covered the old count may not cover the new one, and a `--record` keeps every
reason, so a re-record is a change in the tree rather than a change of mind
about why the row exists.  The rows to drive down are the `gap:` ones; the
`fact:` rows are the census telling the truth about what porting costs.

`target_os` gates are not counted.  A new architecture is bare-metal too, so
"is there a kernel here or a host" does not move when one is added.

The same rule applies to tests: a suite that needs one target's host build
puts the gate on the module, `#[cfg(all(test, target_arch = "x86_64"))] mod
tests { … }`, rather than on each function inside it, so the gate is read
once and a new test cannot arrive without one.

---

## Related documents

- [docs/fmts/comments.md](comments.md), file headers, doc comments, `// SAFETY:`
- [docs/fmts/unsafe-and-safety.md](unsafe-and-safety.md), what is allowed in an
  `unsafe` block
- [docs/fmts/testing.md](testing.md), test layout and registration
- [`docs/architecture.md`](../architecture.md), where each layer sits and why
- [`CONTRIBUTING.md`](../../CONTRIBUTING.md), the short form of these rules
