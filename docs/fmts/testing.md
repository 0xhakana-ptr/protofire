# Testing Specification

> **Status:** normative, except where a rule is marked *convention*.
> **Applies to:** every crate in the workspace.

A test is the only part of a change that says what the code is *supposed* to do
after the person who wrote it has stopped remembering.  The crate split exists so
that a test can run without a boot: `cargo test -p <crate>` is the whole command,
and a crate that needs an emulator to exercise its arithmetic has been filed
wrong.

---

## 1. Where tests live

A **unit** test is a `#[cfg(test)] mod tests` at the end of the module under
test, in that module's own file.  That is the default and it is where a test
belongs: separating the tests from the code they check makes a reader open two
files to see one thing, and a `tests.rs` that exists only to hold a module's
tests is a directory created for the tests rather than for the code.

A second file is worth it when the **module** is already split, `mod.rs`
beside `space.rs`, `table.rs` and so on, and its tests have outgrown one
`mod tests`.  Then a `tests.rs` sibling, declared `#[cfg(test)]
mod tests;`, keeps the module's own files about the mechanism.  A module small
enough to be one file keeps its tests in that file, however long the tests
grow.  **Test-only helpers** live inside the `tests` module, or in a
`test_util.rs` declared `#[cfg(test)]`.

There is no `tests/` directory of integration binaries.  A "test that needs the
whole crate" is a test in the crate, and it can call anything the crate can, the
crate *is* the boundary the split drew.

### Why this differs from a single-crate tree

The previous tree had `tests/<area>/<name>.rs` binaries declared one `[[test]]`
block at a time, and the reason was that a crate of 300,000 lines has no other
way to test a subsystem in isolation: the module graph was one unit, so the
only boundary available was the process.

Here the boundary is the crate.  `cargo test -p fs` builds `fs` and nothing
else, and a test inside `fs/src/pyrofs/mod.rs` has exactly the access an
integration binary had, plus the private items, which an integration binary
could not reach and which are usually where the interesting arithmetic is.

### A crate with no tests fails the gate

[`scripts/check-crate-tests.sh`](../../scripts/check-crate-tests.sh) refuses a
crate above sixty lines of source with no tests, unless its row in
[`scripts/crate-tests-baseline.txt`](../../scripts/crate-tests-baseline.txt)
carries the reason it cannot have one, which is a sentence a reviewer can
disagree with, not a silence.

The same gate refuses a crate whose count **falls**.  Deleting a test is
sometimes right; recording the new number is what makes it a decision.

---

## 2. Unit tests

A unit test drives one thing and asserts one property.  It lives beside the code
because the thing it needs to reach is usually private.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// A depth-one device finishes a read before its submit returns.
    #[test]
    fn a_device_that_does_not_queue_completes_a_read_in_place() {
        let device = MemoryBlockDevice::new("memory", vec![7_u8; BLOCK_SIZE], false);
        let mut buffer = [0_u8; BLOCK_SIZE];
        // SAFETY: the buffer outlives the ticket.
        let ticket = unsafe { device.submit_read(0, &mut buffer) }.expect("submit");
        assert!(ticket.is_done());
    }
}
```

Two things the example shows rather than states: the test's name is the
property in a sentence, and the `// SAFETY:` comment is there because the rule
applies to tests too.

---

## 3. Tests that drive a trait

The most valuable test in this tree is one that exercises a driver through its
trait rather than through its hardware.  `VirtioBlock` is written against
`Transport`, so a host test supplies a `FakeDevice` over a byte array and drives
the *whole* of the driver: initialisation, request encoding, the descriptor
chain, the doorbell, and the used ring.

That is the payoff of putting the machine behind a trait, and it is worth
building the trait for: a driver tested only by booting tells you that it failed
and not which of forty things was wrong.

**A fake is not a mock.**  The `FakeDevice` in `drivers/virtio/block/src/device.rs`
does what a device does, it reads the descriptor chain the driver published and
writes the data, rather than recording that it was called.  A mock that asserts
a call sequence tests the implementation; a fake that behaves like the thing
tests the contract.

---

## 4. What to test

What follows is a floor, not a ceiling.

Changing **a syscall**, new or modified, wants the numbering in `abi` and the
handler exercised through the table.  See
[syscall-abi.md §9](syscall-abi.md#9-tests).  Changing **a parser or wire
format** wants valid, truncated and oversized input, and the layout offsets
pinned against the specification.  Changing **a filesystem** wants its own suite
in the crate, and for a writable one, a recovery or fault-matrix case.  Changing
**the allocator or a frame pool** wants arithmetic under pressure and a mutation
test that the free lists actually fuse.  Changing **a driver** wants a host test
through the trait it implements, and a QEMU boot for the parts the trait cannot
reach.  Changing **a gate or a census** wants a test of the decision function,
so the gate's own logic is not checked only by running it.

---

## 5. A test that cannot fail

A test that cannot fail is worse than no test, because it is counted.

- **Break the code and watch the test fail.**  Every gate in this tree that
  matters has been mutation-tested: flip a constant, delete an assertion, make
  the expected line impossible, and confirm the gate goes red.
- **Test the property, not the implementation.**  A test that asserts the
  sequence of calls passes on an implementation that is wrong in the same way.
- **An assertion about a value the build chose is a prefix match.**  The boot's
  heap address moves with the image; a check that named an address would fail a
  correct kernel the first time a symbol moved.

Two of this tree's own defects were found by a test that could have been written
earlier and was not: the virtqueue's free list was never initialized, and a
write's bytes did not outlive their borrow.  Both are visible to a test that
submits two requests and compares what came back.

---

## 6. Isolation and globals

Tests in one crate share a process, and the harness runs them in parallel.  A
test that installs a global without removing it affects every test that runs
after it, producing a failure whose cause is in a different function entirely.

The rule: **if a test installs a global, it removes it.**  The install pattern
in [code-style.md](code-style.md) exists partly for this.

**A global that stands in for a device is the case that catches people.**  The
architecture crates record what a serial console was asked to write in a
process-wide buffer, because a host has no UART.  Two tests that each clear it
and then assert what they wrote are racing for a resource only one can own, and
the failure is a flake that a serial run hides.  Such a test takes a lock:

```rust
static CONSOLE_TESTS: spin::Mutex<()> = spin::Mutex::new(());

fn serialize() -> spin::MutexGuard<'static, ()> {
    CONSOLE_TESTS.lock()
}
```

Measured, the guard is load-bearing rather than tidy: without it, 1 of 40 runs
of `cargo test -p arch_aarch64 -- --test-threads=8` failed.  With it, 8 of 8
`cargo test --workspace` runs passed.

---

## 7. Running tests

```sh
cargo test -p <crate>          # one crate, which is the point of the split
cargo test --workspace         # every crate
sh scripts/verify.sh p0        # formatting, the workspace build, every test
```

A test run for one crate is fast enough to be the loop: `cargo test -p crypto`
is 64 tests in half a second, and the cryptography arrived from a tree where the
same tests needed the module graph and a boot.

### The boot is a test too

A test cannot exercise what happens on a machine: a page table, an MMIO write, a
device's completion.  That is what `cargo xtask check --machine x86_64` is, and
the gate requires it at `p1` and above.  A `p3` that never boots anything is a
`p2` with a longer name, and both of this tree's recent runtime defects would
have passed one.

### What the gate runs

The tiers accumulate.  **`p0`** runs every crate on the host and builds the
three kernels.  **`p1`** adds the boot on each machine that has an image, all
three.  **`p2`** adds the censuses: architecture, dependencies, per-crate tests,
repository integrity.  **`p3`** adds clippy in every configuration.

---

## 8. Review checklist

- [ ] New behaviour has a test; the test fails before the fix and passes after.
- [ ] The test name describes the property being asserted.
- [ ] Boundary, rejection and error cases are covered, not just the happy path.
- [ ] A test that installs a global removes it, or holds a lock if two tests
      share one.
- [ ] No test passes vacuously, assert that the fixture produced the intended
      condition.
- [ ] `cargo test --workspace` is green.
- [ ] For a behaviour a host cannot reach, the boot gate covers it.

---

## Related documents

- [`docs/fmts/code-style.md`](code-style.md), the global install pattern
- [`CONTRIBUTING.md`](../../CONTRIBUTING.md), the gate and what a change must carry
- [`docs/migration.md`](../migration.md), what each subsystem moved in as, and
  the reasons for the shape it landed in
