# Contributing

## What this tree is

A `no_std` bare-metal kernel for x86_64, aarch64 and riscv64, organised as a
workspace of crates so that every part of it can be built and tested on its own.
`docs/architecture.md` says why the crates are where they are; this document says
what a change has to satisfy.

## The floor

```sh
sh scripts/verify.sh p3
```

That is the gate, and it is the whole of what "green" means.  It runs, in order:

| Step | What it refuses |
|---|---|
| `cargo fmt --check` | formatting drift |
| `scripts/check-docs.sh` | a document that cites a file the tree does not have |
| `cargo doc --workspace` | a doc comment that links to an item the crate does not have |
| `cargo build --workspace` | a crate that does not build for the host |
| `cargo build -p kernel --target <machine>` ×3 | a machine the kernel does not build for |
| `cargo test --workspace` | a failing test |
| `cargo xtask check --machine <machine>`, each machine that has an image | a boot that does not print what its gate requires |
| `scripts/check-arch-fanout.sh` | a `target_arch` gate outside `arch/` that nothing argued for |
| `scripts/check-layering.sh` | a dependency that points at its own layer or above |
| `scripts/check-crate-tests.sh` | a crate with code and no tests, or one that lost tests |
| `scripts/check-repo-integrity.sh` | a tracked file that is ignored, or a build product that is tracked |
| `cargo clippy` ×4 | a lint, in every configuration the tree builds |

The tiers below `p3` exist so the common case is fast: `p0` is formatting, builds
and tests; `p1` adds the boot; `p2` adds the three censuses; `p3` adds clippy.

`just --list` is the short form of the commands; the recipes are one line each
and name the command they run.

## What a change has to carry

**Its gates.**  A behaviour change that no gate exercises is not verified, it is
implemented.  If the mechanism is new, a gate that runs it belongs in the same
change, and if that gate cannot exist yet, the change says so rather than
implying it ran.

**Its documents.**  `docs/architecture.md` for a layering decision, the crate's
own `//!` header for a mechanism.  A document that describes a tree you would
have to guess at is worse than no document.

**Its ratchets.**  Each census records a number.  A change that moves one moves
the baseline in the same commit, with the argument in the baseline's own prose.
The gate refuses a baseline that no longer describes the tree, in either
direction.

## Adding a crate

1. **Pick the layer by what the crate is**, not by what it happens to need.  If it
   needs something above it, either the layer is wrong or the dependency is.
   `docs/architecture.md` has the argument for each layer.
2. **Add it to `scripts/layering.txt`** with the reason.  The gate refuses a crate
   the spec does not name, and refuses a spec row whose crate has gone.
3. **Give it a test.**  The gate refuses a crate above a small size with none,
   unless its row carries the reason it cannot have one, which is a sentence a
   reviewer can disagree with, not a silence.
4. **Record it**: `sh scripts/check-crate-tests.sh --record`, in the same change.

A crate's own `//!` header says what it is, what it names and, the part that
matters, *why it is a crate rather than a module*.  "It is 400 lines" is not a
reason.  "Four layers need it and may not depend on each other" is.

## Writing a test that can fail

A test that cannot fail is worse than no test, because it is counted.

- **Break the code and watch it fail.**  Every gate in this tree that matters has
  been mutation-tested: flip a constant, delete an assertion, make the expected
  line impossible, and confirm the gate goes red.  A gate that stays green under
  a mutation is measuring nothing.
- **Test the property, not the implementation.**  `check-crate-tests.sh` exists
  because a `#[cfg(test)]` module in a crate that does not compile reports zero;
  two architecture crates had carried assertions for weeks that had never been
  compiled once.
- **An assertion about a value the build chose is a prefix match.**  The boot's
  heap address moves with the image; the gate requires the line's shape and not
  its value, because a check that named an address would fail a correct kernel the
  first time a symbol moved.

## The rules that no gate can check

- **A probe that did not fire is zero information**, unless the run reproduced the
  bug.  Measure the reproduction rate before and after a fix.
- **One boot, one log.**  Read conclusions out of a single boot's log; never reason
  across builds.
- **A red gate means the product is broken.**  Fix it, or make the failure
  attributable.  Never widen a gate or loosen its tolerance to go green.
- **One change per commit.**  A commit is the change, its gates and its
  documents, and nothing else.
- **Ask before** changing a frozen syscall number, raising a ratchet, or touching
  an address-space activation path.

## Where the rest lives

| Question | Document |
|---|---|
| Why is this crate here, and what may it name? | `docs/architecture.md`, `scripts/layering.txt` |
| How does the asynchronous model work? | `docs/async_io.md` |
| What exists and what is missing? | each crate's `//!` header |
| What does a gate refuse? | the gate's own header comment |
