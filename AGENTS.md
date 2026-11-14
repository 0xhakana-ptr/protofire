# Protofire, working rules

A `no_std` bare-metal kernel for x86_64, aarch64 and riscv64, built as a
workspace of crates.  There is no package ecosystem to consult and no upstream to
imitate: the tree is the whole world, and every instruction below is load-bearing.

**A rule that can be a gate belongs in a gate, not here.**  What follows is
either something no gate can express or a pointer to the gate that already
expresses it.  When one of these becomes mechanical, delete it from this file: a
healthy `AGENTS.md` gets shorter as the gates get stronger.

## Where the truth lives

- **Why is the tree shaped this way, and which crate may name which?**
  [`docs/architecture.md`](docs/architecture.md) and
  [`scripts/layering.txt`](scripts/layering.txt).
- **What is each directory, grouped by what it is for?**
  [`docs/tree.md`](docs/tree.md).
- **What is here, and why does it have the shape it has?**
  [`docs/migration.md`](docs/migration.md).
- **What exists, and what is missing, on each machine?**
  [`docs/status.md`](docs/status.md).
- **What is missing overall, and which gap blocks which?**
  [`docs/roadmap.md`](docs/roadmap.md).  It carries the counts and the command
  that re-takes them, so the answer is measured rather than remembered.
- **What does a change have to satisfy?**, [`CONTRIBUTING.md`](CONTRIBUTING.md).
- **How does a subsystem work?**, the crate's own `//!` header.
- **What may a contributor rely on?**, this file, and the gate's own header
  comment.
- **What does the kernel enforce, and what does it not?**
  [`SECURITY.md`](SECURITY.md).

The tree is the authority: where a document and the code disagree, the code is
right and the document is the bug.  Moving the document is part of the change,
not a follow-up.

## The gate

```sh
sh scripts/verify.sh p3
```

The tiers accumulate: each one runs everything below it and adds its own.

- **`p0`**, formatting, every crate's tests, the three kernels.
- **`p1`**, the boot: `cargo xtask check --machine <each machine with an
  image>`.  A machine is a hardware description as well as an architecture: the
  riscv64 image boots twice, once on a tree that names a PLIC and once
  (`riscv64-aia`) on one that names an APLIC and an IMSIC.  A controller a boot
  never found is a controller no gate has exercised, which is why the AIA nodes
  live in the gate rather than in a measurement made by hand.
- **`p2`**, the three censuses, architecture fan-out, layering, per-crate test
  counts.
- **`p3`**, clippy in every configuration the tree builds.

The gate requires the boot for a reason no other tier can cover: every runtime
defect this tree has had would have passed a gate that never ran an image.  It
boots every machine whose image exists, because the defect this rule was
written for was aarch64 printing four lines and stopping while a gate that
booted only x86_64 called it green.

`just --list` is the short form of the commands.  `just` is not part of the Rust
toolchain and has to be installed once (`cargo install just`, or a distribution
package); nothing in the gate *needs* it, and `scripts/verify.sh` is what a gate
actually runs.

## The ratchets

A census records a number, refuses growth, and refuses a baseline row that no
longer describes the tree.  Meeting one by recording a new number is a change
that argues for it in the baseline's own prose, which is why
`scripts/layering.txt` is longer than the list of crates it describes.

- **`scripts/check-layering.sh`**, every dependency points downward.
- **`scripts/check-arch-fanout.sh`**, nothing outside `arch/` names a machine.
- **`scripts/check-crate-tests.sh`**, every crate with code has tests, and
  none lost any.
- **`scripts/check-repo-integrity.sh`**, nothing ignored is tracked, and no
  build product is.
- **`scripts/check-docs.sh`**, every path a document cites exists.
- **`scripts/check-comment-punctuation.sh`**, no em dash and no rule line:
  `docs/fmts/comments.md` §4 and §6 in the form a commit cannot pass by
  accident.  The rule was prose and the tree held 1,600 lines that broke it,
  which is this section's own argument for existing.

The architecture census is at **zero** and stays there.  Its one historical row
was `bootloader/src/main.rs`, and the row was wrong in a way worth remembering:
the *symbol* a binary must define is a binary's, but the *instruction* it reaches
for is the machine's.  `bootloader` is the protocol and `arch` is the machine;
mixing them is what put five `target_arch` gates in a crate that is not the
machine.

## Rules no gate can check

- **Verify before you replace.**  A change lands only with the gate green; an
  attempt that failed is reverted in the same session, and nothing exploratory
  stays in the tree.

- **One boot, one log.**  Read conclusions out of a single boot's log; never
  reason across builds.

- **A probe that did not fire is zero information**, unless that run reproduced
  the bug.  Measure the reproduction rate (N of M) before and after a fix, and
  keep probes off the hot path, they perturb exactly what they are looking for.
  When the bug is timing-sensitive, instrument from outside (QEMU's monitor, a
  serial socket).

- **Say what evidence shows the mechanism ran, and name it.**  Quote the log
  line or the gate that shows it, so a reader can re-run it.  The recurring
  defect here is code that is written, wired, and never executed, and a claim
  whose evidence cannot be re-checked is a claim, not a result.

- **A red gate means the product is broken.**  Fix it, or make the failure
  attributable.  Never widen a gate, or loosen its tolerance, to go green.

- **A ratchet moves in the change that moves it.**  A raised count carries its
  argument in the baseline's own prose.

- **One change per commit.**  A commit is the change and its gates and its
  documents, and nothing else: no drive-by refactor, no unrelated formatting, no
  second fix that merely happened to be nearby.  When two things really do have
  to move together, say why in the message.

- **A test that cannot fail is worse than no test**, because it is counted.
  Break the code and watch the test fail.  Every gate in this tree that matters
  has been mutation-tested.

- **An independent kernel.**  Another system's layout is a reference for what is
  reasonable, never the authority.  When this tree follows a convention, the
  reason is in the file that follows it. In other words, we prefer an argument
  like "this is what the trait's implementors require" instead of "other kernels
  do it this way".

## Boundaries

✅ **Always**: run `cargo fmt --all` before committing; end the message with
`Signed-off-by:` and then `Assisted-by:`; write the safety argument at the
`unsafe` block it belongs to; keep a change's code, its gates and its documents
in one commit.

⚠️ **Ask first**: changing or renumbering the syscall range below 120, it is
frozen; raising any ratchet baseline; touching the address-space activation path;
moving a filesystem in, which happens only after a mount has been verified on a
machine.

🚫 **Never**: `git reset --hard`, or `git checkout -- <path>`, over work that is
not yours; leave probe, `TEMPORARY` or debug code in a commit; commit with a gate
red; add a file-level `#![allow(dead_code)]` without the condition that removes
it; write `unsafe` without its argument.

## The development host

Linux, x86_64.  `rust-toolchain.toml` says why: the previous tree also carried
Windows and macOS on Intel, and the cost was not the code, it was that every
measurement had three answers, every script had a shell-difference branch, and a
defect that only appeared on one host was found by whoever ran the gate there.

This tree has one host, and a build that does not work on it is broken rather
than unsupported.

## Licence

Source code is Apache-2.0; prose, every Markdown document, this one included, is
CC BY 4.0.  [`LICENSES/README.md`](LICENSES/README.md) says which files fall on
which side and why the split exists.
