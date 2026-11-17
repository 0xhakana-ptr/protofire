# Contributor specifications

This directory holds the normative specifications for contributing to the
Protofire kernel: how code is written, how it is commented, what `unsafe` may be
used for, how tests are laid out, and what the syscall ABI contract is.

They are written for anyone about to send a patch, a first-time contributor
looking for the house style, and a returning one checking whether a rule they
remember is real.  [`CONTRIBUTING.md`](../../CONTRIBUTING.md) carries the short
form of all of this plus the process around it.  These documents are the detail
behind those bullets: the rationale, the exact rules, the cases that trip people
up, and what is actually enforced versus what is merely expected.

## The documents

Read [`code-style.md`](code-style.md) when writing any Rust in this repository.
It covers formatting, naming, module and file layout, imports, visibility,
error handling, globals, feature gating, and layering.

Read [`comments.md`](comments.md) when opening a file to edit it.  It covers the
file header, module and item docs, `# Safety`/`# Errors`/`# Panics`, section
separators, and `TODO`/`NOTE`.

Read [`unsafe-and-safety.md`](unsafe-and-safety.md) when writing or reviewing an
`unsafe` block.  It covers what `unsafe` is for, the `// SAFETY:` contract, MMIO,
and the locking and panic rules.

Read [`testing.md`](testing.md) when adding behaviour you want to keep.  It
covers where tests live, driving a trait with a fake, and what makes a test able
to fail.

Read [`syscall-abi.md`](syscall-abi.md) when touching `abi/`, `syscall/`, or
`kernel/src/syscall/`.  It covers append-only numbering, the frozen boundary,
adding a syscall, and handler conventions.

Read [`commits.md`](commits.md) when writing a commit message.  It covers
subject and body rules, the type prefixes, the hook's exact semantics, and the
trailers.

Supporting context, if you have not read it yet:

- [`docs/architecture.md`](../architecture.md), why the tree is shaped this way
- [`docs/migration.md`](../migration.md), what is here and why it has the shape
  it has
- [`AGENTS.md`](../../AGENTS.md), the rules no gate can check

## What is enforced, and what is not

The single most useful thing to know before a first change is which rules a
machine will check.  At `p0`: formatting (`cargo fmt --all -- --check`), every
Rust file's header naming its own path (`check_source_headers` in
[`scripts/verify.sh`](../../scripts/verify.sh)), the punctuation §4 and §6 of
[`comments.md`](comments.md) refuse
([`scripts/check-comment-punctuation.sh`](../../scripts/check-comment-punctuation.sh)),
every path a document cites ([`scripts/check-docs.sh`](../../scripts/check-docs.sh)),
the RFC directory's own invariants
([`scripts/check-rfcs.sh`](../../scripts/check-rfcs.sh)), every item a doc
comment links to (`cargo doc` with `RUSTDOCFLAGS=-D warnings`), that the
workspace builds and every crate's tests pass (`cargo build --workspace`, `cargo
test --workspace`), that the kernel builds for all three machines (`cargo build
-p kernel --target <machine>`), and that every commit in the range obeys
[`commits.md`](commits.md) with no merge among them
([`scripts/check-commits.sh`](../../scripts/check-commits.sh)).

At `p1`: that the image boots and prints what it must (`cargo xtask check
--machine <each machine>`).

At `p2`: that a dependency points downward
([`scripts/check-layering.sh`](../../scripts/check-layering.sh)), that no
architecture gate sits outside `arch/`
([`scripts/check-arch-fanout.sh`](../../scripts/check-arch-fanout.sh)), that
every crate with code has tests and none lost any
([`scripts/check-crate-tests.sh`](../../scripts/check-crate-tests.sh)), that
nothing ignored is tracked and no build product is
([`scripts/check-repo-integrity.sh`](../../scripts/check-repo-integrity.sh)), and
that nothing a contributor wrote is hidden by an ignore rule
([`scripts/check-ignored-files.sh`](../../scripts/check-ignored-files.sh)).

At `p3`: lints, and every undocumented `unsafe` (`cargo clippy -- -D warnings`).

**Everything else in this directory is review.**

The rules a machine does not check are the naming conventions, doc-comment
coverage, panic discipline, and the parts of the syscall contract that are not a
number or a record layout.  Treat the unenforced rules as *more* important to get
right, not less: nothing will remind you.

### The gate

```sh
sh scripts/verify.sh p3
```

`p0` is formatting, documentation and tests; `p1` adds the boot; `p2` adds the
five checks; `p3` adds clippy in every configuration.  [`AGENTS.md`](../../AGENTS.md)
says what each tier is for and why the boot is in the gate rather than an extra.

## Changing a specification

These documents are part of the codebase and change like everything else.

- **If a change alters a convention, update the specification in the same
  change.**  A patch that starts naming things differently, or introduces a new
  comment marker, is incomplete until the rule document says so.
- **Do not quietly diverge.**  If a rule here does not match what the code does,
  that is a defect in one of the two, raise it.  The tree is the authority:
  where a document and the code disagree, the code is right and the document is
  the bug.
- **Prefer changing the code to weakening the rule.**  A rule that exists
  because a class of bug is expensive in a kernel should be met with an
  argument, not an exception.

## Related documents

- [`CONTRIBUTING.md`](../../CONTRIBUTING.md), the short form and the process
- [`docs/architecture.md`](../architecture.md), the layers, and why each crate is where it is
- [`AGENTS.md`](../../AGENTS.md), the working rules
