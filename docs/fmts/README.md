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

| Document | Read it when | Covers |
|---|---|---|
| [`code-style.md`](code-style.md) | Writing any Rust in this repository | Formatting, naming, module and file layout, imports, visibility, error handling, globals, feature gating, layering |
| [`comments.md`](comments.md) | Opening a file to edit it | The file header, module and item docs, `# Safety`/`# Errors`/`# Panics`, section separators, `TODO`/`NOTE` |
| [`unsafe-and-safety.md`](unsafe-and-safety.md) | Writing or reviewing an `unsafe` block | What `unsafe` is for, the `// SAFETY:` contract, MMIO, locking and panic rules |
| [`testing.md`](testing.md) | Adding behaviour you want to keep | Where tests live, driving a trait with a fake, what makes a test able to fail |
| [`syscall-abi.md`](syscall-abi.md) | Touching `abi/`, `syscall/`, or `kernel/src/syscall/` | Append-only numbering, the frozen boundary, adding a syscall, handler conventions |
| [`commits.md`](commits.md) | Writing a commit message | Subject and body rules, the type prefixes, the hook's exact semantics, the trailers |

Supporting context, if you have not read it yet:

- [`docs/architecture.md`](../architecture.md), why the tree is shaped this way
- [`docs/migration.md`](../migration.md), what has moved in, and what has not
- [`AGENTS.md`](../../AGENTS.md), the rules no gate can check

## What is enforced, and what is not

The single most useful thing to know before a first change is which rules a
machine will check.

| Rule | Enforced by | Where it runs |
|---|---|---|
| Formatting | `cargo fmt --all -- --check` | `p0` |
| Every path a document cites | [`scripts/check-docs.sh`](../../scripts/check-docs.sh) | `p0` |
| Every item a doc comment links to | `cargo doc` with `RUSTDOCFLAGS=-D warnings` | `p0` |
| The workspace builds, and every crate's tests pass | `cargo build --workspace`, `cargo test --workspace` | `p0` |
| The kernel builds for all three machines | `cargo build -p kernel --target <machine>` | `p0` |
| The image boots and prints what it must | `cargo xtask check --machine <each machine>` | `p1` |
| A dependency that points downward | [`scripts/check-layering.sh`](../../scripts/check-layering.sh) | `p2` |
| No architecture gate outside `arch/` | [`scripts/check-arch-fanout.sh`](../../scripts/check-arch-fanout.sh) | `p2` |
| Every crate with code has tests, and none lost any | [`scripts/check-crate-tests.sh`](../../scripts/check-crate-tests.sh) | `p2` |
| Lints, and every undocumented `unsafe` | `cargo clippy -- -D warnings` | `p3` |
| **Everything else in this directory** | **Review** | |

The rules a machine does not check are the naming conventions, doc-comment
coverage, panic discipline, and the parts of the syscall contract that are not a
number or a record layout.  Treat the unenforced rules as *more* important to get
right, not less: nothing will remind you.

### The gate

```sh
sh scripts/verify.sh p3
```

`p0` is formatting, documentation and tests; `p1` adds the boot; `p2` adds the
three censuses; `p3` adds clippy in every configuration.  [`AGENTS.md`](../../AGENTS.md)
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
