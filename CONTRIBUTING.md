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

That is the gate, and it is the whole of what "green" means.  It runs, in
order:

- `cargo fmt --check`, refuses formatting drift.
- `check_source_headers`, refuses a Rust file whose `# File:` header names a
  path it is not at.  It is a function inside `scripts/verify.sh` rather than a
  script of its own, because it reads no file the rest of the gate does not.
- `scripts/check-comment-punctuation.sh`, refuses an em dash and a rule line of
  box-drawing characters.  `docs/fmts/comments.md` §4 and §6 state the rule;
  this is the form a commit cannot pass by accident.
- `scripts/check-docs.sh`, refuses a document that cites a file the tree does
  not have.
- `scripts/check-rfcs.sh`, refuses an RFC directory that disagrees with itself:
  a number that is not four decimal digits, a status outside the six, a
  supersede link that holds at one end only, an index row written by hand.
- `scripts/check-commits.sh`, refuses a commit message the hook refuses, and a
  merge commit in the range `master` is about to receive.
- `cargo doc --workspace`, refuses a doc comment that links to an item the
  crate does not have.
- `cargo build --workspace`, refuses a crate that does not build for the host.
- `cargo build -p kernel --target <machine>`, three times, refuses a machine
  the kernel does not build for.
- `cargo test --workspace`, refuses a failing test.
- `cargo xtask check --machine <machine>`, for each machine that has an image
  refuses a boot that does not print what its gate requires.
- `scripts/check-arch-fanout.sh`, refuses a `target_arch` gate outside `arch/`
  that nothing argued for.
- `scripts/check-layering.sh`, refuses a dependency that points at its own
  layer or above.
- `scripts/check-crate-tests.sh`, refuses a crate with code and no tests, or
  one that lost tests.
- `scripts/check-repo-integrity.sh`, refuses a tracked file that is ignored,
  or a build product that is tracked.
- `scripts/check-ignored-files.sh`, refuses the other direction: a file that is
  ignored and **not** tracked, when it is not a build product.  `git add -A`
  skips one without a word, so a source file hidden by an ignore rule reaches
  neither the index nor the commit.
- `cargo clippy`, four times, refuses a lint, in every configuration the tree
  builds.

The tiers below `p3` exist so the common case is fast: `p0` is formatting, the
documents, the builds and the tests; `p1` adds the boot of every machine with an
image; `p2` adds the five checks above it; `p3` adds clippy.

`just --list` is the short form of the commands; the recipes are one line each
and name the command they run.

## Continuous integration

`.github/workflows/ci.yml` runs `scripts/ci.sh` on every pull request.  It is a
**subset** of the gate, and it says so rather than passing quietly: a runner
that is not this tree's development host may have no QEMU and no `/dev/kvm`, so
CI declines the boot and runs everything else, which is `VERIFY_NO_BOOT=1 sh
scripts/verify.sh p3` plus `scripts/check-commits.sh` over the pull request's
commits.

Two rules follow from that shape, and both are why the workflow is work and a
comment and nothing else:

- **The workflow defines nothing.**  It calls one script, and the script is in
  the tree where a contributor can run it.  A rule that exists only inside a
  YAML file is a rule no local command reproduces, which is the drift
  `AGENTS.md`'s "a rule that can be a gate belongs in a gate" argues against.
- **A green CI is not the floor.**  The floor is `sh scripts/verify.sh p3` on
  the development host, boot included.  A change is not ready for review until
  that is green locally; CI repeats the part a machine without QEMU can repeat.

When the boot is declined, the run says so:

```
verify[p3]: boot declined (VERIFY_NO_BOOT=1), this run did not start an image
```

That line is the difference between "the boot passed" and "the boot did not
run", which is the one distinction a gate that boots has to keep visible.

The commit message is checked by `scripts/check-commits.sh`, which is in the
gate and in CI.  It applies `scripts/hooks/commit-msg` to every commit in the
range, so a message that breaks `docs/fmts/commits.md` fails a run even in a
clone where the hook was never installed.  Install the hook anyway, with the
command in that specification: the check is cheaper at `git commit` than in a
run that has already built the workspace.

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

## Sending a change

**Work happens on a branch.**  `master` is a landing strip, not a workbench: it
only ever moves by fast-forward, so every commit that arrives is one that was
already reviewed on a branch.  This applies to the maintainer as much as to a
contributor, and for a mechanical reason rather than a stylistic one: the gate's
commit-message check reads `origin/master..HEAD`, which on `master` with nothing
unpushed is empty, and an empty range checks no message at all
([`scripts/check-commits.sh`](scripts/check-commits.sh) says so rather than
calling it a pass).

Name the branch for the change: `futex-wake-key`, not `fix` or `my-work`.

```sh
git switch -c futex-wake-key origin/master
# work, commit
git rebase --autosquash origin/master
sh scripts/verify.sh p3
git push -u origin futex-wake-key
```

A maintainer lands the branch by fast-forward:

```sh
git switch master && git merge --ff-only futex-wake-key && git push
```

`--ff-only` is not a preference either: it is what makes the linearity a fact
rather than a hope, and it refuses rather than silently creating a merge.

That puts two things on the author:

- **Rebase, do not merge.**  `git rebase origin/master` before asking for review,
  and again when `master` moves.  A pull request whose history carries a merge
  commit from `master` cannot be fast-forwarded, so `scripts/check-commits.sh`
  refuses one and names it.
- **Clean up before review, not at merge.**  `git rebase --autosquash` folds a
  `fixup!` commit into the one it belongs to.  Nothing is squashed at merge, so a
  `fixup!` that reaches the pull request reaches `master`.

Rewriting your own branch is normal: `git push --force-with-lease` after a
rebase, never `--force`.  Say in the pull request that you rewrote it, so a
reviewer knows why the diff moved.

**One pull request, one change.**  It may carry several commits when the change
is honestly several steps, but each commit has to stand on its own and pass the
gate on its own, because that is the unit a bisect will land on.

### What review asks

The gate is necessary and not sufficient.  A reviewer reads four questions:

1. **Does the change do what it says, and only that?**  A drive-by fix is a
   second pull request.
2. **Does it carry its evidence?**  A behaviour change names the gate or the log
   line that shows the mechanism ran.
3. **Does it move the documents it invalidates?**  `docs/status.md` for what
   exists, the RFC's status for what was decided, the crate's `//!` header for
   how it works.
4. **Does it leave the tree easier to change?**  This is the one question no
   other rule here answers, and the reviewer is the only reader who can.

**Timing.**  A maintainer gives a pull request its first substantive response
within seven days.  If seven days pass with nothing, comment on the pull request
and say so: the promise is the tree's, and a missed one is a defect in this
document rather than in your change.

**Approval means** the reviewer has read the diff, run the gate, and is willing
to have their name on the commit.  A green CI run is a precondition, not an
approval.

## Attribution

Three roles, and they never cross: **people own the work, tools assist.**

| Trailer | Names | Required | Form |
| --- | --- | --- | --- |
| `Signed-off-by:` | a person | on every commit | `Name <email>` |
| `Co-authored-by:` | a person | one per human co-author | `Name <email>` |
| `Assisted-by:` | a tool | when a tool wrote or shaped the change | `AGENT:MODEL [TOOLS]` |

`Signed-off-by:` is the Developer's Certificate of Origin, version 1.1
([`DCO`](DCO)): by adding it you state that you wrote the change, or have the
right to submit it, and that you submit it under this tree's licence.  `git
commit -s` adds it.  A tool never signs, because a tool cannot make that
statement.

`Assisted-by:` has no address, because a tool has none, and it names the tool
rather than the person driving it:

```
Assisted-by: Claude:claude-sonnet-4.5 coccinelle
Assisted-by: Deepseek:Deepseek-V4.1-Flash-1017
```

A change a model drafted and a person read is assisted.  A change a person wrote
and a formatter reformatted is not: `cargo fmt` and `clippy` are part of the
build, not collaborators.

**Your contribution lands under this tree's licences.**  Code under Apache-2.0,
prose under CC BY 4.0, as [`NOTICE`](NOTICE) states.  There is no separate
agreement to sign and no copyright assignment to make.

Trailers come last, after one blank line, in the order the table lists them.
They are exempt from the 72-column body wrap; keep each on one line.

## Language

Source code, comments, doc comments, commit messages, and every document under
`docs/` are written in **English**.  Issues and pull requests may be written in
English or Simplified Chinese.

The split is not about who is welcome.  It is about what a reader can search.
`git log`, `grep` and `rustdoc` are the whole of how this tree is looked
through, and a rule stated in two languages is a rule where the two statements
drift and the search finds one of them.  A conversation is read once, by the
person it answers; a document is read by everyone who arrives later.

A commit message outside ASCII is refused by `scripts/hooks/commit-msg` and by
`scripts/check-commits.sh`.  A comment outside ASCII is not: a name, a quotation
or a symbol sometimes has no English spelling, and the reviewer decides whether
the one in front of them is that case.  Write the issue in the language you
argue in, and the artifact in the one the tree reads.

## Becoming a maintainer

[`MAINTAINERS`](MAINTAINERS) names one person for the whole tree today.  That is
a fact about the tree's age, not a rule about who may join.

A contributor becomes a maintainer of a subsystem when all three hold:

- they have landed **three changes** to it that a reviewer did not have to
  rewrite, which is the only measure of judgement this tree has;
- they have reviewed at least one change to it, and the review caught something
  or asked a question the author had not considered;
- an existing maintainer nominates them in a commit that adds an `M:` row to
  `MAINTAINERS`, and no other maintainer objects within seven days.

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

- **Why is this crate here, and what may it name?**, `docs/architecture.md` and
  `scripts/layering.txt`.
- **How does the asynchronous model work?**, `docs/async_io.md`.
- **What exists and what is missing?**, each crate's `//!` header, and
  `docs/status.md` for the per-machine census.
- **What does a gate refuse?**, the gate's own header comment.
