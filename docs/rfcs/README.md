# Protofire RFCs

An RFC is a design document for a change that is too large to argue inside a
commit: it states the problem, the options that were really considered, the
decision, and what would show the decision was wrong.  This directory is where
those documents live, and this file is the process that produces them.

The code remains the source of truth about *what exists*,
[`docs/status.md`](../status.md) is the summary of that, and
[`docs/roadmap.md`](../roadmap.md) is what is missing and in what order.  An RFC
is the record of *what was decided and why*, including the options that were not
taken, which no amount of reading the final diff can recover.

An RFC goes one level below those documents on purpose.  A roadmap row says
"shared memory, four numbers, one mechanism"; the RFC is where "two processes
naming one region" stops being a sentence and becomes an interface with a
failure behaviour.  The rule this tree keeps rediscovering is that a decision
recorded only as code is a decision a reader has to reverse-engineer, and the
first reader to get it wrong is the one who changes it.

---

## When one is required

Write one, before the code, when a change would:

- add or change an interface between subsystems that other code will build on,
  the shape a driver, a filesystem or a scheduler hands to its consumers;
- start a new subsystem, or a new machine under `arch/`;
- change a format that outlives a boot: on-disk, on-wire, or the syscall ABI
  beyond what [`docs/fmts/syscall-abi.md`](../fmts/syscall-abi.md) already
  fixes;
- change a policy a document states as settled, including a decision
  [`docs/status.md`](../status.md) records as deliberate, or one
  [`docs/roadmap.md`](../roadmap.md) calls a decision and not wiring;
- need more than one commit to land.

It is **not** required, and is usually a wasted document, for a bug fix, a new
driver that fits an interface that already exists, a test, a ratchet
re-record, or an edit to prose.  The whole of Level 7.5 is the counter-example
worth keeping: five kernel defects were found by a reader, fixed one commit each,
and every one of them was a defect **against** a decision already written down,
so none of them needed an RFC.  When in doubt, an issue is where an idea is
allowed to be unfinished, and an RFC is where it stops being.

## Lifecycle and status

Every RFC opens with a status line, and the status is the first thing a reader
looks at:

| Status | Means |
|--------|-------|
| **Draft** | Written and under discussion; not a decision |
| **Proposed** | Ready for a decision; the commit that carries it is open |
| **Accepted** | Decided.  Code that implements it refers back to it |
| **Implemented** | The code is in the tree; the document now records why |
| **Superseded** | Replaced by a later RFC, which is named in its header |
| **Rejected** | Considered and not taken, with the reason kept |

A merged RFC is a record, not a wiki page.  It gets edited for typos and for its
status moving as the code lands, but a change of decision is a new RFC that
supersedes the old one.  The old document stays: "we thought about this and chose
otherwise" is information, and deleting it would be the same mistake as deleting
a failing test.

## Numbering and layout

Files are `docs/rfcs/<four digits>-<short title>.md`, numbered in the order
they are accepted, starting at `0001`.  A number is never reused, not even after a
rejection.  [`0000-template.md`](0000-template.md) is not an RFC and is not
numbered.

`NNNN` is four **decimal** digits, zero-padded: `0009` is nine and `0010` is ten,
and no file ever carries a letter.  The padding is what makes the directory's
order (`ls`, `sort`, a diff) equal to the numeric order.  Numbers are global and
monotonic, so a skipped number stays skipped.

Two mechanical facts about this directory are checked by
[`scripts/check-rfcs.sh`](../../scripts/check-rfcs.sh), which the gate runs:
those numbers, and the statuses below.  It also **generates** the index from the
documents themselves, so a document's status and the table that lists it cannot
drift apart.  `--record` is how the table is written after a status moves, and a
hand-written row is a failure rather than an edit.

## Writing one

Copy the template and fill it in.  Its sections exist because a design that
cannot answer them is not finished; if one genuinely does not apply, delete it
and say why rather than leaving it empty.

Keep the document about the decision, not about the code that will implement it,
the diff is the diff.  Cite files by name so a reader can find the current shape,
and remember that [`scripts/check-docs.sh`](../../scripts/check-docs.sh) checks
this directory like any other document: a citation that names a file the tree
does not have is a failed build, not a typo.

An RFC that says "we will test it" has no section on how it is proven.  Name the
test, the boot line or the gate, and say what would fail; this tree's own record
is that a claim no gate exercises is "implemented", not "verified".

## Reviewing one

An RFC is reviewed like a commit, and the review is about the design: what the
options really are, which one the evidence supports, and what would show the
choice was wrong to make.  [`MAINTAINERS`](../../MAINTAINERS) names who answers
for the subsystems it touches.

Today the project has one core maintainer, so acceptance is theirs; the rule is
written for the shape the roadmap is working toward, and a second maintainer
changes who answers, not what the answer has to say.

Accepting a design and implementing it are separate acts.  An RFC that is
accepted and then never built is still a decision the next person can read, and
its status says which of the two happened.

## The documents

<!-- rfcs-table:start -->
| RFC | Status | Subject |
|-----|--------|---------|
| [0001](0001-name-a-memory-region-two-processes-both-map.md) | Implemented | Name a memory region two processes both map |
| [0002](0002-wake-the-waiters-a-futex-word-names.md) | Proposed | Wake the waiters a futex word names, not every blocked task |
<!-- rfcs-table:end -->

The table is generated from the documents between the two markers above.  Each
document's own status line is the authority, and
[`scripts/check-rfcs.sh`](../../scripts/check-rfcs.sh) is what keeps the table
saying the same thing.
