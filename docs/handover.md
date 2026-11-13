# Handing this tree to the next session

Written at the end of the session that landed the time-and-randomness level and
fixed the aarch64 stop.  It exists because the next reader will open this tree
without the conversation that produced it, and the three things below are the
ones that were expensive to learn.

`AGENTS.md` is still the rules.  This file is not a second copy of them; it is
what a reader needs that no rule and no gate says.

## Where the work is

| question | answer |
|---|---|
| What does the kernel do today, per machine? | `docs/status.md` |
| What is missing, and in what order does it depend? | `docs/roadmap.md` |
| Why is the tree shaped this way? | `docs/architecture.md`, `scripts/layering.txt` |
| What is the next thing to build? | `docs/roadmap.md` — Level 5, step 5.1 |

The census, re-taken at the end of this session:

```sh
{ grep -ohE 'SyscallNumber::[A-Za-z0-9]+' kernel/src/boot.rs kernel/src/process.rs; } \
  | sed 's/.*:://' | sort -u | wc -l    # 43 served
grep -c 'table.register' kernel/src/boot.rs   # 25 in the registry
grep -cE '^\s{4}[A-Z][A-Za-z0-9]* = [0-9]+,' abi/src/number.rs   # 195 in the enum
find . -name '*.rs' -not -path './target/*' | xargs cat | wc -l  # 94,245 lines
grep -cE '^[0-9]+ ' scripts/layering.txt     # 40 crates
```

## Three things this session learned the hard way

**1. A number in a document is wrong until it is re-taken.**  The network
family said 34 in one place, 32 in another and 14 in a third; it is 43.  Two of
those errors cancelled in the total, which is why the family rows now have to
sum rather than the total alone.  Re-take before arguing about one.

**2. `git commit-tree` keeps no date unless you pass one.**  A rewrite that
drops `GIT_AUTHOR_DATE`/`GIT_COMMITTER_DATE` flattens every commit onto today,
which is worse than the trailer it was fixing.  Every rewrite in this tree
passes the author and committer name, email and date explicitly, and verifies
the tree hash afterwards.

**3. A red gate is the product; a stale document is the bug.**  This tree moved
that rule from `AGENTS.md` into `docs/status.md`, and the rule is what caught
the network census, the `21 number(s) served` fragment left under a correct
`25`, and the `address spaces reaped 4` that the gate has required as `6` for
several sessions.

## What is open

- **Level 5, step 5.1** — the IPv4 header, its checksum, and a round-trip test
  over hand-built bytes.  No device, no syscall: `net/src/lib.rs` is 6 lines and
  grows its first module.  `docs/roadmap.md` carries the eight steps and what
  each is proved by.
- **`SetLength` (20), `StatFd` (30), `ReadDirFd` (31)** — three numbers the
  filesystem already implements (`VNode::set_len`) and the ABI has not been
  given.  Handler, registration, ring-3 intercept and a wrapper each.  They are
  not in a level; they are the leftover of Level 2 and each is one commit.
- **Level 6** is planned and not started: the handle a program can give away.
  Four questions are named in `docs/roadmap.md`, and no work should start
  before they are answered in writing.

## Two habits that cost a session each to learn

- **Sample twice with the guest running.**  A single read of a counter says
  nothing about whether it is moving; the aarch64 stop looked like a deaf core
  until two samples five seconds apart showed a frozen count on a core that was
  executing ring 3.
- **Name the disk you booted.**  A boot against the kernel's own built-in image
  carries no init program, so `ExecProcess` fails and the program spins — which
  looks exactly like the defect being chased.

## The history

The tree carries the previous kernel's history underneath it: 872 commits from
`2026-08-23` to `Protofire 0.8.15`, then this kernel's own.  `git log
--max-parents=0` answers the first commit, and `git log --oneline | tail`
reaches the join.
