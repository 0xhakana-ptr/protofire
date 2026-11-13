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

The order is now: **Level 5 (the network), then Level 6 (finishing the
migration from the previous kernel), then Level 7 (the device model)**.  The
device model moved last on purpose — it decides what a descriptor *is*, and
deciding that before the filesystems and drivers have landed would decide it
against an incomplete set of things a descriptor has to name.

- **Level 5, step 5.1** — the IPv4 header, its checksum, and a round-trip test
  over hand-built bytes.  No device, no syscall: `net/src/lib.rs` is 6 lines and
  grows its first module.  `docs/roadmap.md` carries the eight steps and what
  each is proved by.
- **Level 6 — the migration, and the number that sizes it.**  The previous
  kernel served **194 of 195** syscall numbers; this one serves **43**.  Its
  nine module trees were 301,718 lines against this tree's 94,245.  Three are
  done (`abi`, `arch`, most of `kernel`), five are partial (`fs`, `drivers`,
  `user`, `syscall`, `util`), one has not started (`network`).  The two largest
  gaps are **ten filesystems** (ext4, fat32, exfat, ntfs, btrfs, xfs, f2fs,
  erofs, squashfs, and a FUSE client) and the **drivers** (NVMe, AHCI, USB
  HID/MSD, framebuffer, virtio-gpu, virtio-input).
- **Level 7** is planned and not started: the handle a program can give away.
  Four questions are named in `docs/roadmap.md`, and no work should start
  before they are answered in writing.
- **`SetLength` (20), `StatFd` (30), `ReadDirFd` (31)** — three numbers the
  filesystem already implements (`VNode::set_len`) and the ABI has not been
  given.  Handler, registration, ring-3 intercept and a wrapper each.  They are
  not in a level; they are the leftover of Level 2 and each is one commit.

## The distributed question, and what this tree actually holds

The intended direction is "everything is a service" with a distributed layer
above it, where the kernel supplies mechanism and user space supplies policy.
Measured against the previous kernel, here is what that direction actually has
behind it today — the distinction matters, because a plan built on a guess about
what exists is the way this tree has gone wrong before.

**What exists and is real:**

- A message-passing primitive that can be built on for real: `abi` holds the
  numbering and the `#[repr(C)]` records, `ipc` holds a ring, and the pipe
  already parks a reader and wakes it.  A remote call would go through the same
  shape.
- `async_io` — a request/completion model with a `Service` trait, a bounded
  queue, and one real implementor (`kernel/src/service/clock.rs`).  It has never
  had a device behind it, so its *pending* half has never run.
- `service_table` — a name-to-service table, installed at boot, frozen before
  anything looks one up.  It has one entry (the clock) and no syscall reaches
  it.
- `rights` — two constants and no consumer.  It sits at layer 0 for exactly the
  case where a handle carries rights.
- `Descriptor` — a handle table that already distinguishes copy from transfer
  (`Descriptor::for_owner`), which is the arithmetic a capability passing would
  need.

**What does not exist, and the honest reading of it:**

- **No distributed bus, no device virtualisation, no task migration, no remote
  discovery.**  None of it is in this tree and none of it was in the previous
  one either — `git ls-tree 16b5ef8` finds no module for any of it.  So this is
  not "migrated and lost"; it is a direction nobody has built yet.
- **The kernel does not need much code for it — that part of the reading is
  right.**  `abi` would grow wire records and a numbering for a handle transfer,
  `kernel` would grow the transfer itself and nothing about what is transferred,
  and that is tens of lines rather than thousands.  Everything above it — what a
  service is, how it is found, what a restart policy is — is user space, and is
  the part that would make two distributions able to talk or not.
- **But "the kernel needs little code" is not the same as "this is nearly
  done".**  Two things have to be true before a handle transfer is worth
  designing, and neither is today:
  - **There has to be something worth passing.**  A service handle over a
    service table with one entry and no device behind it is a handle to the
    clock.  The migration is what puts filesystems, drivers and the 152 numbers
    behind it.
  - **The `abi` records have to be worth freezing.**  A handle format frozen
    against a tree with 43 of 195 calls would be frozen against a fraction of
    what it has to describe.

So the reading of the DeepSeek conversation that survives contact with this tree
is: **the architecture it describes is the one this tree is already shaped
for, and the work it implies is small — but it is the last step, not the next
one.**  Building it now would decide a descriptor's third variant against one
service and no device.

**The one thing worth doing early, and it is cheap:** write down the four
questions `docs/roadmap.md`'s Level 7 names.  They are decisions, not code, and
answering them in prose costs a page and does not constrain anything that comes
before.

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
