# RFC 0002: Wake the waiters a futex word names, not every blocked task

- **Status:** Proposed
- **Author(s):** Raiden Lumine <2557597107@qq.com>
- **Date:** 2026-11-17
- **Supersedes:** none

## Summary

Give `Futex` (number 106) its mechanism, and change the one part of the
scheduler it cannot use as it stands.  A futex wait parks the calling task on a
**user address and a value**; a futex wake releases at most N tasks parked on
that address, and only those.  This tree's scheduler has one blocking shape and
it wakes **every** blocked task, so the second half of this RFC is a new state
a task can be in and a wake that selects, and the first half is the call on top
of it.

## Motivation

[`abi/src/number.rs`](../../abi/src/number.rs) freezes `Futex = 106` and nothing
serves it, so a program that calls it is told `NotImplemented`.

[`docs/roadmap.md`](../roadmap.md) lists it as Level 8's third row with a
judgement attached: "one number, and the wrong shape for a kernel with a
scheduler that already parks".  That judgement is right about the scheduler and
this document is where it stops being a sentence.  The wrong shape is
concrete:

[`kernel/src/scheduler/core/wait.rs`](../../kernel/src/scheduler/core/wait.rs)
has `wake_blocked`, and it is a **broadcast**:

```rust
pub fn wake_blocked(&mut self) -> usize {
    let mut woken = 0;
    for task in &mut self.tasks {
        if task.state == State::Blocked {
            task.state = State::Runnable;
            woken += 1;
        }
    }
    woken
}
```

Every blocked task becomes runnable.  That is correct for what it is used for
today, because each of those uses pairs the wake with a **re-check under the
same lock**: `block_unless` runs the caller's own question inside the
scheduler's critical section, so a task woken for somebody else's pipe finds its
pipe still empty and parks again.  A futex cannot work that way, for a reason
that is not an implementation detail:

- a futex's condition lives in **user memory** and the kernel is not allowed to
  read it after the fact: reading it would be a second, unsynchronised opinion
  about a word the program is changing;
- a broadcast storm is therefore not merely wasteful but **wrong**, because
  `FUTEX_WAKE(n)` promises the caller that at most N waiters were released, and
  a program that uses that number to decide whether anyone was listening would
  be told the truth by luck.

So the defect is not "the scheduler is slow".  It is that the scheduler has no
way to name a wait, and a futex is a wait with a name.

## Current state

By file, because this decision has to fit what exists.

**The syscall.**  `Futex = 106` in
[`abi/src/number.rs`](../../abi/src/number.rs).  Nothing registers it; a call
reaches `serve`'s fallthrough and answers `NotImplemented`.

**The blocking primitives.**  [`kernel/src/scheduler/mod.rs`](../../kernel/src/scheduler/mod.rs):

- `block(frame)` parks the running task unconditionally;
- `block_unless(frame, recheck)` parks unless `recheck` answers inside the lock,
  which is the pattern every current waiter uses;
- `block_unless_pid`, `block_unless_exit` are the two specific waits;
- `wake_blocked()` wakes **all** blocked tasks, as quoted above.

**The state.**  [`kernel/src/scheduler/task.rs`](../../kernel/src/scheduler/task.rs)
has `State::{Runnable, Sleeping { until }, Blocked, Finished}`.  `Blocked` is
deliberately not `Sleeping`: a deadline is the clock's answer and a wake is
another task's, and the two are separate because folding them would invent a
deadline for a wait that has none.

**What a task carries.**  `Task` already holds a pid, a parent, a space, a
context, a signal mask, queued signals and per-signal handlers.  It holds
nothing that names **what it is waiting for**.

**Shared memory landed** ([`docs/rfcs/0001`](0001-name-a-memory-region-two-processes-both-map.md)),
which matters here for one reason: a futex word is normally inside a region two
processes share, so the address a waiter parks on is meaningful in more than one
address space.  That is why the key below is a physical frame and an offset
rather than a virtual address.

**The user-pointer rule.**  `address_space::user_range(address, length, write)`
is what validates a pointer, and it walks the calling task's own root.  A futex
call must use it for both the word it reads and the address it parks on.

## Design

### The wait, as the call

`Futex(address, op, value, ...)`.  The first argument is a user address, the
second an operation, and the operations this RFC admits are two:

- **`FUTEX_WAIT`** (0): read the 32-bit word at the address under the scheduler's
  lock; if it is not `value`, answer `WouldBlock` immediately, which is the whole
  point of the call because the caller is expected to retry; if it **is**
  `value`, park until woken or until the optional deadline.
- **`FUTEX_WAKE`** (1): release at most `value` tasks parked on that address.
  Answer how many were released.

The value is compared with **`==` and not `&`**, at 32 bits, because that is what
the call means on every system a program will have been written against.

The comparison happens **under the same lock the wake takes**.  That single fact
is the whole of futex's correctness and it is the same argument `block_unless`
already makes: a waiter that read the word before the lock could park after the
wake it wanted had already fired, and nothing would ever wake it.  So the
comparison is inside the critical section even though it reads user memory,
and that is where this design has to be careful, which the next section is
about.

### The key: a frame and an offset, not a virtual address

Two processes sharing a region map it at addresses that need not be equal.  A
waiter in one and a waker in the other must still find each other, so the key a
wait is filed under is **(physical frame, page offset)**:

- the frame is what the address translates to in the calling task's own root,
  which `address_space` can answer for a page-aligned address, and the offset is
  the low twelve bits of the address;
- two addresses that name the same physical byte in two address spaces get the
  same key, which is exactly what "two processes share a futex word" means;
- a process that maps the same frame twice gets one key, which is a corner case
  nobody will hit and whose behaviour (it is one word) is defensible.

The alternative, the virtual address, is **wrong** and not merely different: two
processes sharing a region at different addresses would never wake each other,
and the bug would look like a hang with no line in the log to say why.

### The new state

A futex wait is not `Blocked`.  `Blocked` means "another task will wake me and I
do not know by what name", which is what a pipe's reader is; the wake is a
broadcast and the re-check filters it.  A futex wait is `Waiting { key, deadline }`:

```rust
Waiting {
    key: FutexKey,        // frame, offset
    deadline: Option<u64>, // the optional timeout, in ticks
}
```

`deadline` is `None` for `FUTEX_WAIT` with no timeout.  `Some(until)` reuses the
scheduler's existing `wake_expired` path, which already walks for
`Sleeping { until }`: one walk handles both states and the timer ceases to care
which kind of wait expired.

### The wake

`wake_key(key, count) -> usize` walks the task list and releases up to `count`
tasks whose state is `Waiting` with that key, in table order.  It does **not**
touch `Blocked` or `Sleeping`.

`count` semantics: `FUTEX_WAKE` with `value = 0` releases nothing and answers
zero, which is a legal call and a useful probe ("is anyone waiting"). `count =
usize::MAX` releases everyone on that key, which is what the ABI's
`FUTEX_WAKE_ALL` will mean when it exists; this RFC serves the count form and
does not invent a flag bit for the other.

### Who parks, and where

The wait runs inside the calling task's own trap, so it parks **the caller**
with the same mechanics `block_unless` uses, and the trap path's existing
`switch_without_saving` is what runs something else.  The difference is that the
task records `Waiting { .. }` instead of `Blocked`, and that the answer the
program gets on resumption is "woken" rather than "retry your call": a futex
wait that returns is done, and the program re-reads the word itself, which is
the contract every futex implementation has, and the reason the kernel never
reads the word again.

### Reading user memory under the scheduler's lock

This is the one part that needs an argument rather than a description.  The
comparison must happen inside the critical section, and the critical section is
the scheduler's, which is the lock the trap path and every other waiter take.

The rule this design states: **the read is a single 32-bit load that the
validator already proved reachable, and it is the only user-memory access the
scheduler takes while holding its lock.**  It is safe for a reason that survives
scrutiny: the page is mapped and user-reachable (`user_range` said so before the
lock), the fault it could still take is the copy-on-write fault on a demoted
page, and that resolver does **not** take the scheduler's lock, it takes the
page-table lock, and the order scheduler-then-tables is the order this kernel
already keeps.  A page that faults for any other reason is a program's bug and
stops the machine, which is the state Level 7.5 spent five commits making
reachable only through `user_range`.

What the design does **not** do is re-read the word after parking: a woken task
does not check it.  That is deliberate, because a re-check would be a second
opinion about a word the waker may already have changed, and futex's contract is
that spurious wakeups are allowed and the program's own loop is the authority.

## Alternatives

**Broadcast, and let each waiter re-check.**  This is what the tree does today
and it is why the roadmap called the shape wrong.  A re-check has to read the
futex word, and the kernel reading it again is a second opinion the program
cannot synchronise with: the value a woken task would compare against is one
some other task may have changed in between, so the comparison proves nothing.
It also breaks `FUTEX_WAKE`'s answer, which promises a bound.

**Key on the virtual address.**  Simplest, and wrong for two processes sharing a
region at different addresses: they would never find each other.  Since a shared
region is the normal home of a futex word, this is not a corner case.

**Key on the region's identifier and an offset.**  It works for the shared-memory
case and fails for the case a futex is also used in: two threads of one process
agreeing on a word in their own heap, which no region names.  A futex's address
is a plain user address, and the key has to be derived from what the address
*is*, not from a table it might be in.

**A hash table of wait queues keyed by address.**  The conventional design, and
it buys O(1) wake at the cost of a second structure with its own locking and its
own reclamation problem (an empty bucket is a bucket somebody may be about to
insert into).  This tree's task count is small and bounded by what a boot starts,
so a walk is a handful of comparisons; a table is a design for a machine that
has thousands of tasks.  When a boot has thousands, the walk becomes a table and
that is a new RFC.

**Deadline as a separate `Sleeping` task, woken by the timer into a futex
wait.**  Two states and two wakes for one wait, and the ordering between them is
a race the design would have to argue.  One state with an optional deadline is
one wake and one walk.

## Drawbacks

- `State` grows a fifth variant, and every `match` on it that exhausts gets a
  new arm.  That is the cost of naming a wait, and it is visible at compile time
  rather than at run time, which is the good kind.
- The scheduler reads user memory.  That is a new kind of access for a
  subsystem that until now only looked at its own structures, and it is the part
  a future reader should be suspicious of.  The argument above is the whole of
  its justification, and if it stops being true the design is wrong.
- The wake is a walk over every task.  For this tree's task counts that is
  cheaper than a table; for a machine with thousands of tasks it is not, and the
  alternative says so.
- A futex word on a page a fork demoted is not writable, so a program that
  shares a futex through a **fork** rather than a region gets a copy-on-write
  fault on its first compare-and-set and stops sharing.  That is the fork
  semantics Level 7.5 fixed in one direction and it is not a futex bug, but it
  is a trap a program will fall into and the design does not prevent it.

## Compatibility and migration

`Futex = 106` is frozen and served for the first time, so there is no old
behaviour to migrate.

`State` is internal to `kernel`, so the new variant has no ABI consequence.  No
`arch` change: every machine parks a task the same way and the deadline reuses
the existing timer path.

`abi` grows the operation constants (`FUTEX_WAIT`, `FUTEX_WAKE`) and
`user_abi` grows two wrappers.  The frozen numbering does not move, and the
flag bits this RFC does not serve (`FUTEX_WAIT_BITSET`, priority inheritance,
`FUTEX_REQUEUE`) are refused as unknown rather than silently ignored, which is
the rule `docs/fmts/syscall-abi.md` §"known flags" states.

There is one migration a reader should know about: `wake_blocked` keeps its
present meaning and its present callers, so the pipe, the process exit and the
signal path are untouched.  This RFC adds a second kind of wait rather than
converting the first, and that is deliberate: converting them would make every
current waiter's correctness argument depend on a key it does not need.

## How this is proven

- **A host test of the key**: two virtual addresses that name the same frame and
  offset produce one key, and two that differ in either produce two.  This is the
  assertion that would have caught the virtual-address alternative, so it is the
  first one written.
- **A host test of the wake selection**: with a scheduler holding three waiters
  on one key and two on another, `wake_key(k1, 2)` releases exactly two of the
  first three and nothing else, and a second call releases the third without
  touching the other two.  The counts are asserted, not just the states, because
  a version that released everything would pass a state check.
- **A host test that `Blocked` is untouched**: a task in `Blocked` beside a
  waiter on the woken key is still `Blocked` after the wake.  That is the
  regression the whole design exists for.
- **A boot exercise in `/bin/init`**: a region is made and forked, both processes
  attach it, one waits on a word with the value it holds, the other writes a new
  value and wakes it, and the waiter's next read sees the new value.  The gate
  line is the shape this tree uses for every mechanism:
  `protofire: futex woke 1 waiter on one key`, required whole, with the count.
- **The negative control**: with `wake_key` replaced by `wake_blocked`, the same
  boot must still pass that line, which is the point of the exercise, because a
  broadcast also wakes the one waiter.  So the exercise that matters asserts the
  **bound**: a second waiter on a *different* key must still be parked after the
  wake, and its own wake is what releases it.  The program asserts that itself
  and exits with a status other than the greeting's byte if it is wrong, which
  is the pattern `/bin/init` already uses for its own checks.

## Unresolved questions

- **`FUTEX_WAIT_BITSET` and `FUTEX_WAKE_BITSET`**: a waiter can select which
  wakes reach it by a bit mask, which is how one word carries several channels.
  This RFC does not serve them and refuses their operation numbers rather than
  ignoring them.  Whether they are needed here depends on a program that wants
  them, and none exists.
- **Priority inheritance** (`FUTEX_LOCK_PI`): the scheduler has no priorities at
  all, so the operation would be a promise about a thing this kernel does not
  have.  Refused by name when a realtime policy exists.
- **A requeue** (`FUTEX_REQUEUE`): it moves waiters from one key to another
  without waking them, which is a performance call a condition variable makes.
  It is one more branch on a structure this RFC already builds, and it needs a
  caller to justify its ordering rules.
- **Chromium's `FUTEX_WAIT` returns `WouldBlock` and the caller re-reads**: this
  design answers `WouldBlock` when the word disagrees and parks when it agrees,
  which is the same contract; what is unresolved is the name, because the ABI's
  error set has no `WouldBlock` and reusing `InvalidArgument` would tell a
  program its call was malformed.  Naming it is an ABI change and belongs in the
  commit that serves the call, not in this document.
