# `async_io`: requests, completions, and what a service is

`async_io` is a request/completion model — a request, a completion, a bounded
queue, and a trait with three methods — and it is deliberately small: no
executor, no task, no future, no scheduler, and this document says why each of
those is absent.

## Where this is going

This crate is the foundation of **everything is a service**.  A disk queue, a
socket's read half, a timer, a kernel thread and a user program all accept a
request and complete it later, and one trait describes all of them — that is
[What "everything is a service" buys](#what-everything-is-a-service-buys) below,
and it is the reason the request is opaque instead of an operation code.

Two layers are named and neither exists yet:

- **A registry**: a name a caller asks for, and a handle it submits through.
  Today a `Service` is a Rust trait that only exists at compile time; there is
  no table in the kernel that turns a name into one, and no way for a process to
  hold a handle.
- **A device or a process behind the trait**: the implementations are
  `MemoryBlockService`, which is a byte slice, and nothing else.  Every driver
  in the tree submits through `block`'s `QueuedBlockDevice` or through a virtio
  queue of its own — a typed method per operation, a ticket per request, an
  `unsafe` buffer contract — and that is a working shape, which is exactly why
  moving one onto this trait is the step that would test the idea instead of
  describing it.

**One of the two layers has landed since this was written.**  `kernel/src/service/table.rs`
is the registry: a name, a handle, and a freeze that closes the table after the
boot installs what it has.  Its first occupant is a clock in the kernel, whose
answer is the machine's own counter — so the shape is no longer only argued, it
is a boot that submits a request by name, drives a `dyn Service` through the
trait, and prints the number that came back.

What is still missing, and it is the larger half: a **device** behind the trait.
The clock answers in the call and has no queue, so nothing yet exercises a
service that completes later except the host tests.  `VirtioBlock` is the
candidate and it is a real change — its `unsafe` buffer contract has to be
described in a request that carries only two words.

The section
[The obligation the trait states and cannot enforce](#the-obligation-the-trait-states-and-cannot-enforce)
already said a driver's version of the check is "a different gate and a later
change" — this section is the same admission in the place a reader starts.

## The model

A [`Service`](../async_io/src/service.rs) accepts a [`Request`](../async_io/src/request.rs)
and either finishes it in the call or leaves it pending.  A later `poll` makes
progress, and a [`Completion`](../async_io/src/completion.rs) arrives once,
carrying the request's own token so the caller can tell which submission it
belongs to.

```
caller                          service
  │ submit(Request{id: 7})         │
  ├───────────────────────────────▶│
  │◀───────────────────────────────┤ None  (accepted; pending)
  │                                │
  │ poll()                         │  ... a device finishes ...
  ├───────────────────────────────▶│
  │◀───────────────────────────────┤ true
  │                                │
  │ pop() ──▶ Some(Completion{id: 7, Ok(4096)})
```

The completions live in the **service's** queue, and the caller takes them from
it.  That is the opposite of what an earlier version of this paragraph said, and
the code is what settled it: a service is the thing that knows a transfer
finished, so a service is the thing that holds the tokens until a caller comes
for them.  Putting the queue in the caller would mean the caller had to be told
where to put a completion before it knew whether the work succeeded.

The queue's accounting is what makes the trait's one obligation checkable —
what went in, what came out, what was refused — and the count of refused pushes
stays on the queue for the same reason.

## Why a trait and not a table of operation codes

The obvious design is a submission queue and a completion queue with an operation
code in each entry.  The previous tree has exactly that: its `io_uring` syscall
decodes an opcode and calls the subsystem that owns it.

That is the wrong shape for a crate at layer 2, because it puts the *set of
operations* in the ABI.  Adding one would mean extending a wire format, and every
service would have to understand operations it does not provide.

Here the request is opaque to the queue.  A service decides what it accepts, and
the crate never learns what an operation is.  The `io_uring` ABI stays what it is,
a program's view of a submission, and is translated into these requests at the
syscall boundary.

## What "everything is a service" buys

A service is anything that accepts a request and completes it later:

- a disk queue, whose completion is a transfer that finished;
- a socket's read half, whose completion is a byte count;
- a timer, whose completion is the expiry;
- **a kernel thread**, whose completion is its return;
- **a user program**, whose completion is its exit status.

The last two are the reason the trait takes opaque requests.  Starting a program
is a request; its completion is `Ok(exit_status)`.  Nothing about that is
I/O-shaped, and a queue with operation codes would have had to grow an
`IORING_OP_SPAWN` to express it, where here it is a service like any other.

## The three methods

`submit` returns `Option<Completion>` because a service *can* finish in the call,
and a caller should not have to poll for something already known.  A disk with a
cached block is the case; a program launch never is.

`poll` reports **"a completion is ready"**, not "something changed".  The first
version of the one test service in this crate returned the second, and a test
failed on it: a poll that decremented a delay had changed something and produced
nothing, and the two answers disagree for exactly one poll per request.  The
trait's word is the one that matters, a driver's poll is "drain what the device
finished", not "advance time".

`cancel` produces a completion.  A caller with nowhere to put a completion for the
request it cancelled would leak its own token, and a service that had already
taken the operation cannot un-take it, so cancellation is a request, not a
command.

## The obligation the trait states and cannot enforce

A service that accepted a request must eventually complete it.  A trait cannot
express that, and a timeout would be a policy this crate has no basis for.

What makes it checkable is that everything a service does goes through the queue:
a request accepted and never completed leaves the queue's accounting disagreeing
with the service's.  The test service in `service_tests.rs` is checked that way,
`every_accepted_request_is_completed`, and a driver's version of that check is a
boot that drains its queue, which is a different gate and a later change.

## Why the queue is bounded

A completion is a value a service produces and a caller takes.  If the producer
can outrun the consumer forever, the queue is a memory leak with a polite name,
and a service that completed four thousand requests during one syscall is exactly
the shape that fills one.

So the queue has a capacity, filling it is an error the producer is told about,
and the refusal is *counted* as well as returned: a service that ignored the error
still leaves a trace, and a boot line that reports it is how a workload that
outran its ring becomes visible instead of being a dropped completion.

The capacity is the caller's, not the crate's.  A const-generic queue would have
had to name a maximum here, which is a policy about how many devices a kernel
runs, and only the kernel knows that.  No producer is wired to this queue
today, so no constant states a length for it; when one arrives, its capacity
and its reason arrive with it.

## What is not here

**No executor.**  Driving a service is a loop, and where that loop lives is the
driver's or the scheduler's: a polling driver spins on `poll`, an
interrupt-driven one calls it from its handler, and the kernel's idle loop calls
it when nothing else is runnable.  An executor here would have to pick one, and a
crate that picked one could not be used by both a boot and a test.

**No `Future`.**  A Rust `Future` is one way to express "poll me later", and it
brings a waker, a task, and a runtime to store the waker in.  The kernel has none
of those yet, and the trait is the smaller statement of the same contract: a
`Future` implementation is a service with one request in flight.

**No scheduler.**  Parking a thread is the scheduler's act; a queue that parked
would have to know what a thread is, which is the edge `scripts/layering.txt`
forbids at layer 2.

## The kernel's use of it today

Nothing yet.  This crate was moved in with its tests and its own `//!` header
says how a service is driven; the kernel has no producer for it, so there is no
boot line and no gate that runs one.

That is a deliberate state and not an oversight.  The completion queue this boot
once drained was a wiring proof, a queue with nothing producing into it, and
the change that made the boot read a file through the syscalls superseded it:
that read is a real operation whose result a reader can verify, and a queue
drained by hand proved less by showing more.  `DISK_SECTORS` and
`COMPLETION_QUEUE_CAPACITY` went with it.

The first real producer will be a driver.  When it arrives, the gate that matters
is a boot that drains the queue after a transfer, not a line printed by a boot
that pushed one completion itself.
