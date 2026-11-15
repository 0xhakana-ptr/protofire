# Security Policy

Protofire is a research prototype of a bare-metal kernel, written to find out
what a small multi-architecture kernel costs.  It is not a product and has not
been audited.

**Do not run it with untrusted workloads, and do not put data you care about
behind it.**

## What the tree actually enforces

This list is short on purpose.  A security document that describes a kernel
some other version of the tree was is worse than no document, because a reader
plans around it.

- **Ring-3 isolation.**  A program reaches the kernel only through the syscall
  gate, and a fault it takes kills the process rather than the machine.  In
  `kernel/src/process.rs` and the per-machine trap paths.

- **User addresses are validated.**  A user address from ring 3 is validated
  before the kernel touches it, and a program's pages are `user: true` while the
  kernel's are not.  In `kernel/src/address_space/`.

- **W^X in the loader.**  An image segment that is both writable and executable
  is refused rather than mapped.  In `kernel/src/loader.rs`.

- **A default-refusing MAC policy.**  It labels subjects and objects, is asked
  before a file is opened or read, and refuses by default.  In
  `security/src/mac/`.

- **Capabilities are descriptors.**  Every capability a program is given is a
  descriptor it can be made to close.  In `kernel/src/syscall/table.rs`.

## What it does not have

Recorded here so that a reader does not assume it: no address-space layout
randomisation, no stack canaries in ring-3 programs, no seccomp-style filter,
no signed images, no encryption at rest, no auditing beyond the MAC denials the
boot prints.

The network stack has three gaps a reader planning around it must know, each
recorded where its mechanism is:

- **`TlsConnect` cannot be used.**  It builds and sends a TLS 1.3 ClientHello
  and then answers `Unsupported`, because there is no TLS server on this machine
  to finish the handshake with.  The record layer, the key schedule and the
  handshake messages are implemented and host-tested; the **call** is not a way
  to reach a server.  `docs/status.md` and `docs/fmts/syscall-abi.md`.

- **No X.509 parser, so no certificate is checked.**  A chain a peer sends is
  carried opaque and the Finished is verified against a key the caller supplies.
  A program that trusts a peer's Finished has authenticated the **handshake**,
  not the peer's name.  `net/src/tls.rs`.

- **`TlsConnect`'s boot probe proves agreement, not rejection.**  It runs both
  sides of a handshake against each other, so a wrong side never appears in it;
  the rejection cases are host tests.  A reader who reads the boot line as
  "TLS refuses forgeries" is reading it wrong.  `docs/status.md`.
  `docs/status.md` is the census of what each machine does and does not do, and
  it is the authority where this list and the tree disagree.

The threat model the tree is built against today is **a program that is wrong**,
not a program that is hostile.  That is what the gates exercise: a program that
writes its own code page, a program that reads past its window, a program that
faults.  A hostile program is the next threat model, and naming it here is the
first step rather than a claim about the code.

## Reporting a vulnerability

Open an issue describing what you found.  This project has no private
vulnerability channel configured, so a report that needs to stay off the public
tracker should say so **without the details** and a private channel will be
arranged.

Useful in a report:

- the machine (x86_64, aarch64 or riscv64) and how it was booted,
- the commit, and whether the tree was modified,
- what the kernel printed, if anything, one boot's serial log is worth more
  than a description of it,
- whether the report is about a **program escaping its window** or about the
  kernel misusing memory, because those are different defects here and the
  second is the more serious one.

## Supported versions

The tree is developed on `master` and there are no releases.  A report against
any older commit is welcome, but only `master` is fixed.
