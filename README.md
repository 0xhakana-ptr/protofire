# 源火内核 Protofire Kernel

A `no_std` bare-metal kernel for x86_64, aarch64 and riscv64, written as a
workspace of crates so that every part of it can be built and tested on its own.

It is an independent kernel.  Other systems are read for what they got right and
not treated as the authority: where this tree follows a convention, the reason
is in the file that follows it.

## Building and running

Linux, x86_64.  One development host is supported and `rust-toolchain.toml` says
why: a tree that also carries Windows and macOS on Intel pays a cost that is not
the code, it is that every measurement has three answers, every script has a
shell-difference branch, and a defect that appears on one host is found by
whoever ran the gate there.

Three things are needed, and the first two are enough to **test** the tree:

```sh
# 1. The toolchain the tree pins.  rustup reads rust-toolchain.toml.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. `just` runs the recipes below.  It is not a build dependency: every recipe
#    is one line naming one command, and `scripts/verify.sh` is what a gate
#    actually runs, so a reader without `just` can copy the command out.
cargo install just        # or: apt install just / dnf install just

# 3. QEMU, only for the tiers that boot something.
#    `cargo test --workspace` and `sh scripts/verify.sh p0` need neither QEMU
#    nor a boot: they build every crate and run its tests on the host.
# 
#    Debian / Ubuntu
apt install qemu-system-x86 qemu-system-arm qemu-system-misc

#    Fedora / RHEL
dnf install qemu-system-x86 qemu-system-arm qemu-system-misc

#    Arch Linux
pacman -S qemu-system-x86 qemu-system-arm qemu-system-misc
```

```sh
just build-x86_64     # the image, into target/x86_64-unknown-none/debug/bootloader
just run-x86_64       # boot it and keep the serial output
just check-x86_64     # boot it and require what it prints
```

`just --list` shows every recipe.  A recipe is one line naming one command;
anything with an argument or a conditional lives in `tools/xtask`, which is Rust
so that its assertions can be tested without an emulator.  Nothing in the gate
*needs* `just`, `scripts/verify.sh` is what a gate actually runs.

### A first change

The smallest useful contribution is a document correction: `docs/status.md` and
`docs/migration.md` state what the code does, and when the two disagree the code
is right and the document is the bug.  `sh scripts/verify.sh p0` proves a
document-only change without booting anything, because `check-docs` refuses a
citation that does not resolve and `check_source_headers` refuses a header that
names a path it is not at.

`CONTRIBUTING.md` is the list a change has to satisfy, `docs/fmts/` is the
format each kind of file is written in, and `MAINTAINERS` says who reviews what.

## The gate

```sh
sh scripts/verify.sh p3
```

`p0` is formatting, every crate's tests, and the three kernels.  `p1` adds the
boot, of every machine that has an image, not just the first one whose console
printed, and each machine's own claims: x86_64's disk write-back, aarch64's
interrupt delivered through its controller.  `p2` adds three censuses,
the architecture gates, the dependency layering, and the per-crate test counts. 
`p3` adds clippy in every configuration.

A census is a ratchet: it records a number, refuses growth, and refuses a
baseline row that no longer describes the tree.  Meeting one by recording a new
number is a change that argues for it in the baseline's own prose.

## Where to read next

- **Why is the tree shaped this way, and which crate may name which?**
  [`docs/architecture.md`](docs/architecture.md).
- **What is here, and why does it have the shape it has?**
  [`docs/migration.md`](docs/migration.md).
- **Which subsystems are in, which are not, and where is the code?**
  [`docs/status.md`](docs/status.md).
- **How does the asynchronous model work?**, [`docs/async_io.md`](docs/async_io.md).
- **What does a change have to satisfy?**, [`CONTRIBUTING.md`](CONTRIBUTING.md).
- **What may a contributor rely on, and what is review-only?**
  [`AGENTS.md`](AGENTS.md).
- **What does a gate refuse?**, the gate's own header comment.
- **What does the kernel enforce, and what does it not?**
  [`SECURITY.md`](SECURITY.md).
- **How is participation expected to go?**
  [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Licence

Source code is Apache-2.0; prose is CC BY 4.0.  [`LICENSES/README.md`](LICENSES/README.md)
says which files fall on which side and why the split exists.
