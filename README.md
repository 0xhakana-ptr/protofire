# 源火内核 Protofire Kernel

A `no_std` bare-metal kernel for x86_64, aarch64 and riscv64, written as a
workspace of crates so that every part of it can be built and tested on its own.

## Why a workspace

The kernel this replaces was one crate of 300,000 lines, and the cost was not
compile time — a touched file rebuilt in under five seconds.  The cost was that
nothing could be tested without building everything, nothing could be built
without compiling everything, and a dependency between two subsystems was a line
of `use` that no one had agreed to.

So each subsystem is its own crate, each crate declares what it may name, and
`scripts/check-layering.sh` refuses anything else.  The measurements that
justified it are in `docs/architecture.md`; the short version is that 4,606 lines
of cryptography and its 64 tests moved in with two import changes, and run on a
host in a third of a second instead of needing a boot.

## Building and running

```sh
just build-x86_64     # the image, into target/x86_64-unknown-none/debug/bootloader
just run-x86_64       # boot it and keep the serial output
just check-x86_64     # boot it and require what it prints
```

`just --list` shows every recipe.  A recipe is one line naming one command;
anything with an argument or a conditional lives in `tools/xtask`, which is Rust
so that its assertions can be tested without an emulator.

## The gate

```sh
sh scripts/verify.sh p3
```

`p0` is formatting, every crate's tests, and the three kernels.  `p1` adds the
boot.  `p2` adds three censuses — the architecture gates, the dependency layering,
and the per-crate test counts.  `p3` adds clippy in every configuration.

A census is a ratchet: it records a number, refuses growth, and refuses a baseline
row that no longer describes the tree.  Meeting one by recording a new number is a
change that argues for it in the baseline's own prose.

## Where to read next

| Question | Document |
|---|---|
| Why is the tree shaped this way? | [`docs/architecture.md`](docs/architecture.md) |
| How does the asynchronous model work? | [`docs/async_io.md`](docs/async_io.md) |
| What does a change have to satisfy? | [`docs/contributing.md`](docs/contributing.md) |
| What does a gate refuse? | the gate's own header comment |

## Licence

Apache-2.0.  [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt) is the text.
