# 源火内核 Protofire Kernel

A `no_std` bare-metal kernel for x86_64, aarch64 and riscv64, written as a
workspace of crates so that every part of it can be built and tested on its own.

It is an independent kernel.  Other systems are read for what they got right and
not treated as the authority: where this tree follows a convention, the reason
is in the file that follows it.

## Building and running

Linux, x86_64.  One development host is supported and `rust-toolchain.toml` says
why: every measurement in the previous tree had three answers, every script had
a shell-difference branch, and a defect that only appeared on one host was found
by whoever ran the gate there.

```sh
cargo install just    # once; a distribution package is preferred where there is one
just build-x86_64     # the image, into target/x86_64-unknown-none/debug/bootloader
just run-x86_64       # boot it and keep the serial output
just check-x86_64     # boot it and require what it prints
```

`just --list` shows every recipe.  A recipe is one line naming one command;
anything with an argument or a conditional lives in `tools/xtask`, which is Rust
so that its assertions can be tested without an emulator.  Nothing in the gate
*needs* `just` — `scripts/verify.sh` is what a gate actually runs.

## The gate

```sh
sh scripts/verify.sh p3
```

`p0` is formatting, every crate's tests, and the three kernels.  `p1` adds the
boot — of every machine that has an image, not just the first one whose console
printed — and each machine's own claims: x86_64's disk write-back, aarch64's
interrupt delivered through its controller.  `p2` adds three censuses — the architecture gates, the dependency
layering, and the per-crate test counts.  `p3` adds clippy in every
configuration.

A census is a ratchet: it records a number, refuses growth, and refuses a
baseline row that no longer describes the tree.  Meeting one by recording a new
number is a change that argues for it in the baseline's own prose.

## Where to read next

| Question | Document |
|---|---|
| Why is the tree shaped this way, and which crate may name which? | [`docs/architecture.md`](docs/architecture.md) |
| What has been moved in, and what has not? | [`docs/migration.md`](docs/migration.md) |
| How does the asynchronous model work? | [`docs/async_io.md`](docs/async_io.md) |
| What does a change have to satisfy? | [`docs/contributing.md`](docs/contributing.md) |
| What may a contributor rely on, and what is review-only? | [`AGENTS.md`](AGENTS.md) |
| What does a gate refuse? | the gate's own header comment |

## Licence

Source code is Apache-2.0; prose is CC BY-SA 4.0.  [`LICENSES/README.md`](LICENSES/README.md)
says which files fall on which side and why the split exists.
