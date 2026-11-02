# File: justfile
# Purpose: The thin entry point.  Workflows live in `tools/xtask`; this file
#          names them, so a reader can find every command in one screen.
#
# The rule for adding a recipe: if it needs an argument, a conditional, or more
# than one command that has to be ordered, it belongs in xtask instead.  The
# previous tree's `Makefile` grew to over a thousand lines of shell, and the
# cost was a gate (`check-make-targets`) whose whole job was checking that the
# recipes, `.PHONY` and `help` still agreed.  A justfile this size does not need
# that gate.

# List the recipes.
default:
    @just --list

# Format check.
fmt-check:
    cargo fmt --all -- --check

# Format.
fmt:
    cargo fmt --all

# Type-check the whole workspace for the host.
check:
    cargo check --offline --workspace

# Build every crate.
build:
    cargo build --offline --workspace

# Build one machine's image.  `just build-x86_64`, `just build-aarch64`,
# `just build-riscv64`.
build-x86_64:
    cargo run --offline --quiet -p xtask -- build --machine x86_64

build-aarch64:
    cargo run --offline --quiet -p xtask -- build --machine aarch64

build-riscv64:
    cargo run --offline --quiet -p xtask -- build --machine riscv64

# Run every crate's tests.
test:
    cargo test --offline --workspace

# Lint.
clippy:
    cargo clippy --offline --workspace --all-targets -- -D warnings

# Boot the x86_64 image and keep its serial output.
run-x86_64:
    cargo run --offline --quiet -p xtask -- run --machine x86_64

# Boot the x86_64 image and require its first console line.
check-x86_64:
    cargo run --offline --quiet -p xtask -- check --machine x86_64

# The gate.  `just verify` is p0; `just verify p3` is the release floor.
verify tier="p0":
    sh scripts/verify.sh {{tier}}
