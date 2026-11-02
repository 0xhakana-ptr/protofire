#!/usr/bin/env sh
# File: scripts/verify.sh
# Purpose: Run the tiered verification gate.
#
# ## The tiers
#
# p0 is what a change cannot land without: formatting, the whole workspace
# built for the host, each machine's kernel built for its own target, and every
# crate's tests.  It is fast because it does not boot anything.
#
# p1 adds the boot: the image is built for x86_64, started under QEMU, and its
# first console line is required.  A tree that compiles and never runs is a tree
# whose boot path has not been exercised since the last change to it — and every
# defect this project has found in its own boot path was found by a boot.
#
# p2 is where the ratchets will go as they arrive: the architecture census (a
# `cfg(target_arch)` outside `arch/` is a question the arch layer should be
# answering), the unsafe-comment census, the dependency census.  None of them
# exists yet, and this tier says so rather than pretending an empty list is a
# gate that passed.
#
# p3 is the release floor.  Today it is p2 plus clippy in both configurations;
# the QEMU matrix grows here as the other two machines get their images.
#
# ## Why tiers at all
#
# The previous tree learned this the expensive way: a gate nobody runs is a gate
# that rots, and one that runs everything is a gate people learn to skip.  The
# tiers are chosen so that the common case — a change to one crate — is answered
# by p0 in seconds, and the release answer is one command.
#
# Usage:
#   sh scripts/verify.sh            # p0
#   sh scripts/verify.sh p1         # p0 + the boot
#   VERIFY_TIER=p3 sh scripts/verify.sh

set -eu

cd "$(dirname "$0")/.."

VERIFY_TIER="${1:-${VERIFY_TIER:-p0}}"

case "$VERIFY_TIER" in
    p0|P0) VERIFY_TIER="p0" ;;
    p1|P1) VERIFY_TIER="p1" ;;
    p2|P2) VERIFY_TIER="p2" ;;
    p3|P3) VERIFY_TIER="p3" ;;
    *)
        printf 'unsupported tier: %s (one of p0, p1, p2, p3)\n' "$VERIFY_TIER" >&2
        exit 1
        ;;
esac

# The machines every tier builds.  A kernel that compiles for one architecture
# and not the others is a kernel whose architecture split is not finished, and
# the failure is cheapest to find here.
MACHINES="x86_64-unknown-none aarch64-unknown-none riscv64gc-unknown-none-elf"

step() {
    printf '==> verify[%s]: %s\n' "$VERIFY_TIER" "$1"
}

fail() {
    printf 'verify[%s] failed: %s\n' "$VERIFY_TIER" "$1" >&2
    exit 1
}

run_p0() {
    step "cargo fmt --check"
    cargo fmt --all -- --check || fail "formatting"

    step "cargo build --workspace"
    cargo build --offline --workspace || fail "the workspace does not build"

    for machine in $MACHINES; do
        step "cargo build -p kernel --target $machine"
        cargo build --offline -p kernel --target "$machine" \
            || fail "the kernel does not build for $machine"
    done

    step "cargo test --workspace"
    # `--workspace` runs each crate's own tests, which is the point of the
    # crate split: a failure names the crate that caused it.
    cargo test --offline --workspace || fail "a crate's tests failed"
}

run_p1() {
    run_p0

    step "cargo xtask check --machine x86_64"
    cargo run --offline --quiet -p xtask -- check --machine x86_64 \
        || fail "the x86_64 image did not reach its console"
}

run_p2() {
    run_p1

    # The architecture census: a `target_arch` gate outside `arch/` is a place a
    # fourth machine has to be taught, and nothing else in the build notices one.
    step "scripts/check-arch-fanout.sh"
    sh scripts/check-arch-fanout.sh || fail "an architecture gate outside arch/"

    # The dependency census is the next one: every crate may name only the
    # crates below it, and there is no file describing that yet.  Saying so is
    # the honest form of an empty gate.
}

run_p3() {
    run_p2

    step "cargo clippy --workspace"
    cargo clippy --offline --workspace --all-targets -- -D warnings \
        || fail "clippy"

    for machine in $MACHINES; do
        step "cargo clippy -p kernel --target $machine"
        cargo clippy --offline -p kernel --target "$machine" -- -D warnings \
            || fail "clippy for $machine"
    done
}

case "$VERIFY_TIER" in
    p0) run_p0 ;;
    p1) run_p1 ;;
    p2) run_p2 ;;
    p3) run_p3 ;;
esac

printf 'verify[%s]: passed\n' "$VERIFY_TIER"
