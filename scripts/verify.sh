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

# The machines with an image that boots, which is a subset of the ones that
# build.  A machine is added here when `cargo xtask check --machine` has
# required lines for it, and not before: `xtask` refuses a machine with no
# expected lines rather than passing a check that asserted nothing.
# riscv64 is in because its image boots: the OpenSBI hand-off, the device
# tree, the kernel's own page table and the heap are all exercised, and the
# machine's required lines are the evidence.
BOOTABLE_MACHINES="x86_64 aarch64 riscv64"

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

    # Documents before code: a citation that does not resolve is cheaper to find
    # than to follow, and the check costs a fraction of a build.
    step "scripts/check-docs.sh"
    sh scripts/check-docs.sh || fail "a document cites a file the tree does not have"

    # The same question one level in: a doc comment that names an item the
    # crate does not have is a reader sent somewhere that is not there, and
    # `cargo doc` is what knows.  It denies `rustdoc::broken_intra_doc_links`
    # through `RUSTDOCFLAGS`, because a warning a run tolerates is a warning
    # nobody reads.
    step "cargo doc --workspace"
    RUSTDOCFLAGS="-D warnings" cargo doc --offline --workspace --no-deps \
        || fail "a doc comment links to an item the crate does not have"

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

    # Every machine whose image this tree can boot is booted here, not just the
    # one whose console printed first.
    #
    # This is the rule the tree keeps relearning: a machine's boot is either
    # exercised or it is not, and a machine that is only built has never had an
    # instruction fetched from it.  aarch64 printed four lines and stopped after
    # the heap, and a gate that booted only x86_64 called that green — so p1 now
    # boots each machine that has an image, and riscv64 is added when it has
    # one rather than when someone remembers.
    for machine in $BOOTABLE_MACHINES; do
        step "cargo xtask check --machine $machine"
        cargo run --offline --quiet -p xtask -- check --machine "$machine" \
            || fail "the $machine image did not print its required lines"
    done
}

run_p2() {
    run_p1

    # The architecture census: a `target_arch` gate outside `arch/` is a place a
    # fourth machine has to be taught, and nothing else in the build notices one.
    step "scripts/check-arch-fanout.sh"
    sh scripts/check-arch-fanout.sh || fail "an architecture gate outside arch/"

    # The dependency census: every crate may name only the crates below it, and
    # `scripts/layering.txt` is where the order is stated.  "No cycles" alone
    # would be the weaker rule — an acyclic graph can still put the filesystem
    # above the scheduler and be wrong in a way no compiler sees.
    step "scripts/check-layering.sh"
    sh scripts/check-layering.sh || fail "a dependency that crosses a layer upward"

    # The test census: a crate the workspace builds and nothing runs is the
    # crate split not paying for itself, and a test that disappeared is a defect
    # that stopped being caught.
    step "scripts/check-crate-tests.sh"
    sh scripts/check-crate-tests.sh || fail "a crate with no tests, or one whose tests fell"

    # The repository itself: a file that is ignored and tracked is one a reader
    # misunderstands, and a committed build product is one a clone pays for.
    # Neither is a defect a compiler or a boot can see.
    step "scripts/check-repo-integrity.sh"
    sh scripts/check-repo-integrity.sh || fail "an ignored file is tracked, or a product is"
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
