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
# whose boot path has not been exercised since the last change to it, and every
# defect this project has found in its own boot path was found by a boot.
#
# p2 is the ratchets: the architecture census (a `cfg(target_arch)` outside
# `arch/` is a question the arch layer should be answering), the dependency
# census, the per-crate test census, and the repository's own integrity.
#
# p3 is the release floor.  It is p2 plus clippy in every configuration the
# tree builds, host and target alike, and it boots all three machines.
#
# The previous tree learned this the expensive way: a gate nobody runs is a gate
# that rots, and one that runs everything is a gate people learn to skip.  The
# tiers are chosen so that the common case, a change to one crate, is answered
# by p0 in seconds, and the release answer is one command.
#
# Usage:
#   sh scripts/verify.sh            # p0
#   sh scripts/verify.sh p1         # p0 + the boot
#   VERIFY_TIER=p3 sh scripts/verify.sh
#   VERIFY_NO_BOOT=1 sh scripts/verify.sh p3   # the floor without an image

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
# `riscv64-aia` is the same image on a tree that names an APLIC and an IMSIC
# instead of a PLIC: the APLIC, the IMSIC and a PCI device's message are only
# exercised there, and a gate that booted only the PLIC machine called the
# whole AIA path implemented rather than verified.
BOOTABLE_MACHINES="x86_64 aarch64 riscv64 riscv64-aia"

# A caller can decline the boot, and the line p1 prints when it does is the
# difference between "the boot passed" and "the boot did not run".  A gate that
# boots has to keep that distinction visible: a log with no image in it and a
# log with a passing image in it otherwise read the same, and the second is the
# one a reader assumes.  `scripts/ci.sh` is the caller that sets this, because a
# CI runner may have no QEMU and no `/dev/kvm`; a person on the development host
# runs p3 without it.
NO_BOOT="${VERIFY_NO_BOOT:-0}"

NO_BOOT="${VERIFY_NO_BOOT:-0}"

step() {
    printf '==> verify[%s]: %s\n' "$VERIFY_TIER" "$1"
}

fail() {
    printf 'verify[%s] failed: %s\n' "$VERIFY_TIER" "$1" >&2
    exit 1
}

# The file-header rule docs/fmts/comments.md states: line 1 is `//! ` and the
# path from the repository root, line 2 is a bare `//!`, and a blank line
# separates the header block from the first body line.  The report answers
# coverage rather than a bare pass so a run that checked nothing cannot look
# the same as one that checked everything.
check_source_headers() {
    path_ok=0
    blank_ok=0
    separated_ok=0
    total=0
    while IFS= read -r file; do
        total=$((total + 1))
        first=$(sed -n '1p' "$file")
        if [ "$first" = "//! $file" ]; then
            path_ok=$((path_ok + 1))
        else
            printf 'bad header path: %s (line 1 is "%s")\n' "$file" "$first" >&2
        fi
        second=$(sed -n '2p' "$file")
        if [ "$second" = "//!" ]; then
            blank_ok=$((blank_ok + 1))
        else
            printf 'bad header line 2: %s (expected a bare "//!", got "%s")\n' "$file" "$second" >&2
        fi
        third=$(sed -n '3p' "$file")
        case "$third" in
            "//!"*|"") ;;
            *) printf 'bad header line 3: %s (expected a description line or the blank separator, got "%s")\n' "$file" "$third" >&2 ;;
        esac
        separated=0
        line_no=3
        while :; do
            line=$(sed -n "${line_no}p" "$file")
            case "$line" in
                "//!"*) line_no=$((line_no + 1)) ;;
                "") separated=1; break ;;
                *) break ;;
            esac
        done
        if [ "$separated" = 1 ]; then
            separated_ok=$((separated_ok + 1))
        else
            printf 'header runs into the body: %s\n' "$file" >&2
        fi
    # `vendor/` is excluded, and the exclusion is the exception that proves the
    # rule rather than a hole in it.  The header rule is about **this tree's**
    # files: line 1 names the file's own path so a reader who finds it in
    # isolation knows where it came from.  A vendored crate's source is not this
    # tree's, it is cargo's, and its `.cargo-checksum.json` is a hash of the
    # bytes: rewriting a vendored file's header makes cargo reject the source it
    # cannot verify, so the exemption is what keeps the directory usable at all.
    # The rule still fires on everything a contributor writes.
    done <<EOF
$(find . -name '*.rs' -not -path './target/*' -not -path './vendor/*' | sed 's|^\./||' | sort)
EOF
    printf 'check_source_headers: path=%d blank=%d separated=%d total=%d\n' \
        "$path_ok" "$blank_ok" "$separated_ok" "$total"
    [ "$path_ok" -eq "$total" ] && [ "$blank_ok" -eq "$total" ] \
        && [ "$separated_ok" -eq "$total" ]
}

run_p0() {
    step "cargo fmt --check"
    cargo fmt --all -- --check || fail "formatting"

    # The headers, before anything that reads them: a file whose first line
    # names a path it is not at is a reader already lost, and the split that
    # moved crates around moved several without moving their headers.
    step "check_source_headers"
    check_source_headers || fail "a Rust file's header does not name its own path, or does not end where the header block ends"

    # Documents before code: a citation that does not resolve is cheaper to find
    # than to follow, and the check costs a fraction of a build.
    # The punctuation `docs/fmts/comments.md` names as not used: an em dash,
    # and a rule line of box-drawing characters.  The rule is prose and stayed
    # prose until the tree held 1,600 lines that broke it, which is the case
    # `AGENTS.md`'s "a rule that can be a gate belongs in a gate" describes.
    step "scripts/check-comment-punctuation.sh"
    sh scripts/check-comment-punctuation.sh \
        || fail "a comment or a document uses punctuation the style refuses"

    step "scripts/check-docs.sh"
    sh scripts/check-docs.sh || fail "a document cites a file the tree does not have"

    # The design record's own invariants: one decimal number per RFC, a status
    # from the fixed set, supersede links that agree at both ends, and an index
    # generated from the documents rather than maintained beside them.  It runs
    # here and not in a later tier because a document that disagrees with itself
    # is the same class of failure as a citation that does not resolve, and it
    # costs a fraction of a build.
    step "scripts/check-rfcs.sh"
    sh scripts/check-rfcs.sh || fail "the RFC directory and its index disagree with themselves"

    # The commit message is part of the change, and until this step nothing in
    # the gate read `git log`: `scripts/hooks/commit-msg` runs at `git commit`
    # only if a contributor installed it by hand, so a message could break every
    # rule in `docs/fmts/commits.md` and this tier stayed green.  The script
    # pipes each commit through that same hook rather than restating its rules,
    # so the check at commit time and the check here cannot disagree.
    step "scripts/check-commits.sh"
    sh scripts/check-commits.sh \
        || fail "a commit message breaks the rules in docs/fmts/commits.md"

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
    # the heap, and a gate that booted only x86_64 called that green, so p1 now
    # boots each machine that has an image, and riscv64 is added when it has
    # one rather than when someone remembers.
    if [ "$NO_BOOT" = "1" ]; then
        step "boot declined (VERIFY_NO_BOOT=1)"
        printf 'verify[%s]: boot declined (VERIFY_NO_BOOT=1), this run did not start an image\n' \
            "$VERIFY_TIER"
    else
        for machine in $BOOTABLE_MACHINES; do
            step "cargo xtask check --machine $machine"
            cargo run --offline --quiet -p xtask -- check --machine "$machine" \
                || fail "the $machine image did not print its required lines"
        done
    fi
}

run_p2() {
    run_p1

    # The architecture census: a `target_arch` gate outside `arch/` is a place a
    # fourth machine has to be taught, and nothing else in the build notices one.
    step "scripts/check-arch-fanout.sh"
    sh scripts/check-arch-fanout.sh || fail "an architecture gate outside arch/"

    # The dependency census: every crate may name only the crates below it, and
    # `scripts/layering.txt` is where the order is stated.  "No cycles" alone
    # would be the weaker rule: an acyclic graph can still put the filesystem
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

    # The other direction of the same question, and the one that had no answer:
    # a file that is **not** tracked and is ignored.  `git add -A` skips one
    # without a word, so a source file hidden by an ignore rule reaches neither
    # the index nor the commit — which is how `.mailmap` was written, added, and
    # absent from the commit whose message said it was added.
    step "scripts/check-ignored-files.sh"
    sh scripts/check-ignored-files.sh \
        || fail "an ignore rule hides a file that is not a build product"
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
