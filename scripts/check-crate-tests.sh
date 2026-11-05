#!/usr/bin/env sh
# File: scripts/check-crate-tests.sh
# Purpose: Every crate that has code has tests, and none of them disappear.
#
# ## The rule
#
# A crate with source and no tests is a crate nobody has run.  This tree's whole
# argument for the crate split is that a crate can be tested on its own, which is
# the reason it exists, so a member of the workspace with a hundred lines and
# zero assertions is the split not paying for itself.
#
# The gate does not demand a number.  A line count is not coverage and a test
# count is not correctness; what it refuses is the *empty* case and the
# *shrinking* one:
#
#   * a crate with more than `MIN_LINES` of source and no test at all fails,
#     unless it is on the exempt list with a reason;
#   * a crate whose test count falls below the recorded one fails, because a
#     deleted test is a defect that stopped being caught.
#
# Tests are deleted for honest reasons: one that duplicated another, one whose
# subject moved to a different crate.  Recording the number makes each deletion a
# change to this file, which is a sentence a reader can disagree with, instead of
# a diff nobody notices in a hundred-line move.
#
# `cargo test -p <name>` reports how many the harness ran, which is the only
# number that means anything: a `#[cfg(test)]` module in a crate that does not
# compile for the host reports zero, and that is exactly the state this gate
# found `arch_aarch64` and `arch_riscv64` in: their whole bodies behind a
# crate-level `cfg(target_arch)`, so their tests had never run once.
#
# Usage:
#   sh scripts/check-crate-tests.sh            # check against the baseline
#   sh scripts/check-crate-tests.sh --record   # rewrite the baseline

set -eu

cd "$(dirname "$0")/.."

BASELINE="${BASELINE:-scripts/crate-tests-baseline.txt}"
CARGO="${CARGO:-cargo}"

# Source lines below which a crate may have no tests.  A crate this small is a
# type definition or a constant, and a test of it would assert that the compiler
# works.
MIN_LINES="${MIN_LINES:-60}"

mode=check
case "${1:-}" in
    '') ;;
    --record) mode=record ;;
    -h|--help)
        sed -n '2,34p' "$0"
        exit 0
        ;;
    *)
        printf 'unsupported argument: %s\n' "$1" >&2
        exit 1
        ;;
esac

work="$(mktemp -d)"
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

"$CARGO" metadata --offline --no-deps --format-version 1 >"$work/meta.json" 2>"$work/meta.err" \
    || {
        printf 'cargo metadata failed:\n' >&2
        cat "$work/meta.err" >&2
        exit 1
    }

# One row per workspace member: `<name> <lines>`, where `lines` is the source the
# crate owns: the `.rs` files under its directory, minus the `target/` a build
# may have written there.
python3 - "$work/meta.json" >"$work/crates.txt" <<'PY'
import json
import os
import sys

with open(sys.argv[1]) as handle:
    metadata = json.load(handle)

root = metadata["workspace_root"]
for package in metadata["packages"]:
    manifest = package["manifest_path"]
    directory = os.path.dirname(manifest)
    lines = 0
    for base, directories, files in os.walk(directory):
        directories[:] = [d for d in directories if d not in ("target", ".git")]
        for name in files:
            if name.endswith(".rs"):
                with open(os.path.join(base, name), errors="replace") as source:
                    lines += source.read().count("\n") + 1
    relative = os.path.relpath(directory, root)
    # The root package's directory contains every member, so walking it counts
    # the whole tree.  Its own source is `src/` alone.
    if relative == ".":
        lines = 0
        for name in os.listdir(os.path.join(directory, "src")):
            if name.endswith(".rs"):
                with open(os.path.join(directory, "src", name), errors="replace") as source:
                    lines += source.read().count("\n") + 1
    print(f"{package['name']} {lines} {relative}")
PY
sort "$work/crates.txt" -o "$work/crates.txt"

# How many tests the harness runs for one crate, over the whole workspace's
# lockfile so a member is measured in the configuration it ships with.
tests_for() {
    "$CARGO" test --offline -p "$1" 2>/dev/null \
        | awk '/^test result:/ { for (i = 1; i <= NF; i++) if ($i == "passed;") { total += $(i - 1) } } END { print total + 0 }'
}

census() {
    while read -r name lines relative; do
        count="$(tests_for "$name")"
        printf '%s %s %s %s\n' "$name" "$lines" "$count" "$relative"
    done <"$work/crates.txt"
}

census >"$work/census.txt"

if [ "$mode" = "record" ]; then
    next="$work/baseline.new"
    # The header, with its blank lines squeezed to one: the original file has a
    # run of them, and a re-record that copied the run verbatim and then added
    # another would grow the header by a line every time the census was taken.
    grep -E '^[[:space:]]*(#|$)' "$BASELINE" 2>/dev/null \
        | awk 'BEGIN { blank = 0 } /^[[:space:]]*$/ { blank = 1; next } { if (blank) print ""; blank = 0; print }' \
        >"$next" || true
    printf '\n' >>"$next"
    # Keep each row's trailing note: it is the argument for the row, and a
    # re-record is a change in the tree, not a change of mind about why it is
    # exempt.
    awk '
        NR == FNR {
            note = ""
            for (i = 4; i <= NF; i++) note = note " " $i
            if (note != "") notes[$1] = note
            next
        }
        {
            if ($1 in notes) printf "%-18s %6s %4s%s\n", $1, $2, $3, notes[$1]
            else printf "%-18s %6s %4s\n", $1, $2, $3
        }
    ' "$BASELINE" "$work/census.txt" >>"$next"
    mv "$next" "$BASELINE"
    printf 'recorded %s crate(s) in %s\n' "$(wc -l <"$work/census.txt" | tr -d ' ')" "$BASELINE"
    exit 0
fi

failed=0

# Baseline rows, comments stripped: `<name> <lines> <tests>`.
# The note after `#` is read before the comment is stripped: it is where an
# exemption lives, and stripping first would make every row look unexempt.
awk '
    {
        note = $0
        sub(/^[^#]*#?/, "", note)
        gsub(/^[[:space:]]+/, "", note)
        line = $0
        sub(/#.*/, "", line)
        if (line ~ /^[[:space:]]*$/) next
        n = split(line, field, /[[:space:]]+/)
        if (n < 3) { printf "malformed baseline line: %s\n", $0 > "/dev/stderr"; bad = 1; next }
        exempt = (note ~ /^exempt/) ? "exempt" : ""
        printf "%s %s %s %s\n", field[1], field[2], field[3], exempt
    }
    END { exit bad }
' "$BASELINE" >"$work/baseline.txt" || exit 1

while read -r name baseline_lines baseline_tests baseline_exempt; do
    count="$(awk -v n="$name" '$1 == n { print $3 }' "$work/census.txt")"
    lines="$(awk -v n="$name" '$1 == n { print $2 }' "$work/census.txt")"

    if [ -z "$count" ]; then
        printf 'crate-tests: `%s` is in the baseline and not in the workspace\n' "$name" >&2
        printf '  the row describes a crate that has moved or been removed\n' >&2
        failed=1
        continue
    fi

    if [ "$count" -lt "$baseline_tests" ]; then
        printf 'crate-tests: `%s` fell from %s test(s) to %s\n' \
            "$name" "$baseline_tests" "$count" >&2
        printf '  a deleted test is a defect that stopped being caught; if the\n' >&2
        printf '  test moved, say so and re-record\n' >&2
        failed=1
    fi

    # The empty case, for a crate big enough to be worth one.
    #
    # An exempt row is a crate whose source has no testable behaviour and cannot
    # have any: the bootloader is entry symbols, a panic handler and an assembly
    # stub, and a test of those is a boot.  The reason is on the row, so a reader
    # can disagree with it.
    exempt="$baseline_exempt"
    if [ "$count" -eq 0 ] && [ "$lines" -ge "$MIN_LINES" ] && [ "$exempt" != "exempt" ]; then
        printf 'crate-tests: `%s` is %s lines with no test\n' "$name" "$lines" >&2
        printf '  a crate the workspace builds and nothing runs is the crate\n' >&2
        printf '  split not paying for itself; add a test or argue the row\n' >&2
        failed=1
    fi
done <"$work/baseline.txt"

# And every crate the workspace has that the baseline does not know about.
while read -r name lines count relative; do
    if ! awk -v n="$name" '$1 == n { found = 1 } END { exit !found }' "$work/baseline.txt"; then
        printf 'crate-tests: `%s` (%s, %s lines, %s test(s)) is not recorded\n' \
            "$name" "$relative" "$lines" "$count" >&2
        printf '  record it deliberately: sh scripts/check-crate-tests.sh --record\n' >&2
        failed=1
    fi
done <"$work/census.txt"

if [ "$failed" != "0" ]; then
    exit 1
fi

total_tests="$(awk '{ total += $3 } END { print total + 0 }' "$work/census.txt")"
printf 'crate-tests check passed: %s crate(s), %s test(s)\n' \
    "$(wc -l <"$work/census.txt" | tr -d ' ')" "$total_tests"
