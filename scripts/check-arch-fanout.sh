#!/usr/bin/env sh
# File: scripts/check-arch-fanout.sh
# Purpose: Count the architecture decisions that live outside `arch/`.
#
# ## The promise this holds
#
# The whole point of the `arch` split is that a machine's differences are the
# architecture crate's, and nothing above it learns which machine it is running
# on.  `arch` names its implementation from a `cfg(target_arch)` table in its own
# manifest, so a target that no crate implements fails to build rather than
# picking one silently, and that only stays true while nothing outside `arch/`
# spells a `target_arch` gate of its own.
#
# A `#[cfg(target_arch = "x86_64")]` in the kernel is not a style problem.  It is
# a place a fourth architecture has to be taught, and it is invisible to every
# other gate: the build succeeds, the tests pass, and the new machine is wrong
# in a way only its own boot would show.
#
# Every `target_arch = "..."` in a `.rs` file outside `arch/`, with line
# comments stripped first: prose that mentions a gate is not a gate.  The
# count is per file, and the baseline records each file with a reason, so a new
# one has to be argued for rather than merely accepted.
#
# The number is expected to fall to zero and the honest way there is one file at
# a time: move the question into `arch`, or say why it cannot be moved.  A row
# that grows fails with its own recorded reason printed, because a reason that
# covered the old count may not cover the new one.
#
# Usage:
#   sh scripts/check-arch-fanout.sh             # check against the baseline
#   sh scripts/check-arch-fanout.sh --record    # rewrite the baseline

set -eu

cd "$(dirname "$0")/.."

BASELINE="${BASELINE:-scripts/arch-fanout-baseline.txt}"

mode=check
case "${1:-}" in
    '') ;;
    --record) mode=record ;;
    -h|--help)
        sed -n '2,36p' "$0"
        exit 0
        ;;
    *)
        printf 'unsupported argument: %s\n' "$1" >&2
        exit 1
        ;;
esac

if [ ! -f "$BASELINE" ]; then
    printf 'arch-fanout baseline not found: %s\n' "$BASELINE" >&2
    printf 'run with --record to create it\n' >&2
    exit 1
fi

work="$(mktemp -d)"
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

# Every `.rs` outside `arch/` that names an architecture, and how many times.
#
# `arch/` is the one place the names are welcome: its crates *are* the
# architectures, and the routing table in `arch/src/lib.rs` is the gate that
# chooses between them.  Everything else is a census subject.
census() {
    find . -name '*.rs' \
        -not -path './target/*' \
        -not -path './arch/*' \
        -not -path './.git/*' \
        `# vendor/ is cargo's source, not this tree's: a crates.io package's` \
        `# own target_arch gates are a fact about that package, and this` \
        `# census is about the crates this tree writes.` \
        -not -path './vendor/*' \
        | sort | while read -r file; do
        rel="${file#./}"
        count="$(awk '
            { line = $0; sub(/\/\/.*/, "", line) }
            {
                rest = line
                while (match(rest, /target_arch *= *"(x86_64|aarch64|riscv64)"/)) {
                    n++
                    rest = substr(rest, RSTART + RLENGTH)
                }
            }
            END { print n + 0 }
        ' "$file")"
        if [ "$count" -gt 0 ]; then
            printf '%s %s\n' "$rel" "$count"
        fi
    done
}

census >"$work/census.txt"

files="$(wc -l <"$work/census.txt" | tr -d ' ')"
occurrences="$(awk '{ total += $2 } END { print total + 0 }' "$work/census.txt")"

# Baseline rows as `<path>\t<count>\t<reason>`; the reason is the text after
# `#`, and may be empty.  Read before either mode runs, because `--record`
# keeps the reasons it finds.
rows_from_baseline() {
    awk '
        {
            line = $0
            reason = ""
            hash = index(line, "#")
            if (hash > 0) {
                reason = substr(line, hash + 1)
                line = substr(line, 1, hash - 1)
            }
            path = ""; count = ""
            n = split(line, field, /[[:space:]]+/)
            for (i = 1; i <= n; i++) {
                if (field[i] == "") continue
                if (path == "") path = field[i]
                else if (count == "") count = field[i]
            }
            if (path == "" || count == "") next
            gsub(/^[[:space:]]+/, "", reason)
            gsub(/[[:space:]]+$/, "", reason)
            printf "%s\t%s\t%s\n", path, count, reason
        }
    ' "$BASELINE"
}

rows_from_baseline >"$work/baseline.tsv"

if [ "$mode" = "record" ]; then
    next_baseline="$work/baseline.new"
    # Keep the prose header and drop the totals line a previous record wrote:
    # there is exactly one, it is appended below, and a record has to be
    # idempotent.
    awk '
        /^# [0-9]+ files?, [0-9]+ occurrences? outside arch\// { next }
        /^#/ { print; next }
        { exit }
    ' "$BASELINE" >"$next_baseline"
    printf '\n# %s file(s), %s occurrence(s) outside arch/\n\n' \
        "$files" "$occurrences" >>"$next_baseline"
    # Keep each row's reason: it is the argument for the row, and a re-record is
    # a change in the tree, not a change of mind about why the row exists.
    awk -v reasons="$work/baseline.tsv" '
        BEGIN {
            while ((getline row < reasons) > 0) {
                split(row, field, "\t")
                reason[field[1]] = field[3]
            }
        }
        {
            if (($1 in reason) && reason[$1] != "") {
                printf "%-52s %s  # %s\n", $1, $2, reason[$1]
            } else {
                printf "%-52s %s\n", $1, $2
            }
        }
    ' "$work/census.txt" >>"$next_baseline"
    mv "$next_baseline" "$BASELINE"
    printf 'recorded %s file(s), %s occurrence(s) in %s\n' \
        "$files" "$occurrences" "$BASELINE"
    unreasoned="$(rows_from_baseline | awk -F'\t' '$3 == "" { n++ } END { print n + 0 }')"
    if [ "$unreasoned" != "0" ]; then
        printf '%s row(s) have no reason yet: the check fails until each says\n' \
            "$unreasoned" >&2
        printf 'whether it is a fact about the machine or a gap to close.\n' >&2
    fi
    exit 0
fi

failed=0

# Every file in the baseline: grown, shrunk, unchanged, or unexplained.
while IFS="$(printf '\t')" read -r path baseline_count reason; do
    case "$baseline_count" in
        *[!0-9]*)
            printf 'baseline count is not a number: %s %s\n' \
                "$path" "$baseline_count" >&2
            failed=1
            continue
            ;;
    esac

    count="$(awk -v p="$path" '$1 == p { print $2 }' "$work/census.txt")"
    count="${count:-0}"

    if [ "$count" -gt "$baseline_count" ]; then
        printf 'arch fanout: %s grew from %s to %s\n' \
            "$path" "$baseline_count" "$count" >&2
        printf '  a gate outside arch/ is one more place a new architecture\n' >&2
        printf '  has to be taught: ask the arch layer instead\n' >&2
        if [ -n "$reason" ]; then
            printf '  this row is recorded as: %s\n' "$reason" >&2
            printf '  the count grew anyway, so the reason does not cover it\n' >&2
        fi
        failed=1
    elif [ "$count" -lt "$baseline_count" ]; then
        printf 'arch fanout: %s shrank from %s to %s\n' \
            "$path" "$baseline_count" "$count" >&2
        printf '  good, but the census has to follow in the same change:\n' >&2
        printf '  sh scripts/check-arch-fanout.sh --record\n' >&2
        failed=1
    elif [ -z "$reason" ]; then
        printf 'arch fanout: %s names an architecture and does not say why\n' \
            "$path" >&2
        printf '  every row is one of two things: a fact about the machine,\n' >&2
        printf '  or a gap to close.  Move the question behind the arch layer,\n' >&2
        printf '  or write the fact down after the count and re-record.\n' >&2
        failed=1
    fi
done <"$work/baseline.tsv"

# And every file the census found that the baseline does not know about.
while read -r path count; do
    if ! awk -F'\t' -v p="$path" '$1 == p { found = 1 } END { exit !found }' \
        "$work/baseline.tsv"; then
        printf 'arch fanout: new gate in %s (%s)\n' "$path" "$count" >&2
        printf '  ask the arch layer instead, or record it with a reason that\n' >&2
        printf '  says why it is a fact about the machine\n' >&2
        failed=1
    fi
done <"$work/census.txt"

if [ "$failed" != "0" ]; then
    exit 1
fi

printf 'arch-fanout check passed: %s file(s), %s occurrence(s), each with a reason\n' \
    "$files" "$occurrences"
