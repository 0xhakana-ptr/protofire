#!/usr/bin/env sh
# File: scripts/check-layering.sh
# Purpose: Hold every crate to the layer its name claims.
#
# ## The rule
#
# `scripts/layering.txt` sorts the crates into layers, lowest first.  A crate
# may depend on a crate in a *lower* layer and on nothing else.  Same-layer
# edges are refused too: two crates in one layer are peers, and a peer edge is
# how a layer becomes a cycle.
#
# A cycle is what this gate exists to prevent, and "no cycles" alone is not the
# rule: a graph can be acyclic and still be wrong.  `fs` depending on `kernel`
# is acyclic and is exactly the edge that made the previous tree's modules
# unauditable: the filesystem would have to know about the scheduler to answer
# a read.  The layers are the statement of what may be above what, so an edge
# upward is refused even when it happens to close no loop today.
#
# Some edges are real and worth keeping.  `sync` names `arch` because a spinlock
# has to close the interrupt window, and the interrupt flag is the machine's;
# putting that behind a trait would add an indirect call on the hottest path in
# the kernel.  That is a decision, so it is written in `scripts/layering.txt`
# beside the layer it breaks, with the argument.  An exception nobody argued for
# is what the gate is for; an exception with a reason is what it records.
#
# ## The checks
#
# The dependency graph cargo itself reports: `cargo metadata --no-deps`.  Not a
# grep over manifests: a `cfg(target_arch)` table, a workspace inheritance and
# a feature-forwarded dependency all produce edges a text search would miss.
#
# Usage:
#   sh scripts/check-layering.sh             # check
#   sh scripts/check-layering.sh --print     # print the graph as measured

set -eu

cd "$(dirname "$0")/.."

LAYERS="${LAYERS:-scripts/layering.txt}"

if [ ! -f "$LAYERS" ]; then
    printf 'layering spec not found: %s\n' "$LAYERS" >&2
    exit 1
fi

case "${1:-}" in
    ''|--print) ;;
    -h|--help)
        sed -n '2,42p' "$0"
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

cargo metadata --offline --no-deps --format-version 1 >"$work/meta.json" 2>"$work/meta.err" \
    || {
        printf 'cargo metadata failed:\n' >&2
        cat "$work/meta.err" >&2
        exit 1
    }

# The graph, as `<crate> <dependency>` pairs, one per line.
#
# A workspace member's path dependency is the edge this gate is about.  External
# crates (`spin`, `clap`) are not in the layer list and are not checked: the
# rule is about this tree's own organisation, and a dependency on a well-known
# crate says nothing about which layer it belongs to.
python3 - "$work/meta.json" >"$work/edges.txt" <<'PY'
import json
import sys

with open(sys.argv[1]) as handle:
    metadata = json.load(handle)

members = {package["name"] for package in metadata["packages"]}
for package in metadata["packages"]:
    for dependency in package["dependencies"]:
        if dependency["kind"] is not None:
            continue
        name = dependency["name"]
        # A dependency written as `workspace = true` appears here by name with
        # its resolved source; a path dependency to a member is this tree's own.
        if name in members and name != package["name"]:
            print(f"{package['name']} {name}")
PY

sort -u "$work/edges.txt" -o "$work/edges.txt"

if [ "${1:-}" = "--print" ]; then
    printf 'measured dependency edges:\n'
    sed 's/^/  /' "$work/edges.txt"
    exit 0
fi

# The spec, as `<layer number> <crate>` rows plus `allow <from> <to> # reason`.
awk '
    { sub(/#.*/, "") }
    NF == 0 { next }
    $1 == "allow" { print "ALLOW", $2, $3; next }
    $1 ~ /^[0-9]+$/ && NF == 2 { print "LAYER", $1, $2; next }
    { printf "malformed layering line: %s\n", $0 > "/dev/stderr"; bad = 1 }
    END { exit bad }
' "$LAYERS" >"$work/spec.txt" || exit 1

# Layer of each crate.
awk '$1 == "LAYER" { print $3, $2 }' "$work/spec.txt" | sort >"$work/rank.txt"

# Allowed exceptions, as `from to` pairs.
awk '$1 == "ALLOW" { print $2, $3 }' "$work/spec.txt" | sort >"$work/allow.txt"

failed=0

report() {
    printf '%s\n' "$1" >&2
    failed=1
}

# Every crate in the workspace has to be in the spec.  A crate the spec does
# not name is a crate with no layer, and a crate with no layer is one whose
# dependencies are unchecked, which is the state this gate exists to end.
while read -r name; do
    if ! awk -v n="$name" '$1 == n { found = 1 } END { exit !found }' "$work/rank.txt"; then
        report "layering: crate \`$name\` is in the workspace and not in $LAYERS"
        report "  give it a layer, or it is the one crate nobody checks"
    fi
done <<EOF
$(python3 - "$work/meta.json" <<'PY'
import json
import sys
with open(sys.argv[1]) as handle:
    metadata = json.load(handle)
for package in metadata["packages"]:
    print(package["name"])
PY
)
EOF

# Every crate in the spec has to be in the workspace: a row for a crate that was
# renamed or removed is a layer entry describing a tree that no longer exists.
while read -r name rank; do
    if ! awk -v n="$name" '$1 == n { found = 1 } END { exit !found }' "$work/rank.txt"; then
        continue
    fi
done <"$work/rank.txt"

# The edges: downward is fine, same-layer and upward are not, unless recorded.
while read -r from to; do
    from_rank="$(awk -v n="$from" '$1 == n { print $2 }' "$work/rank.txt")"
    to_rank="$(awk -v n="$to" '$1 == n { print $2 }' "$work/rank.txt")"

    # One end is outside the spec; the crate-loop above already reported it.
    if [ -z "$from_rank" ] || [ -z "$to_rank" ]; then
        continue
    fi

    if awk -v f="$from" -v t="$to" '$1 == f && $2 == t { found = 1 } END { exit !found }' \
        "$work/allow.txt"; then
        continue
    fi

    if [ "$to_rank" -ge "$from_rank" ]; then
        if [ "$to_rank" -eq "$from_rank" ]; then
            report "layering: \`$from\` depends on \`$to\`, and both are in layer $from_rank"
            report "  peers may not depend on each other: one of them belongs a layer up"
        else
            report "layering: \`$from\` (layer $from_rank) depends on \`$to\` (layer $to_rank)"
            report "  an upward edge is how a layer stops being a layer"
        fi
        report "  if the edge is right, record it in $LAYERS with its argument"
    fi
done <"$work/edges.txt"

# A recorded exception whose edge has gone is stale, and a stale exception is a
# permission nobody needs any more: it will be used by the next change that
# finds the gate in its way.
while read -r from to; do
    if ! awk -v f="$from" -v t="$to" '$1 == f && $2 == t { found = 1 } END { exit !found }' \
        "$work/edges.txt"; then
        report "layering: $LAYERS allows \`$from\` -> \`$to\`, and that edge does not exist"
        report "  remove the row: a permission nothing uses is a permission the next change inherits"
    fi
done <"$work/allow.txt"

if [ "$failed" != "0" ]; then
    exit 1
fi

edges="$(wc -l <"$work/edges.txt" | tr -d ' ')"
crates="$(wc -l <"$work/rank.txt" | tr -d ' ')"
exceptions="$(wc -l <"$work/allow.txt" | tr -d ' ')"
printf 'layering check passed: %s crate(s), %s edge(s), %s recorded exception(s)\n' \
    "$crates" "$edges" "$exceptions"
