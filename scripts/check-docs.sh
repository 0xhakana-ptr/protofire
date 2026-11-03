#!/usr/bin/env sh
# File: scripts/check-docs.sh
# Purpose: Fail when a document names a file the tree does not have.
#
# ## Why this is a gate and not a habit
#
# A document that cites a path is making a claim a reader will follow.  When the
# path moves and the sentence does not, the reader is sent to a file that is not
# there — and the document still reads as authoritative, which is what makes this
# class of drift expensive: nobody can tell a claim about the code from a claim
# about a tree that no longer exists.
#
# The previous tree learned this twice.  An audit of its `docs/` found twelve
# citations of files that were not there: four that had moved when a module was
# reorganised, and the rest that had never existed.  Then a crate split moved
# forty-four more, and a header rule caught those but only because it happened to
# look at the first line of every source file.
#
# ## What is checked
#
# The documents checked are every Markdown file at the root of the tree and
# every one under `docs/`, one level deep — `docs/` and its subdirectories,
# because a specification under `docs/fmts/` cites paths for the same reason a
# README does and a gate that skipped it would be checking the documents that
# cite least.  A crate's own `//!` header is not checked here: the compiler
# reads it, and a path in a doc comment is a citation a reader follows the same
# way — but the crate headers are also where a mechanism is stated in prose
# that names no files, and a gate over all of them would mostly be checking
# prose.
#
# 1. A backticked path with a separator (`docs/architecture.md`,
#    `scripts/layering.txt`, `bootloader/src/main.rs`) must exist.
# 2. A backticked bare filename (`check-layering.sh`, `service_tests.rs`) must
#    exist somewhere under the tree.  A document says `check-layering.sh` because
#    the directory it is in is prose; requiring the full path in every sentence
#    would make the prose worse and the check no stronger.
# 3. A relative Markdown link must resolve from the document that holds it.  This
#    one is exact, and it is the only check here that can be.
#
# What is not checked: prose, and a path written as a pattern (`src/...`,
# `{cell,profiler}`).  A pattern is not a claim about one file.

set -eu

cd "$(dirname "$0")/.."

work="$(mktemp -d)"
cleanup() {
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

failed=0

# Every backticked token that looks like a path, with the document and line it
# came from.
#
# The token set is "contains a dot-extension we care about" — a `.sh`, `.txt`,
# `.md`, `.rs`, `.toml`, `.ld`, `.S`.  That is deliberately narrow: a backticked
# `VecDeque` is not a path, and a check that guessed would refuse prose.
for document in README.md AGENTS.md LICENSES/README.md docs/*.md docs/fmts/*.md; do
    [ -f "$document" ] || continue
    grep -n -oE '`[A-Za-z0-9_./{}*<>-]+\.(sh|txt|md|rs|toml|ld|S)`' "$document" \
        | sed 's/`//g' \
        | while IFS=: read -r line path; do
            # A pattern is not a file.
            case "$path" in
                *"..."*|*"<"*|*">"*|*"{"*|*"}"*|*"*"*) continue ;;
            esac
            printf '%s\t%s\t%s\n' "$document" "$line" "$path"
        done
done >"$work/paths.txt"

while IFS="$(printf '\t')" read -r document line path; do
    case "$path" in
        */*)
            if [ ! -e "$path" ]; then
                printf '%s:%s: no such path `%s`\n' "$document" "$line" "$path" >&2
                failed=1
            fi
            ;;
        *)
            # A bare name: found anywhere under the tree.
            if ! find . -name "$path" -not -path './target/*' -not -path './.git/*' \
                -print -quit | grep -q .; then
                printf '%s:%s: no file named `%s`\n' "$document" "$line" "$path" >&2
                failed=1
            fi
            ;;
    esac
done <"$work/paths.txt"

# Relative Markdown links resolve from the document that holds them.
for document in README.md AGENTS.md LICENSES/README.md docs/*.md docs/fmts/*.md; do
    [ -f "$document" ] || continue
    directory="$(dirname "$document")"
    grep -oE '\]\([^)#]+' "$document" 2>/dev/null | sed 's/](//' | while read -r target; do
        case "$target" in
            http://*|https://*|mailto:*|/*) continue ;;
        esac
        if [ ! -e "$directory/$target" ]; then
            printf '%s: link `%s` does not resolve\n' "$document" "$target" >&2
            exit 1
        fi
    done || failed=1
done

if [ "$failed" != "0" ]; then
    exit 1
fi

citations="$(wc -l <"$work/paths.txt" | tr -d ' ')"
printf 'docs check passed: %s citation(s) resolve\n' "$citations"
