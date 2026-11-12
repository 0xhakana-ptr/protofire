#!/usr/bin/env sh
# File: scripts/check-ignored-files.sh
# Purpose: Refuse a source file that an ignore rule hides.
#
# ## The defect this exists for
#
# `.gitignore` begins with `.*`, which ignores every dot-file, and then names the
# ones to keep with `!` rules.  That is a good shape — a dot-file is a tool's
# configuration far more often than it is source — and it fails in one direction:
# a dot-file that **should** be in the tree and is not named by a `!` rule is
# ignored, and `git add -A` skips it without a word.
#
# Measured: `.mailmap` was written, `git add -A` was run, `git status` was clean,
# and the file was not in the commit.  The commit message said it was.  Nothing
# in the gate could tell, because every check asked about files git already
# knows and this one was not one of them.
#
# `git ls-files --ignored --cached` does not catch it either — that asks about
# files that are **tracked** and ignored, which is the opposite state.
#
# ## What is asked
#
# Every ignored path under the repository, tracked or not, and for each: is it
# something a build writes, or something an editor or the OS writes?  If it is
# neither, it is a file someone wrote on purpose and the ignore set is hiding
# it.  The answer has to be empty.
#
# The two lists below are the whole of what may be ignored.  A new entry is a
# new thing the ignore set is allowed to hide, which is a fact worth a line in a
# diff — and the failure says which rule to reach for instead.
#
# Usage:
#   sh scripts/check-ignored-files.sh

set -eu

cd "$(dirname "$0")/.."

GIT="${GIT:-git}"

# Build products: what a command in this tree writes.  The same spirit as
# `check-repo-integrity.sh`'s list, and overlapping on purpose — that script asks
# whether a product is *tracked*, this one whether a product is the only thing an
# ignore rule is hiding.
PRODUCT_PATTERNS='*.disk *.log *.img *.iso *.o *.d *.pyc *.pyo *.rs.bk
*rustc-ice-*.txt *.swp *.swo *~'

# Editor and operating-system droppings.  These are never source, on any
# machine this tree is edited on.
DROPPING_PATTERNS='.DS_Store Thumbs.db desktop.ini .directory *\#*#'

# Directories whose whole contents are a build's output.
PRODUCT_DIRECTORIES='target target-elf __pycache__'

matches() {
    # $1 is a path, $2 a whitespace-separated list of shell globs.
    path="$1"
    base=$(basename "$path")
    for pattern in $2; do
        case $base in
            $pattern) return 0 ;;
        esac
    done
    return 1
}

in_product_directory() {
    path="$1"
    for directory in $PRODUCT_DIRECTORIES; do
        case $path in
            "$directory"|"$directory"/*|*/"$directory"/*)
                return 0
                ;;
        esac
    done
    return 1
}

# Enumerate every ignored path.  `--others` is the untracked half that
# `--cached` misses, and the combination is what catches a file that was never
# added; `--directory` would collapse a whole ignored tree into one name, so it
# is not used.
ignored=$("$GIT" ls-files --others --ignored --exclude-standard --directory \
    | sed 's:/$::')

suspect=""
for path in $ignored; do
    [ -e "$path" ] || continue
    if in_product_directory "$path"; then
        continue
    fi
    if matches "$path" "$PRODUCT_PATTERNS"; then
        continue
    fi
    if matches "$path" "$DROPPING_PATTERNS"; then
        continue
    fi
    # An empty file hides nothing worth having: a placeholder that a tool
    # created is not source, and reporting it would make the check noisy enough
    # that a reader stops reading it.
    if [ -f "$path" ] && [ ! -s "$path" ]; then
        continue
    fi
    suspect="$suspect$path
"
done

if [ -n "$suspect" ]; then
    printf 'check-ignored-files: these are ignored and are not build products:\n' >&2
    printf '%s\n' "$suspect" | sed '/^$/d; s/^/  /' >&2
    printf '\nAn ignore rule is hiding a file someone wrote on purpose.  Two ways\n' >&2
    printf 'out, and they are not the same:\n' >&2
    printf '\n  * the file belongs in the tree — name it with a `!` rule beside the\n' >&2
    printf '    other `!` rules in the root .gitignore, and say why it is kept;\n' >&2
    printf '  * the file does not belong in the tree — delete it, and if a tool\n' >&2
    printf '    writes it, add a rule naming that tool.\n' >&2
    printf '\nA file that is ignored is invisible to `git add -A`, which is how one\n' >&2
    printf 'reached a commit message without reaching a commit.\n' >&2
    exit 1
fi

printf 'check-ignored-files: every ignored path is a build product or a tool'"'"'s own\n'
