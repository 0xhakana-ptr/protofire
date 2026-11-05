#!/usr/bin/env sh
# File: scripts/check-repo-integrity.sh
# Purpose: Nothing ignored is tracked, and nothing tracked is a build product.
#
# ## The rule
#
# A `.gitignore` describes what a build writes, and what a build writes must not
# be committed.  The two halves of that statement fail differently:
#
#   * a product this tree committed once — `tools/__pycache__` was, before the
#     rule that ignores it existed — is a product a clone pays for and nobody
#     reads;
#   * a file that is tracked **and** matches an ignore rule is the worse state,
#     because git keeps tracking it and the rule silently stops meaning what its
#     author thought.  `git add -f` is how that happens, and a rule added later
#     over an already-tracked file is the other way.
#
# The first is asked by name, against the product extensions this build writes.
# The second is asked by git itself, and the answer has to be empty.
#
# ## Why a gate and not a `.gitignore` per directory
#
# The patterns that matter are extension and directory-name patterns — `*.log`,
# `*.o`, `*.d`, `__pycache__/` — and git applies those at every depth from the
# file that states them.  A copy in each crate would be fourteen copies of a rule
# that already fires, and each copy is a file someone has to keep in step.  What
# a second `.gitignore` buys is a rule scoped to one directory, and this tree has
# no artifact scoped to one directory: cargo writes one `target/` at the root.
#
# So the question "does the ignore set still describe the tree" is asked once,
# here, over the whole repository.
#
# ## What this does not check
#
# That the patterns are *complete*.  A build product nobody has written a rule
# for is invisible to the second check, because git has nothing to compare it
# against; the first check names the extensions this build actually writes, so it
# catches those even with no rule.  A product in an extension neither list names
# is caught by a reader looking at the diff, which is what
# `docs/fmts/commits.md` asks for and what no script can do.
#
# Usage:
#   sh scripts/check-repo-integrity.sh

set -eu

cd "$(dirname "$0")/.."

GIT="${GIT:-git}"

# Extensions and names a build of this tree writes.  Each is the output of a
# command the gates run, and the list is closed on purpose: a new entry is a new
# thing a build writes, which is a fact worth a line in a diff.
PRODUCTS='*.pyc
*.pyo
*.o
*.d
*.log
*.disk
*.img
*.iso
*.rs.bk
*rustc-ice-*.txt'

# Check one: tracked and ignored.
#
# `--ignored` lists ignored paths, `--cached` restricts that to the index, and
# `--exclude-standard` applies the whole ignore set a clone would have — the
# `.gitignore` chain plus `.git/info/exclude`.
tracked_but_ignored="$("$GIT" ls-files --ignored --cached --exclude-standard)" || exit 1
if [ -n "$tracked_but_ignored" ]; then
    printf 'check-repo-integrity: tracked and ignored:\n' >&2
    printf '%s\n' "$tracked_but_ignored" | sed 's/^/  /' >&2
    printf '\nA file here is tracked, so editing it changes the commit, and ignored,\n' >&2
    printf 'so a reader believes it is a build product.  Either the rule is too wide\n' >&2
    printf 'or the file should not be tracked: `git rm --cached <path>`, or narrow\n' >&2
    printf 'the rule.\n' >&2
    exit 1
fi

# Check two: a tracked product by extension, whatever the ignore set says.
#
# This is the check the `.gitignore` cannot make about itself: it names the
# products this build writes, so a `git add -f` of one is caught here even if a
# rule for it was never written.
tracked_products=""
for pattern in $PRODUCTS; do
    found="$("$GIT" ls-files -- ":(glob)**/$pattern" ":(glob)$pattern" 2>/dev/null | sort -u)"
    if [ -n "$found" ]; then
        tracked_products="$tracked_products$found
"
    fi
done
if [ -n "$tracked_products" ]; then
    printf 'check-repo-integrity: tracked build products:\n' >&2
    printf '%s\n' "$tracked_products" | sed '/^$/d; s/^/  /' >&2
    printf '\nEach of these is something a build writes.  Remove it with\n' >&2
    printf '`git rm --cached <path>`.  If it is a source file that happens to end\n' >&2
    printf 'this way, add a `!` rule for it to the root .gitignore and say why.\n' >&2
    exit 1
fi

printf 'check-repo-integrity: nothing ignored is tracked, no build product is tracked\n'
