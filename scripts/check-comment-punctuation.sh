#!/usr/bin/env sh
# File: scripts/check-comment-punctuation.sh
# Purpose: Refuse the punctuation `docs/fmts/comments.md` names as not used.
#
# ## The rule this enforces
#
# §4 of that document: "Punctuation is the plain set: comma, colon,
# parenthesis.  The em dash is not used."  §6: a section label is `// Label`
# and there are no rule lines of dashes, equals signs or box-drawing
# characters.
#
# ## Why a gate and not a rule
#
# The rule was prose and the tree held 1,600 lines that broke it, including
# 212 added in one session by a reader who had the document open.  A rule a
# contributor has to remember lapses exactly when the contributor is busy,
# which is the case `AGENTS.md`'s "a rule that can be a gate belongs in a gate"
# describes.  The prose stays, because it says why; this refuses.
#
# ## Three checks, and what each is for
#
# 1. **The em dash.**  §4's.  It is refused in `.rs` and `.md` both: a
#    document is read by the same reader, and a rule governing only comments
#    would leave the prose about them exempt from it.
#
# 2. **A rule line.**  §6's.  The form is a comment or a Markdown heading
#    whose text is mostly box-drawing characters: `// ── Label ─────────`.
#    It is matched as *four or more* box-drawing characters in a row, which a
#    rule is and a diagram is not: a tree uses `│`, `├` and `└` singly.
#
#    Two shapes have to be excluded, and both are diagrams rather than
#    decoration.  A fenced block is a diagram by construction: an ASCII or
#    Unicode sketch of a queue, a layout or a sequence, where the lines
#    carry arrows and boxes rather than dividing sections.  A `.md` line
#    that begins with a tree character is the same thing outside a fence.
#    The exclusion is stated as "inside a fence" and "starts with a tree
#    character" rather than as a list of files, so a new diagram is allowed
#    and a new rule line is not.
#
# 3. **A run of `=` or `-` used as a rule** in a comment.  Same section, and
#    the same shape: three or more, alone on the line after the comment
#    marker.  It is matched at the start of a comment because that is where a
#    rule goes; a sentence containing a hyphen is not one.
#
# ## Output
#
# One line per offence naming the file and the line, so a reader can jump to
# it, then a count.  The exit status is what a gate reads.

set -eu

cd "$(dirname "$0")/.."

offences=0
files=0

report() {
    printf '%s:%s: %s\n' "$1" "$2" "$3" >&2
    offences=$((offences + 1))
}

for file in $(git ls-files '*.rs' '*.md'); do
    files=$((files + 1))
    case "$file" in
        # The style document quotes the characters it forbids.  A gate that
        # refused its own quotation could not describe what it refuses, and
        # this is the one exemption, named rather than pattern-matched so a
        # second file cannot join it quietly.
        docs/fmts/comments.md) continue ;;
    esac

    # 1. The em dash, anywhere.
    while IFS= read -r hit; do
        [ -n "$hit" ] || continue
        report "$file" "${hit%%:*}" "em dash (use a comma or a colon)"
    done <<EOF
$(LC_ALL=C grep -n -o '—' "$file" 2>/dev/null || true)
EOF

    # 2. A rule of box-drawing characters: four or more in a row, outside a
    #    fenced block and not on a line that starts with a tree character.
    #    `awk` walks the file so the fence state is known at each line.
    while IFS= read -r hit; do
        [ -n "$hit" ] || continue
        report "$file" "${hit%%:*}" "rule line of box-drawing characters"
    done <<EOF
$(LC_ALL=C awk '
    /^[[:space:]]*```/ { fenced = !fenced; next }
    fenced { next }
    /^[[:space:]]*(│|├|└)/ { next }
    /(─|═|━){4,}/ { printf "%d:%s\n", NR, $0 }
' "$file" 2>/dev/null || true)
EOF

    # 3. A rule of `=` or `-` in a comment: three or more, at the start.
    while IFS= read -r hit; do
        [ -n "$hit" ] || continue
        report "$file" "${hit%%:*}" "rule line of equals signs or dashes"
    done <<EOF
$(LC_ALL=C grep -n -E '^[[:space:]]*(//|//!|#)[[:space:]]*(=|-){3,}[[:space:]]*$' "$file" 2>/dev/null || true)
EOF
done

if [ "$offences" -ne 0 ]; then
    printf 'comment-punctuation check FAILED: %d offence(s) in %d file(s)\n' \
        "$offences" "$files" >&2
    exit 1
fi

printf 'comment-punctuation check passed: %d file(s), no em dash and no rule lines\n' \
    "$files"
