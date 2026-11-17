# Commit Message Specification

> **Status:** normative.
> **Applies to:** every commit you push, and every commit in a pull request.

A commit message is the only part of a change that outlives every refactor of
the code it describes. The diff shows *what* changed and can be regenerated at
any time; the message records *why*, and it is the one artifact that cannot be
reconstructed afterwards. Rewriting it means rewriting published history, which
is why the rules here are worth getting right before the commit, not in review.

Commits are also unusual among the conventions in this directory in that they
are **fully machine-checked**, in two places.  [`scripts/hooks/commit-msg`](../../scripts/hooks/commit-msg)
runs on every `git commit`, and it is installed once:

```sh
ln -s ../../scripts/hooks/commit-msg .git/hooks/commit-msg
```

[`scripts/check-commits.sh`](../../scripts/check-commits.sh) runs the same hook
over a range, and the gate runs it at `p0`, so a clone that never installed the
hook still fails a run when a message breaks a rule.  Installing it is worth
doing anyway: the check is cheaper at `git commit` than in a run that has
already built the workspace.

This document is the exact semantics of that hook, the places where it is easy
to trip over, and the parts of the convention it cannot see at all.

[`CONTRIBUTING.md`](../../CONTRIBUTING.md) carries the short form.  Read that
first; read this when a commit is rejected, when a reviewer asks for a trailer
you have not written before, or when you want to know whether a rule is
enforced or merely expected.

---

## 1. The subject line

```
<type>: <Imperative summary>
```

One line. The canonical shape is the type prefix, a colon, a space, and then a
summary of the change written as a command.

**Example:**

```
fix: Drop the extra ELR advance in aarch64 svc dispatch
```

The two halves of that summary, **imperative mood** and **capitalised first
word**, are both required, and together they produce a specific form that is
not the same as either habit people arrive with.  `fix: Drop the extra ELR
advance …` is correct: imperative and capitalised.  Each of these is wrong on
the grounds named: `fix: Dropped the extra ELR advance …` (past tense),
`fix: drop the extra ELR advance …` (not capitalised), `fix: Drops the extra ELR
advance …` (third person), and `fix: Fixing the ELR advance …` (gerund).

Read the subject as the completion of the sentence *"This commit will…"*. It
will *drop* the ELR advance; it did not *drop* it, and it is not *dropping* it.

This is the most common error in this repository's own history: a subject that
starts lowercase, or one that uses the capitalised past tense, are two
different ways of missing the same rule. The rule is not retroactive (published
history stays as it is), but it applies to every new commit.

Only the last two columns of the table are machine-checked; see §5.

### Subject rules

The hook enforces four of these: at most 72 characters (for ASCII subjects
only), no trailing period, no leading or trailing whitespace, and not a bare
generic word.  Review enforces the other three: a `<type>:` prefix (see §2),
imperative mood, and a capitalised first word.  `Merge …` and `Revert …` are
exempt from all seven.

---

## 2. Type prefixes

Every commit carries a type. This is a rule, not a preference: the history that
predates the hook stays as it is, but every commit the hook sees has to comply,
and a specification that described reality more loosely than the code would be
the wrong way round.

**`feat:`** is new user-visible behaviour or capability.  **`fix:`** is a defect
fix, a change that makes something broken work.  **`refactor:`** is
restructuring with no intended change in behaviour.  **`chore:`** is build,
tooling, dependencies, housekeeping, no behaviour change.  **`docs:`** is
documentation only.  **`test:`** is tests only.  **`style:`** is formatting and
whitespace only, no semantic change.

**Choose by what the change does, not by which file it touches.** A new test
that also fixes the bug it was written for is a `fix:`; a `Cargo.toml` edit that
changes compiled behaviour is not a `chore:`.

### Scope (optional)

A parenthesised scope narrows the area:

```
fix(ata): Drop the PIO timeout to the controller's minimum
docs(fmts): Describe the trailer exemption in the body-wrap check
```

Use the module or subsystem name, the same vocabulary as
the crate the change is in. Scope is permitted but not required, and the
history uses it where the change is one part of a crate, `fix(scripts)`,
`refactor(kernel)`, `feat(x86_64)`, rather than everywhere; introduce it
deliberately rather than by habit.

### Release markers

The one exception to the required prefix is a release marker, which names the
version instead of a type:

```
Protofire 0.3.0
Protofire 0.1.1: Reuse the majority of the former unused constants
```

A release marker still obeys the length and trailing-period rules. The second
example above does not, it is 104 characters and ends in a period, and it is
one of the four commits in this history the hook rejects. Do not copy it.

---

## 3. The body

After the subject, a blank line, then prose.

- **Say why.** The diff already carries the *what* in more detail than prose
  can. What the reader cannot recover is the problem you were solving, the
  alternative you rejected, and the constraint that forced this shape.
- **Do not restate the diff** as a list of files, and do not narrate the
  obvious. Mention a file only where its involvement is not what a reader would
  expect.
- **Wrap at 72 characters.** `git log` indents the body by four columns, so 72
  is what fits an 80-column terminal.
- **Reference the issue** where one exists: `Fixes #123`.
- **One logical change per commit.** If the body is growing past a few lines,
  that is usually a signal that the commit is doing two things.

A body is optional in the sense that the hook does not require one. It is not
optional in the sense that matters: a subject alone is enough only when the
reason is genuinely self-evident, which is rarer than it feels at the time.

---

## 4. What the hook checks, exactly

`scripts/hooks/commit-msg` is a short `sh` script and is worth reading in full.
The order below is the order it executes; it reports the **first** failure and
exits, so a message with two problems needs two attempts to fix.

Before any check runs, every line whose first non-whitespace character is `#` is
**deleted** from the message (this strips the comment block `git commit` puts in
the editor template).

The hook checks, in order:

1. A subject line exists, otherwise `empty subject line`.
2. No leading or trailing whitespace on the subject, otherwise `subject must
   not have leading/trailing whitespace`.
3. A `Merge …` or `Revert …` subject exits **0 here**, skipping every check
   below.
4. The subject does not end in `.`, otherwise `subject must not end with a
   period`.
5. The subject is not a bare generic word, otherwise `subject '<word>' carries
   no information`.
6. The subject is pure ASCII, otherwise `subject must be ASCII`.
7. The subject is at most 72 **bytes**, otherwise `subject too long (N > 72
   chars)`.
8. Every body line is pure ASCII unless it is trailer-shaped, otherwise `body
   has non-ASCII prose`.
9. Every body line is at most 72 characters, otherwise `body has lines over 72
   chars`.
10. `Signed-off-by:` appears somewhere in the message, otherwise `missing
    Signed-off-by trailer`.

### The traps

- **A body line starting with `#` is silently removed, not rejected.** The
  stripping in step 0 is meant for the editor template, but it cannot tell a
  template comment from your prose. `#123 is the root cause` disappears from the
  commit. Write `Fixes #123` or `Issue #123` instead.
- **`Merge` and `Revert` skip everything, including the signature check.** These
  subjects are generated by git and are exempt by design. The exemption covers
  the whole hook, so a `Revert …` commit is not required to be signed off.
- **A non-ASCII subject is refused before its length is measured.** Step 6 is a
  `LC_ALL=C` test for any byte outside `0x20`–`0x7E`. The waiver in step 7 that
  used to accompany it is now unreachable for a subject, and remains only in
  the hook's code for a message that never reaches it. §7 says why.
- **The generic-word check is a fixed literal list**, matched against the whole
  subject:
  `update|Update|fix|Fix|fixup|cleanup|Cleanup|typo|wip|WIP|Wip`. With a type
  prefix required, it will rarely fire, `fix: …` is not the bare word `fix`.
  Note the list is inconsistent about case (`wip`, `WIP`, and `Wip` are all
  present; `UPDATE` and `Fixup` are not), so do not treat it as an exhaustive
  guard.
- **The body-wrap check exempts trailer-shaped lines.** A line matching
  `^[[:alpha:]][[:alnum:]_-]*:` is skipped, which is how `Signed-off-by:` stays
  on one line. It also means `Note: <a very long line>` escapes the check.
- **The subject is not re-checked for wrapping.** Step 7 starts at line 2; the
  subject is governed by step 6 alone.
- **Body length is counted in characters, not bytes**, so a CJK body line is
  measured fairly, unlike the subject check, which is byte-based and therefore
  waived for non-ASCII.

---

## 5. What the hook does not check

Everything here is a rule of this specification and none of it is machine
enforced. Following §3 of
[`CONTRIBUTING.md`](../../CONTRIBUTING.md#what-a-change-has-to-carry), treat these as *more*
important to get right, because nothing will remind you:

- **The type prefix.** Not checked at all, `Add a thing` passes the hook.
- **Imperative mood and capitalisation.** The hook has no parser for English.
- **A body.** A bare subject with no body passes.
- **Anything about the trailers except that `Signed-off-by:` exists.** The hook
  cannot tell `Signed-off-by: Claude <noreply@anthropic.com>` from a person, so
  a commit that violates the DCO policy by having a tool sign passes cleanly.
  See [`CONTRIBUTING.md`](../../CONTRIBUTING.md) for the
  trailer policy and the fixed roles, people sign and co-author, tools assist.
- **Whether `Assisted-by:` is present** when a tool was involved, or whether its
  `AGENT:MODEL [TOOLS]` shape is right.
- **Trailer order.** `Signed-off-by:` comes first, then `Co-authored-by:` and
  `Assisted-by:`, the order the example in §6 uses, the order the trailer
  table in [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
  lists, and the order every AI-assisted commit in this history carries.

Attribution trailers are exempt from the 72-character body wrap. Keep each on a
single line.

---

## 6. Attribution trailers

The trailer policy, which trailer names what, and the rule that the roles never
cross, is specified in
[`CONTRIBUTING.md`](../../CONTRIBUTING.md) and is not
duplicated here. The complete form for an AI-assisted commit:

```
Fix ATA timeouts on cold boot

Explain why, not what.

Signed-off-by: Ada Kernelson <ada@example.com>
Co-authored-by: Bob Lin <bob@example.com>
Assisted-by: Claude:claude-sonnet-4.5 coccinelle
```

`Signed-off-by:` is the only one the hook requires, and `git commit -s` adds it.
It is also the only one that must name a person.

---

## 7. The message is in English

Every commit message is written in English.  Issues and pull requests may be
written in English or Simplified Chinese
([`CONTRIBUTING.md`](../../CONTRIBUTING.md)), and a conversation is often the only
place an argument is worth having in a second language.  A commit message is not
a conversation: it is the one artifact an archaeology of this history reads, and
`git log` and `grep` are the whole of how it is read.  A rule stated in two
languages is a rule where the two statements drift and the search finds one of
them.

This section used to permit Chinese subjects and waived the 72-byte limit for
any non-ASCII byte.  The waiver is still described in §4, because the hook still
computes it, and the permission it served is gone: step 6 refuses a non-ASCII
subject outright, and step 8 refuses non-ASCII body prose.  A trailer line is
exempt from step 8, because the name in `Signed-off-by:` is a person's and some
names have no ASCII spelling.  The history that predates this rule stays as it
is.

The type prefix is ASCII either way.  A subject is still a title, so it does not
end in a full stop, in any language's punctuation, and it is written as a
command rather than as a report of something already done (§1).

A comment and a document are a different question.  `CONTRIBUTING.md` asks for
English there and keeps a reviewer's judgement for a name, a quotation or a
symbol that has none; this document's rule is only about the trailer-bearing,
greppable text a commit message is.

---

## 8. Amend, fixup, and autosquash

This tree lands a pull request by fast-forward, so **nothing is squashed at
merge**: a `fixup!` commit that reaches a pull request reaches `master`.
`git commit --fixup=<sha> -s` is still how a review round is answered, and
`git rebase --autosquash` before asking for the next round folds it in.  The `-s`
matters: the generated `fixup! <subject>` subject passes the hook on its own, but
a fixup commit carries no `Signed-off-by:` unless you ask for one.

- **Every commit must stand on its own**, including a fixup that has not been
  folded in yet, because each one is a commit a bisect can land on.
- **`git commit --amend` re-runs the hook.**  This is the fix for a rejected
  message, and the reason the check being local matters: you find out at commit
  time, not in a run that has already built the workspace.
- **`git push --force-with-lease`** after a rewrite, never `--force`.
- **Every commit in the range is checked**, not only the tip, because nothing is
  squashed and each one lands as it was written.  The hook runs at `git commit`;
  `scripts/check-commits.sh` runs it over `origin/master..HEAD` in the gate.
- **A merge commit in the range is refused.**  This is not a rule about message
  text, and it lives in the same script because that script already walks the
  range: `master` lands by fast-forward, and a merge cannot be fast-forwarded.
  The check reports the merge and its subject, and the fix is
  `git rebase origin/master`.  A merge commit's subject is generated by git and
  the hook exempts it on that ground, so without this check a range whose only
  defect was the merge would pass every message rule and then fail at the
  landing command.

---

## 9. Review checklist

- [ ] Subject is `<type>: <Imperative capitalised summary>`, `Add`, not `Adds`,
      `Added`, or `Adding`.
- [ ] The type matches what the change actually does.
- [ ] At most 72 characters, no trailing period, no leading/trailing space.
- [ ] The body says why, and would still make sense to a reader who has not seen
      the diff.
- [ ] No body line starts with `#`.
- [ ] `Signed-off-by:` present, naming a person, not a tool.
- [ ] `Assisted-by:` present if a tool was involved; no role crossing.
- [ ] The subject and the body prose are English.
- [ ] `git log --oneline -1` reads as a sentence you would want to find later.

---

## Related documents

- [`CONTRIBUTING.md`](../../CONTRIBUTING.md), the short form of these rules,
  the trailer policy, and the review process
- [`docs/fmts/comments.md`](comments.md), the same question for the comments
  inside the change
- [`DCO`](../../DCO), the certificate `Signed-off-by:` makes
