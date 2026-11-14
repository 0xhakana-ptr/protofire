# Licences

Two licences cover this tree, and which one applies depends on what the file is.

- **Source code**, every `.rs`, `.S`, `.ld`, `Cargo.toml`, `justfile` and
  script, is [Apache-2.0](Apache-2.0.txt).
- **Prose**, every `.md`, this file included, is [CC BY 4.0](CC-BY-4.0.txt).
- **The certificate fixtures under `certs/`** are under whatever their own
  files state.

## Why two

A licence written for software and a licence written for prose ask different
questions.  Apache-2.0 is about patents, source distribution and the state of
modified files; CC BY is about attribution.  A README under Apache-2.0 is
legally fine and is a poor fit: nothing in it is a patent question, and the
section about "modified source files" has nothing to say about a paragraph.

## What CC BY asks of a document's author

- **Attribution**, name this project and say what you changed.

That is the whole of it.  Nothing is asked of someone who merely *reads* the
documents or *builds* the kernel, which is what the Apache-2.0 half covers.

## Why attribution and not share-alike

This tree's prose used to be CC BY-SA 4.0, and the argument for it was that
documentation should stay documentation anyone can improve.  The argument does
not hold for what this prose actually is.  A corpus with share-alike is a
commons, an encyclopedia, a manual several projects write together, where the
point is that no one can take the work closed.  This tree's prose is one
project's own record: why a subsystem is shaped the way it is, and what has and
has not been built.  Nobody forks it into a competing body of knowledge, and a
reader who quotes a paragraph in a bug report is not a threat to it.

What share-alike cost was real.  Its boundary with Apache-2.0 is not obvious
to a reader, "is this paragraph inside a source file part of the code or the
prose?" has no answer, and the clause itself is untested in the one place
people now copy text from, which is a language model's context.  Attribution
is understood by every reader and asked for by every licence, and it is the
one thing this tree actually wants from a quoter.

The source half is unchanged, and the two halves are still separated by what a
file *is*: `.md` against `.rs`, with no file in both.

## The source-code half, in one paragraph

Apache-2.0, and every source file carries its provenance at the top.  There is
no per-file licence header: a header repeated in four hundred files is four
hundred places to update and one more thing to read before the code.  The
crate-level rule, what this crate is, what it may name, and where its code came
from, lives in each crate's `//!` header, which is the form
[`NOTICE`](../NOTICE) describes.
