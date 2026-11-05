# Licences

Two licences cover this tree, and which one applies depends on what the file is:

| What | Licence | Text |
|---|---|---|
| Source code, every `.rs`, `.S`, `.ld`, `Cargo.toml`, `justfile`, script | Apache-2.0 | [`Apache-2.0`](Apache-2.0.txt) |
| Prose, every `.md`, this file included | CC BY-SA 4.0 | [`CC-BY-SA-4.0`](CC-BY-SA-4.0.txt) |
| The certificate fixtures under `certs/` | as their own files state |, |

## Why two

A licence written for software and a licence written for prose ask different
questions.  Apache-2.0 is about patents, source distribution and the state of
modified files; CC BY-SA is about attribution and about a derived work staying
under the same terms.  A README under Apache-2.0 is legally fine and is a poor
fit: nothing in it is a patent question, and the section about "modified source
files" has nothing to say about a paragraph.

Using one licence for each kind of file is what the Rust project, the Linux
kernel's documentation subtree and most projects with substantial prose do.

## What CC BY-SA asks of a document's author

- **Attribution**, name this project and say what you changed.
- **Share-alike**, a document derived from one of ours carries the same
  licence, so the documentation stays documentation anyone can improve.

Neither asks anything of someone who merely *reads* the documents or *builds*
the kernel, which is what the Apache-2.0 half covers.

## The source-code half, in one paragraph

Apache-2.0, and every source file carries its provenance at the top.  There is
no per-file licence header: a header repeated in four hundred files is four
hundred places to update and one more thing to read before the code.  The
crate-level rule, what this crate is, what it may name, and where its code came
from, lives in each crate's `//!` header, which is the form
[`NOTICE`](../NOTICE) describes.
