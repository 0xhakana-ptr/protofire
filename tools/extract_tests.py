#!/usr/bin/env python3
"""Extract a trailing `#[cfg(test)] mod tests { ... }` into a sibling tests.rs.

Usage: extract_tests.py <file.rs> "<one-line purpose>"

A file's module path is derived from its location: `a/b/src/c.rs` is module
`a::b::c` inside crate `b`, and `a/b/src/c/mod.rs` is module `a::b::c` inside
crate `b`.  `use super::X` becomes `use crate::<module>::X`, and a bare
`super::y` becomes `crate::<module>::y`.

The script refuses anything that is not a clean tail: a test module with code
after it would take that code with it.
"""

import os
import re
import sys


def module_path(path):
    """The path a `super::` in this file resolves against, as `crate::…`."""
    parts = path.replace("\\", "/").split("/")
    # Drop the leading "./" and find the "src" segment.
    if parts and parts[0] == ".":
        parts = parts[1:]
    try:
        i = parts.index("src")
    except ValueError:
        raise SystemExit(f"{path}: no src/ segment")
    manifest = os.path.join("/".join(parts[:i]), "Cargo.toml")
    crate = parts[i - 1]
    if os.path.exists(manifest):
        for line in open(manifest):
            if line.startswith("name = "):
                crate = line.split("=", 1)[1].strip().strip('"')
                break
    rest = parts[i + 1 :]
    if rest and rest[-1] == "mod.rs":
        rest = rest[:-1]
    elif rest:
        rest[-1] = rest[-1][: -len(".rs")]
    # Inside the crate, paths start at the crate root: the crate's own name is
    # not a module in it.
    return "::".join(["crate"] + rest) if rest else "crate"


def extract(path, purpose):
    src = open(path).read()
    match = re.search(r"#\[cfg\(test\)\]\nmod ([A-Za-z0-9_]+) \{", src)
    if not match:
        return f"SKIP {path}: no trailing #[cfg(test)] mod"
    marker = match.group(0)
    i = match.start()

    head = src[:i]
    tail = src[i:]

    # The module must run to the end of the file.
    depth = 0
    started = False
    close = None
    for n, ch in enumerate(tail):
        if ch == "{":
            depth += 1
            started = True
        elif ch == "}":
            depth -= 1
            if started and depth == 0:
                close = n
                break
    if close is None:
        return f"SKIP {path}: unbalanced module"
    if tail[close + 1 :].strip():
        return f"SKIP {path}: code after the test module"

    body = tail[len(marker) : close]
    dedented = "\n".join(
        line[4:] if line.startswith("    ") else line for line in body.splitlines()
    ).strip("\n")

    module = module_path(path)
    # `super::` inside the extracted code resolves against the module the tests
    # moved out of, so it takes that module's path.  A nested `super::super::`
    # climbs one more level, which is the crate root here.
    def rewrite(match):
        levels = len(match.group(1))
        if levels == 1:
            return f"{module}::"
        return "crate::"

    dedented = re.sub(r"\b((?:super::)+)", rewrite, dedented)

    base = os.path.dirname(path)
    stem = os.path.basename(path)
    if stem != "mod.rs":
        base = os.path.join(base, stem[: -len(".rs")])
    os.makedirs(base, exist_ok=True)
    out = os.path.join(base, "tests.rs")
    if os.path.exists(out):
        return f"SKIP {path}: {out} already exists"

    header = (
        f"//! {out.lstrip('./')}\n//!\n"
        f"//! {purpose.strip()}\n//!\n"
        "//! Extracted from the module so that a reader following the mechanism does\n"
        "//! not have to scroll past every case it has to satisfy; see\n"
        "//! `docs/fmts/testing.md` §1.\n"
    )
    open(out, "w").write(header + "\n" + dedented + "\n")
    open(path, "w").write(head.rstrip() + "\n\n#[cfg(test)]\nmod tests;\n")
    return f"OK {path} -> {out} ({len(dedented.splitlines())} lines)"


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    print(extract(sys.argv[1], sys.argv[2]))
