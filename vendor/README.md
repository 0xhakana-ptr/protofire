# vendor

The registry crates `Cargo.lock` names, as sources, so that a clone with no
network and an empty `CARGO_HOME` builds.

Nothing here is this tree's code.  Every directory is one crate at the version
the lockfile pinned, laid out exactly as `cargo vendor` wrote it, and
`.cargo-checksum.json` beside each is what cargo checks the sources against.
Editing anything in this directory is therefore the wrong repair, always: the
checksum will refuse the build, which is the point of the file being here.

`.cargo/config.toml` is what makes cargo read this directory instead of
crates.io.  It carries the argument in full; the short form is that every gate
runs `cargo ... --offline`, and before this directory existed those flags read
as a property of the build when they were a property of one machine's
`~/.cargo` cache.

## Regenerating it

```sh
cargo vendor --versioned-dirs vendor
```

Run it after any change to a dependency, and commit the result with the change
that needed it.  `cargo` names the crates whose checksums no longer match when
a vendor directory disagrees with the lockfile, so a stale copy fails the build
rather than silently using old sources.

The directory is 27 MiB and 25 crates.  That is the price of a gate that means
the same thing on a machine that has never built this tree.
