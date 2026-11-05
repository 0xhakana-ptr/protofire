# `certs/`: the trust anchors

This directory is data, not code.  Nothing here is compiled, nothing here is
linked, and no crate depends on it: a file in here is a **build input**, read
at image-build time and embedded into the kernel's trust store.  The kernel
never reads this directory at run time.

## Why it is a directory and not a `const` in a crate

Because the thing it holds is a *decision* rather than a program.  A root
certificate is bytes a CA published; a TOML file beside it says which root a
machine is built to trust and why.  Encoding that as a Rust array would make
every certificate rotation a rebuild of a crate that also contains code, and
would hide the one question a reader should be able to ask of a trust store, "what is this machine trusting, and who said so", inside a source file.

## What a trust anchor is for here

An anchor is the root of a certificate chain: the one key a verifier accepts
without a chain to vouch for it.  A boot that checks the image it is about to
load, or a program that verifies a server, reduces every question about a
signature to "is this chain rooted at something in the store".

So this directory is the bottom of the boot's integrity story.  Everything
above it, a signature over the kernel image, a secure-boot check, a TLS
handshake, is only as strong as the set of anchors here, and a machine built
with an anchor nobody argued for is a machine that trusts whoever holds that
key.

## Two kinds of anchor

| | |
|---|---|
| **built-in** | a file in `trusted_keys/`, read at build time and embedded into the image |
| **added at run time** | the `TrustAnchorAdd` syscall (#194), withdrawn by `TrustAnchorRemove` (#195) |

A run-time anchor is the caller's own trust decision and is not inherited by
another program: what it grants is the ability to verify a chain against one
more root, for that caller's handshakes.  That is why the syscall is
unprivileged and why the built-in set is the one a rebuild is needed to change.

## The file format

`trusted_keys/*.toml` describes one anchor each:

```toml
# A comment saying whose key this is and why this machine trusts it.
pem = """
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
"""
```

The `pem` field holds the certificate itself.  PEM rather than raw DER because
a certificate a reader can compare against a CA's published copy is a
certificate a reviewer can check; base64 in a text file is also a diff a human
can read.

## What is here today

`trusted_keys/demo_key.toml` is a placeholder with no key in it, and it says
so.  A demonstration anchor was considered and not added: an image that ships
trusting a key generated for the tree is an image that trusts whoever generated
it, and calling that "the demo set" does not make it not a key.  The first real
anchor arrives with the boot-integrity check that consumes it, in a change that
can argue for this machine trusting that root.
