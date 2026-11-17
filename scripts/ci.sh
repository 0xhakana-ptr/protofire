#!/usr/bin/env sh
# File: scripts/ci.sh
# Purpose: The continuous integration run, as a command a person can repeat.
#
# ## What this is
#
# CI runs this script and nothing else.  The workflow that calls it is four
# lines, and that is deliberate: a rule that exists only inside a YAML file is a
# rule no local command can reproduce, so the two drift and the one a
# contributor can run is the one that stops being updated.  Everything here is
# spelled as a command in this tree.
#
# ## What it runs, and what it leaves out
#
# `VERIFY_NO_BOOT=1 sh scripts/verify.sh p3`, which is the release floor with
# the image step declined, plus `scripts/check-commits.sh` over the pull
# request's commits.  The boot is the part that is left out, and it is left out
# because a runner is not this tree's development host: it may have no `qemu`
# installed, no `/dev/kvm`, and no budget for a TCG boot of four machine
# descriptions.  A tier that failed for a reason the tree cannot fix is a tier
# people stop reading.
#
# The boot is therefore still the contributor's, on the development host, and
# `VERIFY_NO_BOOT` prints a line when it is declined so a green CI run cannot be
# mistaken for a run that booted.  `AGENTS.md` and `CONTRIBUTING.md` both say a
# green CI is not the floor; this is the mechanism behind that sentence.
#
# ## The range
#
# `scripts/check-commits.sh` chooses its own range: `origin/master..HEAD` when
# that ref resolves, and `HEAD` with a note when it does not.  A CI checkout
# that fetched one commit therefore still checks the commit it has, and says
# which range it checked.
#
# Usage:
#   sh scripts/ci.sh

set -eu

cd "$(dirname "$0")/.."

printf '==> ci: sh scripts/verify.sh p3 (boot declined)\n'
VERIFY_NO_BOOT=1 sh scripts/verify.sh p3

printf '==> ci: sh scripts/check-commits.sh\n'
sh scripts/check-commits.sh

printf 'ci: passed (the boot was declined; run `sh scripts/verify.sh p3` on the development host)\n'
