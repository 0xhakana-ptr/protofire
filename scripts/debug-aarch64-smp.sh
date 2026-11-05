#!/usr/bin/env sh
# File: scripts/debug-aarch64-smp.sh
# Purpose: Boot the aarch64 image with two cores under a gdb stub, so the point
#          a core stops at can be read instead of guessed.
#
# ## Why this exists
#
# The two-core aarch64 boot does not finish, and every instrument that was added
# to the kernel could only report which branch a core did *not* reach.  What is
# missing is the one fact a serial log cannot carry: which instruction each core
# is sitting on when the machine goes quiet.  That is what a stub is for.
#
# ## How to use it
#
# Run this in one terminal.  It starts QEMU frozen (`-S`) with a gdb server on
# port 1234 and the serial output to a file and to this terminal.
#
#     sh scripts/debug-aarch64-smp.sh
#
# Then run the commands it prints in a second terminal.  The script does not
# drive gdb itself: an interactive session is the point, and a script that
# answered the questions in advance would be another instrument that cannot say
# what it did not think of.
#
# ## Why `-smp 2` here and not in the gate
#
# The gate boots one core because two do not finish.  This script boots two
# because that is the case under investigation, and it is deliberately not what
# `verify.sh` runs.

set -eu

cd "$(dirname "$0")/.."

IMAGE="target/aarch64-unknown-none/debug/bootloader"
LOG="${LOG:-/tmp/aarch64-smp.log}"
DISK="${DISK:-/tmp/aarch64-smp.disk}"

if [ ! -f "$IMAGE" ]; then
    printf 'debug-aarch64-smp: no image at %s; build it first:\n' "$IMAGE" >&2
    printf '  cargo build --offline -p bootloader --target aarch64-unknown-none\n' >&2
    exit 1
fi

# The disk the machine boots with, because the boot formats and reads it.  It is
# the size `xtask` uses; a smaller one changes what the driver reports.
if [ ! -f "$DISK" ]; then
    dd if=/dev/zero of="$DISK" bs=1024 count=1024 status=none
fi

rm -f "$LOG"

printf 'image : %s\n' "$IMAGE"
printf 'log   : %s\n' "$LOG"
printf 'disk  : %s\n' "$DISK"
printf '\nStarting QEMU frozen on :1234.  In another terminal:\n\n'
printf '  gdb-multiarch %s\n' "$IMAGE"
printf '\n  (gdb) target remote :1234\n'
printf '  (gdb) continue\n'
printf '\nLet it run until the serial output stops.  Then:\n\n'
printf '  Ctrl-C in gdb              # stop the machine\n'
printf '  (gdb) info threads\n'
printf '  (gdb) thread apply all bt\n'
printf '  (gdb) thread apply all info registers pc sp elr_el1 spsr_el1\n'
printf '  (gdb) thread apply all x/8i $pc\n'
printf '\nThe log is being written to %s; `tail -f %s` in a third terminal\n' "$LOG" "$LOG"
printf 'shows it live.  Send back what gdb prints.\n\n'

exec qemu-system-aarch64 \
    -machine virt \
    -cpu max \
    -smp 2 \
    -m 512M \
    -drive "file=$DISK,format=raw,if=none,id=blk0" \
    -device virtio-blk-pci,drive=blk0,disable-legacy=on \
    -kernel "$IMAGE" \
    -display none \
    -no-reboot \
    -no-shutdown \
    -serial "file:$LOG" \
    -monitor none \
    -s -S
