#!/usr/bin/env sh
# File: scripts/check-x8664-boot.sh
# Purpose: Prove the image reaches its own console.
#
# This is the first gate the new tree has, and it exists because everything
# below it is invisible without one.  "It builds" says the linker was happy;
# this says the boot assembly's page tables, long mode, GDT, stack, the call
# into Rust, the serial port's divisor programming and the halt loop all worked
# in one boot.  A tree that cannot say that cannot say anything about what it
# does next.
#
# The assertion is an exact line, not a substring: the line names the loader,
# and a PVH boot and a multiboot2 boot are different code paths through the
# same function.  Any of them producing the other's line is the failure this
# gate is for.
set -eu

cd "$(dirname "$0")/.."

CARGO="${CARGO:-cargo}"
QEMU="${QEMU:-qemu-system-x86_64}"
PROFILE="${PROFILE:-debug}"
TARGET="x86_64-unknown-none"
KERNEL="target/$TARGET/$PROFILE/bootloader"
TIMEOUT="${TIMEOUT:-15}"

FEATURES="${FEATURES:-}"
if [ -n "$FEATURES" ]; then
    "$CARGO" build --offline -p bootloader --target "$TARGET" --features "$FEATURES"
else
    "$CARGO" build --offline -p bootloader --target "$TARGET"
fi

if [ ! -f "$KERNEL" ]; then
    printf 'boot check: no image at %s\n' "$KERNEL" >&2
    exit 1
fi

work="$(mktemp -d)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM

log="$work/serial.log"
set +e
timeout "${TIMEOUT}s" "$QEMU" \
    -machine q35 -cpu max -m 512M \
    -kernel "$KERNEL" \
    -display none -no-reboot -no-shutdown \
    -serial "file:$log" >/dev/null 2>&1
status=$?
set -e

# 124 is `timeout` stopping a machine that is, by design, still running: the
# kernel halts rather than exiting, because there is no firmware to return to.
case "$status" in
    0|124) ;;
    *) printf 'boot check: qemu exited with %s\n' "$status" >&2; exit 1 ;;
esac

expected="protofire 0.1.0: entered via pvh, console up, stage 1"
# The line on the wire ends in CRLF — `write_byte` sends `\r` before every `\n`
# because the reader is a terminal — so the match is against lines whose
# trailing carriage return has been stripped.  The CR is not what this check is
# about, and a rule that required it would fail the moment a sink that drops it
# is used.
if ! tr -d '\r' <"$log" | grep -qxF "$expected"; then
    printf 'boot check: the image did not reach its console\n' >&2
    printf '  expected the line: %s\n' "$expected" >&2
    if [ -s "$log" ]; then
        printf '  serial log (%s bytes):\n' "$(wc -c <"$log" | tr -d ' ')" >&2
        sed 's/^/    /' "$log" >&2
    else
        printf '  the serial log is empty: the boot died before COM1 was programmed\n' >&2
    fi
    exit 1
fi

printf 'boot check passed: the image reached its console via pvh\n'
