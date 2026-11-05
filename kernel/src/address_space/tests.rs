//! kernel/src/address_space/tests.rs
//!
//! The permission rules' tests: what each section is for, that a device window
//! wins over an image rule, and the user window that refuses what is not in it.

use super::Rule;
use super::permissions_at;
use super::permissions_for;
use paging::Cache;
use paging::Permissions;

#[cfg(target_os = "none")]
use paging::PAGE_SIZE;

/// The rules a host test can see, standing in for an image's linker
/// script.
///
/// The numbers are made up and the *shape* is what the image has: text
/// first, then read-only data, then writable data — a `BTreeMap` of ranges
/// would be a different test.
const TEXT: u64 = 0x1000;
const TEXT_END: u64 = 0x8000;
const RODATA: u64 = 0x8000;
const RODATA_END: u64 = 0xC000;

const RULES: [Rule; 2] = [
    Rule {
        start: TEXT as usize,
        end: TEXT_END as usize,
        permissions: Permissions::KERNEL_READ_EXECUTE,
    },
    Rule {
        start: RODATA as usize,
        end: RODATA_END as usize,
        permissions: Permissions {
            writable: false,
            executable: false,
            user: false,
            cache: Cache::Normal,
        },
    },
];

/// Text is executable and not writable; rodata is neither.
///
/// The whole reason this table exists: the boot maps every page writable
/// and executable, so a store into a `const` succeeds instead of faulting
/// and an instruction fetched from a data page runs.
#[test]
fn the_permissions_are_what_the_sections_are_for() {
    let text = permissions_at(&RULES, TEXT as usize);
    assert!(text.executable);
    assert!(!text.writable);

    let rodata = permissions_at(&RULES, RODATA as usize);
    assert!(!rodata.executable);
    assert!(!rodata.writable);
}

/// A region owns its start and not its end: the two ranges meet and do not
/// overlap.
///
/// `end` is exclusive because that is how a linker places the next section
/// — `__text_end` and `__rodata_start` are the same address — and a rule
/// that claimed its end would give that address two permissions.
#[test]
fn a_region_owns_its_start_and_not_its_end() {
    assert!(permissions_at(&RULES, TEXT as usize).executable);
    assert!(
        !permissions_at(&RULES, TEXT_END as usize).executable,
        "the byte at the end of text belongs to rodata, which is not code"
    );
    assert!(!permissions_at(&RULES, TEXT_END as usize).writable);
}

/// An address in no rule keeps the boot's answer.
///
/// A region this kernel has no opinion about is one it must not newly
/// forbid: firmware tables and the loader's structures are still being
/// read, and a page that started faulting would stop the boot.
#[test]
fn an_unclaimed_address_keeps_the_boots_permissions() {
    let unclaimed = permissions_at(&RULES, 0);
    assert_eq!(unclaimed, Permissions::KERNEL_READ_WRITE);
    assert!(unclaimed.writable);
}

/// An empty rule set leaves every address as the boot left it.
#[test]
fn no_rules_means_no_changes() {
    assert_eq!(permissions_at(&[], 0x1000), Permissions::KERNEL_READ_WRITE);
}

/// A device window makes its range uncached, and everything else keeps the
/// rule it would have had.
///
/// This is the rule the aarch64 boot needed the moment translation went
/// on: with no entry of its own, the PL011 at `0x0900_0000` is Normal
/// memory, and a cached read of a status register is a console that stops
/// printing for a reason that looks like a dead UART.
///
/// The two addresses either side of the boundary are the test's point: a
/// window owns its start and not its end, so `0x0800_0000` is a device and
/// `0x4000_0000` — where RAM begins — is not.
#[test]
fn a_device_window_is_uncached_and_ends_where_it_ends() {
    let windows: &[(usize, usize)] = &[(0x0000_0000, 0x4000_0000)];

    let uart = permissions_for(&RULES, windows, 0x0900_0000);
    assert_eq!(uart, Permissions::DEVICE);
    assert_eq!(uart.cache, Cache::Device);
    assert!(uart.writable && !uart.executable);

    assert_eq!(
        permissions_for(&RULES, windows, 0x3FFF_F000),
        Permissions::DEVICE,
        "the last page below RAM is still a device"
    );
    assert_eq!(
        permissions_for(&RULES, windows, 0x4000_0000),
        Permissions::KERNEL_READ_WRITE,
        "RAM itself is ordinary memory again"
    );
}

/// A device window wins over an image rule.
///
/// The two overlap only if the firmware loaded the image on top of a
/// device, which is not a state a permission rule can repair — but the
/// ordering has to be decided rather than left to whichever loop runs
/// first, and the decision is that a register is a register.
#[test]
fn a_device_window_beats_an_image_rule() {
    let windows: &[(usize, usize)] = &[(TEXT as usize, TEXT_END as usize)];
    let in_text = permissions_for(&RULES, windows, TEXT as usize);
    assert!(
        !in_text.executable,
        "the window's answer, not the text rule"
    );
    assert_eq!(in_text.cache, Cache::Device);
}

/// The user window is above the kernel and a range has to fit inside it.
///
/// The three things this tests are the three a syscall depends on: a
/// kernel address is refused, a range that wraps is refused, and a range
/// whose end crosses the boundary is refused.  A validator that got any of
/// them wrong would let a program write one byte past its own pages.
#[test]
fn the_user_window_refuses_what_is_not_in_it() {
    use super::USER_BASE;
    use super::USER_WINDOW;
    use super::is_user_range;

    let first = USER_BASE;
    assert!(
        is_user_range(first, 1),
        "the first user byte is a user byte"
    );
    assert!(!is_user_range(first - 1, 1), "the last kernel byte is not");
    assert!(
        !is_user_range(0x4000_0000, 16),
        "a kernel address is refused"
    );

    assert!(
        is_user_range(first, USER_WINDOW),
        "a whole window from its start fits"
    );
    assert!(
        is_user_range(super::USER_LIMIT - 1, 1),
        "the last user byte is a user byte"
    );
    assert!(
        !is_user_range(super::USER_LIMIT, 1),
        "and the byte after it is not"
    );

    // A range that wraps must be refused rather than read as "ends before
    // it starts, so it is fine".
    assert!(
        !is_user_range(usize::MAX - 1, 8),
        "an overflowing range is not a user range"
    );
}

/// A machine with no device windows behaves exactly as it did before the
/// question was asked.
///
/// x86_64 answers with an empty slice — it has no fixed peripheral
/// window — so this is that machine's case, and the assertion is that
/// introducing the question changed nothing for it.
#[test]
fn no_windows_leaves_the_rules_alone() {
    assert_eq!(
        permissions_for(&RULES, &[], TEXT as usize),
        permissions_at(&RULES, TEXT as usize)
    );
    assert_eq!(
        permissions_for(&RULES, &[], 0x0900_0000),
        Permissions::KERNEL_READ_WRITE
    );
}
