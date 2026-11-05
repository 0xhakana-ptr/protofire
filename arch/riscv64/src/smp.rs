//! arch/riscv64/src/smp.rs
//!
//! The machine's other harts: which ones exist, and the one call that starts
//! one.
//!
//! ## What the machine has
//!
//! The device tree lists the harts — `/cpus`'s `cpu@` children, each `reg`
//! naming its hart id and `status` saying whether firmware means to use it —
//! and the firmware owns the power state.  A hart that is not running is
//! parked in M-mode, and S-mode cannot wake one by writing a register: it
//! **asks**, through the HSM extension, and the firmware enters the hart at
//! the address the ask names, with the hart's id in `a0` and the asker's
//! opaque word in `a1`.
//!
//! ## What a started hart does, and what it deliberately does not
//!
//! A started hart gets a stack of its own, the trap vector, and one job:
//! record that it is online, and park.  It does not run the scheduler — the
//! scheduler is a single structure today, and two harts in it would be two
//! writers nothing locks.  It does not take interrupts: `sstatus.SIE` stays
//! clear, so the park is a park and not a second CPU feeding ticks into code
//! that assumes one hart.  What the boot can prove is that the hart came up:
//! the flag it stores is what the boot hart's line reads, and a hart that
//! never stores it is a line that says so rather than a boot that hangs.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

/// How many harts past the boot one this tree starts.
///
/// The gate's machine asks for two harts in total.  The stacks the entry
/// assembly reserves are sized from this number — one fact, interpolated into
/// the assembly rather than written there a second time — and a machine whose
/// tree names more harts than the cap has a boot that starts the first of
/// them rather than one that guesses at a bigger reservation.
pub const MAX_SECONDARY_HARTS: usize = 4;

/// The stack one parked hart owns, in bytes.
///
/// The hart runs one function that stores one atomic and parks.  The size is
/// the boot stack's, not a bound small enough to be clever: a bound that
/// tight has to be re-derived the first time the hart's job grows, and the
/// memory it reserves is address space the machine has.
pub const SECONDARY_STACK_BYTES: usize = 65536;

/// The hart the firmware cold-booted, as the entry assembly recorded it.
static BOOT_HART: AtomicUsize = AtomicUsize::new(0);

/// Record the boot hart the entry assembly saw in `a0`.
///
/// Called once, from the entry assembly, before anything reads it.  The boot
/// hart is not assumed to be hart zero: it is whichever hart the firmware
/// chose, and the list of harts to start is the machine's minus this one.
pub fn set_boot_hart(hart: usize) {
    BOOT_HART.store(hart, Ordering::Release);
}

/// The hart the firmware cold-booted.
pub fn boot_hart() -> usize {
    BOOT_HART.load(Ordering::Acquire)
}

/// The hart id each started slot was given.
static SLOT_HART: [AtomicUsize; MAX_SECONDARY_HARTS] =
    [const { AtomicUsize::new(0) }; MAX_SECONDARY_HARTS];

/// The flag a started hart stores the moment it is running.
static ONLINE: [AtomicBool; MAX_SECONDARY_HARTS] =
    [const { AtomicBool::new(false) }; MAX_SECONDARY_HARTS];

/// How many harts the firmware refused to start, if it refused any.
static REFUSED: AtomicUsize = AtomicUsize::new(0);

/// The firmware's answer for the harts it would not start.
///
/// A refusal is a fact about the machine's state, not a reason to stop: the
/// boot reports it and carries on with the harts it has, which is what makes
/// the count a line a reader can act on rather than an error nobody sees.
pub fn refused_harts() -> usize {
    REFUSED.load(Ordering::Acquire)
}

/// The hart id the boot hart asked the firmware to start into `slot`.
pub fn secondary_hart_id(slot: usize) -> usize {
    SLOT_HART[slot].load(Ordering::Acquire)
}

/// Whether the hart started into `slot` has recorded that it is running.
pub fn secondary_online(slot: usize) -> bool {
    ONLINE[slot].load(Ordering::Acquire)
}

/// The firmware's HSM extension, and the function that starts a hart.
///
/// The extension id is the ASCII of `"HSM"`, which is how the specification
/// names them: three bytes, big-endian, in the register that names them.
#[cfg(target_os = "none")]
const SBI_EXT_HSM: u64 = 0x48534D;
#[cfg(target_os = "none")]
const SBI_HSM_HART_START: u64 = 0;

/// Ask the firmware to enter `hart` at `start`, handing it `opaque`.
///
/// # Safety
///
/// Called once per hart, from the boot hart, after the bss is clear and the
/// trap vector's address is one a hart can be entered at.  The firmware
/// enters the target hart in S-mode with `a0` = the hart id and `a1` =
/// `opaque`, which is the contract the entry assembly's secondary path is
/// written against.
#[cfg(target_os = "none")]
unsafe fn sbi_hart_start(hart: u64, start: u64, opaque: u64) -> i64 {
    let error: i64;
    // SAFETY: the HSM hart-start call.  Every register the firmware can eat
    // is declared late-out, for the same reason the timer call's are: an
    // undeclared clobber is a register the interrupted code loses silently.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") hart => error,
            inlateout("a1") start => _,
            inlateout("a2") opaque => _,
            lateout("a3") _,
            lateout("a4") _,
            lateout("a5") _,
            inlateout("a6") SBI_HSM_HART_START => _,
            inlateout("a7") SBI_EXT_HSM => _,
            options(nostack)
        )
    };
    error
}

/// Start every hart the machine names past the boot one.
///
/// Answers how many the firmware **accepted** — the count of slots the boot
/// can wait on.  A hart the tree lists but the firmware refuses is counted in
/// [`refused_harts`] and reported, not dropped: the difference between "the
/// machine has one hart" and "the machine has two and one refused" is the
/// whole of what a reader of the log needs.
///
/// The boot hart runs this after its own tables are up and the bss is clear —
/// the bss clear is the boot hart's, and a hart started before it would find
/// whatever the firmware left in the flags it is about to store.
///
/// # Safety
///
/// Called once, from the boot hart, with the trap vector installed.  The
/// started hart is entered at [`secondary_entry_address`], whose path touches
/// only its own stack, the vector and the flag.
#[cfg(target_os = "none")]
pub unsafe fn start_secondary_harts() -> usize {
    let Some((harts, count)) = crate::boot::hart_list() else {
        // A machine that cannot say what it has starts none of it, which is
        // the same answer the device tree's absence gets everywhere else.
        return 0;
    };
    let boot = boot_hart();
    let mut asked = 0usize;
    for &hart in &harts[..count] {
        if hart == boot {
            continue;
        }
        if asked == MAX_SECONDARY_HARTS {
            break;
        }
        let slot = asked;
        SLOT_HART[slot].store(hart, Ordering::Release);
        // SAFETY: the caller's contract is this function's — once per hart,
        // from the boot hart, with the entry address the secondary path owns.
        let error =
            unsafe { sbi_hart_start(hart as u64, secondary_entry_address() as u64, slot as u64) };
        if error == 0 {
            asked += 1;
        } else {
            REFUSED.fetch_add(1, Ordering::Release);
        }
    }
    asked
}

// The address the firmware enters a started hart at, as the assembly defined
// it.  A `//` and not a `///`: a doc comment on an extern block decorates
// nothing.
#[cfg(target_os = "none")]
unsafe extern "C" {
    static secondary_entry: u8;
}

#[cfg(target_os = "none")]
fn secondary_entry_address() -> usize {
    // `addr_of!` takes the address without creating a reference; there is a
    // run of instructions there, not a value.
    core::ptr::addr_of!(secondary_entry) as usize
}

/// The function a started hart runs, by the name the entry assembly calls.
///
/// The firmware hands back what the boot hart put in the ask: the hart's own
/// id in `a0` and the slot the boot hart chose in `a1`.  The slot is the only
/// thing the hart needs — its stack and its flag are both indexed by it, and
/// the boot hart only ever hands out slots the reservation holds, which is
/// the promise the entry assembly's stack setup is written against.
///
/// # Safety
///
/// `extern "C"` because the entry assembly calls it, with the registers the
/// firmware's start contract names.  It does not return: a hart with nothing
/// to run parks, and a park that returned would fall into whatever follows.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn riscv64_secondary_main(hart: usize, slot: usize) -> ! {
    let _ = hart;
    ONLINE[slot].store(true, Ordering::Release);
    park()
}

/// Stop this hart until something it cannot yet name arrives.
///
/// `sstatus.SIE` is clear, so no interrupt is taken and the loop does not
/// exit — which is the point: the hart is parked, not idle, and the change
/// that gives it work is the change that gives it a wake.
#[cfg(target_os = "none")]
fn park() -> ! {
    loop {
        // SAFETY: `wfi` is the wait-for-interrupt hint, and with `SIE` clear
        // no interrupt is taken on this hart.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}
