//! kernel/src/boot.rs
//!
//! The boot sequence: what a machine does in order, once, from the point where
//! it can run Rust to the point where it stops.
//!
//! The crate root keeps what has to be at the root, the allocator, the modules
//! themselves, and the re-exports that spell the public names.  The *order* of
//! the boot is a subject with a beginning and an end, and it had grown to more
//! than a thousand lines inside `lib.rs`: the console, the handshake, the page
//! table, the frame pool, the interrupt table, the other CPUs, the heap, the
//! filesystem, the namespace, the syscall table, the policy, the timer, and
//! then three programs.  Each of those is a fact about one subsystem *and* a
//! decision about when it runs relative to the others; keeping them in one
//! function is right, and keeping that function in a file of its own is what
//! lets a reader find it.
//!
//! `halt` and the allocator stay in the root: one is the machine's stop
//! spelled once for every caller, and the other is a `#[global_allocator]`,
//! which the language requires at the crate root of the binary that links it.
//! Everything else the boot touches is named here.

use crate::BootStage;
use crate::halt;

/// The boot, from the point where a machine is up to the point where it stops.
///
/// This takes a [`crate::BootInfo`] through `arch::boot_info()` rather than a
/// loader's registers: parsing the handshake is the architecture's business,
/// and the previous tree's entry took x86_64's convention for the whole tree's.
/// A new machine supplies its own `arch::boot_info()` and nothing here changes.
///
/// The console is what makes this boot observable, so it comes first: every
/// line below is a claim, and a claim nothing can read is not evidence.
pub fn kernel_main() -> ! {
    arch::serial::init();

    // The heap's diagnostics go to the same console, and this is where that is
    // decided.  `allocator` reports through a sink it is handed rather than
    // through a kernel macro, which is what lets its tests run on a host; the
    // price is this line, and a boot that omitted it would lose every
    // allocation-failure message without failing anything.
    //
    // SAFETY: `write_to_console` is a `fn(&str)` that writes the UART and
    // allocates nothing, required, because the allocator may call it from
    // inside a failed allocation.
    unsafe { allocator::diag::set_writer(Some(crate::console::write_to_console)) };

    // The boot CPU's own slot, before any trap can arrive: a handler that asked
    // which CPU it was on would read a slot nothing had written.
    //
    // The **machine's** id for this CPU, not the slot: the slot is the kernel's
    // numbering, and the boot line that reports `id` is reporting the hart or
    // core the machine named.  The two coincide on a machine whose firmware
    // cold-boots CPU zero, which is why passing the slot looked right.
    crate::per_cpu::register(crate::per_cpu::BOOT_SLOT, arch::current_cpu_id(), true);

    let boot = arch::boot_info();

    arch::serial::write_str("protofire 0.1.0: entered via ");
    arch::serial::write_str(boot.loader.as_str());
    arch::serial::write_str(", console up, stage ");
    arch::serial::write_u32(BootStage::ConsoleUp as u32);
    arch::serial::write_str("\n");

    crate::console::report_handshake();

    // SAFETY: called once, from the kernel's entry, with the console up so a
    // failure past this point is visible.  The table it installs covers the
    // code performing the install.
    unsafe { crate::boot_pages::install() };

    // Interrupts: a table of gates, the sink a frame goes to, and the machine's
    // other CPUs.
    #[cfg(target_os = "none")]
    {
        // SAFETY: called once, with the console up and before any program can
        // run, the caller's contract for both steps.
        unsafe { crate::interrupts::install() };
        crate::cpus::start_the_others();
    }

    // The heap, and then the filesystem that needs it.
    crate::heap::bring_up();
    let namespace = crate::volume::mount_everything();

    // The registry that outlives this function, and the policy proven through
    // it rather than beside it.
    install_registry(namespace);
    crate::policy::exercise();

    let read_ok = crate::volume::read_greeting_through_syscall();

    arch::serial::write_str("protofire: filesystem ");
    if read_ok {
        arch::serial::write_str(
            "mounted and read /greeting.txt through syscall open/read/close, label ",
        );
        arch::serial::write_str(crate::volume::BOOT_VOLUME_LABEL);
    } else {
        arch::serial::write_str("FAILED to read /greeting.txt through syscall open/read/close");
    }
    arch::serial::write_str("\n");

    // The external controller's line, then the console's source.  The timer
    // itself was brought up before the other CPUs started, and the code that
    // enters a program arms it.
    #[cfg(target_os = "none")]
    crate::tick::bring_up_external();
    #[cfg(target_os = "none")]
    crate::tick::bring_up_console_source();
    #[cfg(target_os = "none")]
    crate::tick::bring_up();

    // A program, at ring 3, calling back.
    // What each CPU has taken so far, before the programs start: the timer is
    // up by now, so the boot CPU's count is real.
    #[cfg(target_os = "none")]
    crate::cpus::report_activity();
    #[cfg(target_os = "none")]
    crate::tick::report_console();

    // The service table: what this kernel offers by name, installed once and
    // then closed.  Placed after the timer, because the clock service reads it,
    // and before the programs, because a program's calls are what will use the
    // table next.
    #[cfg(target_os = "none")]
    {
        let installed = crate::service::install_all();
        arch::serial::write_str("protofire: services installed = ");
        arch::serial::write_u32(installed as u32);
        arch::serial::write_str(", frozen\n");

        // The self-test goes **through the table** rather than calling the
        // service: a boot that called `Clock` directly would exercise none of
        // what this change added.
        match crate::service::read_the_clock() {
            Some(reading) => {
                arch::serial::write_str("protofire: clock service answered ");
                arch::serial::write_hex(reading as u64);
                arch::serial::write_str(" through the table\n");
            }
            None => {
                arch::serial::write_str("protofire: clock service did not answer\n");
            }
        }
    }

    // The network card, when the machine has one.  Placed here rather than with
    // the disk because nothing mounts on a network: the exchange is a self-test
    // of the two queues, and a machine without a card prints nothing and boots
    // exactly as it did.
    #[cfg(target_os = "none")]
    crate::devices::exercise_network();

    crate::programs::run();

    halt()
}

/// Build the syscall registry, register the handlers a boot serves, and install
/// it so the calls outlive this function.
///
/// Until this existed the table was a local: built here, used three times,
/// dropped.  That proves the handlers work and is not a syscall interface, a
/// table that exists only inside one call is a table nothing else can reach,
/// and the first thing that would have discovered it is the first trap that
/// tried to serve a call.
fn install_registry(namespace: fs::MountTable) {
    let mut table = crate::syscall::SyscallTable::new();
    table.set_namespace(alloc::sync::Arc::new(namespace));
    table.register(::syscall::SyscallNumber::Open, crate::syscall::open);
    table.register(::syscall::SyscallNumber::Read, crate::syscall::read);
    table.register(::syscall::SyscallNumber::Write, crate::syscall::write);
    table.register(::syscall::SyscallNumber::Close, crate::syscall::close);
    table.register(::syscall::SyscallNumber::Stat, crate::syscall::stat);
    table.register(
        ::syscall::SyscallNumber::CreateDir,
        crate::syscall::create_dir,
    );
    table.register(
        ::syscall::SyscallNumber::RemovePath,
        crate::syscall::remove_path,
    );
    table.register(::syscall::SyscallNumber::Rename, crate::syscall::rename);
    table.register(
        ::syscall::SyscallNumber::MacGetStatus,
        crate::syscall::mac_get_status,
    );
    table.register(
        ::syscall::SyscallNumber::MacSetMode,
        crate::syscall::mac_set_mode,
    );
    table.register(
        ::syscall::SyscallNumber::MacAddRule,
        crate::syscall::mac_add_rule,
    );
    // The memory calls.  Their numbers and their argument slots are frozen, so
    // the handlers take the shape the ABI already published for them.
    table.register(::syscall::SyscallNumber::Mmap, crate::syscall::mmap);
    table.register(::syscall::SyscallNumber::Munmap, crate::syscall::munmap);
    table.register(::syscall::SyscallNumber::Brk, crate::syscall::brk);
    table.register(
        ::syscall::SyscallNumber::ReclaimPages,
        crate::syscall::reclaim_pages,
    );
    let served = table.served();

    // SAFETY: called once, after the namespace is set and every handler is
    // registered, before anything can serve a call.
    unsafe { crate::syscall::install(table) };

    arch::serial::write_str("protofire: syscall table installed, ");
    arch::serial::write_u32(served as u32);
    arch::serial::write_str(" number(s) served\n");
}
