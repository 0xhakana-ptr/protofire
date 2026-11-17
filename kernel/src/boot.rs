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
/// loader's registers: parsing the handshake is the architecture's business, so
/// no one machine's convention leaks into the entry every machine shares.
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

    // The heap, then the NVMe controller whose namespace the mount will take,
    // and then the filesystem that needs them.  The controller comes up before
    // the mount because a namespace mounted over it has to find the device
    // already there; a bring-up after the mount would be a device the table
    // never saw.
    crate::heap::bring_up();
    crate::pcspkr::boot_check();
    crate::nvme::bring_up();
    crate::ahci::bring_up();
    crate::xhci::bring_up();
    crate::virtio_input::bring_up();
    crate::virtio_gpu::bring_up();
    let namespace = crate::volume::mount_everything();
    // The mount is where the kernel first allocates in volume, so it is where a
    // check reading a second view of the arena stops agreeing with the
    // allocator that carved it.  Compiles out with the check it calls.
    #[cfg(debug_assertions)]
    crate::heap::check_after_mount();

    // The display: found on the bus, given a mode, and reported.  After the
    // heap because the probe allocates, and before the programs because
    // whatever draws on this screen will be reachable from them.
    // The screen, installed before the rest of the boot prints: everything
    // after this line reaches the framebuffer as well as the serial port, and
    // the two lines below are the boot's own proof of it.
    if let Some(display) = crate::framebuffer::probe() {
        crate::console_screen::install(display.framebuffer);
        arch::serial::write_str("protofire: screen installed, ");
        arch::serial::write_u32(crate::console_screen::columns() as u32);
        arch::serial::write_str(" by ");
        arch::serial::write_u32(crate::console_screen::rows() as u32);
        arch::serial::write_str(" cell(s)\n");
    }

    // The virtio GPU, when the machine has one: its mode is the device's own
    // answer, the resource is backed by memory this kernel owns, and the band
    // it presents is the evidence a screendump reads from outside the guest.
    // After the display probe because the two are different devices on the
    // same machine and the bochs one owns the console; this one is proven, not
    // drawn on.
    crate::virtio_gpu::announce();
    crate::virtio_gpu::prove();

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

    // The clock the time calls read, recorded now that the timer's rate is a
    // measurement rather than a claim.  Its line is the evidence that the
    // division a program will get is over a rate this machine reported: a boot
    // that recorded nothing would answer every `GetTimeOfDay` with
    // `Unsupported`, which looks the same as a machine with no timer.
    #[cfg(target_os = "none")]
    match unsafe { crate::time::bring_up() } {
        Some((origin, rate)) => {
            arch::serial::write_str("protofire: time origin ");
            arch::serial::write_hex(origin);
            arch::serial::write_str(" at ");
            arch::serial::write_u32((rate / 1_000_000) as u32);
            arch::serial::write_str(" MHz\n");
        }
        None => {
            arch::serial::write_str("protofire: no clock rate, the time calls will refuse\n");
        }
    }

    // The random generator, seeded from this boot's own timing.
    //
    // Two reads, compared, and the comparison is the evidence: a generator
    // that answered the same eight bytes twice is one whose counter never
    // advanced, and the line would say so rather than needing a reader to
    // eyeball two hex numbers.  The readings themselves are printed because
    // they are **output**, public by definition, and a line that named only
    // "seeded" would be a claim rather than a measurement.
    #[cfg(target_os = "none")]
    match unsafe { crate::random::seed() } {
        Some(_) => {
            let mut first = [0u8; 8];
            let mut second = [0u8; 8];
            let read =
                crate::random::fill(&mut first).is_ok() && crate::random::fill(&mut second).is_ok();
            arch::serial::write_str("protofire: random seeded, two reads ");
            arch::serial::write_str(if read {
                if first == second {
                    "the same"
                } else {
                    "differ"
                }
            } else {
                "failed"
            });
            arch::serial::write_str("\n");
        }
        None => {
            arch::serial::write_str("protofire: no seed, the random call will refuse\n");
        }
    }

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

    // The local-domain socket: a name this boot binds, connects to, accepts and
    // moves bytes through both ways.  Deliberately outside the network exercise
    // above, because none of it needs a card: a local connection is two pipes
    // and a name, and a machine with no network is a machine where this still
    // works.  Its result is the probe's own line; a boot whose line says
    // MISMATCH is a boot the gate refuses.
    #[cfg(target_os = "none")]
    let _ = crate::local::probe();

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
    // The two console calls: a program's own line, and a read that answers
    // zero because this machine has no input device yet.  `ReadConsole` is
    // served rather than refused so a shell can tell "nothing yet" from "no
    // such call".
    table.register(
        ::syscall::SyscallNumber::WriteDebug,
        crate::syscall::write_debug,
    );
    table.register(
        ::syscall::SyscallNumber::ReadConsole,
        crate::syscall::read_console,
    );
    // The device list and the whole-machine flush.  `ListBlockDevices` answers
    // the disks the boot found, in the order it found them, and `Sync` is the
    // explicit half of durability where `Fsync` is the per-file half.
    table.register(
        ::syscall::SyscallNumber::ListBlockDevices,
        crate::syscall::list_block_devices,
    );
    table.register(::syscall::SyscallNumber::Sync, crate::syscall::sync);
    table.register(::syscall::SyscallNumber::Close, crate::syscall::close);
    // The two duplicates.  `Dup` answers the lowest free slot and `Dup2` places
    // the copy on a number the caller names, closing whatever was there: the
    // pair is how a program puts a file on standard output without a window in
    // which the number is free.
    table.register(::syscall::SyscallNumber::Dup, crate::syscall::dup);
    table.register(::syscall::SyscallNumber::Dup2, crate::syscall::dup2);
    // The descriptor control call.  One number and a command word, carrying the
    // seven commands a program uses to read or move a descriptor's state:
    // `F_DUPFD`, the two per-descriptor flags, the two status flags, and the
    // two pipe-capacity commands.
    table.register(::syscall::SyscallNumber::Fcntl, crate::syscall::fcntl);
    // The four extended-attribute calls.  Every filesystem that has them
    // already implements them; what was missing was the packed list this ABI
    // now names in `fs_abi::XattrEntryRecord`.
    table.register(
        ::syscall::SyscallNumber::SetXattr,
        crate::syscall::set_xattr,
    );
    table.register(
        ::syscall::SyscallNumber::GetXattr,
        crate::syscall::get_xattr,
    );
    table.register(
        ::syscall::SyscallNumber::ListXattr,
        crate::syscall::list_xattr,
    );
    table.register(
        ::syscall::SyscallNumber::RemoveXattr,
        crate::syscall::remove_xattr,
    );
    // The three access queries and the three ownership reads.  The queries
    // need an identity and compute against it; the reads are the unchecked
    // half, who owns a file and what its bits are.
    table.register(
        ::syscall::SyscallNumber::AccessQuery,
        crate::syscall::access_query,
    );
    table.register(
        ::syscall::SyscallNumber::AccessQueryAt,
        crate::syscall::access_query_at,
    );
    table.register(
        ::syscall::SyscallNumber::AccessQueryFd,
        crate::syscall::access_query_fd,
    );
    table.register(
        ::syscall::SyscallNumber::PermissionMetadata,
        crate::syscall::permission_metadata,
    );
    table.register(
        ::syscall::SyscallNumber::PermissionMetadataAt,
        crate::syscall::permission_metadata_at,
    );
    table.register(
        ::syscall::SyscallNumber::PermissionMetadataFd,
        crate::syscall::permission_metadata_fd,
    );
    // The truncate.  A number the ABI froze at twenty and this table served
    // nothing for until now: `VNode::set_len` existed and no program could
    // reach it, which is the whole of what that gap was.
    table.register(
        ::syscall::SyscallNumber::SetLength,
        crate::syscall::set_length,
    );
    table.register(::syscall::SyscallNumber::Stat, crate::syscall::stat);
    // The two descriptor-shaped readings of the same facts: a stat and a
    // listing, asked of the descriptor rather than of the path it was opened
    // at.  A program handed a descriptor never learns the path, which is what
    // these two exist to spare it.
    table.register(::syscall::SyscallNumber::StatFd, crate::syscall::stat_fd);
    table.register(
        ::syscall::SyscallNumber::ReadDirFd,
        crate::syscall::read_dir_fd,
    );
    // The seek.  It answers a position rather than a status, which is why the
    // ABI has it return the new offset: a caller that sought to the end needs
    // the size, and no other call in this group gives it.
    table.register(::syscall::SyscallNumber::Seek, crate::syscall::seek);
    // The two flushes.  `Fsync` waits for the data and its metadata,
    // `Fdatasync` for the data alone; a filesystem that cannot separate them
    // answers the stronger one, which is a superset of what the weaker asks.
    table.register(::syscall::SyscallNumber::Fsync, crate::syscall::fsync);
    table.register(
        ::syscall::SyscallNumber::Fdatasync,
        crate::syscall::fdatasync,
    );
    // The punch.  One mode is defined, `FALLOC_FL_PUNCH_HOLE |
    // FALLOC_FL_KEEP_SIZE`, and `VNode::punch_hole` is what answers it: only
    // the NTFS volume makes holes in this tree, so the other filesystems
    // refuse with the word their default gives.
    table.register(
        ::syscall::SyscallNumber::Fallocate,
        crate::syscall::fallocate,
    );
    // The two data-reduction flags.  PyroFS persists the byte and refuses a
    // bit that is not the program's, which is why `GetFileFlags` answering is
    // a fact about the volume rather than about this table.
    table.register(
        ::syscall::SyscallNumber::GetFileFlags,
        crate::syscall::get_file_flags,
    );
    table.register(
        ::syscall::SyscallNumber::SetFileFlags,
        crate::syscall::set_file_flags,
    );
    table.register(
        ::syscall::SyscallNumber::CreateDir,
        crate::syscall::create_dir,
    );
    table.register(
        ::syscall::SyscallNumber::RemovePath,
        crate::syscall::remove_path,
    );
    table.register(::syscall::SyscallNumber::Rename, crate::syscall::rename);
    table.register(::syscall::SyscallNumber::ReadDir, crate::syscall::read_dir);
    // The anchored five.  Their handlers and their ring-3 forwards landed in
    // the change before this one; the registrations are here because a
    // handler this table does not hold is a number that answers
    // `NotImplemented`, which is how the first program to call one found it.
    table.register(::syscall::SyscallNumber::OpenAt, crate::syscall::open_at);
    table.register(::syscall::SyscallNumber::StatAt, crate::syscall::stat_at);
    table.register(
        ::syscall::SyscallNumber::RenameAt,
        crate::syscall::rename_at,
    );
    table.register(
        ::syscall::SyscallNumber::CreateDirAt,
        crate::syscall::create_dir_at,
    );
    table.register(
        ::syscall::SyscallNumber::RemovePathAt,
        crate::syscall::remove_path_at,
    );
    table.register(
        ::syscall::SyscallNumber::MacGetStatus,
        crate::syscall::mac_get_status,
    );
    // The packet filter.  Four numbers above the frozen range, and the one
    // policy this build lets a program install that changes what the demux does
    // with a packet.  `FilterAddRule` and `FilterGetStats` take a record, so
    // their buffers are borrowed in the trap path; the other two name words and
    // answer at once.
    table.register(
        ::syscall::SyscallNumber::FilterAddRule,
        crate::syscall::filter_add_rule,
    );
    table.register(
        ::syscall::SyscallNumber::FilterRemoveRule,
        crate::syscall::filter_remove_rule,
    );
    table.register(
        ::syscall::SyscallNumber::FilterSetDefaultAction,
        crate::syscall::filter_set_default_action,
    );
    table.register(
        ::syscall::SyscallNumber::FilterGetStats,
        crate::syscall::filter_get_stats,
    );
    // Multicast routing's six numbers.  `MrtInit` and `MrtDone` are the switch
    // and take no record; `MrtAddVif` and `MrtAddMfc` take one, so their
    // buffers are borrowed in the trap path; the two removals name words.
    table.register(::syscall::SyscallNumber::MrtInit, crate::syscall::mrt_init);
    table.register(::syscall::SyscallNumber::MrtDone, crate::syscall::mrt_done);
    table.register(
        ::syscall::SyscallNumber::MrtAddVif,
        crate::syscall::mrt_add_vif,
    );
    table.register(
        ::syscall::SyscallNumber::MrtDelVif,
        crate::syscall::mrt_del_vif,
    );
    table.register(
        ::syscall::SyscallNumber::MrtAddMfc,
        crate::syscall::mrt_add_mfc,
    );
    table.register(
        ::syscall::SyscallNumber::MrtDelMfc,
        crate::syscall::mrt_del_mfc,
    );
    // IPsec's five.  `IpsecAddSp` and `IpsecAddSa` take a record, so their
    // buffers are borrowed in the trap path; `IpsecGetStats` writes one.  The
    // two removals name words: a policy by its id and an association by the SPI
    // a manager has, which is in every packet on the wire.
    table.register(
        ::syscall::SyscallNumber::IpsecAddSp,
        crate::syscall::ipsec_add_sp,
    );
    table.register(
        ::syscall::SyscallNumber::IpsecDelSp,
        crate::syscall::ipsec_del_sp,
    );
    table.register(
        ::syscall::SyscallNumber::IpsecAddSa,
        crate::syscall::ipsec_add_sa,
    );
    table.register(
        ::syscall::SyscallNumber::IpsecDelSa,
        crate::syscall::ipsec_del_sa,
    );
    table.register(
        ::syscall::SyscallNumber::IpsecGetStats,
        crate::syscall::ipsec_get_stats,
    );
    // DCCP's seven.  `DccpAccept` and `DccpRecv` park, so their branches are
    // the trap path's: a handler that cannot park does not hold a number whose
    // caller may have to wait.  The other five answer at once.
    table.register(
        ::syscall::SyscallNumber::DccpBind,
        crate::syscall::dccp_bind,
    );
    table.register(
        ::syscall::SyscallNumber::DccpListen,
        crate::syscall::dccp_listen,
    );
    table.register(
        ::syscall::SyscallNumber::DccpConnect,
        crate::syscall::dccp_connect,
    );
    table.register(
        ::syscall::SyscallNumber::DccpAccept,
        crate::syscall::dccp_accept,
    );
    table.register(
        ::syscall::SyscallNumber::DccpSend,
        crate::syscall::dccp_send,
    );
    table.register(
        ::syscall::SyscallNumber::DccpRecv,
        crate::syscall::dccp_recv,
    );
    table.register(
        ::syscall::SyscallNumber::DccpClose,
        crate::syscall::dccp_close,
    );
    // The one TLS call, above the frozen boundary like the rest.  It is
    // registered because a number the ABI names should answer something a
    // program can act on, and `Unsupported` after a hello is built and sent is
    // a different answer from `NotImplemented`: the first says the machine
    // understood the call and has no peer, the second says it has no call.
    table.register(
        ::syscall::SyscallNumber::TlsConnect,
        crate::syscall::tls_connect,
    );
    // The trust anchors a program adds at run time.  They are separate from
    // the built-in set `certs/` compiles in, and nothing here can withdraw one
    // of those: a program's anchor is its own trust decision.
    table.register(
        ::syscall::SyscallNumber::TrustAnchorAdd,
        crate::syscall::trust_anchor_add,
    );
    table.register(
        ::syscall::SyscallNumber::TrustAnchorRemove,
        crate::syscall::trust_anchor_remove,
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
    // Time, randomness and the two calls that report what this build is.
    // `GetTimeOfDay` and `GetRandom` answer from the clock and the generator
    // the boot seeded; `SystemInfo` and `AbiInfo` answer from the scheduler's
    // own counters and from constants, which is why they are here and not in
    // `process.rs`: nothing about them is the running program's.
    table.register(
        ::syscall::SyscallNumber::GetTimeOfDay,
        crate::syscall::get_time_of_day,
    );
    table.register(
        ::syscall::SyscallNumber::GetRandom,
        crate::syscall::get_random,
    );
    table.register(
        ::syscall::SyscallNumber::SystemInfo,
        crate::syscall::system_info,
    );
    table.register(::syscall::SyscallNumber::AbiInfo, crate::syscall::abi_info);
    // The network's first call, and the smallest: what the boot's exercise
    // installed is what a program asks about here.  The datagram calls
    // beside it are the two that answer at once, the receive parks, and a
    // handler that cannot park does not hold its number; its branch is in
    // the trap path, where the scheduler's parking machinery is.
    table.register(
        ::syscall::SyscallNumber::NetworkStatus,
        crate::syscall::network_status,
    );
    // The IPv6 side, beside it: the number is above the frozen boundary and
    // the record is its own, because `NetworkStatus`'s fourteen address
    // bytes are IPv4's and a sixteen-byte address does not fit where a
    // four-byte one goes.
    table.register(
        ::syscall::SyscallNumber::Ipv6Status,
        crate::syscall::ipv6_status,
    );
    // The machine's name, and the lookup a program asks by one.  A name is
    // not a socket and needs none of the calls below: it is a fact about this
    // boot's machine, which is why the two calls that set and read it are here
    // beside the status records.
    table.register(
        ::syscall::SyscallNumber::GetHostName,
        crate::syscall::get_host_name,
    );
    table.register(
        ::syscall::SyscallNumber::SetHostName,
        crate::syscall::set_host_name,
    );
    // A socket's two ends.  The handlers answer at once, which is what the
    // table is for: where a socket is is a fact the table holds, not a wait.
    table.register(
        ::syscall::SyscallNumber::GetSockName,
        crate::syscall::get_sock_name,
    );
    table.register(
        ::syscall::SyscallNumber::GetPeerName,
        crate::syscall::get_peer_name,
    );
    // The options a program may change about a socket.  Two handlers, one per
    // direction, because a set takes a validated value and a get writes into
    // one: the registry's argument shape has one buffer per call, and the two
    // calls differ in which way the bytes move.
    table.register(
        ::syscall::SyscallNumber::SetSockOpt,
        crate::syscall::set_sock_opt,
    );
    // The local-domain socket: a name two processes meet at, and the connection
    // they read and write through.  `BindLocal` and `ConnectLocal` answer at
    // once and the connect's own wake is what a waiting accept learns of;
    // `AcceptLocal` is registered here too, and its parking is the trap path's
    // branch, which is what `usize::MAX` from the handler means.
    table.register(
        ::syscall::SyscallNumber::BindLocal,
        crate::syscall::bind_local,
    );
    table.register(
        ::syscall::SyscallNumber::ConnectLocal,
        crate::syscall::connect_local,
    );
    table.register(
        ::syscall::SyscallNumber::AcceptLocal,
        crate::syscall::accept_local,
    );
    // The raw socket: a protocol number instead of a port, and the internet
    // layer's own payload.  `RecvRawPacket` parks like the datagram receive,
    // and its branch is in the trap path; the other two answer through the
    // registry.
    table.register(
        ::syscall::SyscallNumber::CreateRawSocket,
        crate::syscall::create_raw_socket,
    );
    table.register(
        ::syscall::SyscallNumber::SendRawPacket,
        crate::syscall::send_raw_packet,
    );
    table.register(
        ::syscall::SyscallNumber::GetSockOpt,
        crate::syscall::get_sock_opt,
    );
    // The lookup runs a socket exchange, so it is a handler that answers as
    // soon as the wire does rather than one that parks: the wait inside it is
    // bounded and the caller's own frame keeps running.
    #[cfg(target_os = "none")]
    table.register(
        ::syscall::SyscallNumber::ResolveHostname,
        crate::syscall::resolve_hostname,
    );
    table.register(::syscall::SyscallNumber::BindUdp, crate::syscall::bind_udp);
    table.register(
        ::syscall::SyscallNumber::SendToUdp,
        crate::syscall::send_to_udp,
    );
    // The stream calls that answer at once.  The accept parks, a handler
    // that cannot park does not hold it, and its branch is in the trap
    // path, where the scheduler's parking machinery is.
    table.register(
        ::syscall::SyscallNumber::ConnectTcp,
        crate::syscall::connect_tcp,
    );
    table.register(
        ::syscall::SyscallNumber::ListenTcp,
        crate::syscall::listen_tcp,
    );
    let served = table.served();

    // SAFETY: called once, after the namespace is set and every handler is
    // registered, before anything can serve a call.
    unsafe { crate::syscall::install(table) };

    arch::serial::write_str("protofire: syscall table installed, ");
    arch::serial::write_u32(served as u32);
    arch::serial::write_str(" number(s) served\n");
}
