//! apps/init/src/main.rs
//!
//! `init`: the first program the kernel execs from its own filesystem, in
//! ring 3, a **compiled** program, not machine code the boot copies from an
//! array.
//!
//! ## What it does, and why that
//!
//! One file read, end to end: `open` the boot's `/greeting.txt`, `read` it,
//! `close` the descriptor, and `exit` with the **first byte**.  That is the
//! whole of the proof that a program built by the workspace's own toolchain,
//! delivered as bytes in a filesystem, was loaded by the kernel's loader,
//! mapped into a fresh address space, and run: the exit status is the file's
//! content, and content cannot be faked by a call that skipped the read.
//!
//! On top of that read stands the rest of what a filesystem is for, in the
//! order a program would use it: map a page and read its own break, **write**
//! a file and read the bytes back, `stat` what it wrote, make a directory,
//! open and stat *relative to* that directory, list the directory, rename
//! the file, and remove a file it made for the purpose.  Every one of those
//! is a call this kernel serves, and the kernel prints its own line beside
//! each answer, a program here cannot print a value, so the boot log is
//! where the evidence lives.
//!
//! ## Ring 3, and where the wrappers live
//!
//! `init` runs unprivileged and reaches everything through syscalls, which is
//! the point: a bug here faults this process, not the machine.  The calls go
//! through the `user_abi` crate's one gate per machine, and this file is the
//! program, not the gate: it names what it does and the order it does it in,
//! which is the part that is init's and nobody else's.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
use core::panic::PanicInfo;

#[cfg(target_os = "none")]
use user_abi::AT_FDCWD;
#[cfg(target_os = "none")]
use user_abi::CLOCK_MONOTONIC;
#[cfg(target_os = "none")]
use user_abi::MAP_ANONYMOUS_PRIVATE;
#[cfg(target_os = "none")]
use user_abi::MMAP_BYTES;
#[cfg(target_os = "none")]
use user_abi::OPEN_READ;
#[cfg(target_os = "none")]
use user_abi::OPEN_WRITE_CREATE;
#[cfg(target_os = "none")]
use user_abi::PROT_READ_WRITE;
#[cfg(target_os = "none")]
use user_abi::SIGUSR1;
#[cfg(target_os = "none")]
use user_abi::SYSTEM_INFO_SCHEDULER;
#[cfg(target_os = "none")]
use user_abi::insist;
#[cfg(target_os = "none")]
use user_abi::is_error;
#[cfg(target_os = "none")]
use user_abi::sys_abi_info;
#[cfg(target_os = "none")]
use user_abi::sys_accept_tcp;
#[cfg(target_os = "none")]
use user_abi::sys_bind_udp;
#[cfg(target_os = "none")]
use user_abi::sys_brk;
#[cfg(target_os = "none")]
use user_abi::sys_close;
#[cfg(target_os = "none")]
use user_abi::sys_connect_tcp;
#[cfg(target_os = "none")]
use user_abi::sys_create_dir_at;
#[cfg(target_os = "none")]
use user_abi::sys_exit;
#[cfg(target_os = "none")]
use user_abi::sys_fork;
#[cfg(target_os = "none")]
#[cfg(target_os = "none")]
use user_abi::sys_get_host_name;
#[cfg(target_os = "none")]
use user_abi::sys_get_peer_name;
#[cfg(target_os = "none")]
use user_abi::sys_get_random;
#[cfg(target_os = "none")]
use user_abi::sys_get_sock_name;
#[cfg(target_os = "none")]
use user_abi::sys_get_sock_opt;
#[cfg(target_os = "none")]
use user_abi::sys_get_time_of_day;
#[cfg(target_os = "none")]
use user_abi::sys_ipv6_status;
#[cfg(target_os = "none")]
use user_abi::sys_listen_tcp;
#[cfg(target_os = "none")]
use user_abi::sys_mmap;
#[cfg(target_os = "none")]
use user_abi::sys_network_status;
#[cfg(target_os = "none")]
use user_abi::sys_open;
#[cfg(target_os = "none")]
use user_abi::sys_open_at;
#[cfg(target_os = "none")]
use user_abi::sys_read;
#[cfg(target_os = "none")]
use user_abi::sys_read_dir;
#[cfg(target_os = "none")]
use user_abi::sys_recv_from_udp;
#[cfg(target_os = "none")]
use user_abi::sys_remove_path_at;
#[cfg(target_os = "none")]
use user_abi::sys_rename_at;
#[cfg(target_os = "none")]
use user_abi::sys_resolve_hostname;
#[cfg(target_os = "none")]
use user_abi::sys_send_signal;
#[cfg(target_os = "none")]
#[cfg(target_os = "none")]
use user_abi::sys_send_to_udp;
#[cfg(target_os = "none")]
use user_abi::sys_set_host_name;
#[cfg(target_os = "none")]
use user_abi::sys_set_signal_mask;
#[cfg(target_os = "none")]
use user_abi::sys_set_sock_opt;
#[cfg(target_os = "none")]
use user_abi::sys_sigsuspend;
#[cfg(target_os = "none")]
use user_abi::sys_spawn;
#[cfg(target_os = "none")]
use user_abi::sys_stat;
#[cfg(target_os = "none")]
#[cfg(target_os = "none")]
use user_abi::sys_stat_at;
#[cfg(target_os = "none")]
use user_abi::sys_system_info;
#[cfg(target_os = "none")]
#[cfg(target_os = "none")]
use user_abi::sys_wait_process_of;
#[cfg(target_os = "none")]
use user_abi::sys_wait_signal;
#[cfg(target_os = "none")]
use user_abi::sys_write;

/// The path `init` reads first, NUL-terminated in its own `.rodata`.
///
/// A file the boot's namespace answers for: `/tmp` is the tmpfs the boot
/// mounts for scratch space, so what this program writes is a file the
/// kernel holds, not a constant this program was handed.
#[cfg(target_os = "none")]
static GREETING_PATH: &[u8] = b"/greeting.txt\0";

/// The names this program passes **relative** to the descriptor it opened,
/// which is the whole of what the `*At` calls are for.
#[cfg(target_os = "none")]
static NOTE_NAME: &[u8] = b"note.txt\0";
#[cfg(target_os = "none")]
static KEPT_NAME: &[u8] = b"kept.txt\0";
#[cfg(target_os = "none")]
static NOTES_NAME: &[u8] = b"notes\0";
#[cfg(target_os = "none")]
static ANCHORED_NAME: &[u8] = b"at.txt\0";
#[cfg(target_os = "none")]
static SCRATCH_NAME: &[u8] = b"scratch.txt\0";
/// The one absolute path this program lists, because `ReadDir` has no `*At`
/// twin served yet and the directory is named by its path.
#[cfg(target_os = "none")]
static NOTES_DIR: &[u8] = b"/tmp/notes\0";
/// The program this process starts: the tree's second image, on the same
/// volume this program's own bytes came from.
#[cfg(target_os = "none")]
static SHELL_PATH: &[u8] = b"/bin/shell\0";
/// The status the shell answers when it ran: the greeting's length, which
/// no constant this process carries can fake.
#[cfg(target_os = "none")]
const SHELL_STATUS: usize = 23;
/// The absolute path of the `/tmp` mount, reached once through the sentinel
/// to become every later call's anchor.
#[cfg(target_os = "none")]
static TMP_MOUNT: &[u8] = b"/tmp\0";

/// The bytes written into the note file and read back after the rename.
#[cfg(target_os = "none")]
static NOTE_TEXT: &[u8] = b"protofire was here\n";

/// The bytes the datagram exchange sends: the child's payload, the parent's
/// expectation, and the child's exit status all name the same nine bytes.
#[cfg(target_os = "none")]
static DATAGRAM_TEXT: &[u8] = b"protofire";

/// The read's buffer length: longer than the greeting, shorter than a page.
#[cfg(target_os = "none")]
const BUFFER_LEN: usize = 32;

/// What a panic does in a program with no unwinder: stop.
///
/// There is nowhere to unwind to and no console this program owns.  Stopping
/// leaves the machine in a state a debugger can read, and the kernel's
/// fatal-fault machinery is what turns it into a line if it ever fires.
#[cfg(target_os = "none")]
#[cfg_attr(target_os = "none", panic_handler)]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// The host build, which is a typecheck and nothing else.
#[cfg(not(target_os = "none"))]
fn main() {}

/// The program's entry, named by the linker script.
///
/// Machine-only: the host build links its own crt, whose `_start` this would
/// collide with, and a host has no syscalls to reach.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut buffer = [0u8; BUFFER_LEN];

    // The greeting read, and the exit status it decides.
    //
    // The path's address is this image's own `.rodata`, at the address the
    // linker fixed, the loader maps the segments at their linked addresses,
    // which is why the constant is the truth and not a guess.
    let first = read_first_byte(
        insist(sys_open(GREETING_PATH.as_ptr() as usize, OPEN_READ)),
        &mut buffer,
    );

    // Two memory calls, and the kernel prints both answers.
    //
    // What makes the pair worth having is that neither number can be
    // invented: the mapping's base is inside this program's window and the
    // break is past its own stack, and a kernel that had mapped nothing
    // could not name either.
    //
    // The **store** is the part that proves the mapping is real: a page the
    // kernel reported but did not map faults here, and the boot would show
    // the fault instead of the exit status.
    let mapping = insist(sys_mmap(
        0,
        MMAP_BYTES,
        PROT_READ_WRITE,
        MAP_ANONYMOUS_PRIVATE,
    ));
    // SAFETY: the kernel just answered with a base it mapped writable for
    // this program, one page long, which is what this program asked for.
    unsafe { core::ptr::write_volatile(mapping as *mut u8, first as u8) };
    let _ = insist(sys_brk(0));

    // The anchor: an open of `/tmp` itself, held for the whole program.
    //
    // Every name below is relative to it, which is what makes the `*At`
    // calls' evidence lines name a descriptor, the kernel's proof that the
    // path was resolved against where the caller was, not against a root
    // the caller happened to share.
    let tmp = insist(sys_open_at(
        AT_FDCWD,
        TMP_MOUNT.as_ptr() as usize,
        OPEN_READ,
    ));

    // The write: create a file through the anchor, put bytes in it, close it.
    //
    // The kernel prints how many bytes it accepted; the read-back below is
    // what says they are the bytes this program sent.
    let note = insist(sys_open_at(
        tmp,
        NOTE_NAME.as_ptr() as usize,
        OPEN_WRITE_CREATE,
    ));
    insist(sys_write(note, NOTE_TEXT));
    insist(sys_close(note));

    // The read back, through a fresh open: the bytes are the file's now, not
    // the descriptor's.  A mismatch is a step that lied, and ends the
    // program the same way a refused call does.
    let note = insist(sys_open_at(tmp, NOTE_NAME.as_ptr() as usize, OPEN_READ));
    let mut back = [0u8; NOTE_TEXT.len()];
    let read = insist(sys_read(note, &mut back));
    insist(sys_close(note));
    if read != NOTE_TEXT.len() || back != *NOTE_TEXT {
        sys_exit(201);
    }

    // The stat, anchored: the file's own record, read from the memory the
    // kernel filled.  Kind 2 is `FILE_KIND_FILE`; the size is what the
    // write left.
    let mut record = [0u8; 16];
    insist(sys_stat_at(tmp, NOTE_NAME.as_ptr() as usize, &mut record));
    let (kind, size) = user_abi::stat_words(&record);
    if kind != 2 || size != NOTE_TEXT.len() {
        sys_exit(202);
    }

    // The directory, made through the anchor, then opened to be one.
    insist(sys_create_dir_at(tmp, NOTES_NAME.as_ptr() as usize));
    let notes = insist(sys_open_at(tmp, NOTES_NAME.as_ptr() as usize, OPEN_READ));

    // A name inside it, relative to *that* descriptor, two anchors deep.
    let anchored = insist(sys_open_at(
        notes,
        ANCHORED_NAME.as_ptr() as usize,
        OPEN_WRITE_CREATE,
    ));
    insist(sys_write(anchored, b"five"));
    insist(sys_close(anchored));

    let mut record = [0u8; 16];
    insist(sys_stat_at(
        notes,
        ANCHORED_NAME.as_ptr() as usize,
        &mut record,
    ));
    let (kind, size) = user_abi::stat_words(&record);
    if kind != 2 || size != 4 {
        sys_exit(203);
    }

    // The listing: one entry of the directory, by index, parsed the way the
    // ABI's record says, four words, then the name where the third word
    // points.
    let mut entry = [0u8; 64];
    let written = insist(sys_read_dir(NOTES_DIR.as_ptr() as usize, 0, &mut entry));
    if !lists_name(&entry, written, ANCHORED_NAME) {
        sys_exit(204);
    }

    // The rename, each side anchored at the `/tmp` descriptor: both names
    // resolve into the same filesystem, which is what a rename requires
    // one that crossed volumes would be a copy and a delete, and this
    // kernel refuses that rather than approximating it.  Then the read back
    // under the new name, the bytes moved with it.
    insist(sys_rename_at(
        tmp,
        NOTE_NAME.as_ptr() as usize,
        tmp,
        KEPT_NAME.as_ptr() as usize,
    ));
    let kept = insist(sys_open_at(tmp, KEPT_NAME.as_ptr() as usize, OPEN_READ));
    let mut back = [0u8; NOTE_TEXT.len()];
    let read = insist(sys_read(kept, &mut back));
    insist(sys_close(kept));
    if read != NOTE_TEXT.len() || back != *NOTE_TEXT {
        sys_exit(205);
    }

    // The plain stat, one absolute name: the same record without an anchor,
    // for the file the rename left behind.
    let mut record = [0u8; 16];
    insist(sys_stat(b"/tmp/kept.txt\0".as_ptr() as usize, &mut record));
    let (kind, size) = user_abi::stat_words(&record);
    if kind != 2 || size != NOTE_TEXT.len() {
        sys_exit(207);
    }

    // The remove, of a file made for the purpose: created, closed, gone.
    let scratch = insist(sys_open_at(
        tmp,
        SCRATCH_NAME.as_ptr() as usize,
        OPEN_WRITE_CREATE,
    ));
    insist(sys_close(scratch));
    insist(sys_remove_path_at(tmp, SCRATCH_NAME.as_ptr() as usize));
    if !is_error(sys_open_at(tmp, SCRATCH_NAME.as_ptr() as usize, OPEN_READ)) {
        sys_exit(206);
    }

    // The spawn, and the wait that supervises it: this process starts the
    // tree's second program, and its own exit waits for the child's.  The
    // child's status is the greeting's length, a number that is only on
    // the wire because the kernel loaded a second image from the filesystem
    // and ran it, which is the whole of what this pair of calls proves.
    let shell = insist(sys_spawn(SHELL_PATH.as_ptr() as usize));

    // The signal: the child arms its own handler, announces itself, and
    // spins for the delivery.  This process's part is the **send**, the
    // payload names the delivery, "ID", and the child's handler checks it
    // before counting it, and the wait for the child's exit is the proof
    // the delivery landed: a handler that never ran leaves a child that
    // never stops spinning.
    let mut record = [0u8; 24];
    insist(sys_wait_signal(&mut record));
    let (signal, sender, payload) = user_abi::signal_words(&record);
    if signal != SIGUSR1 || sender != shell || payload != 0x5348 {
        sys_exit(209);
    }
    insist(sys_send_signal(shell, SIGUSR1, 0x4944));
    let status = insist(sys_wait_process_of(shell));
    if status != SHELL_STATUS {
        sys_exit(208);
    }

    // The mask: the same exchange under a blocked signal.  The child's
    // announcement queues, this process's wait would skip it, and the
    // suspend runs the ring with everything unblocked, answers with the
    // queued record, and puts this process's mask back.  The delivery and
    // the exit follow as they did above.
    let _previous = insist(sys_set_signal_mask(1 << SIGUSR1));
    let second = insist(sys_spawn(SHELL_PATH.as_ptr() as usize));
    let mut record = [0u8; 24];
    insist(sys_sigsuspend(0, &mut record));
    let (signal, sender, payload) = user_abi::signal_words(&record);
    if signal != SIGUSR1 || sender != second || payload != 0x5348 {
        sys_exit(211);
    }
    insist(sys_send_signal(second, SIGUSR1, 0x4944));
    let status = insist(sys_wait_process_of(second));
    if status != SHELL_STATUS {
        sys_exit(210);
    }
    let restored = insist(sys_set_signal_mask(0));
    if restored != (1 << SIGUSR1) {
        sys_exit(212);
    }

    // The time and the information calls: four numbers served by the
    // registry, reached from ring 3.  Each one writes a record this program
    // reads back, which is what makes the kernel's line proof of a call
    // rather than of a handler that was compiled.
    //
    // The clock is checked for the two things a monotonic reading must have:
    // it is a number (the call answered), and two readings taken across work
    // do not go backwards.  The *gap* is not asserted, an emulator can hand
    // out the same reading twice in a row and that is not a defect, so the
    // claim is the weaker, true one.
    let mut time = [0u8; user_abi::TIME_RECORD_BYTES];
    insist(sys_get_time_of_day(CLOCK_MONOTONIC, &mut time));
    let (first_seconds, first_nanoseconds) = user_abi::time_words(&time);
    if first_nanoseconds >= 1_000_000_000 {
        sys_exit(213);
    }
    let mut later = [0u8; user_abi::TIME_RECORD_BYTES];
    insist(sys_get_time_of_day(CLOCK_MONOTONIC, &mut later));
    let (later_seconds, later_nanoseconds) = user_abi::time_words(&later);
    if (later_seconds, later_nanoseconds) < (first_seconds, first_nanoseconds) {
        sys_exit(214);
    }

    // The random call fills the buffer it was given, and the length it answers
    // is the length it was asked for.  Two draws being different is the
    // property that matters and it is checked here rather than assumed: a
    // generator that repeated itself would satisfy every other claim.
    let mut first_draw = [0u8; 16];
    let mut second_draw = [0u8; 16];
    if insist(sys_get_random(&mut first_draw)) != first_draw.len() {
        sys_exit(215);
    }
    if insist(sys_get_random(&mut second_draw)) != second_draw.len() {
        sys_exit(216);
    }
    if first_draw == second_draw {
        sys_exit(217);
    }

    // The two records, read back field by field against what the ABI says they
    // mean.  `AbiInfo` is the one a program can trust before anything else, so
    // the check is that this build's own numbering is what the record carries:
    // a slot count that was not above the highest call this program made would
    // mean the record and the table had drifted apart.
    let mut abi = [0u8; user_abi::ABI_INFO_BYTES];
    insist(sys_abi_info(&mut abi));
    let (version, slots, frozen) = user_abi::abi_words(&abi);
    if version == 0 || slots <= user_abi::SYS_WAIT_PROCESS_OF || frozen != 121 {
        sys_exit(218);
    }

    let mut system = [0u8; user_abi::SYSTEM_INFO_BYTES];
    insist(sys_system_info(SYSTEM_INFO_SCHEDULER, &mut system));
    // The frame counts are the fields this program can check against a fact it
    // already knows: the pool manages frames, and it cannot be handing out more
    // of them than it manages.
    let managed = read_word(&system, 6);
    let free = read_word(&system, 7);
    if managed == 0 || free > managed {
        sys_exit(219);
    }

    // The network: what this machine's card is, read from the record the
    // kernel filled.  The checks are the ones a program can make without
    // knowing the wire: a card the kernel drives, and three addresses that
    // are not the zeros a boot with no card would have left behind, the
    // values themselves are the kernel's line to print, because a program
    // here cannot.
    let mut network = [0u8; user_abi::NETWORK_STATUS_BYTES];
    insist(sys_network_status(&mut network));
    let (state, hardware, protocol, gateway) = user_abi::network_record(&network);
    if state != user_abi::NETWORK_STATUS_UP
        || hardware == [0; 6]
        || protocol == [0, 0, 0, 0]
        || gateway == [0, 0, 0, 0]
    {
        sys_exit(220);
    }

    // The machine's name: set one, read it back, and the two must agree.  The
    // name is the one fact about this machine a program can set itself, and a
    // call that answered but stored nothing would read back an empty string,
    // which is what a machine nobody named answers.
    const NAME: &str = "protofire";
    let mut name = [0u8; 64];
    let written = sys_get_host_name(&mut name);
    // The boot set no name, so the first answer is an empty string and not an
    // error: a name is not a permission and a machine that was never named is
    // not a machine that failed.
    if user_abi::is_error_status(written) || written != 0 {
        sys_exit(226);
    }
    if user_abi::is_error_status(sys_set_host_name(NAME)) {
        sys_exit(227);
    }
    let written = sys_get_host_name(&mut name);
    if written != NAME.len() || name[..NAME.len()] != *NAME.as_bytes() {
        sys_exit(228);
    }

    // The IPv6 side, read the same way: the interface must report an address
    // family whose link-local address is `fe80::` plus the MAC's own
    // modified EUI-64, the one fact a program can check without the wire,
    // and the one that says the address was derived from this card rather
    // than copied from somewhere.  A boot whose IPv6 side answered nothing
    // exits here rather than letting the IPv4 lines stand in for it.
    let mut ipv6 = [0u8; user_abi::IPV6_STATUS_BYTES];
    insist(sys_ipv6_status(&mut ipv6));
    let (ipv6_state, has_global, _neighbours, link_local, _global) =
        user_abi::ipv6_status_record(&ipv6);
    if ipv6_state != 1
        || link_local[0] != 0xFE
        || link_local[1] != 0x80
        || link_local[8] != (hardware[0] ^ 0x02)
        || link_local[9] != hardware[1]
        || link_local[10] != hardware[2]
        || link_local[11] != 0xFF
        || link_local[12] != 0xFE
        || link_local[13] != hardware[3]
        || link_local[14] != hardware[4]
        || link_local[15] != hardware[5]
    {
        // `has_global` is read and not asserted: a boot with no router is
        // the normal case, and a program that required one would fail on
        // every machine this tree runs on.
        let _ = has_global;
        sys_exit(221);
    }

    // The datagram exchange, between this process and a fork of it.  The
    // parent binds a port and receives; the child binds another, sends one
    // datagram to the parent's port, and exits with the length it sent as
    // its status.  A datagram to this machine's own address is delivered
    // through the kernel's demux, which is what loopback is, so the
    // exchange proves the bind, the send, the receive, and the port the
    // sender record names, all from ring 3.
    let socket = insist(sys_bind_udp(8612));
    let child = insist(sys_fork());
    if child == 0 {
        // The child's side: bind the port the parent's record will name,
        // send the one datagram, and its status is the length it sent, a
        // number only a completed send could have answered with.
        let mine = insist(sys_bind_udp(8613));
        let sent = insist(sys_send_to_udp(
            mine,
            user_abi::pack_address(protocol),
            DATAGRAM_TEXT,
            8612,
        ));
        sys_exit(sent);
    }
    // The parent's side.  The child may not have sent yet, so this receive
    // may park; the child's send is what wakes it.
    let mut datagram = [0u8; 16];
    let mut sender = [0u8; user_abi::UDP_SENDER_RECORD_BYTES];
    let count = insist(sys_recv_from_udp(socket, &mut datagram, &mut sender));
    let (source, source_port) = user_abi::sender_record(&sender);
    if count != DATAGRAM_TEXT.len()
        || source != protocol
        || source_port != 8613
        || &datagram[..DATAGRAM_TEXT.len()] != DATAGRAM_TEXT
    {
        sys_exit(221);
    }
    // The child's exit is the exchange's other half: a send that completed
    // is a child that exits with the length it sent.
    let child_status = insist(sys_wait_process_of(child));
    if child_status != DATAGRAM_TEXT.len() {
        sys_exit(222);
    }
    insist(sys_close(socket));

    // The stream exchange, the same two processes the datagram exchange
    // used: this process listens on a port and accepts; the fork connects,
    // writes its nine bytes, and reads the echo back, the child's own read
    // parks until this process's echo arrives, which is the wake the
    // stream's write makes.  The child's exit status is the echo's first
    // byte, which only a completed round trip could have carried.
    let listener = insist(sys_listen_tcp(9003));
    let child = insist(sys_fork());
    if child == 0 {
        // The child's side: connect, write, read the echo, and its status
        // is the echo's first byte.
        let stream = insist(sys_connect_tcp(user_abi::pack_address(protocol), 9003));
        insist(sys_write(stream, DATAGRAM_TEXT));
        let mut back = [0u8; 16];
        let count = insist(sys_read(stream, &mut back));
        if count != DATAGRAM_TEXT.len() {
            sys_exit(225);
        }
        sys_exit(back[0] as usize);
    }
    // The parent's side.  The accept may park until the child's handshake
    // opens one; the child's connect is what wakes it.
    let stream = insist(sys_accept_tcp(listener));

    // The stream's two ends, which is a fact the kernel holds and a program
    // cannot see any other way: this end answers on the port it listened on,
    // and the peer's port is the one the child connected from.  Both are
    // sixteen-byte `sockaddr_in` records, and the family word is read in host
    // order while the port is read in network order, which is the one detail a
    // hand-written record gets wrong.
    let mut socket = [0u8; user_abi::SOCKADDR_IN_BYTES];
    let size = insist(sys_get_sock_name(stream, &mut socket));
    if size != user_abi::SOCKADDR_IN_BYTES
        || user_abi::sockaddr_family(&socket) != 2
        || user_abi::sockaddr_port(&socket) != 9003
        || user_abi::sockaddr_address(&socket) != protocol
    {
        sys_exit(229);
    }
    let size = insist(sys_get_peer_name(stream, &mut socket));
    if size != user_abi::SOCKADDR_IN_BYTES
        || user_abi::sockaddr_family(&socket) != 2
        // The child's own port is the table's to choose, so this asserts that
        // it is **a** port and not zero: a record that answered nothing would
        // be all zeros and pass a check that only looked at the family.
        || user_abi::sockaddr_port(&socket) == 0
        || user_abi::sockaddr_address(&socket) != protocol
    {
        sys_exit(230);
    }

    // A socket option, set and read back from ring 3.  The number is chosen
    // so that both directions are exercised: a setter that stored nothing and
    // a getter that answered a default would disagree, and the option is one
    // this stack acts on, so a program is changing real behaviour rather than
    // filling a field.
    let narrowed = 4000_usize;
    if insist(sys_set_sock_opt(
        stream,
        user_abi::SOL_SOCKET,
        user_abi::SO_RCVBUF,
        &narrowed.to_le_bytes(),
    )) != 0
    {
        sys_exit(232);
    }
    let mut option = [0u8; core::mem::size_of::<usize>()];
    let written = insist(sys_get_sock_opt(
        stream,
        user_abi::SOL_SOCKET,
        user_abi::SO_RCVBUF,
        &mut option,
    ));
    if written != core::mem::size_of::<usize>() || usize::from_le_bytes(option) != narrowed {
        sys_exit(233);
    }
    // An option this build does not serve is refused, which is the half that
    // stops a program believing it set something.  `SO_KEEPALIVE` is a real
    // option number this stack has no keepalive to act on.
    if !user_abi::is_error_status(sys_set_sock_opt(stream, user_abi::SOL_SOCKET, 1, &[1])) {
        sys_exit(234);
    }

    let mut buffer = [0u8; 16];
    let count = insist(sys_read(stream, &mut buffer));
    if count != DATAGRAM_TEXT.len() || &buffer[..count] != DATAGRAM_TEXT {
        sys_exit(223);
    }
    insist(sys_write(stream, &buffer[..count]));
    let child_status = insist(sys_wait_process_of(child));
    if child_status != DATAGRAM_TEXT[0] as usize {
        sys_exit(224);
    }
    insist(sys_close(stream));
    insist(sys_close(listener));

    // The lookup a program asks by name.  Its answer is not asserted: the
    // name is resolved by whatever server the wire has, and a machine whose
    // network is not QEMU's may have none.  What the call proves either way is
    // that a program can reach it and that its answer is a status rather than
    // a refusal this build would give an unimplemented number.
    let resolved = sys_resolve_hostname("example.com");
    if user_abi::is_not_implemented(resolved) {
        // The number this build does not serve answers `NotImplemented`, and
        // that is the one answer a lookup must never give: it would mean the
        // call was never wired, which is exactly what this program is here to
        // rule out.
        sys_exit(231);
    }

    // The anchors are done with, and a slot closed is a slot the kernel got
    // back: the exit's release line reports what this program left open,
    // which is nothing.
    insist(sys_close(notes));
    insist(sys_close(tmp));

    sys_exit(first)
}

/// Whether a filled `ReadDir` record names the expected entry.
///
/// The record's fourth word is the name's length and its third is where the
/// name starts; the name that follows is compared byte for byte against the
/// static, which is what makes "the listing answered" a claim about *this*
/// entry and not about a buffer that stopped being zeros.
#[cfg(target_os = "none")]
fn lists_name(entry: &[u8; 64], written: usize, expected: &[u8]) -> bool {
    let _ = written;
    let mut offset_bytes = [0u8; 8];
    let mut len_bytes = [0u8; 8];
    offset_bytes.copy_from_slice(&entry[16..24]);
    len_bytes.copy_from_slice(&entry[24..32]);
    let offset = usize::from_le_bytes(offset_bytes);
    let len = usize::from_le_bytes(len_bytes);
    // The expected static is NUL-terminated for the kernel's sake; the
    // record's name is not.  The comparison is against the name alone.
    let name = &expected[..expected.len() - 1];
    offset + len <= entry.len() && &entry[offset..offset + len] == name
}

/// One word of a record, little-endian, at `index` words in.
#[cfg(target_os = "none")]
fn read_word(record: &[u8; 64], index: usize) -> usize {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&record[index * 8..index * 8 + 8]);
    usize::from_le_bytes(bytes)
}

/// Read the file and answer its first byte, closing the descriptor on the way
/// out either way: a slot left open in the table the kernel keeps is the kind
/// of leak that shows up as a limit much later.
#[cfg(target_os = "none")]
fn read_first_byte(descriptor: usize, buffer: &mut [u8]) -> usize {
    let read = insist(sys_read(descriptor, buffer));
    insist(sys_close(descriptor));
    if read == 0 {
        return 1;
    }
    buffer[0] as usize
}
