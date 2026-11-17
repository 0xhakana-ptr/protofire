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
use user_abi::FILE_FLAG_COMPRESSED;
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
use user_abi::PUNCH_HOLE_KEEP_SIZE;
#[cfg(target_os = "none")]
use user_abi::SEEK_CUR;
#[cfg(target_os = "none")]
use user_abi::SEEK_END;
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
use user_abi::sys_accept_local;
#[cfg(target_os = "none")]
use user_abi::sys_accept_tcp;
#[cfg(target_os = "none")]
use user_abi::sys_access_query;
#[cfg(target_os = "none")]
use user_abi::sys_bind_local;
#[cfg(target_os = "none")]
use user_abi::sys_bind_udp;
#[cfg(target_os = "none")]
use user_abi::sys_brk;
#[cfg(target_os = "none")]
use user_abi::sys_close;
#[cfg(target_os = "none")]
use user_abi::sys_connect_local;
#[cfg(target_os = "none")]
use user_abi::sys_connect_tcp;
#[cfg(target_os = "none")]
use user_abi::sys_create_dir_at;
#[cfg(target_os = "none")]
use user_abi::sys_create_raw_socket;
#[cfg(target_os = "none")]
use user_abi::sys_dup;
#[cfg(target_os = "none")]
use user_abi::sys_dup2;
#[cfg(target_os = "none")]
use user_abi::sys_exit;
#[cfg(target_os = "none")]
use user_abi::sys_fallocate;
#[cfg(target_os = "none")]
use user_abi::sys_fcntl;
#[cfg(target_os = "none")]
use user_abi::sys_fdatasync;
#[cfg(target_os = "none")]
use user_abi::sys_fork;
#[cfg(target_os = "none")]
use user_abi::sys_fsync;
#[cfg(target_os = "none")]
use user_abi::sys_get_file_flags;
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
use user_abi::sys_get_xattr;
#[cfg(target_os = "none")]
use user_abi::sys_ipv6_status;
#[cfg(target_os = "none")]
use user_abi::sys_list_block_devices;
#[cfg(target_os = "none")]
use user_abi::sys_list_xattr;
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
use user_abi::sys_permission_metadata;
#[cfg(target_os = "none")]
use user_abi::sys_poll;
#[cfg(target_os = "none")]
use user_abi::sys_read;
#[cfg(target_os = "none")]
use user_abi::sys_read_console;
#[cfg(target_os = "none")]
use user_abi::sys_read_dir;
#[cfg(target_os = "none")]
use user_abi::sys_read_dir_fd;
#[cfg(target_os = "none")]
use user_abi::sys_recv_from_udp;
#[cfg(target_os = "none")]
use user_abi::sys_recv_raw_packet;
#[cfg(target_os = "none")]
use user_abi::sys_remove_path_at;
#[cfg(target_os = "none")]
use user_abi::sys_remove_xattr;
#[cfg(target_os = "none")]
use user_abi::sys_rename_at;
#[cfg(target_os = "none")]
use user_abi::sys_resolve_hostname;
#[cfg(target_os = "none")]
use user_abi::sys_seek;
#[cfg(target_os = "none")]
use user_abi::sys_send_raw_packet;
#[cfg(target_os = "none")]
use user_abi::sys_send_signal;
#[cfg(target_os = "none")]
#[cfg(target_os = "none")]
use user_abi::sys_send_to_udp;
#[cfg(target_os = "none")]
use user_abi::sys_set_fd_flags;
#[cfg(target_os = "none")]
use user_abi::sys_set_file_flags;
#[cfg(target_os = "none")]
use user_abi::sys_set_host_name;
#[cfg(target_os = "none")]
use user_abi::sys_set_length;
#[cfg(target_os = "none")]
use user_abi::sys_set_signal_mask;
#[cfg(target_os = "none")]
use user_abi::sys_set_sock_opt;
#[cfg(target_os = "none")]
use user_abi::sys_set_xattr;
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
use user_abi::sys_stat_fd;
#[cfg(target_os = "none")]
use user_abi::sys_sync;
#[cfg(target_os = "none")]
use user_abi::sys_system_info;
#[cfg(target_os = "none")]
#[cfg(target_os = "none")]
use user_abi::sys_wait_process_of;
#[cfg(target_os = "none")]
use user_abi::sys_wait_signal;
#[cfg(target_os = "none")]
use user_abi::sys_write;
#[cfg(target_os = "none")]
use user_abi::sys_write_debug;

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
/// The absolute path the attribute exercise uses: a file this program created
/// earlier in the same run, so a set that stored nothing cannot be mistaken
/// for a get that worked.
#[cfg(target_os = "none")]
static XATTR_PATH: &[u8] = b"/tmp/kept.txt\0";
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

    // The truncate, on a descriptor this program opened for writing.  The
    // whole claim is a **shrunk file**, so it is checked by stat rather than
    // by the call's status: a handler that answered zero without reaching the
    // node would satisfy the status and fail the size.  The descriptor's
    // position does not move, which is why the reopen below reads from the
    // start rather than from where the write left off.
    let truncated = insist(sys_open_at(
        notes,
        ANCHORED_NAME.as_ptr() as usize,
        OPEN_WRITE_CREATE,
    ));
    insist(sys_set_length(truncated, 2));
    insist(sys_close(truncated));

    let mut record = [0u8; 16];
    insist(sys_stat_at(
        notes,
        ANCHORED_NAME.as_ptr() as usize,
        &mut record,
    ));
    let (kind, size) = user_abi::stat_words(&record);
    if kind != 2 || size != 2 {
        sys_exit(240);
    }

    // The two console calls, and the pair is deliberately checked together:
    // `WriteDebug` puts a line on the screen and the serial port, and
    // `ReadConsole` answers zero because this machine has no keyboard driver
    // yet.  A program that expected a byte would park for ever, so what is
    // asserted is that the call is **served** and honest about it.
    let said_line = b"protofire: init says this through write_debug\n";
    let said = insist(sys_write_debug(said_line));
    // The length is the program's own constant, so the assertion is that the
    // kernel answered the count it was given rather than a number of its own.
    if said != said_line.len() {
        sys_exit(254);
    }
    let mut line = [0u8; 32];
    let typed = insist(sys_read_console(&mut line));
    if typed != 0 {
        sys_exit(255);
    }

    // The two duplicates, exercised where the descriptor table is already
    // holding a file: `Dup` answers a second handle on the same file, and
    // `Dup2` puts one on a number the caller names.  Both are checked on what
    // makes them distinct rather than on their answers alone -- the duplicate
    // reads the original's bytes, and the placed copy's number is the one that
    // was asked for.
    let held = insist(sys_open(GREETING_PATH.as_ptr() as usize, OPEN_READ));
    let duplicate = insist(sys_dup(held));
    if duplicate == held {
        sys_exit(251);
    }
    let placed = insist(sys_dup2(held, 12));
    if placed != 12 {
        sys_exit(251);
    }
    // Closing the original leaves both copies, which is what a handle rather
    // than an alias means.  The placed copy is read to prove it names the same
    // file: a fresh empty descriptor would answer zero bytes.
    insist(sys_close(duplicate));
    insist(sys_close(held));
    let mut copied = [0u8; 4];
    let read = insist(sys_read(placed, &mut copied));
    if read == 0 {
        sys_exit(251);
    }
    insist(sys_close(placed));

    // The descriptor control call, on a file whose access mode this program
    // chose: `F_GETFL` must answer the mode the open asked for, which is a fact
    // about this descriptor and not a constant.  `F_DUPFD` then places a copy
    // at or above seven, which is the floor the call exists for.
    let control = insist(sys_open(GREETING_PATH.as_ptr() as usize, OPEN_READ));
    if sys_fcntl(control, user_abi::F_GETFL, 0) != OPEN_READ {
        sys_exit(251);
    }
    let high = insist(sys_fcntl(control, user_abi::F_DUPFD, 7));
    if high < 7 {
        sys_exit(251);
    }
    insist(sys_close(high));
    insist(sys_close(control));

    // The device list and the whole-machine flush.  The record is the ABI's
    // `BlockDeviceInfoRecord`, read field by field at the offsets the ABI
    // publishes, so a handler that wrote the words where `#[repr(C)]` does not
    // put them fails here rather than passing a plausible-looking answer.
    let mut disk = [0u8; user_abi::BLOCK_DEVICE_INFO_RECORD_SIZE];
    insist(sys_list_block_devices(0, &mut disk));
    let block_size = u64::from_le_bytes(
        disk[user_abi::BLOCK_DEVICE_INFO_BLOCK_SIZE_OFFSET
            ..user_abi::BLOCK_DEVICE_INFO_BLOCK_SIZE_OFFSET + 8]
            .try_into()
            .expect("eight bytes"),
    );
    let block_count = u64::from_le_bytes(
        disk[user_abi::BLOCK_DEVICE_INFO_BLOCK_COUNT_OFFSET
            ..user_abi::BLOCK_DEVICE_INFO_BLOCK_COUNT_OFFSET + 8]
            .try_into()
            .expect("eight bytes"),
    );
    // The disk this boot attached, as the driver describes it: sectors of 512
    // bytes, a positive count, and writable.  The count is asserted as "above
    // zero" rather than as a number because it belongs to the image.
    if block_size != 512
        || block_count == 0
        || disk[user_abi::BLOCK_DEVICE_INFO_READ_ONLY_OFFSET] != 0
    {
        sys_exit(222);
    }
    // The name in the record is NUL-terminated and non-empty: a device with no
    // name is a record the handler answered without filling.
    if disk[0] == 0 {
        sys_exit(223);
    }
    // The devices past the first are ones this machine may or may not have:
    // x86_64 boots an NVMe controller and a SATA one beside the virtio disk,
    // and the other two machines have neither.  So what is asserted is the ABI
    // and not the machine's census: indexes past the first are listed until
    // the list refuses, which is what a machine's end looks like, and every
    // record named on the way must be as well-formed as the first, never a
    // zeroed one -- which is the answer a handler that walks past its own end
    // would give.
    let mut index = 1usize;
    loop {
        if user_abi::is_error_status(sys_list_block_devices(index, &mut disk)) {
            break;
        }
        let size = u64::from_le_bytes(
            disk[user_abi::BLOCK_DEVICE_INFO_BLOCK_SIZE_OFFSET
                ..user_abi::BLOCK_DEVICE_INFO_BLOCK_SIZE_OFFSET + 8]
                .try_into()
                .expect("eight bytes"),
        );
        let count = u64::from_le_bytes(
            disk[user_abi::BLOCK_DEVICE_INFO_BLOCK_COUNT_OFFSET
                ..user_abi::BLOCK_DEVICE_INFO_BLOCK_COUNT_OFFSET + 8]
                .try_into()
                .expect("eight bytes"),
        );
        if size == 0 || count == 0 || disk[0] == 0 {
            sys_exit(224);
        }
        index += 1;
        if index == 64 {
            sys_exit(225);
        }
    }
    // Every mounted filesystem flushed, in one call.
    insist(sys_sync());

    // The listing: one entry of the directory, by index, parsed the way the
    // ABI's record says, four words, then the name where the third word
    // points.
    let mut entry = [0u8; 64];
    let written = insist(sys_read_dir(NOTES_DIR.as_ptr() as usize, 0, &mut entry));
    if !lists_name(&entry, written, ANCHORED_NAME) {
        sys_exit(204);
    }

    // The same two readings asked of the **descriptor** instead of a name:
    // `StatFd` and `ReadDirFd`.  The directory is already open here, and the
    // point of the pair is that a caller holding it never needs the name it
    // was opened at.  Each answer is checked against the path form's, so a
    // call that read a different anchor fails rather than passing on a
    // plausible record.
    let mut by_descriptor = [0u8; 16];
    insist(sys_stat_fd(notes, &mut by_descriptor));
    let (kind, size) = user_abi::stat_words(&by_descriptor);
    // A directory's stat: kind 1 is `FILE_KIND_DIRECTORY`, and the size is
    // the backend's to choose, so only the kind is asserted.
    if kind != 1 {
        sys_exit(241);
    }

    let mut listed = [0u8; 64];
    let listed_bytes = insist(sys_read_dir_fd(notes, 0, &mut listed));
    if !lists_name(&listed, listed_bytes, ANCHORED_NAME) {
        sys_exit(242);
    }

    // The seek, on a fresh descriptor so nothing above depends on where it
    // leaves the position.  Two of the five whence values are checked, and
    // the pair is chosen because they are the two an unsigned offset cannot
    // express: from the end (a distance this program did not compute as an
    // absolute) and backwards from the current position.
    //
    // The read after each seek is the proof the position moved: the bytes that
    // come back are the ones at the offset the answer named, so a seek that
    // answered a number without moving would read from the wrong place.
    //
    // The file is the one this program wrote as `five` and truncated to two
    // bytes above, so its content is `fi` and its last byte sits at one.
    let seeker = insist(sys_open_at(
        notes,
        ANCHORED_NAME.as_ptr() as usize,
        OPEN_READ,
    ));
    let at_end = insist(sys_seek(seeker, -1, SEEK_END));
    if at_end != 1 {
        sys_exit(243);
    }
    let mut tail = [0u8; 1];
    if insist(sys_read(seeker, &mut tail)) != 1 || tail[0] != b'i' {
        sys_exit(244);
    }

    // Two back from here: the read above left the position at two, so this
    // lands on the first byte.  The step is what makes the case a *negative*
    // offset from the current position rather than an absolute one.
    let back = insist(sys_seek(seeker, -2, SEEK_CUR));
    if back != 0 {
        sys_exit(245);
    }
    let mut head = [0u8; 1];
    if insist(sys_read(seeker, &mut head)) != 1 || head[0] != b'f' {
        sys_exit(246);
    }
    insist(sys_close(seeker));

    // The two flushes, on the descriptor this program just wrote through.  The
    // answer is zero either way, so the check is that neither refuses: a
    // program that flushed and one that did not print the same status, which
    // is why the kernel's own line names which of the two ran.
    //
    // The write descriptor is reopened here rather than reused because the one
    // above was closed; a flush of a closed descriptor is the refusal this
    // would be testing instead of the call.
    let flushing = insist(sys_open_at(
        notes,
        ANCHORED_NAME.as_ptr() as usize,
        OPEN_WRITE_CREATE,
    ));
    insist(sys_fsync(flushing));
    insist(sys_fdatasync(flushing));
    insist(sys_close(flushing));

    // The punch and the two data-reduction flags, on a file at the **root**
    // rather than under `/tmp`, because the root is PyroFS and the tmpfs
    // answers `Unsupported` to the flags: a filesystem that does not carry the
    // byte says so rather than pretending the flag went somewhere.
    //
    // Two calls here are expected to be **refused**, and the program asserts
    // the refusal rather than success, so a later change that gives either one
    // its capability fails this check and has to come here and say so.
    //
    // 1. The punch: only this tree's NTFS volume makes holes, and the root is
    //    PyroFS.
    // 2. `Fsync` on this file: the driver never negotiates
    //    `VIRTIO_BLK_F_FLUSH`, so the card cannot answer a flush request.  That
    //    is a Level 7 gap and not this level's, and the honest thing for this
    //    program to do is record it rather than assert around it.
    let flagged = insist(sys_open(
        b"/flagged.txt\0".as_ptr() as usize,
        OPEN_WRITE_CREATE,
    ));
    insist(sys_write(flagged, b"four"));

    // The flush on the **real** volume, which is the case that was broken until
    // the driver learned to negotiate `VIRTIO_BLK_F_FLUSH`.  Before that, this
    // call submitted a request the card ignored and the driver's wait spun to
    // its fifty-million poll limit before answering `TimedOut`; the call was
    // served and unusable at the same time.
    if user_abi::is_error_status(sys_fsync(flagged)) {
        sys_exit(253);
    }

    let read_flags = sys_get_file_flags(flagged);
    if user_abi::is_error_status(read_flags) {
        sys_exit(252);
    }
    if read_flags != 0 {
        sys_exit(247);
    }

    // The set is refused on this volume, and that is the third thing this
    // block records rather than an obstacle.  PyroFS persists the flags byte
    // only in its V4 format, and the boot image is not V4: the volume says
    // `Unsupported`, which is the answer this tree prefers to a call that
    // wrote into a field the format would not keep.  A remount would lose it,
    // and a program told the call worked would have been lied to.
    let set = sys_set_file_flags(flagged, FILE_FLAG_COMPRESSED, 0);
    if !user_abi::is_error_status(set) {
        sys_exit(248);
    }
    // And nothing changed, which the read back says.
    let after = sys_get_file_flags(flagged);
    if user_abi::is_error_status(after) || after != 0 {
        sys_exit(249);
    }

    // The punch, refused by a volume that does not make holes.
    let punched = sys_fallocate(flagged, PUNCH_HOLE_KEEP_SIZE, 0, 2);
    if !user_abi::is_error_status(punched) {
        sys_exit(250);
    }
    insist(sys_close(flagged));

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

    // The four extended-attribute calls, on the file the rename left behind.
    // The round trip is what makes them evidence: the value read back is the
    // one written, and the list is parsed with the ABI's own offsets rather
    // than with the writer's, so a packing the handler got wrong fails here
    // rather than passing a plausible byte count.
    let attribute_name = b"user.motd\0";
    let attribute_value = b"hello";
    insist(sys_set_xattr(
        XATTR_PATH.as_ptr() as usize,
        attribute_name,
        attribute_value,
    ));
    let mut attribute = [0u8; 16];
    let read = insist(sys_get_xattr(
        XATTR_PATH.as_ptr() as usize,
        attribute_name,
        &mut attribute,
    ));
    if read != attribute_value.len() || attribute[..read] != attribute_value[..] {
        sys_exit(251);
    }
    let mut packed = [0u8; 128];
    let listed = insist(sys_list_xattr(XATTR_PATH.as_ptr() as usize, &mut packed));
    let record_size = user_abi::XATTR_ENTRY_RECORD_SIZE;
    if listed < record_size + attribute_value.len() {
        sys_exit(251);
    }
    let name_len = usize::from_le_bytes(
        packed[user_abi::XATTR_ENTRY_RECORD_NAME_LEN_OFFSET
            ..user_abi::XATTR_ENTRY_RECORD_NAME_LEN_OFFSET + 8]
            .try_into()
            .unwrap_or_default(),
    );
    let name_at = usize::from_le_bytes(
        packed[user_abi::XATTR_ENTRY_RECORD_NAME_OFFSET_OFFSET
            ..user_abi::XATTR_ENTRY_RECORD_NAME_OFFSET_OFFSET + 8]
            .try_into()
            .unwrap_or_default(),
    );
    if name_len != attribute_name.len() - 1
        || packed[name_at..name_at + name_len] != attribute_name[..name_len]
    {
        sys_exit(251);
    }
    insist(sys_remove_xattr(
        XATTR_PATH.as_ptr() as usize,
        attribute_name,
    ));
    if !is_error(sys_get_xattr(
        XATTR_PATH.as_ptr() as usize,
        attribute_name,
        &mut attribute,
    )) {
        sys_exit(251);
    }

    // The ownership read and the access query, on the same file.  The read is
    // unchecked and says what the mode is; the query says what this process may
    // do with it, which is a different answer and the one that needs an
    // identity.  Both records are parsed with the ABI's offsets, so a handler
    // that wrote the words elsewhere fails here.
    let mut ownership = [0u8; user_abi::PERMISSION_METADATA_RECORD_SIZE];
    insist(sys_permission_metadata(
        XATTR_PATH.as_ptr() as usize,
        &mut ownership,
    ));
    let mode = u16::from_le_bytes(
        ownership[user_abi::PERMISSION_METADATA_RECORD_MODE_OFFSET
            ..user_abi::PERMISSION_METADATA_RECORD_MODE_OFFSET + 2]
            .try_into()
            .unwrap_or_default(),
    );
    // tmpfs creates files `0o666`, and the mode is asserted as that number
    // rather than as "not zero": a handler that answered a default would pass
    // the weaker check.
    if mode != 0o666 {
        sys_exit(251);
    }

    let mut access = [0u8; user_abi::ACCESS_QUERY_RECORD_SIZE];
    insist(sys_access_query(
        XATTR_PATH.as_ptr() as usize,
        user_abi::ACCESS_WRITE_BIT,
        &mut access,
    ));
    let granted = u16::from_le_bytes(
        access[user_abi::ACCESS_QUERY_RECORD_GRANTED_MODE_BITS_OFFSET
            ..user_abi::ACCESS_QUERY_RECORD_GRANTED_MODE_BITS_OFFSET + 2]
            .try_into()
            .unwrap_or_default(),
    );
    let flags = u32::from_le_bytes(
        access[user_abi::ACCESS_QUERY_RECORD_FLAGS_OFFSET
            ..user_abi::ACCESS_QUERY_RECORD_FLAGS_OFFSET + 4]
            .try_into()
            .unwrap_or_default(),
    );
    if granted & user_abi::ACCESS_WRITE_BIT == 0 || flags & user_abi::ACCESS_QUERY_FLAG_ALLOWED == 0
    {
        sys_exit(251);
    }

    // The per-descriptor flag, and the readiness question.  The flag is read
    // back as a record rather than trusted: `F_GETFD` is the call that says
    // whether the byte landed.  The poll asks about a file, which is always
    // ready, so the answer is one and the record says why.
    let flagged = insist(sys_open(XATTR_PATH.as_ptr() as usize, OPEN_READ));
    insist(sys_set_fd_flags(flagged, user_abi::FD_CLOEXEC));
    if sys_fcntl(flagged, user_abi::F_GETFD, 0) != user_abi::FD_CLOEXEC {
        sys_exit(251);
    }
    insist(sys_set_fd_flags(flagged, 0));
    if sys_fcntl(flagged, user_abi::F_GETFD, 0) != 0 {
        sys_exit(251);
    }

    let mut asked = [user_abi::PollFd {
        fd: flagged as i32,
        events: user_abi::POLL_IN,
        revents: 0,
    }];
    let ready = insist(sys_poll(&mut asked));
    if ready != 1 || asked[0].revents & user_abi::POLL_IN == 0 {
        sys_exit(251);
    }
    insist(sys_close(flagged));

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

    // The local-domain socket: a name this process binds, a fork that
    // connects to it, an accept, and bytes in **both** directions.  Both ways
    // is the property a pipe-based local socket has to have and the previous
    // tree's did not: its connection was one pipe, so the server could never
    // answer.
    //
    // The child's exit status is the answer it received, which only a
    // connection that carried bytes back could have put in its register.
    const LOCAL_NAME: &[u8] = b"protofire.init.local";
    const ASK: &[u8] = b"local";
    const ANSWER: &[u8] = b"reply";

    let local_listener = insist(sys_bind_local(LOCAL_NAME));
    let local_child = insist(sys_fork());
    if local_child == 0 {
        let connection = insist(sys_connect_local(LOCAL_NAME));
        insist(sys_write(connection, ASK));
        let mut answer = [0u8; 16];
        let count = insist(sys_read(connection, &mut answer));
        if count != ANSWER.len() {
            sys_exit(236);
        }
        sys_exit(answer[0] as usize);
    }
    let connection = insist(sys_accept_local(local_listener));
    let mut question = [0u8; 16];
    let count = insist(sys_read(connection, &mut question));
    if count != ASK.len() || &question[..count] != ASK {
        sys_exit(237);
    }
    insist(sys_write(connection, ANSWER));
    let local_status = insist(sys_wait_process_of(local_child));
    // The child exits with the first byte of the answer, `r`, which is what a
    // connection that carried bytes back leaves in its register.
    if local_status != ANSWER[0] as usize {
        sys_exit(238);
    }
    insist(sys_close(connection));
    insist(sys_close(local_listener));

    // A raw socket: a protocol number instead of a port, and a packet this
    // process sends to itself, which is the one exchange a raw socket can
    // make without an answer from the wire.  The protocol is 253, which
    // RFC 3692 reserves for experimentation: nothing else on this machine
    // sends or receives it, so the packet the receive finds is the packet
    // this send put there.
    //
    // What the exchange proves is the whole path: the descriptor names a
    // protocol, the send composes an IP header with this machine's own
    // address, and the demux hands the payload back to the socket that named
    // the protocol.
    const RAW_PROTOCOL: u8 = 253;
    const RAW_PAYLOAD: &[u8] = b"raw";
    let raw = insist(sys_create_raw_socket(RAW_PROTOCOL));
    if insist(sys_send_raw_packet(
        raw,
        user_abi::pack_address(protocol),
        RAW_PAYLOAD,
    )) != RAW_PAYLOAD.len()
    {
        sys_exit(239);
    }
    let mut raw_buffer = [0u8; 16];
    let mut raw_sender = [0u8; 4];
    let raw_count = insist(sys_recv_raw_packet(raw, &mut raw_buffer, &mut raw_sender));
    if raw_count != RAW_PAYLOAD.len()
        || &raw_buffer[..raw_count] != RAW_PAYLOAD
        || raw_sender != protocol
    {
        sys_exit(235);
    }
    insist(sys_close(raw));

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
