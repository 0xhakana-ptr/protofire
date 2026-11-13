//! apps/init/src/main.rs
//!
//! `init`: the first program the kernel execs from its own filesystem, in
//! ring 3 — a **compiled** program, not machine code the boot copies from an
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
//! each answer — a program here cannot print a value, so the boot log is
//! where the evidence lives.
//!
//! ## Ring 3, and the one boundary the census records
//!
//! `init` runs unprivileged and reaches everything through syscalls, which is
//! the point: a bug here faults this process, not the machine.  The calls go
//! through **one gate per machine** — `syscall6`, six argument words in, one
//! answer out — plus the `exit` that does not return, and every operation
//! above them is a machine-independent wrapper that names the number and the
//! slots.  A new architecture teaches this file two pieces of assembly, not
//! one per operation, which is the whole reason the gate looks like this.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
use core::arch::asm;
#[cfg(target_os = "none")]
use core::panic::PanicInfo;

// The paths, NUL-terminated in this image's own `.rodata`.
//
// A file the boot's namespace answers for: `/tmp` is the tmpfs the boot
// mounts for scratch space, so what this program writes is a file the
// kernel holds, not a constant this program was handed.

/// The path `init` reads first.
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

/// The bytes written into `/tmp/note.txt` and read back after the rename.
#[cfg(target_os = "none")]
static NOTE_TEXT: &[u8] = b"protofire was here\n";

/// The read's buffer length: longer than the greeting, shorter than a page.
#[cfg(target_os = "none")]
const BUFFER_LEN: usize = 32;

/// The ABI's syscall numbers, spelled here because a program compiles against
/// the numbering, not against the kernel's crate.
#[cfg(target_os = "none")]
const SYS_OPEN: usize = 2;
#[cfg(target_os = "none")]
const SYS_EXIT: usize = 3;
#[cfg(target_os = "none")]
const SYS_READ: usize = 5;
#[cfg(target_os = "none")]
const SYS_WRITE: usize = 6;
#[cfg(target_os = "none")]
const SYS_CLOSE: usize = 7;
#[cfg(target_os = "none")]
#[cfg(target_os = "none")]
#[cfg(target_os = "none")]
const SYS_CREATE_DIR_AT: usize = 35;
#[cfg(target_os = "none")]
const SYS_REMOVE_PATH_AT: usize = 36;
#[cfg(target_os = "none")]
const SYS_STAT: usize = 27;
#[cfg(target_os = "none")]
const SYS_READ_DIR: usize = 28;
#[cfg(target_os = "none")]
#[cfg(target_os = "none")]
const SYS_OPEN_AT: usize = 32;
#[cfg(target_os = "none")]
const SYS_STAT_AT: usize = 33;
#[cfg(target_os = "none")]
const SYS_RENAME_AT: usize = 34;
#[cfg(target_os = "none")]
const SYS_MMAP: usize = 67;
#[cfg(target_os = "none")]
const SYS_BRK: usize = 92;

/// The open flags this program uses.
#[cfg(target_os = "none")]
const OPEN_READ: usize = 1;
#[cfg(target_os = "none")]
const OPEN_WRITE_CREATE: usize = 2 | 4;
/// Readable and writable, which is what a mapping this program stores into
/// needs.  Not executable: the kernel refuses write-xor-execute together, and
/// a page of data is not a page of code.
#[cfg(target_os = "none")]
const PROT_READ_WRITE: usize = 1 | 2;
/// Anonymous private memory: the only kind this kernel maps.
#[cfg(target_os = "none")]
const MAP_ANONYMOUS_PRIVATE: usize = 0x20 | 0x02;
/// One page, which is the smallest mapping worth asking for.
#[cfg(target_os = "none")]
const MMAP_BYTES: usize = 4096;
/// The descriptor value that means "resolve from the caller's own base".
#[cfg(target_os = "none")]
const AT_FDCWD: usize = (-100_isize) as usize;

// The gate, one per machine.
//
// Six argument words in, one answer out — the whole of the ABI's calling
// convention, which is why there is one of these and not one per operation.

/// The call gate: `int 0x80`, arguments in `rdi`..`r9`, answer in `rax`.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn syscall6(
    number: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> usize {
    let answer: u64;
    // SAFETY: `int 0x80` with the arguments in the registers the ABI names;
    // the kernel validates every one of them and answers with a value.
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number as u64 => answer,
            in("rdi") a0 as u64,
            in("rsi") a1 as u64,
            in("rdx") a2 as u64,
            // `int 0x80`, so the fourth argument is `rcx` and not `r10`: the
            // tree's call gate is the interrupt, and the trap entry reads the
            // six words from `rdi, rsi, rdx, rcx, r8, r9`.  Writing `r10` put
            // the flags where nothing reads them, and every call was refused
            // as `InvalidArgument` — measured, both calls answered `-1` on
            // x86_64 while the other two machines were fine.
            in("rcx") a3 as u64,
            in("r8") a4 as u64,
            in("r9") a5 as u64,
            options(nostack)
        );
    }
    answer as usize
}

/// The call gate: `svc #0`, number in `x8`, arguments in `x0`..`x5`.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn syscall6(
    number: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> usize {
    let answer: usize;
    // SAFETY: `svc #0` with the arguments in the registers the ABI names.
    unsafe {
        asm!(
            "svc #0",
            in("x8") number,
            inlateout("x0") a0 => answer,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            in("x4") a4,
            in("x5") a5,
            options(nostack)
        );
    }
    answer
}

/// The call gate: `ecall`, number in `a7`, arguments in `a0`..`a5`.
#[cfg(all(target_os = "none", target_arch = "riscv64"))]
fn syscall6(
    number: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> usize {
    let answer: usize;
    // SAFETY: `ecall` with the arguments in the registers the ABI names.
    unsafe {
        asm!(
            "ecall",
            in("a7") number,
            inlateout("a0") a0 => answer,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            in("a5") a5,
            options(nostack)
        );
    }
    answer
}

// The operations.  Machine-independent: each one names its number and packs
// its slots, which is the whole of what a wrapper is for.

/// `open(path, flags)`: the descriptor, or the ABI's error encoding.
#[cfg(target_os = "none")]
fn sys_open(path: usize, flags: usize) -> usize {
    syscall6(SYS_OPEN, path, flags, 0, 0, 0, 0)
}

/// `read(descriptor, offset, buffer, length)`: the byte count.
#[cfg(target_os = "none")]
fn sys_read(descriptor: usize, buffer: &mut [u8]) -> usize {
    // The offset is `READ_OFFSET_CURRENT`: the descriptor's own position,
    // which is what a caller that just wants the next bytes asks for.
    syscall6(
        SYS_READ,
        descriptor,
        usize::MAX,
        buffer.as_mut_ptr() as usize,
        buffer.len(),
        0,
        0,
    )
}

/// `write(descriptor, buffer, length)`: the bytes accepted.
#[cfg(target_os = "none")]
fn sys_write(descriptor: usize, buffer: &[u8]) -> usize {
    syscall6(
        SYS_WRITE,
        descriptor,
        buffer.as_ptr() as usize,
        buffer.len(),
        0,
        0,
        0,
    )
}

/// `close(descriptor)`.
#[cfg(target_os = "none")]
fn sys_close(descriptor: usize) -> usize {
    syscall6(SYS_CLOSE, descriptor, 0, 0, 0, 0, 0)
}

/// `create_dir_at(dirfd, path)`.
#[cfg(target_os = "none")]
fn sys_create_dir_at(dirfd: usize, path: usize) -> usize {
    syscall6(SYS_CREATE_DIR_AT, dirfd, path, 0, 0, 0, 0)
}

/// `remove_path_at(dirfd, path)`.
#[cfg(target_os = "none")]
fn sys_remove_path_at(dirfd: usize, path: usize) -> usize {
    syscall6(SYS_REMOVE_PATH_AT, dirfd, path, 0, 0, 0, 0)
}

/// `stat(path, record, length)`: zero, with the record filled.
#[cfg(target_os = "none")]
fn sys_stat(path: usize, record: &mut [u8; 16]) -> usize {
    syscall6(
        SYS_STAT,
        path,
        record.as_mut_ptr() as usize,
        record.len(),
        0,
        0,
        0,
    )
}

/// `read_dir(path, index, buffer, length)`: the bytes written.
#[cfg(target_os = "none")]
fn sys_read_dir(path: usize, index: usize, buffer: &mut [u8]) -> usize {
    syscall6(
        SYS_READ_DIR,
        path,
        index,
        buffer.as_mut_ptr() as usize,
        buffer.len(),
        0,
        0,
    )
}

/// `open_at(dirfd, path, flags)`: the descriptor, or the error encoding.
#[cfg(target_os = "none")]
fn sys_open_at(dirfd: usize, path: usize, flags: usize) -> usize {
    syscall6(SYS_OPEN_AT, dirfd, path, flags, 0, 0, 0)
}

/// `stat_at(dirfd, path, record, length)`: zero, with the record filled.
#[cfg(target_os = "none")]
fn sys_stat_at(dirfd: usize, path: usize, record: &mut [u8; 16]) -> usize {
    syscall6(
        SYS_STAT_AT,
        dirfd,
        path,
        record.as_mut_ptr() as usize,
        record.len(),
        0,
        0,
    )
}

/// `rename_at(old_dirfd, old, new_dirfd, new)`.
#[cfg(target_os = "none")]
fn sys_rename_at(old_dirfd: usize, old_path: usize, new_dirfd: usize, new_path: usize) -> usize {
    syscall6(
        SYS_RENAME_AT,
        old_dirfd,
        old_path,
        new_dirfd,
        new_path,
        0,
        0,
    )
}

/// `mmap(hint, length, prot, flags)`: the base address, or an error encoding.
#[cfg(target_os = "none")]
fn sys_mmap(hint: usize, length: usize, protection: usize, flags: usize) -> usize {
    syscall6(SYS_MMAP, hint, length, protection, flags, 0, 0)
}

/// `brk(new_break)`: the break the kernel now holds.
#[cfg(target_os = "none")]
fn sys_brk(requested: usize) -> usize {
    syscall6(SYS_BRK, requested, 0, 0, 0, 0, 0)
}

/// `exit(status)`: control does not come back.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn sys_exit(status: usize) -> ! {
    unsafe {
        asm!(
            "int 0x80",
            in("rax") SYS_EXIT as u64,
            in("rdi") status as u64,
            options(noreturn, nostack)
        );
    }
}

/// `exit(status)`: control does not come back.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn sys_exit(status: usize) -> ! {
    unsafe {
        asm!(
            "svc #0",
            in("x8") SYS_EXIT,
            in("x0") status,
            options(noreturn, nostack)
        );
    }
}

/// `exit(status)`: control does not come back.
#[cfg(all(target_os = "none", target_arch = "riscv64"))]
fn sys_exit(status: usize) -> ! {
    unsafe {
        asm!(
            "ecall",
            in("a7") SYS_EXIT,
            in("a0") status,
            options(noreturn, nostack)
        );
    }
}

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

/// Whether a syscall's answer is the ABI's error encoding.
///
/// The ABI encodes an error as a word with its high bit set, which is the one
/// test a program needs: a successful answer is a small positive number — a
/// descriptor, a count, an address inside the user window.
#[cfg(target_os = "none")]
const fn is_error(answer: usize) -> bool {
    answer & (1 << (usize::BITS - 1)) != 0
}

/// End the program because a step did not do what it was told.
///
/// Any answer this program cannot use ends it here, with a status the boot's
/// exit line shows as not the greeting's byte — which is how a broken step
/// turns the gate red instead of the program printing something plausible
/// and carrying on over a hole.  Which step broke is the kernel log's to
/// say: every call's answer is printed beside the mechanism that served it.
#[cfg(target_os = "none")]
fn insist(answer: usize) -> usize {
    if is_error(answer) {
        sys_exit(200);
    }
    answer
}

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
    // linker fixed — the loader maps the segments at their linked addresses,
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
    // calls' evidence lines name a descriptor — the kernel's proof that the
    // path was resolved against where the caller was, not against a root
    // the caller happened to share.
    let tmp = insist(sys_open_at(
        AT_FDCWD,
        b"/tmp\0".as_ptr() as usize,
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
    let (kind, size) = stat_words(&record);
    if kind != 2 || size != NOTE_TEXT.len() {
        sys_exit(202);
    }

    // The directory, made through the anchor, then opened to be one.
    insist(sys_create_dir_at(tmp, NOTES_NAME.as_ptr() as usize));
    let notes = insist(sys_open_at(tmp, NOTES_NAME.as_ptr() as usize, OPEN_READ));

    // A name inside it, relative to *that* descriptor — two anchors deep.
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
    let (kind, size) = stat_words(&record);
    if kind != 2 || size != 4 {
        sys_exit(203);
    }

    // The listing: one entry of the directory, by index, parsed the way the
    // ABI's record says — four words, then the name where the third word
    // points.
    let mut entry = [0u8; 64];
    let written = insist(sys_read_dir(NOTES_DIR.as_ptr() as usize, 0, &mut entry));
    if !lists_name(&entry, written, ANCHORED_NAME) {
        sys_exit(204);
    }

    // The rename, each side anchored at the `/tmp` descriptor: both names
    // resolve into the same filesystem, which is what a rename requires —
    // one that crossed volumes would be a copy and a delete, and this
    // kernel refuses that rather than approximating it.  Then the read back
    // under the new name — the bytes moved with it.
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
    let (kind, size) = stat_words(&record);
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

    // The anchors are done with, and a slot closed is a slot the kernel got
    // back: the exit's release line reports what this program left open,
    // which is nothing.
    insist(sys_close(notes));
    insist(sys_close(tmp));

    sys_exit(first)
}

/// The two words of a filled `FileStat` record, as the ABI lays them out.
#[cfg(target_os = "none")]
fn stat_words(record: &[u8; 16]) -> (usize, usize) {
    let mut kind_bytes = [0u8; 8];
    let mut size_bytes = [0u8; 8];
    kind_bytes.copy_from_slice(&record[..8]);
    size_bytes.copy_from_slice(&record[8..]);
    (
        usize::from_le_bytes(kind_bytes),
        usize::from_le_bytes(size_bytes),
    )
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
