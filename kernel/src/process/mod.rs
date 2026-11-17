//! kernel/src/process/mod.rs
//!
//! One program, running at EL0, calling back into the kernel.
//!
//! What the kernel does with a program's supervisor call: two kinds of
//! answer.  The calls whose object lives in the scheduler or the pipe
//! `Exit`, `Sleep`, a pipe's `Read` and `Write`, `Fork`, `ExecProcess`,
//! `GetPid`, `GetPpid`, the three waits and `Pipe`, are served here,
//! because their object is.  Everything else is forwarded to the registry's
//! table, after this file has done the one thing only it can do: turned the
//! ring-3 words into the borrows the handlers take.  A number with neither
//! a branch here nor a handler in the table answers `NotImplemented`.
//!
//! The image a program runs is machine code, so it lives in `arch` and this
//! file asks for it.  An array here would have to be right for three
//! architectures, and there is no array that is: `svc` and `x8` are aarch64's,
//! `int $0x80` and `eax` are x86_64's.  The two moved to their machines in the
//! change that added the second machine's ring 3, and the comment that
//! described them stayed behind for a while afterwards.
//!
//! ## Sleeping
//!
//! `Sleep` is the first call that does not answer immediately.  It records a
//! deadline in the scheduler and answers `Exit`-shaped, not because the
//! program has ended, but because the frame the handler holds must describe
//! what runs next, and what runs next is another task.  The program resumes
//! when the timer wakes it, with its context exactly as the trap saved it.

/// A program's bytes, for a caller that writes them into a frame.
///
/// Asked of the machine: a program is machine code, and the array is this
/// architecture's, `svc` and `x8` on aarch64, `int $0x80` and `eax` on x86_64.
/// The kernel names one function and gets whichever machine answered.
pub fn program_bytes(number: u16) -> [u8; arch::PROGRAM_LEN] {
    arch::program_bytes(number)
}

/// A program's length in bytes.
pub const PROGRAM_LEN: usize = arch::PROGRAM_LEN;

/// The number of the program that reads the pipe.
pub const PIPE_READER: u16 = arch::PIPE_READER;

/// The number of the program that writes to it.
pub const PIPE_WRITER: u16 = arch::PIPE_WRITER;

/// Where the `n`th program's pages go.
///
/// Each program gets a gigabyte of the user window, far more than it uses and
/// far enough apart that one overrunning its pages cannot reach another's.  The
/// spacing is the point: two programs at the same address would be two programs
/// whose address spaces differ and whose *virtual* addresses collide, which is
/// correct and makes a log that says "0x80_0000_0000" twice less useful.
pub const fn program_base(number: u16) -> usize {
    crate::address_space::USER_BASE + (number as usize) * 0x4000_0000
}

/// Where the `n`th program's stack top is.
///
/// The **end** of the stack page, not its start.  The page is mapped at
/// `program_base + 0x1000`, and a stack pointer at its first byte has no stack:
/// the first `push` writes the byte before it, which is unmapped.  Every
/// earlier program ran without touching the stack, so this was invisible until
/// one did, the pipe reader's first instruction is a load from `[rsp]`, and it
/// took a page fault.
pub const fn program_stack_top(number: u16) -> usize {
    program_base(number) + 0x2000
}

/// The page the `n`th program's stack lives on.
pub const fn program_stack_page(number: u16) -> usize {
    program_base(number) + 0x1000
}

/// How far below the stack top `exec` starts the image it hands over.
///
/// The stack's top is a boundary, not storage, the same rule the boot's
/// hand-over keeps, so `exec` writes its words below it and starts the image
/// with the pointer moved down to them.  The block is the one inheritance an
/// `exec` has: `[sp]` is a user pointer to a NUL-terminated path the kernel
/// placed at [`EXEC_PATH_OFFSET`], and an image that wants no path simply
/// never reads it.
///
/// The 96 is deliberate: a program's own push writes below its hand-over
/// pointer, 16 bytes down on aarch64 and riscv64, 8 on x86_64, and the
/// first version's 64-byte block put the path's tail *inside* that push
/// zone.  The aarch64 parent's push overwrote the path's `t` and NUL with
/// the pointer's own bytes, the copy read a truncated string, and the exec
/// failed with a path nobody could have guessed.  The block now ends 32
/// bytes below the hand-over pointer, past every machine's push write.
pub const EXEC_BLOCK_BYTES: usize = 96;

/// Where in the `exec` block the path's bytes begin.
pub const EXEC_PATH_OFFSET: usize = 16;

/// What the kernel does with a program's supervisor call.
///
/// `Write` prints a fixed line, the program's arguments are not read, because
/// a pointer in a register is an address this kernel has no way to validate
/// yet, and reading one would be trusting a value from ring 3.  `Exit` ends the
/// program.  Everything else answers `NotImplemented`, which is what the
/// registry would say anyway and says here without a lookup.
#[cfg(target_os = "none")]
#[cfg(target_os = "none")]
pub fn serve(call: arch::CallFrame, frame: &mut arch::Context) -> arch::CallOutcome {
    use arch::CallOutcome;

    let number = call.number;
    // Every call that reaches the descriptor table is the running process's,
    // and the table checks that the descriptor belongs to it.  One binding, so
    // a path that forgets it cannot pass the wrong one.
    let caller = crate::scheduler::current_pid();

    // The families, in the order this function used to try the branches.  A
    // family answers `Some` when it serves the number and `None` when it does
    // not, which is the same test the chain of `if number == ...` made.
    // Each family is tried in turn and only while the previous ones answered
    // `None`.  A list of calls would evaluate all five before any is inspected,
    // and a family that is not the one serving the number would still run; the
    // original chain of `if number == ...` stopped at the first match, so this
    // does too.
    if let Some(outcome) = serve_lifecycle(call, frame, number, caller) {
        return outcome;
    }
    if let Some(outcome) = serve_signals(call, frame, number, caller) {
        return outcome;
    }
    if let Some(outcome) = serve_io(call, frame, number, caller) {
        return outcome;
    }
    if let Some(outcome) = serve_memory(call, frame, number, caller) {
        return outcome;
    }
    if let Some(outcome) = serve_network(call, frame, number, caller) {
        return outcome;
    }

    // Everything else is a call this boot does not serve.  `encode_error` is
    // the ABI's own encoding, so the program reads the same word it would from
    // a handler that answered through the registry.
    CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotImplemented))
}

// The families, each in a file of its own.  `serve` is the list; a family is
// the branches, and the split is by what a call does rather than by length.
#[cfg(target_os = "none")]
mod io;
#[cfg(target_os = "none")]
mod lifecycle;
#[cfg(target_os = "none")]
mod memory;
#[cfg(target_os = "none")]
mod network;
#[cfg(target_os = "none")]
mod signals;

#[cfg(target_os = "none")]
use io::serve_io;
#[cfg(target_os = "none")]
use lifecycle::serve_lifecycle;
#[cfg(target_os = "none")]
use memory::serve_memory;
#[cfg(target_os = "none")]
use network::serve_network;
#[cfg(target_os = "none")]
use signals::serve_signals;

/// The mask bits the ABI defines: one per signal, `1..=31`.  Bit 0 and
/// everything above are signals this ABI does not define, and a mask word
/// that named one would be a promise about a signal no send can carry.
#[cfg(target_os = "none")]
const SIGNAL_KNOWN_MASK: usize = 0xFFFF_FFFE;

/// The byte length of the ABI's `ProcessSignalRecord`, the record `WaitSignal`
/// answers with: three words, signal, sender, payload.
#[cfg(target_os = "none")]
const SIGNAL_RECORD_BYTES: usize = 24;

/// Write a `ProcessSignalRecord` into the caller's memory, little-endian word
/// by word, the same layout rule `Stat`'s record keeps.
#[cfg(target_os = "none")]
fn write_signal_record(buffer: &mut [u8], signal: usize, sender_pid: u32, payload: usize) {
    buffer[..8].copy_from_slice(&signal.to_le_bytes());
    buffer[8..16].copy_from_slice(&(sender_pid as usize).to_le_bytes());
    buffer[16..24].copy_from_slice(&payload.to_le_bytes());
}

/// Copy a NUL-terminated path out of the caller's memory, answering it as a
/// `&str` that borrows the buffer the caller hands in.
///
/// One shape for both `Open` and `ExecProcess`, which take the same kind of
/// argument: an address in the caller's memory.  Every byte is checked against
/// the user window before it is read, the length is bounded, the string must
/// be UTF-8, and the copy happens once, the caller's bytes are the kernel's
/// for the length of the call, which is what makes the rest of the handler
/// ordinary kernel code.  The buffer is the caller's: the borrow must not
/// outlive the stack slot the copied bytes live in.
/// Read a length-delimited name out of the caller's memory.
///
/// The calls that name a host take a pointer and a length rather than a
/// NUL-terminated string, which is the one difference between them and a
/// path: a name is bytes and its length is the caller's, so there is nothing
/// to scan for.  The bytes are checked to be UTF-8 here, because a name is
/// text a program will print and a handler that took a byte string would put
/// a program's chosen garbage into the log.
#[cfg(target_os = "none")]
fn copy_user_name(
    name_ptr: usize,
    length: usize,
    bytes: &mut [u8; NAME_MAX],
) -> Result<&str, abi::Error> {
    if length == 0
        || length > NAME_MAX
        || !crate::address_space::user_range(name_ptr, length, false)
    {
        return Err(abi::Error::InvalidArgument);
    }
    // SAFETY: the range is inside the user window and mapped in the calling
    // task's own root, which `user_range` checked, and the pages behind it are
    // that task's mappings, installed on this CPU.
    let source = unsafe { core::slice::from_raw_parts(name_ptr as *const u8, length) };
    bytes[..length].copy_from_slice(source);
    core::str::from_utf8(&bytes[..length]).map_err(|_| abi::Error::InvalidArgument)
}

/// The longest name a call that names a host moves in one buffer, from the
/// ABI that states it.
#[cfg(target_os = "none")]
const NAME_MAX: usize = abi::network::HOST_NAME_MAX;

#[cfg(target_os = "none")]
fn copy_user_path(path_ptr: usize, bytes: &mut [u8; OPEN_PATH_MAX]) -> Result<&str, abi::Error> {
    let mut length = 0;
    loop {
        // The add is checked, not the sum: `path_ptr + length` overflows for a
        // pointer near the top of the address space, which a debug build turns
        // into a panic **in the kernel** and a release build into a wrapped
        // number that the window check would then judge on its own, probably
        // admitting it.  A caller that names `usize::MAX` is one the kernel
        // must refuse, not one it computes an address for.
        let Some(address) = path_ptr.checked_add(length) else {
            return Err(abi::Error::InvalidArgument);
        };
        if length == OPEN_PATH_MAX || !crate::address_space::user_range(address, 1, false) {
            return Err(abi::Error::InvalidArgument);
        }
        // SAFETY: the byte is in the user window and mapped in the calling
        // task's own root, which `user_range` just checked.
        let byte = unsafe { *(address as *const u8) };
        bytes[length] = byte;
        if byte == 0 {
            break;
        }
        length += 1;
    }
    core::str::from_utf8(&bytes[..length]).map_err(|_| abi::Error::InvalidArgument)
}

/// Take one datagram from a bound socket, answering the call's status word.
///
/// `None` is "nothing arrived", which is the caller's signal to park;
/// `Some` is the answer, the byte count, or an error encoded the ABI's way.
/// The sender record is written here, because the receive that answers and
/// the re-check under the park's lock must fill the same record the same
/// way, and one writer is how that stays true.
#[cfg(target_os = "none")]
fn receive_datagram_answer(
    socket: &alloc::sync::Arc<crate::net::UdpSocket>,
    destination: &mut [u8],
    sender: &mut [u8],
) -> Option<usize> {
    match socket.try_recv(destination) {
        Err(error) => Some(abi::syscall::encode_error(error)),
        Ok(None) => None,
        Ok(Some((source, source_port, count))) => {
            // The record's shape follows the address's family.  A caller that
            // passes the flag gets the sixteen-byte record it asked for; one
            // that passes zero gets the two-word record it always did, and a
            // datagram from an IPv6 peer has no two-word form, which is why
            // this answers `InvalidArgument` rather than truncating an
            // address into a word a program would read as something else.
            match source {
                net::address::Address::V4(bytes) => {
                    let record = abi::network::UdpSenderRecord {
                        address: abi::network::pack_address(bytes),
                        port: source_port as usize,
                    };
                    sender[..8].copy_from_slice(&record.address.to_le_bytes());
                    sender[8..16].copy_from_slice(&record.port.to_le_bytes());
                }
                net::address::Address::V6(bytes) => {
                    if sender.len() < abi::network::UDP_SENDER6_RECORD_SIZE {
                        return Some(abi::syscall::encode_error(abi::Error::InvalidArgument));
                    }
                    sender[..16].copy_from_slice(&bytes);
                    sender[16..16 + core::mem::size_of::<usize>()]
                        .copy_from_slice(&source_port.to_le_bytes());
                }
            }
            Some(count)
        }
    }
}

/// Write four bytes as a dotted quad, from the word the ABI packs them in.
///
/// The same shape `devices.rs`'s writer is, one layer down: a byte per
/// octet, through `write_str`, so the line stays one line.
#[cfg(target_os = "none")]
fn write_ipv4_word(word: usize) {
    for (index, byte) in abi::network::unpack_address(word).iter().enumerate() {
        if index != 0 {
            arch::serial::write_str(".");
        }
        arch::serial::write_u32(*byte as u32);
    }
}

/// The name a `Stat` evidence line prints for the ABI's kind word.
///
/// The words are the log's, not the wire's: the record carries the number,
/// and a boot line that printed the number would be one a reader had to
/// decode against the ABI to read at all.
#[cfg(target_os = "none")]
fn stat_kind_name(kind: usize) -> &'static str {
    match kind {
        abi::fs::FILE_KIND_DIRECTORY => "directory",
        abi::fs::FILE_KIND_FILE => "file",
        abi::fs::FILE_KIND_DEVICE => "device",
        abi::fs::FILE_KIND_SYMLINK => "symlink",
        _ => "unknown",
    }
}

/// The longest path a ring-3 `Open` or `ExecProcess` may name.
///
/// The registry's [`PATH_MAX`](crate::syscall::PATH_MAX) is the format's bound;
/// this is the copy's, because the copy happens on a trap stack that one page
/// of memory has to hold, frame and all.  A path this kernel mounts is a few
/// dozen bytes, and a caller that needs more is a caller a later change can
/// serve from the heap.
#[cfg(target_os = "none")]
const OPEN_PATH_MAX: usize = 128;

#[cfg(target_os = "none")]
/// Hand a built context to the installed registry, and turn its answer into
/// the outcome a program reads.
///
/// One spelling of the registry round-trip: the success value goes back as the
/// call's answer, a registry error goes back encoded the ABI's own way, and no
/// registry at all answers `NotImplemented`, which is the same word the
/// fallthrough below answers for a number no handler serves.
fn through_registry(
    context: &mut syscall::SyscallContext,
    path: Option<&str>,
    second_path: Option<&str>,
    buffer: Option<&mut [u8]>,
) -> arch::CallOutcome {
    let mut arguments = crate::syscall::Arguments {
        context,
        path,
        second_path,
        buffer,
        second_buffer: None,
    };
    finish_registry_call(&mut arguments)
}

/// [`through_registry`] with a second read-only buffer.
///
/// `SetXattr` and `GetXattr` are the two calls that name two buffers, and this
/// is the reason it exists rather than a fifth parameter on every other caller:
/// a call that carries a name and a value reaches the registry here, and every
/// call that carries one goes through the four-argument form above.
///
/// Target only: the calls that carry two windows are the ones the trap path
/// hands a caller's memory to, and a host has no trap path.
#[cfg(target_os = "none")]
fn through_registry_with(
    context: &mut syscall::SyscallContext,
    path: Option<&str>,
    second_path: Option<&str>,
    buffer: Option<&mut [u8]>,
    second_buffer: Option<&[u8]>,
) -> arch::CallOutcome {
    let mut arguments = crate::syscall::Arguments {
        context,
        path,
        second_path,
        buffer,
        second_buffer,
    };
    finish_registry_call(&mut arguments)
}

/// Serve one call and act on its outcome.
///
/// The wake and the yield are here rather than in a handler because a handler
/// runs with the registry's lock held, and the scheduler's lock is one a parked
/// task holds while it re-checks its fact: a wake from inside one is a lock
/// order two CPUs can invert.  Both entry points above end here so the two
/// copies of that rule cannot drift.
#[cfg(target_os = "none")]
fn finish_registry_call(arguments: &mut crate::syscall::Arguments<'_>) -> arch::CallOutcome {
    match crate::syscall::serve(arguments) {
        Some(Ok(dispatch)) => {
            // A call that made something a parked task waits for wakes
            // **here**, after the registry's lock is gone: a handler runs with
            // that lock held, and the scheduler's lock is one a parked task
            // holds while it re-checks its fact, so a wake from inside the
            // handler is a lock order two CPUs can invert.
            if dispatch.wake {
                // The wake is here and not in the handler: a handler runs with
                // the registry's lock held, and a parked task holds the
                // scheduler's while it re-checks its fact, so a wake from
                // inside one is a lock order two CPUs can invert.
                #[cfg(target_os = "none")]
                {
                    let woken = crate::scheduler::wake_blocked();
                    if woken > 0 {
                        // SAFETY: the boot's own IPI path, installed before
                        // any program ran.
                        unsafe { arch::send_ipi_to_others() };
                    }
                    arch::serial::write_str("protofire: a local connect woke ");
                    arch::serial::write_u32(woken as u32);
                    arch::serial::write_str(" blocked task(s), descriptor ");
                    arch::serial::write_u32(dispatch.value as u32);
                    arch::serial::write_str("\n");
                }
                #[cfg(not(target_os = "none"))]
                let _ = dispatch.value;
            }
            arch::CallOutcome::Return(dispatch.value)
        }
        Some(Err(error)) => arch::CallOutcome::Return(abi::syscall::encode_error(error)),
        None => arch::CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotImplemented)),
    }
}

/// What the program's `Write` prints.
///
/// Fixed, and the program passes no pointer: a program's buffer is an address
/// in ring 3, and this kernel has no way to check one yet.  A handler that
/// dereferenced `x1` would be reading whatever the program put there, which is
/// the promise `kernel/src/syscall/mod.rs` refuses to make, and this is the
/// same refusal one layer down.
/// The length `Write` answers with.
///
/// A program compares nothing today, the return path is proven by the exit
/// status of a program that does, but the number is what the call answers and
/// a program that read `x0` would find it here.
#[cfg(target_os = "none")]
const PROGRAM_OUTPUT: usize = 21;

#[cfg(test)]
mod tests {
    /// A program's pages are in its own window, and two windows do not overlap.
    ///
    /// The spacing is what makes an overrun visible: two programs at one
    /// address would be two whose virtual addresses collide, and a fault in one
    /// would read as a fault in the other.
    #[test]
    fn two_programs_get_different_windows() {
        let one = super::program_base(1);
        let two = super::program_base(2);
        assert_ne!(one, two);
        assert!(one >= crate::address_space::USER_BASE);
        assert!(
            two - one >= 0x4000_0000,
            "a gigabyte apart, so an overrun does not reach the next program"
        );
        assert!(super::program_stack_top(1) > super::program_base(1));
        assert!(super::program_stack_top(1) < super::program_base(2));
        assert!(
            super::program_stack_page(1) < super::program_stack_top(1),
            "the stack page is below the pointer that starts in it"
        );
    }
}
