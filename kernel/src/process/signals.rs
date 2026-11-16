//! kernel/src/process/signals.rs
//!
//! Signals and faults: sending one, waiting for one, the mask, the handler a
//! program installs for its own faults, and the return from one.
//!
//! One family of `serve`'s branches, moved out so the dispatcher reads as a
//! list of families.  `None` means this family does not serve `number` and
//! `serve` tries the next one; `Some(outcome)` is the call's answer and ends
//! the dispatch.

use super::SIGNAL_KNOWN_MASK;
use super::SIGNAL_RECORD_BYTES;
use super::write_signal_record;

pub(crate) fn serve_signals(
    call: arch::CallFrame,
    frame: &mut arch::Context,
    number: usize,
    caller: Option<u32>,
) -> Option<arch::CallOutcome> {
    use arch::CallOutcome;
    use syscall::SyscallNumber;
    let _ = (&call, &*frame, number, caller);
    if number == SyscallNumber::InstallExceptionHandler as usize {
        // `InstallExceptionHandler(address)`: the program takes its own faults
        // from here on, and `0` withdraws the handler.  A fault after this is
        // the program's to answer; the kernel reports the hand-off and resumes
        // the program at the address it named.
        let address = call.arguments[0];
        if !crate::scheduler::install_exception_handler(address) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::NotFound,
            )));
        }
        arch::serial::write_str("protofire: process ");
        arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
        if address == 0 {
            arch::serial::write_str(" withdrew its fault handler\n");
        } else {
            arch::serial::write_str(" installed a fault handler at ");
            arch::serial::write_hex(address as u64);
            arch::serial::write_str("\n");
        }
        return Some(CallOutcome::Return(0));
    }
    if number == SyscallNumber::ReturnFromException as usize {
        // `ReturnFromException(value)`: the handler is done, and the value is
        // the call's answer.  The trap path resumes the handler's caller,
        // which is the program at the instruction after this `svc`.
        // `ReturnFromException(resume, value)`: where the handler wants the
        // program to continue, and the call's answer.  The handler supplies
        // both because the address is a fact about the program's own
        // instructions, a fixed-width machine could add one size, x86_64
        // cannot.
        crate::scheduler::return_from_exception(call.arguments[0], call.arguments[1], frame);
        return Some(CallOutcome::Exit);
    }
    if number == SyscallNumber::SendSignal as usize {
        let pid = call.arguments[0] as u32;
        let signal = call.arguments[1];
        let payload = call.arguments[2];
        if !abi::process::is_valid_process_signal(signal) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        if syscall::validate_known_flags(
            call.arguments[3],
            abi::process::PROCESS_SIGNAL_KNOWN_FLAGS,
        )
        .is_err()
        {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let sender = crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS);
        match crate::scheduler::send_signal(sender, pid, signal, payload) {
            Ok(()) => {
                arch::serial::write_str("protofire: process ");
                arch::serial::write_u32(sender);
                arch::serial::write_str(" sent signal ");
                arch::serial::write_u32(signal as u32);
                arch::serial::write_str(" to process ");
                arch::serial::write_u32(pid);
                arch::serial::write_str("\n");
                return Some(CallOutcome::Return(0));
            }
            Err(error) => {
                return Some(CallOutcome::Return(abi::syscall::encode_error(error)));
            }
        }
    }
    if number == SyscallNumber::WaitSignal as usize {
        // Waiting for one: the record is where the kernel writes the ABI's
        // `ProcessSignalRecord`, signal, sender, payload, and the wait
        // parks on the ring, woken by the send that fills it.  The retry is
        // the WaitProcess shape: the parked call resumes at the call, and
        // the retry asks the ring again.
        let record = call.arguments[0];
        let length = call.arguments[1];
        if length < SIGNAL_RECORD_BYTES {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        if !crate::address_space::is_user_range(record, length) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The handler writes
        // the record and nothing past it.
        let destination = unsafe { core::slice::from_raw_parts_mut(record as *mut u8, length) };
        match crate::scheduler::wait_signal(frame) {
            Some((signal, sender_pid, payload)) => {
                write_signal_record(destination, signal, sender_pid, payload);
                arch::serial::write_str("protofire: a signal wait answered signal ");
                arch::serial::write_u32(signal as u32);
                arch::serial::write_str(" from process ");
                arch::serial::write_u32(sender_pid);
                arch::serial::write_str("\n");
                return Some(CallOutcome::Return(0));
            }
            // Parked: the send's wake resumes the call for a retry.
            None => {
                if !crate::scheduler::has_selectable() {
                    crate::scheduler::idle_until_woken();
                }
                return Some(crate::scheduler::switch_without_saving(frame));
            }
        }
    }

    // The mask, and the suspend that runs a ring under one.  Both take the
    // mask as a bit-per-signal word; the mask's known set is the signals'
    if number == SyscallNumber::SetSignalMask as usize {
        let mask = call.arguments[0];
        let flags = call.arguments[1];
        if syscall::validate_known_flags(flags, abi::process::PROCESS_SIGNAL_KNOWN_FLAGS).is_err()
            || mask & !SIGNAL_KNOWN_MASK != 0
        {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let previous = crate::scheduler::set_signal_mask(mask as u32);
        return Some(CallOutcome::Return(previous as usize));
    }
    if number == SyscallNumber::SigSuspend as usize {
        let mask = call.arguments[0];
        let flags = call.arguments[1];
        if syscall::validate_known_flags(flags, abi::process::PROCESS_SIGNAL_KNOWN_FLAGS).is_err()
            || mask & !SIGNAL_KNOWN_MASK != 0
        {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let record = call.arguments[2];
        let length = call.arguments[3];
        if length < SIGNAL_RECORD_BYTES {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        if !crate::address_space::is_user_range(record, length) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.
        let destination = unsafe { core::slice::from_raw_parts_mut(record as *mut u8, length) };
        match crate::scheduler::sigsuspend(frame, mask as u32) {
            Some((signal, sender_pid, payload)) => {
                write_signal_record(destination, signal, sender_pid, payload);
                arch::serial::write_str("protofire: a suspend answered signal ");
                arch::serial::write_u32(signal as u32);
                arch::serial::write_str(" from process ");
                arch::serial::write_u32(sender_pid);
                arch::serial::write_str(", mask put back\n");
                return Some(CallOutcome::Return(0));
            }
            None => {
                if !crate::scheduler::has_selectable() {
                    crate::scheduler::idle_until_woken();
                }
                return Some(crate::scheduler::switch_without_saving(frame));
            }
        }
    }

    // Arming, and disarming, the handler a program's own code provides for
    // one signal.  The contract is the exception handler's, which is why the
    // address needs no trust the fault path did not already extend: the
    // handler runs in the program, on the program's stack, and its way out
    if number == SyscallNumber::SetSignalHandler as usize {
        let signal = call.arguments[0];
        let action = call.arguments[1];
        let handler = call.arguments[2];
        let taken = action <= 1
            && syscall::validate_known_flags(
                call.arguments[3],
                abi::process::PROCESS_SIGNAL_KNOWN_FLAGS,
            )
            .is_ok()
            && crate::scheduler::set_signal_handler(signal, action, handler);
        if taken {
            return Some(CallOutcome::Return(0));
        }
        return Some(CallOutcome::Return(abi::syscall::encode_error(
            abi::Error::InvalidArgument,
        )));
    }
    if number == SyscallNumber::SigReturn as usize {
        // The delivered-signal handler's exit, and the half that makes the
        // delivery **transparent**: the delivery displaced the program's
        // argument registers for its record, and only the kernel kept them.
        // They go back here, and the interrupted flow resumes at `a0`, the
        // resume the delivery handed the handler, with the registers it
        // would have had had the signal never arrived.
        if !crate::scheduler::signal_return(frame, call.arguments[0]) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        return Some(CallOutcome::Exit);
    }

    None
}
