//! abi/src/process/tests.rs
//!
//! The process wire format: the termination record, the spawn options, and the
//! signal frame's layout.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::process::PROCESS_SIGNAL_FLAG_NONE;
use crate::process::PROCESS_SIGNAL_KNOWN_FLAGS;
use crate::process::PROCESS_SIGNAL_MAX;
use crate::process::PROCESS_SIGNAL_MIN;
use crate::process::PROCESS_SIGNAL_RECORD_PAYLOAD_OFFSET;
use crate::process::PROCESS_SIGNAL_RECORD_SENDER_PID_OFFSET;
use crate::process::PROCESS_SIGNAL_RECORD_SIGNAL_OFFSET;
use crate::process::PROCESS_SIGNAL_RECORD_SIZE;
use crate::process::PROCESS_SPAWN_FLAG_INHERIT_STDERR;
use crate::process::PROCESS_SPAWN_FLAG_INHERIT_STDIN;
use crate::process::PROCESS_SPAWN_FLAG_INHERIT_STDIO;
use crate::process::PROCESS_SPAWN_FLAG_INHERIT_STDOUT;
use crate::process::PROCESS_SPAWN_FLAG_INHERIT_WORKING_DIR;
use crate::process::PROCESS_SPAWN_FLAG_OVERRIDE_ARGUMENTS;
use crate::process::PROCESS_SPAWN_FLAG_OVERRIDE_ENVIRONMENT;
use crate::process::PROCESS_SPAWN_FLAG_OVERRIDE_WORKING_DIR;
use crate::process::PROCESS_SPAWN_OPTIONS_ARGC_OFFSET;
use crate::process::PROCESS_SPAWN_OPTIONS_ARGV_OFFSET;
use crate::process::PROCESS_SPAWN_OPTIONS_ENV_OFFSET;
use crate::process::PROCESS_SPAWN_OPTIONS_ENVC_OFFSET;
use crate::process::PROCESS_SPAWN_OPTIONS_FLAGS_OFFSET;
use crate::process::PROCESS_SPAWN_OPTIONS_SIZE;
use crate::process::PROCESS_SPAWN_OPTIONS_WORKING_DIR_LEN_OFFSET;
use crate::process::PROCESS_SPAWN_OPTIONS_WORKING_DIR_OFFSET;
use crate::process::PROCESS_SPAWN_STRING_REF_LEN_OFFSET;
use crate::process::PROCESS_SPAWN_STRING_REF_PTR_OFFSET;
use crate::process::PROCESS_SPAWN_STRING_REF_SIZE;
use crate::process::PROCESS_TERMINATION_KIND_EXCEPTION;
use crate::process::PROCESS_TERMINATION_KIND_EXIT;
use crate::process::PROCESS_TERMINATION_KIND_NONE;
use crate::process::PROCESS_TERMINATION_RECORD_ERROR_CODE_OFFSET;
use crate::process::PROCESS_TERMINATION_RECORD_FAULT_ADDRESS_OFFSET;
use crate::process::PROCESS_TERMINATION_RECORD_FAULT_ADDRESS_PRESENT_OFFSET;
use crate::process::PROCESS_TERMINATION_RECORD_KIND_OFFSET;
use crate::process::PROCESS_TERMINATION_RECORD_SIZE;
use crate::process::PROCESS_TERMINATION_RECORD_STATUS_OFFSET;
use crate::process::PROCESS_TERMINATION_RECORD_VECTOR_OFFSET;
use crate::process::ProcessSignalRecord;
use crate::process::ProcessSpawnOptions;
use crate::process::ProcessSpawnStringRef;
use crate::process::ProcessTerminationRecord;
use crate::process::WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS;
use crate::process::WAIT_SIGNAL_BLOCK_INDEFINITELY_TICKS;
use crate::process::is_valid_process_signal;
use core::mem::offset_of;

#[test]
fn process_termination_record_constructors_encode_expected_fields() {
    assert_eq!(
        ProcessTerminationRecord::none(),
        ProcessTerminationRecord {
            kind: PROCESS_TERMINATION_KIND_NONE,
            status: 0,
            vector: 0,
            error_code: 0,
            fault_address_present: 0,
            fault_address: 0,
        }
    );

    assert_eq!(
        ProcessTerminationRecord::exited(23),
        ProcessTerminationRecord {
            kind: PROCESS_TERMINATION_KIND_EXIT,
            status: 23,
            vector: 0,
            error_code: 0,
            fault_address_present: 0,
            fault_address: 0,
        }
    );

    assert_eq!(
        ProcessTerminationRecord::exception(14, 0x4, Some(0x7fff_ffff_d000)),
        ProcessTerminationRecord {
            kind: PROCESS_TERMINATION_KIND_EXCEPTION,
            status: 0,
            vector: 14,
            error_code: 0x4,
            fault_address_present: 1,
            fault_address: 0x7fff_ffff_d000,
        }
    );
}

#[test]
fn process_termination_record_exposes_aarch64_abort_decoder() {
    let record = ProcessTerminationRecord::exception(0x24, 0x4f, Some(0x4040_2000));
    let syndrome = record
        .aarch64_abort_syndrome()
        .expect("aarch64 abort syndrome");

    assert_eq!(syndrome.fault_status_code(), 0x0f);
    assert_eq!(syndrome.fault_status_name(), "permission fault level 3");
    assert_eq!(syndrome.access_kind(), "write");
}

#[test]
fn process_termination_record_size_matches_layout() {
    assert_eq!(
        PROCESS_TERMINATION_RECORD_SIZE,
        size_of::<ProcessTerminationRecord>()
    );
    assert_eq!(
        PROCESS_TERMINATION_RECORD_KIND_OFFSET,
        offset_of!(ProcessTerminationRecord, kind)
    );
    assert_eq!(
        PROCESS_TERMINATION_RECORD_STATUS_OFFSET,
        offset_of!(ProcessTerminationRecord, status)
    );
    assert_eq!(
        PROCESS_TERMINATION_RECORD_VECTOR_OFFSET,
        offset_of!(ProcessTerminationRecord, vector)
    );
    assert_eq!(
        PROCESS_TERMINATION_RECORD_ERROR_CODE_OFFSET,
        offset_of!(ProcessTerminationRecord, error_code)
    );
    assert_eq!(
        PROCESS_TERMINATION_RECORD_FAULT_ADDRESS_PRESENT_OFFSET,
        offset_of!(ProcessTerminationRecord, fault_address_present)
    );
    assert_eq!(
        PROCESS_TERMINATION_RECORD_FAULT_ADDRESS_OFFSET,
        offset_of!(ProcessTerminationRecord, fault_address)
    );
}

#[test]
fn blocking_wait_timeout_uses_reserved_non_zero_sentinel() {
    assert_ne!(WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS, 0);
    assert_eq!(WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS, usize::MAX);
    assert_eq!(
        WAIT_SIGNAL_BLOCK_INDEFINITELY_TICKS,
        WAIT_PROCESS_BLOCK_INDEFINITELY_TICKS
    );
}

#[test]
fn process_signal_range_and_flags_are_stable() {
    assert_eq!(PROCESS_SIGNAL_MIN, 1);
    assert_eq!(PROCESS_SIGNAL_MAX, 31);
    assert_eq!(PROCESS_SIGNAL_FLAG_NONE, 0);
    assert_eq!(PROCESS_SIGNAL_KNOWN_FLAGS, 0);
    assert!(!is_valid_process_signal(0));
    assert!(is_valid_process_signal(PROCESS_SIGNAL_MIN));
    assert!(is_valid_process_signal(PROCESS_SIGNAL_MAX));
    assert!(!is_valid_process_signal(PROCESS_SIGNAL_MAX + 1));
}

#[test]
fn process_signal_record_layout_matches_public_offsets() {
    let record = ProcessSignalRecord::new(3, 17, 0xfeed);
    assert_eq!(
        PROCESS_SIGNAL_RECORD_SIZE,
        core::mem::size_of::<ProcessSignalRecord>()
    );
    assert_eq!(PROCESS_SIGNAL_RECORD_SIGNAL_OFFSET, 0);
    assert_eq!(
        PROCESS_SIGNAL_RECORD_SENDER_PID_OFFSET,
        core::mem::size_of::<usize>()
    );
    assert_eq!(
        PROCESS_SIGNAL_RECORD_PAYLOAD_OFFSET,
        core::mem::size_of::<usize>() * 2
    );
    assert_eq!(record.signal, 3);
    assert_eq!(record.sender_pid, 17);
    assert_eq!(record.payload, 0xfeed);
}

#[test]
fn signal_frame_size_and_layout() {
    use crate::process::SIGNAL_FRAME_REGS;
    use crate::process::SIGNAL_FRAME_SIZE;
    use crate::process::SignalFrame;
    // The registers first, then where the interrupted code was: the
    // handler's return only has to find the frame, and the kernel's
    // restore reads it in the order below.
    assert_eq!(SIGNAL_FRAME_SIZE, 152);
    assert_eq!(SIGNAL_FRAME_SIZE, core::mem::size_of::<SignalFrame>());
    let after_regs = 8 * SIGNAL_FRAME_REGS;
    assert_eq!(core::mem::offset_of!(SignalFrame, regs), 0);
    assert_eq!(core::mem::offset_of!(SignalFrame, orig_rip), after_regs);
    assert_eq!(core::mem::offset_of!(SignalFrame, orig_rsp), after_regs + 8);
    assert_eq!(
        core::mem::offset_of!(SignalFrame, orig_rflags),
        after_regs + 16
    );
    assert_eq!(core::mem::offset_of!(SignalFrame, signal), after_regs + 24);
}

#[test]
fn aarch64_signal_frame_size_and_layout() {
    use crate::process::AARCH64_SIGNAL_FRAME_REGS;
    use crate::process::AARCH64_SIGNAL_FRAME_SIZE;
    use crate::process::AArch64SignalFrame;
    assert_eq!(AARCH64_SIGNAL_FRAME_SIZE, 280);
    assert_eq!(
        AARCH64_SIGNAL_FRAME_SIZE,
        core::mem::size_of::<AArch64SignalFrame>()
    );
    let after_regs = 8 * AARCH64_SIGNAL_FRAME_REGS;
    assert_eq!(core::mem::offset_of!(AArch64SignalFrame, regs), 0);
    assert_eq!(
        core::mem::offset_of!(AArch64SignalFrame, orig_elr),
        after_regs
    );
    assert_eq!(
        core::mem::offset_of!(AArch64SignalFrame, orig_sp),
        after_regs + 8
    );
    assert_eq!(
        core::mem::offset_of!(AArch64SignalFrame, orig_spsr),
        after_regs + 16
    );
    assert_eq!(
        core::mem::offset_of!(AArch64SignalFrame, signal),
        after_regs + 24
    );
}

#[test]
fn riscv64_signal_frame_size_and_layout() {
    use crate::process::RISCV64_SIGNAL_FRAME_REGS;
    use crate::process::RISCV64_SIGNAL_FRAME_SIZE;
    use crate::process::RiscV64SignalFrame;
    assert_eq!(RISCV64_SIGNAL_FRAME_SIZE, 272);
    assert_eq!(
        RISCV64_SIGNAL_FRAME_SIZE,
        core::mem::size_of::<RiscV64SignalFrame>()
    );
    let after_regs = 8 * RISCV64_SIGNAL_FRAME_REGS;
    assert_eq!(core::mem::offset_of!(RiscV64SignalFrame, regs), 0);
    assert_eq!(
        core::mem::offset_of!(RiscV64SignalFrame, orig_sepc),
        after_regs
    );
    assert_eq!(
        core::mem::offset_of!(RiscV64SignalFrame, orig_sstatus),
        after_regs + 8
    );
    assert_eq!(
        core::mem::offset_of!(RiscV64SignalFrame, signal),
        after_regs + 16
    );
}

#[test]
fn process_spawn_options_constructors_encode_expected_fields() {
    assert_eq!(
        ProcessSpawnStringRef::new(0x4000, 24),
        ProcessSpawnStringRef {
            ptr: 0x4000,
            len: 24,
        }
    );

    assert_eq!(
        ProcessSpawnOptions::defaults(),
        ProcessSpawnOptions {
            flags: 0,
            argv: 0,
            argc: 0,
            env: 0,
            envc: 0,
            working_dir: 0,
            working_dir_len: 0,
        }
    );

    assert_eq!(
        ProcessSpawnOptions::override_argv(0x4100, 3),
        ProcessSpawnOptions {
            flags: PROCESS_SPAWN_FLAG_OVERRIDE_ARGUMENTS,
            argv: 0x4100,
            argc: 3,
            env: 0,
            envc: 0,
            working_dir: 0,
            working_dir_len: 0,
        }
    );

    assert_eq!(
        ProcessSpawnOptions::override_env(0x4200, 2),
        ProcessSpawnOptions {
            flags: PROCESS_SPAWN_FLAG_OVERRIDE_ENVIRONMENT,
            argv: 0,
            argc: 0,
            env: 0x4200,
            envc: 2,
            working_dir: 0,
            working_dir_len: 0,
        }
    );

    let combined = ProcessSpawnOptions::override_argv_env(0x4300, 4, 0x4400, 5);
    assert_eq!(
        combined,
        ProcessSpawnOptions {
            flags: PROCESS_SPAWN_FLAG_OVERRIDE_ARGUMENTS | PROCESS_SPAWN_FLAG_OVERRIDE_ENVIRONMENT,
            argv: 0x4300,
            argc: 4,
            env: 0x4400,
            envc: 5,
            working_dir: 0,
            working_dir_len: 0,
        }
    );
    assert!(combined.overrides_arguments());
    assert!(combined.overrides_environment());

    let override_working_dir = ProcessSpawnOptions::override_working_dir(0x4500, 12);
    assert_eq!(
        override_working_dir,
        ProcessSpawnOptions {
            flags: PROCESS_SPAWN_FLAG_OVERRIDE_WORKING_DIR,
            argv: 0,
            argc: 0,
            env: 0,
            envc: 0,
            working_dir: 0x4500,
            working_dir_len: 12,
        }
    );
    assert!(override_working_dir.overrides_working_dir());

    let inherited =
        ProcessSpawnOptions::inherit_working_dir().with_flags(PROCESS_SPAWN_FLAG_INHERIT_STDIO);
    assert_eq!(
        inherited.flags,
        PROCESS_SPAWN_FLAG_INHERIT_WORKING_DIR | PROCESS_SPAWN_FLAG_INHERIT_STDIO
    );
    assert!(inherited.inherits_working_dir());
    assert!(inherited.inherits_stdin());
    assert!(inherited.inherits_stdout());
    assert!(inherited.inherits_stderr());
    assert_eq!(
        ProcessSpawnOptions::inherit_stdio().flags,
        PROCESS_SPAWN_FLAG_INHERIT_STDIN
            | PROCESS_SPAWN_FLAG_INHERIT_STDOUT
            | PROCESS_SPAWN_FLAG_INHERIT_STDERR
    );
}

#[test]
fn process_spawn_abi_sizes_match_layout() {
    assert_eq!(
        PROCESS_SPAWN_STRING_REF_SIZE,
        size_of::<ProcessSpawnStringRef>()
    );
    assert_eq!(PROCESS_SPAWN_OPTIONS_SIZE, size_of::<ProcessSpawnOptions>());
    assert_eq!(
        PROCESS_SPAWN_STRING_REF_PTR_OFFSET,
        offset_of!(ProcessSpawnStringRef, ptr)
    );
    assert_eq!(
        PROCESS_SPAWN_STRING_REF_LEN_OFFSET,
        offset_of!(ProcessSpawnStringRef, len)
    );
    assert_eq!(
        PROCESS_SPAWN_OPTIONS_FLAGS_OFFSET,
        offset_of!(ProcessSpawnOptions, flags)
    );
    assert_eq!(
        PROCESS_SPAWN_OPTIONS_ARGV_OFFSET,
        offset_of!(ProcessSpawnOptions, argv)
    );
    assert_eq!(
        PROCESS_SPAWN_OPTIONS_ARGC_OFFSET,
        offset_of!(ProcessSpawnOptions, argc)
    );
    assert_eq!(
        PROCESS_SPAWN_OPTIONS_ENV_OFFSET,
        offset_of!(ProcessSpawnOptions, env)
    );
    assert_eq!(
        PROCESS_SPAWN_OPTIONS_ENVC_OFFSET,
        offset_of!(ProcessSpawnOptions, envc)
    );
    assert_eq!(
        PROCESS_SPAWN_OPTIONS_WORKING_DIR_OFFSET,
        offset_of!(ProcessSpawnOptions, working_dir)
    );
    assert_eq!(
        PROCESS_SPAWN_OPTIONS_WORKING_DIR_LEN_OFFSET,
        offset_of!(ProcessSpawnOptions, working_dir_len)
    );
}
