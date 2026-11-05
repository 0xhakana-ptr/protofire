//! kernel/src/programs.rs
//!
//! The boot's programs: build them, map them, and let the scheduler run them.
//!
//! ## Why here and not in `process`
//!
//! `process` is what the kernel does with a program's *call*, the handler a
//! trap reaches.  This module is what the *boot* does with a program: pick an
//! address space, copy the machine code in, hand a pipe end through the stack,
//! and enter the first one.  A reader asking "how does a call get served" reads
//! `process`; one asking "what does this boot start" reads this file.

#[cfg(target_os = "none")]
use crate::scheduler::Scheduler;
#[cfg(target_os = "none")]
use crate::scheduler::Task;

/// The process id the boot's own work is done under.
///
/// A program the kernel starts is a child of this, which is a fact rather than
/// a placeholder: there is no `fork`, so nothing in this tree has a program for
/// a parent.
pub const BOOT_PROCESS: u32 = 0;

/// How the boot's three programs are arranged.
///
/// One program proves the entry path; it cannot prove a switch, because a
/// switch needs something to switch to.  Three programs that each print their
/// number exercise a second and third address space, two contexts saved and
/// restored, a sleep that parks a task and a read that parks a task on a pipe,
/// and three exits reaped.
///
/// A log that shows the numbers interleaved is the evidence; one program twice
/// looks the same as one program once, which is why the number is the program's
/// own value and not the kernel's counter.
#[cfg(target_os = "none")]
pub fn run() {
    use crate::process;

    // SAFETY: both sinks are installed once, before ring 3 is entered.
    unsafe {
        arch::set_call_sink(process::serve);
        arch::set_preempt_sink(crate::scheduler::preempt);
    }

    // The pipe table, before any program can make one.
    //
    // SAFETY: called once, before ring 3 is entered.
    unsafe { crate::pipe::install() };

    // The pipe the reader waits on, made before either program runs.  The
    // writer is program 2 and the reader is program 3, so the ordering is the
    // point: the reader reaches its `Read` first, its loop is shorter and it
    // makes no earlier call, and the pipe is empty, so it blocks.  Program 2's
    // write is what ends that wait, and nothing else can.
    let Some((reader_end, writer_end)) = make_pipe() else {
        return;
    };

    let mut scheduler = Scheduler::new();
    for number in [1u16, 2, 3] {
        let Some(task) = build_task(number, reader_end, writer_end) else {
            return;
        };
        scheduler.add(task);
    }

    // Install it, then enter the first program in it.
    //
    // `enter_user_with_context` does not return: the first program's trap
    // brings us back into the kernel and the scheduler takes it from there.  So
    // the entry is the first task's context installed by hand rather than
    // through a switch.
    let first = scheduler.current().map(|task| *task.context());
    // SAFETY: called once, before any program runs.
    unsafe { crate::scheduler::install(scheduler) };

    let Some(context) = first else {
        arch::serial::write_str("protofire: no program to run\n");
        return;
    };

    // Now, and not before: everything that runs at ring 0 is done.
    //
    // SAFETY: the timer's line is enabled, so a fire is a delivered interrupt,
    // and the sink and the scheduler are both installed.
    if let Some(frequency) = unsafe { arch::timer_frequency() } {
        // SAFETY: as above.
        unsafe { arch::arm_timer(frequency, crate::tick::TIME_SLICE_US) };
    } else {
        arch::serial::write_str("protofire: no timer to arm for the programs\n");
    }

    arch::serial::write_str("protofire: entering ring 3\n");
    // SAFETY: the entry is mapped `user` in the installed space, the first
    // task's root is not yet installed, so this switches to it as it enters.
    let Some(root) = crate::scheduler::first_root() else {
        arch::serial::write_str("protofire: no root table for the first program\n");
        return;
    };
    unsafe {
        arch::switch_address_space(root);
        arch::enter_user_with_context(&context)
    }
}

/// The host build has no ring 3 to enter.
#[cfg(not(target_os = "none"))]
pub fn run() {}

/// Make the pipe two of the boot's programs share.
///
/// Answers both ends, or `None` when the table has no room, in which case the
/// boot says so rather than starting programs whose descriptors name nothing.
#[cfg(target_os = "none")]
fn make_pipe() -> Option<(usize, usize)> {
    let pipe = alloc::sync::Arc::new(crate::pipe::Pipe::new(ipc::DEFAULT_PIPE_CAPACITY));
    let reader = match crate::pipe::attach(crate::pipe::End::reader(pipe.clone())) {
        Some(descriptor) => descriptor,
        None => {
            arch::serial::write_str("protofire: no room for a pipe end\n");
            return None;
        }
    };
    let writer = match crate::pipe::attach(crate::pipe::End::writer(pipe)) {
        Some(descriptor) => descriptor,
        None => {
            arch::serial::write_str("protofire: no room for a pipe end\n");
            return None;
        }
    };
    Some((reader, writer))
}

/// Build one program: its address space, its frames, and its task.
///
/// The two frames are the program's image and its stack.  The pipe's end, when
/// this program is one of the two that shares one, is written into the stack
/// before the program runs, because that is the one place both sides agree on:
/// a program reads `[sp]` for its descriptor.
#[cfg(target_os = "none")]
fn build_task(number: u16, reader_end: usize, writer_end: usize) -> Option<Task> {
    use crate::address_space::AddressSpace;
    use crate::process;

    let mut space = unsafe { AddressSpace::new() }?;
    let image = crate::address_space::allocate_image_frame()?;
    let stack = crate::address_space::allocate_image_frame()?;
    space.own(image);
    space.own(stack);

    let bytes = process::program_bytes(number);
    // SAFETY: `image` is a live frame the allocator handed out and zeroed, and
    // the program is smaller than one page; this boot is identity mapped, so
    // the frame's physical address is one the kernel can write.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), image as *mut u8, bytes.len());
    }

    let handed_stack_top = hand_over_pipe(number, stack, reader_end, writer_end);

    let base = process::program_base(number);
    let stack_page = process::program_stack_page(number);
    // SAFETY: both frames belong to this space, and the two virtual addresses
    // are this program's own window.
    let mapped = unsafe { space.map(base, image, false) && space.map(stack_page, stack, true) };
    if !mapped {
        arch::serial::write_str("protofire: a program could not be mapped\n");
        return None;
    }

    arch::serial::write_str("protofire: program ");
    arch::serial::write_u32(number as u32);
    arch::serial::write_str(" mapped at ");
    arch::serial::write_hex(base as u64);
    arch::serial::write_str("\n");

    let stack_top = handed_stack_top.unwrap_or_else(|| process::program_stack_top(number));
    let mut task = Task::new(
        match number {
            n if n == process::PIPE_READER => "reader",
            n if n == process::PIPE_WRITER => "writer",
            _ => "one",
        },
        base,
        stack_top,
        space,
    );
    // The process tree this boot has: every program the kernel starts is its
    // own process, and the boot is the parent of each.  A framework that
    // `fork`ed would fill these from the caller instead; nothing here does,
    // and saying which is which is better than a zero that could mean either.
    task.identify(number as u32, BOOT_PROCESS);
    Some(task)
}

/// Put a program's pipe end where its first instruction looks for it.
///
/// A program receives a value from the boot through the one place both sides
/// agree on, and this boot writes it before the program runs: the reader reads
/// `[rsp]` for its descriptor, and the writer finds its own at `[rsp]` too.
/// The word above it is the writer's payload.
///
/// The stack's top is a boundary, not storage: a program's `rsp` points at it
/// and `[rsp]` is the first four bytes *above* it.  So the words go below the
/// boundary and the stack pointer moves down to them, which is what a `push`
/// would have done, done early.
///
/// The **physical** frame, not its virtual address: a program's pages are
/// mapped in its own address space, and the boot is running through the
/// kernel's, so the virtual address is one this walk does not reach.  The
/// frame is identity mapped here, so the kernel writes the bytes where they
/// will be and the program reads them through its own mapping of the same page.
#[cfg(target_os = "none")]
fn hand_over_pipe(
    number: u16,
    stack: usize,
    reader_end: usize,
    writer_end: usize,
) -> Option<usize> {
    use crate::process;

    let descriptor = match number {
        n if n == process::PIPE_READER => reader_end,
        n if n == process::PIPE_WRITER => writer_end,
        _ => return None,
    };
    let base = (stack + paging::PAGE_SIZE - 32) as *mut u64;
    // SAFETY: `stack` is the frame this space owns for its stack, the program
    // has not run, and the two words are inside it.
    unsafe {
        base.write(descriptor as u64);
        base.add(1).write(0x64_63_62_61); // "abcd", little-endian
    }
    Some(process::program_stack_top(number) - 32)
}
