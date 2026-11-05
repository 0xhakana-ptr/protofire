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

    // SAFETY: called once, before any program runs.
    unsafe { crate::scheduler::install(scheduler) };

    // The boot CPU's own first task, claimed through the same call a started
    // CPU uses.  `enter_user_with_context` does not return: the first program's
    // trap brings us back into the kernel and the scheduler takes it from
    // there, so this is the only chance to say which task the boot CPU is
    // running.  A task recorded as taken anywhere else would be a second answer
    // to that question, and the two would disagree the moment a started CPU
    // claimed one at the same time.
    let first = match crate::scheduler::claim(crate::per_cpu::BOOT_SLOT) {
        crate::scheduler::Claim::Took(task) => crate::scheduler::start_of(task),
        // The boot CPU has not entered a program yet, so it cannot already be
        // running one, and a boot with no task is a line rather than a stop.
        // Both are answered the same way: nothing to enter.
        crate::scheduler::Claim::NothingToRun | crate::scheduler::Claim::AlreadyRunning => None,
    };

    // The other CPUs' source of work, installed before any of them is woken.
    //
    // SAFETY: called once, after the scheduler exists and before any CPU can
    // ask it for a task.
    #[cfg(target_os = "none")]
    unsafe {
        arch::set_work_sink(crate::programs::claim_for_this_cpu);
        arch::set_finished_sink(crate::programs::boot_is_finished);
    }

    let Some((root, context)) = first else {
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

    // The started CPUs are woken now, so they and this CPU enter programs at
    // nearly the same moment.  Before this line they had nothing to run; after
    // it they have the tasks the scheduler holds.
    #[cfg(target_os = "none")]
    crate::cpus::wake_them();

    arch::serial::write_str("protofire: entering ring 3\n");
    // SAFETY: the root is the claimed task's own table, every root shares the
    // kernel's entry 0 so the switch is safe from here, and the context is that
    // task's frame.
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

/// What a started CPU runs: the task the scheduler gives it, and its root.
///
/// ## Why this is here and not in `scheduler`
///
/// The answer is two things the scheduler does not know about: which task it
/// picked, and which root table that task runs through.  The second is the
/// address space's, and joining them is what a program's *start* is, which is
/// this module's subject.
///
/// ## Why the CPU asks rather than being told
///
/// A CPU that was handed a task at start would have been handed it before the
/// scheduler existed: the boot starts the other CPUs before it builds the
/// queue.  So a started CPU waits, and asks each time it is woken, and the
/// answer is "nothing yet" until the boot has installed the queue and sent the
/// wake.
///
/// # Safety
///
/// Called from a started CPU's wait loop, after the boot installed the
/// scheduler.  The root it answers is a live table and the context is the
/// frame of a task the scheduler has marked as running on this CPU.
#[cfg(target_os = "none")]
pub fn claim_for_this_cpu(cpu: usize) -> Option<(usize, arch::Context)> {
    let task = match crate::scheduler::claim(cpu) {
        crate::scheduler::Claim::Took(task) => task,
        // A core asking for work while it still holds a task is the mistake
        // this type exists to make visible, and the safe answer is "nothing":
        // the core waits for its next wake instead of taking a task another CPU
        // may be running.
        crate::scheduler::Claim::AlreadyRunning | crate::scheduler::Claim::NothingToRun => {
            return None;
        }
    };
    let (root, context) = crate::scheduler::start_of(task)?;
    let pid = crate::scheduler::pid_of(task).unwrap_or(0);
    arch::serial::write_str("protofire: cpu ");
    arch::serial::write_u32(cpu as u32);
    arch::serial::write_str(" runs process ");
    arch::serial::write_u32(pid);
    arch::serial::write_str("\n");
    Some((root, context))
}

/// Whether the boot has ended, for a started CPU that has to notice.
///
/// The kernel's answer, injected into `arch` for the reason the work source is:
/// the flag lives here, and a machine crate that named it would be a cycle.
#[cfg(target_os = "none")]
pub fn boot_is_finished() -> bool {
    crate::FINISHED.load(core::sync::atomic::Ordering::Acquire)
}

/// How many programs exited on a CPU other than the boot one.
///
/// The counter the boot line reads.  It is the one number that separates "two
/// CPUs are online" from "two CPUs ran programs": a machine whose started CPU
/// only takes ticks prints zero here even though its tick count grows.
#[cfg(target_os = "none")]
pub static PROGRAMS_ON_OTHER_CPUS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Record that a program ended on `cpu`, which is not the boot CPU.
#[cfg(target_os = "none")]
pub fn note_program_ran_on(cpu: usize) {
    PROGRAMS_ON_OTHER_CPUS.fetch_add(1, core::sync::atomic::Ordering::Release);
    arch::serial::write_str("protofire: program ended on cpu ");
    arch::serial::write_u32(cpu as u32);
    arch::serial::write_str("\n");
}

/// How many programs ended on a CPU other than the boot one.
#[cfg(target_os = "none")]
pub fn programs_on_other_cpus() -> usize {
    PROGRAMS_ON_OTHER_CPUS.load(core::sync::atomic::Ordering::Acquire)
}

/// Record that the boot has ended, for every CPU to see.
#[cfg(target_os = "none")]
pub fn mark_finished() {
    crate::FINISHED.store(true, core::sync::atomic::Ordering::Release);
}

/// Report what the boot's programs did, then stop the machine.
///
/// ## Why this is one function now
///
/// The lines were inline in the exit handler, which was right while the CPU
/// that exited was the CPU that ended the machine.  With two CPUs the exit
/// that empties the machine is not necessarily the exit being served: a CPU
/// that finds nothing to run waits first, and the *waiting* side is where the
/// last task's absence becomes known.  One spelling, called from both.
///
/// It ends by stopping every CPU, so a caller that reaches the end does not
/// return.
#[cfg(target_os = "none")]
pub fn report_and_finish() -> ! {
    // One report, whoever gets here first.
    //
    // Both CPUs can reach this function: each notices the machine is finished
    // from its own wait loop, and neither can see the other's decision.  The
    // exchange is what makes "the boot is over" a claim with one owner; the CPU
    // that loses stops without printing, because the other is already printing.
    if crate::FINISHED.swap(true, core::sync::atomic::Ordering::AcqRel) {
        crate::idle_this_cpu()
    }

    let (switches, exited) = crate::scheduler::statistics();
    let ticks = crate::tick::TIMER_TICKS.load(core::sync::atomic::Ordering::Acquire) as u32;
    arch::serial::write_str("protofire: every program exited, ");
    arch::serial::write_u32(exited as u32);
    arch::serial::write_str(" exit(s), ");
    arch::serial::write_u32(ticks);
    arch::serial::write_str(" tick(s), ");
    arch::serial::write_u32(switches as u32);
    arch::serial::write_str(" switch(es)\n");

    // The process tree, as the exits recorded it.  The announcing program's
    // status is its own pid because it asks `GetPid` and exits with the answer;
    // the pipe's two programs have no identity call, so their status is
    // whatever their last call left in the argument register, reported as it
    // is rather than filtered.
    arch::serial::write_str("protofire: exit statuses ");
    let mut first = true;
    for (pid, status) in crate::scheduler::exit_statuses() {
        if !first {
            arch::serial::write_str(", ");
        }
        first = false;
        arch::serial::write_u32(pid);
        arch::serial::write_str(" -> ");
        arch::serial::write_u32(status as u32);
    }
    arch::serial::write_str("\n");

    // Whether the timer moved the CPU, as a fact and not a count: the count
    // depends on the emulator's speed, and a line that required a particular
    // one would be a gate on the host.
    if switches > 1 && ticks > 0 {
        arch::serial::write_str("protofire: the timer preempted, ");
        arch::serial::write_u32((switches - 1) as u32);
        arch::serial::write_str(" switch(es) from ticks\n");
    } else {
        arch::serial::write_str("protofire: the timer did not preempt\n");
    }

    // Where the programs ran: the two CPUs are useful only if programs ran on
    // both, and a machine whose started CPU took ticks and no program would
    // otherwise look the same in every other line.
    arch::serial::write_str("protofire: parallel, programs ended on ");
    arch::serial::write_u32(programs_on_other_cpus() as u32);
    arch::serial::write_str(" non-boot cpu(s)\n");

    crate::finish_and_halt()
}

/// A host has no machine to finish: the scheduler's own tests never install a
/// scheduler, so nothing reaches this; the signature exists so the scheduler
/// compiles where no CPU can idle.
#[cfg(not(target_os = "none"))]
pub fn report_and_finish() -> ! {
    panic!("report_and_finish called on a host: there is no boot to end")
}
