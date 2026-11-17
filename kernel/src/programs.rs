//! kernel/src/programs.rs
//!
//! The boot's programs: build them, map them, and let the scheduler run them.
//!
//! ## The three modules a reader can confuse
//!
//! [`crate::loader`] **reads** an image: bytes in, an entry point and a page
//! plan out.  This file **places** one: it picks a virtual base, copies the
//! bytes into frames, maps them, builds a stack, and enters the result.  And
//! [`crate::process`] is what the kernel does with a program's *call*, the
//! handler a trap reaches.
//!
//! So a reader asking "is this file a program this kernel can run" reads
//! `loader`; one asking "what does this boot start, and where does it put it"
//! reads this file; one asking "how does a call get served" reads `process`.
//! This file is the only one of the three that knows all of them, which is
//! what makes it the boot's and not a library's.
//!
//! It differs from the exec path in one way worth stating: this file builds
//! the boot's own programs from bytes `arch` supplies, and the scheduler's
//! `build_image_space` builds a program from a **file** the filesystem holds.
//! The first needs no filesystem and proves the entry path; the second needs
//! the registry and proves a program that arrived after the boot.

#[cfg(target_os = "none")]
use crate::scheduler::Scheduler;
#[cfg(target_os = "none")]
use crate::scheduler::Task;

/// The process id the boot's own work is done under.
///
/// A program the kernel starts is a child of this, which is a fact rather than
/// a placeholder.  A forked child gets a different answer: its parent is the
/// program that forked it, recorded by the fork, not by the boot.
pub const BOOT_PROCESS: u32 = 0;

/// How the boot's three programs are arranged.
///
/// One program proves the entry path; it cannot prove a switch, because a
/// switch needs something to switch to.  Three programs that each print their
/// number exercise a second and third address space, two contexts saved and
/// restored, a sleep that parks a task and a read that parks a task on a pipe,
/// and the exits reaped, the boot's three, plus the fourth process its fork
/// creates, whose space is reaped beside theirs.
///
/// A log that shows the numbers interleaved is the evidence; one program twice
/// looks the same as one program once, which is why the number is the program's
/// own value and not the kernel's counter.
#[cfg(target_os = "none")]
pub fn run() {
    use crate::process;

    // SAFETY: all three sinks are installed once, before ring 3 is entered.
    unsafe {
        arch::set_call_sink(process::serve);
        arch::set_preempt_sink(crate::scheduler::preempt);
        arch::set_fault_sink(crate::scheduler::die_from_fault);
    }

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
    // The owner is the process that will **hold** the end, not the one that
    // made the pipe: the boot makes it and hands it to a program through the
    // program's stack, and from then on the program's exit is what must close
    // it.  Registering both ends as the boot's own would leave them open for
    // ever, the boot outlives every program, and a reader waiting on a
    // writer that had exited would never see end-of-file.  Measured: with the
    // boot as owner, the writer's exit released nothing and the boot hung.
    let reader = match crate::pipe::attach(
        crate::pipe::End::reader(pipe.clone()),
        crate::process::PIPE_READER as u32,
    ) {
        Some(descriptor) => descriptor,
        None => {
            arch::serial::write_str("protofire: no room for a pipe end\n");
            return None;
        }
    };
    let writer = match crate::pipe::attach(
        crate::pipe::End::writer(pipe),
        crate::process::PIPE_WRITER as u32,
    ) {
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

    // SAFETY: a fresh root, owned by this space and by no other, which is the
    // constructor's contract.
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

    // The exec-path block, for **every** program: the boot's choice of
    // executable, where a program that execs reads it.  The pipe hand-over is
    // the pipe programs' alone, but the exec path is every program's, the
    // boot does not know which one will want to become another.
    // The exec-path block, for **every** program: the boot's choice of
    // executable, where a program that execs reads it.  The pipe hand-over is
    // the pipe programs' alone, but the exec path is every program's, the
    // boot does not know which one will want to become another.
    // The virtual stack page, which is what the exec-path pointer must
    // name: the bytes are written through the frame's identity mapping, but
    // the program reads the pointer through its own mapping, so the value
    // has to be the address as the program sees it.
    let stack_page_virtual = process::program_stack_page(number);
    write_exec_path(stack, stack_page_virtual);
    let handed_stack_top = hand_over_pipe(number, stack, reader_end, writer_end);

    let base = process::program_base(number);
    let stack_page = process::program_stack_page(number);
    // The same pair `image_space` maps for a loaded program, stated here for
    // the boot's own: the image is machine code and is read-execute, the stack
    // holds the hand-over words and is read-write and not executable.  The
    // stack was executable until `map` stopped inventing the execute bit, and
    // nothing about a program's stack ever wanted one.
    let image_permissions = paging::Permissions {
        writable: false,
        executable: true,
        user: true,
        cache: paging::Cache::Normal,
    };
    let stack_permissions = paging::Permissions {
        writable: true,
        executable: false,
        user: true,
        cache: paging::Cache::Normal,
    };
    // SAFETY: both frames belong to this space, and the two virtual addresses
    // are this program's own window.
    let mapped = unsafe {
        space.map(base, image, image_permissions) && space.map(stack_page, stack, stack_permissions)
    };
    if !mapped {
        arch::serial::write_str("protofire: a program could not be mapped\n");
        return None;
    }

    arch::serial::write_str("protofire: program ");
    arch::serial::write_u32(number as u32);
    arch::serial::write_str(" mapped at ");
    arch::serial::write_hex(base as u64);
    arch::serial::write_str("\n");

    // The stack pointer every program starts at: 32 bytes below the page's
    // top, which is where the hand-over block sits.  A pipe program's
    // descriptor is at `[rsp]`; the exec path is at `[rsp-32]` for **every**
    // program, one shape, not one per hand-over combination.
    let stack_top = process::program_stack_top(number) - 32;
    let _ = handed_stack_top;
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
    // own process, and the boot is the parent of each.  The one process here
    // with a program for a parent is the one `fork` creates, and the fork
    // fills these from the caller's own ids rather than from the boot's.
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

/// The path the boot hands each program as its own choice of executable,
/// NUL-terminated.
///
/// A program that execs reads the pointer at `[rsp-32]`, written beside the
/// pipe descriptor by [`hand_over_pipe`], and passes it to `ExecProcess`
/// unchanged.  The boot names the program the tree builds rather than a
/// constant the caller guesses at, which is what makes "the boot execs its
/// own init" a fact about the boot and not an agreement between two arrays.
#[cfg(target_os = "none")]
const EXEC_PATH_FROM_BOOT: &str = "/bin/init";

/// Write the boot's choice of executable into a program's stack: a pointer at
/// `PAGE - 64` to the NUL-terminated path at `PAGE - 56`.
///
/// The same shape the kernel's exec block leaves for a program it starts, a
/// program reads `[rsp-32]` and passes it straight to `ExecProcess`, because
/// the two are one convention: what the boot leaves at start, what `exec`
/// leaves after becoming.  Every program gets it, not just the ones that
/// currently exec: which program wants to become another is the program's
/// decision, not the boot's.
#[cfg(target_os = "none")]
fn write_exec_path(stack: usize, virtual_page: usize) {
    // The value is the **virtual** address, `virtual_page + PAGE_SIZE - 88`:
    // the program reads the pointer through its own mapping, and a physical
    // address there would be a number outside the user window, the one
    // thing every path check exists to refuse.  The first version wrote the
    // frame's identity-mapped address, and the program execed a pointer the
    // path check refused, spinning silently at its end.
    let pointer_value = virtual_page + paging::PAGE_SIZE - 88;
    // SAFETY: `stack` is the frame the program owns for its stack, the
    // program has not run, and the block is inside the page.
    unsafe {
        let ptr_at = (stack + paging::PAGE_SIZE - 96) as *mut u64;
        ptr_at.write(pointer_value as u64);
        let path_at = (stack + paging::PAGE_SIZE - 88) as *mut u8;
        for (index, byte) in EXEC_PATH_FROM_BOOT.as_bytes().iter().enumerate() {
            path_at.add(index).write(*byte);
        }
        path_at.add(EXEC_PATH_FROM_BOOT.len()).write(0);
    }
}

/// What a started CPU runs: the task the scheduler gives it, and its root.
///
/// A started CPU is given two things the scheduler does not know about: which
/// task it picked, and which root table that task runs through.  The second is
/// the address space's, and joining them is what a program's *start* is, which
/// is this module's subject.
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

/// Whether the boot has ended, **without recording anything**.
///
/// The predicate any CPU may ask anywhere.  Reading one atomic and no side
/// effect is the whole of what separates it from [`boot_is_finished`], and the
/// separation matters: "this CPU will not touch a user space again" is the
/// statement the reaping side frees address spaces on, so a look that recorded
/// itself would let a CPU still inside its trap path count as gone.  That
/// mistake was made once here and its symptom was a fault at `0x60000000`, one
/// byte past the top of RAM.
///
/// A caller asks this to decide whether it still has anything to contribute,
/// and a "yes" means it does not: the scheduler's idle loop uses it to stop.
/// [`boot_is_finished`] is the call that records the stop, and it belongs where
/// a CPU has actually decided.
#[cfg(target_os = "none")]
pub fn boot_has_ended() -> bool {
    crate::FINISHED.load(core::sync::atomic::Ordering::Acquire)
}

/// A host has no boot to end, so the answer is always no.
#[cfg(not(target_os = "none"))]
pub fn boot_has_ended() -> bool {
    false
}

/// Whether the boot has ended, for a started CPU that has **decided to stop**.
///
/// The kernel's answer, injected into `arch` for the reason the work source is:
/// the flag lives here, and a machine crate that named it would be a cycle.
///
/// A CPU that asks this and hears "yes" is a CPU about to stop, and the answer
/// is where it records that.  It is the one place every started CPU passes
/// through on its way out and no CPU passes on its way in, which is what makes
/// it the right place to say "I will not touch a user space again", the
/// statement the reaping side waits for.  Recording it any later would be a
/// claim made after the CPU had stopped, which nothing could wait on.
///
/// A caller that only wants to know whether the boot is over asks
/// [`boot_has_ended`].  This one is a decision to stop, and the caller halts
/// immediately afterwards; `wait_for_work` is the shape it is for.
#[cfg(target_os = "none")]
pub fn boot_is_finished() -> bool {
    let finished = crate::FINISHED.load(core::sync::atomic::Ordering::Acquire);
    if finished {
        crate::per_cpu::park(crate::per_cpu::current_slot());
    }
    finished
}

/// A host has no boot to finish, so the answer is always no.
///
/// Present so the scheduler's idle loop compiles and its documentation links
/// resolve on a host build, where there is no machine to end.  A `true` here
/// would be a claim about a machine that does not exist.
#[cfg(not(target_os = "none"))]
pub fn boot_is_finished() -> bool {
    false
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

/// When this CPU should stop waiting for the others to confirm they parked.
///
/// How many times the reaping side asks before it stops waiting for the others.
///
/// Counted in turns of its own loop, not in seconds, because the clock is the
/// thing that cannot be trusted here, a slice computed from a claimed rate
/// that the counter does not keep is what made the wait run long in the first
/// place.  A turn sends nothing and reads one atomic, so the number is cheap.
///
/// The value has to clear the ordinary case with a wide margin: a CPU that is
/// merely slow to notice `FINISHED` parks within a handful of its own idle
/// turns.  A hundred million turns is far beyond that and is still a fraction
/// of a second on any machine this tree runs on, which is the bound's job
/// finite, not exact.
#[cfg(target_os = "none")]
const PARK_WAIT_TURNS: u32 = 100_000_000;

/// Every how many turns the wait re-sends the inter-CPU line.
#[cfg(target_os = "none")]
const PARK_PING_TURNS: u32 = 100_000;

/// The CPUs that are online and never confirmed they parked, if any.
#[cfg(target_os = "none")]
fn unconfirmed_cpus() -> usize {
    (0..crate::per_cpu::MAX_CPUS)
        .filter(|slot| crate::per_cpu::slot(*slot).online() && !crate::per_cpu::is_parked(*slot))
        .count()
}

/// Report what the boot's programs did, then stop the machine.
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
    //
    // The loser parks **before** it stops.  It is a CPU that will never run a
    // program again, and saying so is what lets the winner's wait below end:
    // a loser that halted silently would leave the winner spinning for a CPU
    // that had already gone, which is a hang on every boot with two CPUs.
    if crate::FINISHED.swap(true, core::sync::atomic::Ordering::AcqRel) {
        crate::per_cpu::park(crate::per_cpu::current_slot());
        crate::idle_this_cpu()
    }

    // Wait until every CPU that is online has said it will not reach into a
    // user space again, and only then release anything.
    //
    // `FINISHED` is a **request**, not a proof.  The other CPU can hold that
    // flag and still be walking a page table, restoring a trap frame, or one
    // instruction from reading a user address; it records itself parked only
    // when its own idle loop asks whether the boot is over, and that is the
    // last moment it can still name one of these tables.  Releasing before
    // that produced a data abort inside the heap allocator's free-list walk and
    // an instruction abort at 0x0, a table the boot CPU had already handed to
    // the pool, read by the CPU that was still using it.  It reproduced on six
    // boots in ten with two CPUs and never with one, which is exactly the shape
    // of a claim about "the other CPU" that was never checked.
    //
    // This CPU parks itself first: it is about to stop running programs, and
    // the count would never be complete otherwise.
    crate::per_cpu::park(crate::per_cpu::current_slot());
    // Wait for them, but **not for ever**.
    //
    // The wait used to be a spin with no end, on the argument that the others
    // would park as soon as they saw `FINISHED`.  What a debugger found was a
    // CPU that never saw it: asleep in `wfi`, its counter frozen, its timer
    // never firing, because this machine's `CNTFRQ_EL0` claims 1 GHz while the
    // counter moves at a fraction of that, so a slice computed from the claimed
    // rate is a wait far longer than the boot.  The other CPU was not refusing
    // to park; it had no interrupt to wake it with.
    //
    // A boot that ends is worth more than a proof that it ended cleanly, so
    // this is bounded by **this** CPU's counter rather than by the other's
    // timer. Past the bound the reaping goes ahead and the line says which CPUs
    // never confirmed.  That is safe for the reason the deferral exists: at
    // this point every task is `Finished`, so no CPU will *enter* a program
    // again, and the only reach left into those tables is one that was already
    // inside a trap path, which is what the confirmation was for.  A boot that
    // says so is honest about it; a boot that hangs says nothing.
    //
    // SAFETY: the boot's own IPI path, installed before any program ran.
    unsafe { arch::send_ipi_to_others() };

    // The bound is counted in this loop's own turns, not in seconds: the clock
    // is the thing under suspicion, and a bound that asked the suspect how long
    // to wait is how the original hang happened.  See `PARK_WAIT_TURNS`.
    let mut turns = 0u32;
    while !crate::per_cpu::all_parked() {
        turns += 1;
        if turns.is_multiple_of(PARK_PING_TURNS) {
            // SAFETY: as above.
            unsafe { arch::send_ipi_to_others() };
        }
        if turns >= PARK_WAIT_TURNS {
            break;
        }
        core::hint::spin_loop();
    }

    // Every task is finished and every other CPU has been told the boot is
    // over, so no CPU is inside a program and none will enter one.  This is the
    // one moment the whole machine's task set is quiescent, and it is where the
    // address spaces go back.
    //
    // ## Why not at each exit
    //
    // Because the first version did exactly that and it was wrong.  A task's
    // slot is cleared by the switch that leaves it, so "no CPU holds this task"
    // is true the instant it exits, and it is not the condition that matters.
    // The other CPU may still be installed on that task's root: it can be in
    // its own trap path, returning through a frame that belongs to the program,
    // with the scheduler's lock not held.  Freeing then produced 186 page
    // faults at `0x8080000030`, program 2's stack, in six boots of eight: a
    // frame the kernel still walked, in a pool that had given it to someone
    // else.
    //
    // A finished task's pages are not needed for it to stay finished.  Holding
    // them until the machine stops costs nothing and removes the whole class of
    // race, which is the trade this boot's programs cannot observe.
    let reaped = crate::scheduler::reap_address_spaces();

    let (switches, exited, delivered) = crate::scheduler::statistics();
    let ticks = crate::tick::TIMER_TICKS.load(core::sync::atomic::Ordering::Acquire) as u32;
    arch::serial::write_str("protofire: every program exited, ");
    arch::serial::write_u32(exited as u32);
    arch::serial::write_str(" exit(s), ");
    arch::serial::write_u32(ticks);
    arch::serial::write_str(" tick(s), ");
    arch::serial::write_u32(switches as u32);
    arch::serial::write_str(" switch(es), ");
    arch::serial::write_u32(delivered as u32);
    arch::serial::write_str(" signal delivery(ies)\n");

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

    // What the placement rule did, as a fact rather than a policy.  A task is
    // not pinned to a CPU: any task that left its CPU is selectable by another,
    // so a task that was preempted or woken may resume somewhere else.  The
    // count is how often that happened, and the last one names the process and
    // both CPUs, because a total alone does not say what moved.
    let (migrations, last) = crate::scheduler::migrations();
    arch::serial::write_str("protofire: task migrations ");
    arch::serial::write_u32(migrations as u32);
    if let Some((pid, from, to)) = last {
        arch::serial::write_str(", last process ");
        arch::serial::write_u32(pid);
        arch::serial::write_str(" from cpu ");
        arch::serial::write_u32(from as u32);
        arch::serial::write_str(" to cpu ");
        arch::serial::write_u32(to as u32);
    }
    arch::serial::write_str("\n");

    // The placement rule's other half.  A migration says a task **moved**; this
    // says a switch put one back where it last ran, which is the placement the
    // rule prefers and the one a migration costs.  The two numbers together are
    // what a reader compares: a boot whose home count is zero moved everything
    // it placed, and a boot whose migration count is zero never had to.
    let (homed, homed_last) = crate::scheduler::placings_home();
    arch::serial::write_str("protofire: task placings home ");
    arch::serial::write_u32(homed as u32);
    if let Some((pid, cpu)) = homed_last {
        arch::serial::write_str(", last process ");
        arch::serial::write_u32(pid);
        arch::serial::write_str(" on cpu ");
        arch::serial::write_u32(cpu as u32);
    }
    arch::serial::write_str("\n");

    // The frames the exits gave back, and the pool they went into.  A boot that
    // reaped nothing prints the same `0` here as a boot whose release path
    // never ran, which is why the free count is beside it: the pool started
    // with every frame free, so the number that matters is how many came back
    // after the programs took them.
    arch::serial::write_str("protofire: address spaces reaped ");
    arch::serial::write_u32(reaped as u32);
    arch::serial::write_str(", ");
    arch::serial::write_u32(crate::address_space::free_frames() as u32);
    arch::serial::write_str(" frame(s) free\n");

    // The device's completion messages, taken from the trap path.
    //
    // The count is here rather than beside the wiring because it is a total,
    // and the wiring's line is a claim about what was armed: a boot can arm
    // every register and still take nothing, which is exactly the state that
    // hid this mechanism for a session.  An IMSIC file holds one pending bit
    // per identity, so the number is how many times the **trap** ran, not how
    // many completions the device finished, several completions that arrive
    // before the first is claimed share a bit, which is why the count is small
    // and its own place on the report is what makes it readable.
    arch::serial::write_str("protofire: block completion message(s) taken = ");
    arch::serial::write_u32(
        crate::BLOCK_MESSAGES.load(core::sync::atomic::Ordering::Acquire) as u32,
    );
    arch::serial::write_str("\n");

    // The network card's, on its own line and its own identity.  Two counts
    // rather than one total because two devices are the claim: a sum would say
    // a message arrived without saying which device sent it, and a boot whose
    // card never delivered one while the disk delivered two would read as
    // three.
    arch::serial::write_str("protofire: network message(s) taken = ");
    arch::serial::write_u32(
        crate::NETWORK_MESSAGES.load(core::sync::atomic::Ordering::Acquire) as u32,
    );
    arch::serial::write_str("\n");

    // A boot that gave up waiting says so, and says on how many CPUs.  This is
    // the line that turns "the machine ended" from an assumption into a fact
    // with a number: zero is a boot where every CPU confirmed, and a count is a
    // boot where one of them did not answer and the reaping went ahead anyway.
    // Without it the bound above would be a silent widening of a rule, the
    // thing this tree's gates exist to refuse.
    let unconfirmed = unconfirmed_cpus();
    if unconfirmed > 0 {
        arch::serial::write_str("protofire: ended without confirmation from ");
        arch::serial::write_u32(unconfirmed as u32);
        arch::serial::write_str(" cpu(s)\n");
    }

    crate::finish_and_halt()
}

/// A host has no machine to finish: the scheduler's own tests never install a
/// scheduler, so nothing reaches this; the signature exists so the scheduler
/// compiles where no CPU can idle.
#[cfg(not(target_os = "none"))]
pub fn report_and_finish() -> ! {
    panic!("report_and_finish called on a host: there is no boot to end")
}
