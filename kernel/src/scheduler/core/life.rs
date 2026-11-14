//! kernel/src/scheduler/core/life.rs
//!
//! The three events in a task's life that are not a switch: it is forked, it
//! becomes another program, and its pages are released.
//!
//! A fork shares the running task's pages with a child, so the child resumes
//! at the instruction after the parent's `fork` with the parent's registers
//! and a read-only view of the parent's pages.  An exec replaces the task's
//! image with another program's and starts it from that image's first
//! instruction, keeping the task, its pid and its window.  The release is the
//! other end: pages go back once nothing walks them, and
//! `Scheduler::reap_finished` argues why that moment is the end of the boot
//! rather than each exit.

use super::Scheduler;
#[cfg(target_os = "none")]
use crate::scheduler::task::State;
#[cfg(target_os = "none")]
use crate::scheduler::task::Task;
#[cfg(target_os = "none")]
use arch::Context;

impl Scheduler {
    /// Fork the running task.
    ///
    /// Bare metal only: a host has no address space to copy, and a fork that
    /// answered a pid it could not give a space to would be a promise the
    /// machine cannot keep.
    ///
    /// The child is added to the end of the run queue, so a parent that forks
    /// gets its own answer before the child runs: a child that ran first would
    /// return zero before the parent had learned its pid, and a program that
    /// printed the two would show them in the wrong order.
    ///
    /// The frame is handed in rather than read from the task: the context a
    /// task holds is the one its last switch saved, from before
    /// the call that is running now.  A child resuming there would re-execute
    /// its parent's whole path from the last switch, including the `fork` that
    /// created it, and the boot showed exactly that: one fork became seven,
    /// each child forking in turn.
    ///
    /// The frame the trap path holds is the one that names the instruction
    /// **after** the call.  So that is what a child inherits, and the live
    /// frame is also where the parent's answer is written.
    #[cfg(target_os = "none")]
    pub fn fork_current(&mut self, cpu: usize, frame: &Context) -> Option<usize> {
        let parent = self.running.get(cpu).copied().flatten()?;
        let parent_pid = self.tasks.get(parent)?.pid();
        let parent_context = *frame;

        // The parent's space, shared frame by frame.  A task with no space is
        // one sharing the kernel's, which a program never has: a fork of it
        // would be a fork of nothing.
        // Borrowed, not copied: a space owns a growable frame list, and the
        // fork reads it to decide what to share.  A copy would be a second
        // ownership of the same frames, which the pool's co-owner count would
        // then believe was two spaces when there was one.
        let parent_space = self.tasks.get(parent)?.space.as_ref()?;
        // SAFETY: the parent's space is live and this boot is the only writer.
        let child_space = unsafe { crate::address_space::fork_from(parent_space) }?;

        let pid = self.next_pid;
        self.next_pid += 1;

        let mut child = Task::new("child", 0, 0, child_space);
        child.identify(pid, parent_pid);
        // The context, not a fresh one: the child resumes at the instruction
        // after its parent's `fork`, on the stack page the two now share.
        *child.context_mut() = parent_context;
        // And the child's answer is zero, written into its own copy of the
        // frame.  The parent's register is untouched, so the same instruction
        // returns the pid in one process and zero in the other, which is the
        // whole of what `fork` answers.
        arch::set_return_value(child.context_mut(), 0);
        self.tasks.push(child);

        // **The child starts with its parent's descriptors**, copied and owned
        // by the child.  A `fork` that handed the child nothing would make
        // every inherited descriptor a number the child could not use, and
        // because the table refuses another process's slot, the child's first
        // read of a pipe its parent opened would answer `InvalidArgument`
        // rather than data.  The copy raises each pipe end's count, so
        // end-of-file waits for **both** processes to close theirs.
        //
        // Reported when it copied something: a boot whose programs open
        // nothing before forking has no line here, and a line printed for
        // every fork would say the mechanism ran on a boot that never used it.
        #[cfg(target_os = "none")]
        if let Some(copied) = crate::syscall::inherit(parent_pid, pid)
            && copied > 0
        {
            arch::serial::write_str("protofire: forked process ");
            arch::serial::write_u32(pid);
            arch::serial::write_str(" inherited ");
            arch::serial::write_u32(copied as u32);
            arch::serial::write_str(" descriptor(s)\n");
        }

        Some(pid as usize)
    }

    /// Replace the running task's image with the file at `path`, and start it
    /// over.
    ///
    /// This is `exec`: the same task, the same pid, the same parent, running a
    /// different program from that program's first instruction.  What carries
    /// over is the **identity** and nothing else, a fresh root, the file's
    /// segments mapped at the addresses the loader accepted, a stack of the
    /// kernel's own choosing above the image, and a context built from
    /// scratch, because a program that asked to become another does not resume
    /// where it was.  The window is the loaded image's own decision now: the
    /// program was linked at a base, and the loader maps what it linked.
    ///
    /// ## The order that makes releasing the old space sound
    ///
    /// The old root is installed on the CPU serving the call when this runs,
    /// and freeing a root the machine is translating through is a fault on the
    /// next instruction.  So the new space is built first, the task is swapped
    /// onto it, and `switch_address_space` installs the new root, which on
    /// every machine is a whole-TLB flush, **before** the old space is
    /// released.  At the moment of the release no CPU translates through the
    /// old root: this one just switched away, the machine's switches all flush,
    /// and the task is marked running here and nowhere else, so no other CPU
    /// ever held it.  A release done before the switch would have the pool
    /// handing the old root's frame to the new space while this CPU still
    /// walked it.
    ///
    /// ## Why the failure is answerless rather than partial
    ///
    /// Every step that can fail happens before the task is touched: the file
    /// is read whole, the image is loaded into a whole new space, and only
    /// then is the task's space, context and frame replaced.  A failure
    /// leaves the task exactly as it was, running the program it was running,
    /// and the caller answers an error rather than a pid.
    /// Read a program file and build the address space it runs in.
    ///
    /// This is the whole of what an image needs, the file read whole from
    /// the registry's filesystem, parsed into segments, mapped page by page
    /// at the addresses the loader accepted, a stack of the kernel's own
    /// choosing above the image, the window and break recorded, and the exec
    /// block written at the stack's top.  Both [`Self::exec_current`] and
    /// [`Self::spawn_from_file`] end here, because both need all of it and
    /// neither half of it is exec's alone; an exec replaces the calling
    /// task's image with what comes back, a spawn hands it to a task that
    /// does not exist yet.
    ///
    /// Answers the space, the entry, and the stack pointer the program
    /// starts at.  Every failure inside releases the space it built, so a
    /// refused image costs the pool nothing, which is also why the parse
    /// runs before `AddressSpace::new` allocates the root: a caller that
    /// parsed afterwards and answered `None` on a malformed file left a
    /// frame behind for every attempt, and any ring-3 program can attempt
    /// it as often as it likes.
    #[cfg(target_os = "none")]
    fn build_image_space(path: &str) -> Option<(crate::address_space::AddressSpace, usize, usize)> {
        // The file, whole, from the filesystem the registry serves.  The read
        // is bounded by the loader's own ceiling, a program bigger than this
        // is one the caller refuses before it maps.
        let bytes = crate::syscall::read_file(
            path,
            security::mac::MAC_TYPE_SYSTEM,
            crate::loader::MAX_IMAGE_BYTES,
        )
        .ok()?;

        // The image, parsed **before** any frame is taken.  The order is the
        // leak: `AddressSpace::new` allocates the root table, so a caller that
        // parsed afterwards and answered `None` on a malformed file left a
        // frame behind for every attempt, and any ring-3 program can attempt
        // it as often as it likes, which makes a local mistake into a way to
        // exhaust the pool.  `load` takes nothing but the bytes, so it goes
        // first and a refused image costs nothing.
        let image = match crate::loader::load(&bytes, arch::ELF_MACHINE) {
            Ok(image) => image,
            Err(_) => return None,
        };
        let mut space = unsafe { crate::address_space::AddressSpace::new() }?;
        // The loader's own line: the file was read and parsed into segments,
        // which is the one fact the exec'd and opened lines cannot carry
        // they say a program ran, this one says the *loader* ran.
        arch::serial::write_str("protofire: loaded ");
        arch::serial::write_str(path);
        arch::serial::write_str(", ");
        arch::serial::write_u32(image.segment_count as u32);
        arch::serial::write_str(" segment(s), entry ");
        arch::serial::write_hex(image.entry as u64);
        arch::serial::write_str("\n");
        // One slot per page the image can have, not per segment: the list
        // merges segments that share a page, so its size is the page count of
        // the largest image the loader admits.  It was `MAX_SEGMENTS * 2`
        // sixteen, which is a bound on segments and was doing double duty as
        // a bound on pages, and the two are not the same number.
        // `MAX_IMAGE_FRAMES`, not the space's ownership bound: this array is
        // one slot per page an **image** can have, and the ownership bound now
        // also covers what a program acquires at run time.  Sizing this by the
        // latter made it 32 KiB of kernel stack, which is a fault three frames
        // below `USER_BASE` rather than a refusal.
        let mut mapped: [Option<(usize, usize, paging::Permissions)>;
            crate::address_space::MAX_IMAGE_FRAMES] =
            [None; crate::address_space::MAX_IMAGE_FRAMES];
        for segment in image.segments() {
            for plan in crate::loader::pages(segment) {
                let permissions = paging::Permissions {
                    writable: segment.writable,
                    executable: segment.executable,
                    user: true,
                    cache: paging::Cache::Normal,
                };
                let existing = mapped
                    .iter_mut()
                    .find(|slot| matches!(slot, Some((va, _, _)) if *va == plan.virtual_address));
                if let Some(slot) = existing
                    && let Some((_, frame, perms)) = slot
                {
                    // The page is shared: this segment's bytes join the frame
                    // it already has, and the permissions widen to whatever
                    // both segments need.
                    perms.writable |= permissions.writable;
                    perms.executable |= permissions.executable;
                    if plan.copy_len > 0 {
                        // SAFETY: both ranges are in bounds, the loader
                        // checked the file range, and the frame is a whole
                        // page whose offset the plan names.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                bytes[plan.file_offset..].as_ptr(),
                                (*frame as *mut u8).add(plan.frame_offset),
                                plan.copy_len,
                            );
                        }
                    }
                    // SAFETY: the address passed the loader's window check,
                    // and the frame is this space's own.
                    let mapped_again =
                        unsafe { space.map_page_with(plan.virtual_address, *frame, *perms) };
                    if !mapped_again {
                        unsafe { space.release() };
                        return None;
                    }
                    continue;
                }
                // SAFETY: the frame comes from the pool.
                let Some(frame) = crate::address_space::allocate_image_frame() else {
                    unsafe { space.release() };
                    return None;
                };
                if !space.own(frame) {
                    unsafe { space.release() };
                    return None;
                }
                if plan.copy_len > 0 {
                    // SAFETY: both ranges are in bounds, the loader checked
                    // the file range, and the frame is a whole page whose
                    // offset the plan names.
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            bytes[plan.file_offset..].as_ptr(),
                            (frame as *mut u8).add(plan.frame_offset),
                            plan.copy_len,
                        );
                    }
                }
                // SAFETY: the address passed the loader's window check, and
                // the frame is this space's own.
                let mapped_now =
                    unsafe { space.map_page_with(plan.virtual_address, frame, permissions) };
                if !mapped_now {
                    unsafe { space.release() };
                    return None;
                }
                let Some(slot) = mapped.iter_mut().find(|slot| slot.is_none()) else {
                    unsafe { space.release() };
                    return None;
                };
                *slot = Some((plan.virtual_address, frame, permissions));
            }
        }

        // The stack, one page past the image's own end: the loader's layout is
        // the program's, and the stack is the kernel's addition to it.
        //
        // Answered rather than propagated with `?`: the space exists by now and
        // has frames in it, so every way out of this function has to release it
        // or the frames stay taken.  A `?` here would be the same leak the
        // parse order above was moved to avoid.
        let Some(image_top) = image.image_top() else {
            unsafe { space.release() };
            return None;
        };
        let stack_page = (image_top + paging::PAGE_SIZE) & !(paging::PAGE_SIZE - 1);
        // SAFETY: the frame comes from the pool.
        let Some(stack_frame) = crate::address_space::allocate_image_frame() else {
            unsafe { space.release() };
            return None;
        };
        if !space.own(stack_frame) {
            unsafe { space.release() };
            return None;
        }
        // SAFETY: the address is one page past the loader's checked segments,
        // which puts it in the same window; the frame is this space's own.
        let stack_ok = unsafe {
            space.map_page_with(
                stack_page,
                stack_frame,
                paging::Permissions {
                    writable: true,
                    executable: false,
                    user: true,
                    cache: paging::Cache::Normal,
                },
            )
        };
        if !stack_ok {
            unsafe { space.release() };
            return None;
        }

        // Where this program may grow: its window, and the break it grows
        // from.  Recorded here because this is the only place that knows both
        //, the window is what `program_base` names, and the image's end is
        // what the loader computed a few lines up and was, until now, dropped.
        //
        // The break starts **one page past the stack**, so a program's `Brk`
        // cannot grow into its own stack.  The reservations a `Mmap` makes come
        // down from the window's top, so the two ends meet in the middle and
        // the gap between them is what a program can actually use.
        let window_base = crate::process::program_base(1);
        let window_end = window_base + crate::address_space::USER_WINDOW;
        let break_base = stack_page + paging::PAGE_SIZE;
        space.set_window(window_base, window_end);
        space.set_brk(break_base);

        // The exec block: the one inheritance an `exec` carries.  The words go
        // below the stack top, the pointer starts at them, and the path's
        // bytes sit where [`crate::process::EXEC_PATH_OFFSET`] says, written
        // through the frame's physical address, the same place the boot writes
        // a pipe end into a stack it has not started yet.  The path is the one
        // this exec was called with, which is what a program that wants to
        // re-exec itself reads.
        let stack_top = stack_page + paging::PAGE_SIZE;
        let block_top = stack_top - crate::process::EXEC_BLOCK_BYTES;
        // SAFETY: the frame is the new space's own stack, zeroed by the pool
        // and not yet run; the block is `EXEC_BLOCK_BYTES` at its top and the
        // path is far shorter than the block.
        unsafe {
            let block =
                (stack_frame + paging::PAGE_SIZE - crate::process::EXEC_BLOCK_BYTES) as *mut u64;
            // The word at [sp] points at the path's bytes, not at itself: a
            // program reads [sp] and passes it straight to `Open`, so the
            // pointer is the one value that has to name the bytes.
            block.write((block_top + crate::process::EXEC_PATH_OFFSET) as u64);
            block.add(1).write(0);
            let path_at = (block.cast::<u8>()).add(crate::process::EXEC_PATH_OFFSET);
            for (index, byte) in path.as_bytes().iter().enumerate() {
                path_at.add(index).write(*byte);
            }
            path_at.add(path.len()).write(0);
        }

        Some((space, image.entry, block_top))
    }

    /// Start a new task running the program at `path`, and answer its pid.
    ///
    /// This is `spawn`: a **new** task, a **new** pid, the caller as its
    /// parent, running a program the caller named.  The image is the shared
    /// [`Self::build_image_space`] construction, the same read, the same
    /// loader, the same stack and exec block an `exec` builds, and what
    /// differs is where it lands: not the calling task's own image, but a
    /// task that did not exist before this call.  The child inherits
    /// nothing: no descriptors, no address space, no position, a fresh
    /// process opens its own files, which is the reading least privilege
    /// needs of a program the caller chose but did not vouch for byte for
    /// byte.
    ///
    /// The child is [`State::Runnable`] when this answers, so the next CPU
    /// that asks for work claims it; nothing here runs it directly, because
    /// the caller keeps the CPU it is on and the answer it is waiting for.
    #[cfg(target_os = "none")]
    pub fn spawn_from_file(&mut self, path: &str, parent_pid: u32) -> Option<u32> {
        let (space, entry, block_top) = Self::build_image_space(path)?;
        let pid = self.next_pid;
        self.next_pid += 1;

        let mut child = Task::new("child", entry, block_top, space);
        child.identify(pid, parent_pid);
        self.tasks.push(child);
        Some(pid)
    }

    #[cfg(target_os = "none")]
    pub fn exec_current(&mut self, cpu: usize, frame: &mut Context, path: &str) -> Option<u32> {
        let task_index = self.running.get(cpu).copied().flatten()?;

        // The image, built: read, parsed, mapped, stacked, and carrying the
        // exec block.  The construction is [`Self::build_image_space`]'s,
        // which is what a spawned task shares, the one thing an exec and a
        // spawn both need is the whole of this, and neither half of it is
        // exec's alone.
        let (space, entry, block_top) = Self::build_image_space(path)?;

        let new_root = space.root();
        // Every exit from here releases the space it built.  The task index
        // came from `running[cpu]` and the space was built around it, so the
        // lookups cannot fail today, but "cannot fail" and "leaks a whole
        // address space if it does" are not a pair worth keeping, and the
        // checked form costs one branch on a path that already parsed a file.
        let Some(pid) = self.tasks.get(task_index).map(|task| task.pid()) else {
            unsafe { space.release() };
            return None;
        };
        let Some(task) = self.tasks.get_mut(task_index) else {
            unsafe { space.release() };
            return None;
        };
        // The space the task ran in before this call, if it had one of its own.
        // `None` means it ran on the kernel's table, which no ring-3 task does;
        // the arm exists so the possibility is stated, and it carries on rather
        // than returning, because the new space is already installed in the
        // task and it is the one the epilogue will run on.
        let old_space = task.space.replace(space);
        // A fresh context, not a copy: the program starts at its own first
        // instruction, on a stack that carries the exec block and nothing from
        // the program it replaced.
        *task.context_mut() = crate::scheduler::starting_context(entry, block_top);
        // And the trap frame resumes the new image, because the caller's
        // epilogue is what returns to a program and this task is the one
        // running.
        *frame = *task.context();

        // SAFETY: the new root is a live table this task owns, and every root
        // shares the kernel's entry 0, which covers the code performing the
        // call.
        unsafe { arch::switch_address_space(new_root) };
        // **Retired, not released.**  The old space is garbage to this CPU the
        // moment the switch above returns, and it is not garbage to every CPU:
        // a task is not pinned, and the boot's own log shows migrations, so a
        // CPU that ran this task a moment ago may still have the old root
        // installed and be inside its trap path.  Freeing here handed live
        // frames back to the pool, a data abort inside the heap allocator and
        // an instruction abort at 0x0, six boots in ten on the machine whose
        // second CPU migrates most, and the fix is the deferral every finished
        // task already takes: hold the space until
        // [`reap_finished`](Self::reap_finished), where every task has finished
        // and every other CPU has been told to stop.
        //
        // A full array leaks the space rather than dropping it: nothing here
        // can free a frame that another CPU may still reach, and a boot that
        // has exec'd eight times has already said what it needed to say.
        if let Some(old_space) = old_space
            && let Some(slot) = self.retired.iter_mut().find(|slot| slot.is_none())
        {
            *slot = Some(old_space);
        }
        Some(pid)
    }

    /// Release every finished task's address space, answering how many went
    /// back.
    ///
    /// ## When this is safe, and why the caller must say
    ///
    /// A finished task's pages are free only when nothing will translate
    /// through them again.  Clearing the task's slot is **not** that condition:
    /// the CPU that leaves a task keeps the task's root installed while it
    /// waits for work, and it can be inside its trap path with no lock held.
    /// Releasing at each exit produced 186 page faults at `0x8080000030`,
    /// program 2's stack, in six boots of eight, a frame the kernel still
    /// walked, handed by the pool to someone else.
    ///
    /// So this is called once, after every task has finished and every other
    /// CPU has been told the boot is over.  At that point no CPU is inside a
    /// program and none will enter one, which is the whole of the safety
    /// argument, and it is the caller's to make rather than this function's to
    /// guess.
    ///
    /// A task whose space is already gone is skipped, so a second call answers
    /// zero instead of freeing a frame twice.
    ///
    /// The spaces an `exec` retired go back here too, and for the same reason:
    /// they are unreachable from this CPU and not necessarily from every other
    /// one, and this is the only moment the whole task set is quiescent.
    #[cfg(target_os = "none")]
    pub fn reap_finished(&mut self) -> usize {
        let mut reaped = 0;
        for task in &mut self.tasks {
            if task.state != State::Finished {
                continue;
            }
            let Some(space) = task.space.take() else {
                continue;
            };
            // SAFETY: the caller promises the machine is finished, so no CPU is
            // running a program and none will: every task is `Finished` and
            // every other CPU has been told to stop.
            unsafe { space.release() };
            reaped += 1;
        }
        // The exec'd spaces, under the same promise.  They are released after
        // the tasks' own so the count above stays the number of processes that
        // finished, which is what the boot's line reports; these are spaces no
        // task ever finished in, and a reader asking "how many programs ran and
        // ended" must not see them added.
        for slot in &mut self.retired {
            if let Some(space) = slot.take() {
                // SAFETY: as above, the machine is finished.
                unsafe { space.release() };
            }
        }
        reaped
    }
}
