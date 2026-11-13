//! kernel/src/service/table.rs
//!
//! A table from a name to a service, and the rule that keeps it a table.
//!
//! ## Parked on purpose
//!
//! This module is built and tested, and **nothing further should be added to it
//! without deciding it is time for "everything is a service"**.  That direction
//! is for later; the table exists so it has a base when it is reached.  What
//! makes that a decision rather than a note: no driver implements
//! [`async_io::Service`], no syscall reaches this table, and the ring-3 half
//! ([`apps/service_manager`](../../../apps/service_manager)) is still a shell.
//! `docs/status.md` carries the reasoning and the prerequisites.
//!
//! ## What a service is, here
//!
//! [`async_io::Service`]: a thing that accepts a request and completes it
//! later.  A driver, a timer, a thread and a program are all describable that
//! way, and this module is the place a caller finds one by name instead of by
//! knowing which crate implemented it.
//!
//! ## The three rules, and why each is here
//!
//! **Written only during boot.**  [`install`] refuses after [`freeze`], and the
//! boot is what calls both.  A table anything can write at any time is a table
//! whose contents nobody can state: the answer to "which services exist" would
//! depend on what ran before, and every reader would have to defend against a
//! service appearing or being replaced underneath it.
//!
//! **Read-only afterwards, and cheap to read.**  A [`Shared`] is an `Arc` the
//! caller keeps: finding a service is one lookup, and using it afterwards is a
//! function call rather than another lookup that could disagree with the first.
//!
//! **No persistence.**  The table is a `static` in this module.  It is rebuilt
//! every boot from the services the boot installs, and a machine that changed
//! its mind about what exists cannot leave a stale entry for the next boot to
//! find.
//!
//! Those three are the whole design.  What they rule out is the shape where a
//! name outlives the code that answers for it and every entry is a string
//! somebody once wrote: here a name is `&'static str` chosen by the installer,
//! and what it answers with is a live `dyn Service`, so a caller that asks for
//! `"clock"` gets something it can submit to or nothing at all.
//!
//! ## Why the entry is a trait object and not a concrete type
//!
//! Because the point of the table is that the caller does not know what it
//! found.  A table of `MemoryBlockService` would answer one question about one
//! implementation; the trait is what lets a driver and a timer sit in the same
//! array and be driven by the same loop.
//!
//! ## The lock
//!
//! [`sync::Mutex`] is a spinlock that masks interrupts while held, which is
//! what this table needs: a lookup can happen in a trap, and a lookup that
//! could be interrupted by a lookup is a lock taken twice on one CPU.  The lock
//! is held for the length of one lookup or one installation and never across a
//! call to a service.

use alloc::boxed::Box;
use alloc::sync::Arc;

use async_io::Completion;
use async_io::Request;
use async_io::Service;
use sync::Mutex;

/// The most services one boot may install.
///
/// Fixed rather than growable, and that is the first rule showing: the table is
/// sized once and the array is the bound, so "the table is full" is an answer
/// [`install`] can give rather than an allocation that might fail later.  Eight
/// is more than the devices, the clock, the program launcher and the scheduler
/// need together, and a boot that reaches it is a boot whose service list wants
/// reading rather than one that wants a bigger number.
pub const MAX_SERVICES: usize = 8;

/// A service the table holds, as the caller drives it.
///
/// `Box<dyn Service>` inside a lock inside an `Arc`: the box is because the
/// trait has no size, the lock is because [`Service`] takes `&mut self` and two
/// callers can hold the same handle, and the `Arc` is because a handle outlives
/// the lookup that produced it.
pub type Shared = Arc<Mutex<Box<dyn Service + Send>>>;

/// One entry: the name the boot chose, and the thing it answers with.
struct Entry {
    name: &'static str,
    service: Shared,
}

impl Entry {
    /// Whether this entry answers to `name`.
    ///
    /// A byte comparison rather than a string comparison because both sides are
    /// known to be UTF-8: the name is `&'static str` and the query is `&str`.
    /// Doing it by bytes keeps the table usable before anything that needs an
    /// allocator to compare strings.
    fn answers_to(&self, name: &str) -> bool {
        self.name.len() == name.len() && self.name.as_bytes() == name.as_bytes()
    }
}

/// The table itself.
///
/// A value with methods, and the module's global is one instance of it.  That
/// shape is not decoration: a table that can only exist as one global cannot be
/// tested without tests sharing it, and the first version of this file had
/// exactly that defect — one test filled the table and the rest failed on
/// `TableFull` in whatever order the harness chose.  A boot wants one table; a
/// test wants as many as it has cases.
pub struct Table {
    entries: [Option<Entry>; MAX_SERVICES],
    /// Whether [`freeze`] has been called, after which `install` refuses.
    frozen: bool,
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

impl Table {
    /// An empty, unfrozen table.
    pub const fn new() -> Self {
        // `[None; MAX_SERVICES]` needs `Option<Entry>: Copy`, which an `Entry`
        // holding an `Arc` is not.  The `const` block repeats the value
        // instead, which is why this is a `const fn` with a loop-shaped
        // initialiser rather than the array literal it looks like it should be.
        Self {
            entries: [const { None }; MAX_SERVICES],
            frozen: false,
        }
    }

    /// How many entries are installed.
    pub fn installed(&self) -> usize {
        self.entries.iter().filter(|slot| slot.is_some()).count()
    }

    /// The entry answering to `name`, if one is installed.
    fn find(&self, name: &str) -> Option<&Shared> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.answers_to(name))
            .map(|entry| &entry.service)
    }

    /// Install `service` under `name` in **this** table.
    ///
    /// The same rules the free function applies, and the free function is a
    /// lock and a call to this: one implementation, so a test that installs
    /// into its own table is checking the code a boot runs.
    pub fn install(&mut self, name: &'static str, service: Shared) -> Result<(), InstallError> {
        if self.frozen {
            return Err(InstallError::Frozen);
        }
        if self.find(name).is_some() {
            return Err(InstallError::NameTaken);
        }
        let Some(slot) = self.entries.iter_mut().find(|slot| slot.is_none()) else {
            return Err(InstallError::TableFull);
        };
        *slot = Some(Entry { name, service });
        Ok(())
    }

    /// Freeze this table.
    pub fn freeze(&mut self) {
        self.frozen = true;
    }

    /// Whether this table is frozen.
    pub fn is_frozen(&self) -> bool {
        self.frozen
    }

    /// The service answering to `name` in this table.
    pub fn lookup(&self, name: &str) -> Option<Shared> {
        self.find(name).cloned()
    }
}

/// The one table this boot has.
static SERVICES: Mutex<Table> = Mutex::new(Table::new());

/// Why an installation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallError {
    /// A service already answers to that name.
    ///
    /// Reported rather than replacing: two installers that both believe they
    /// own a name is a boot whose service list is wrong, and the one that
    /// arrived second should be told so rather than silently winning.
    NameTaken,
    /// Every slot is in use.
    TableFull,
    /// [`freeze`] has been called.
    ///
    /// The boot installs its services and then freezes the table; an install
    /// after that is code that meant to run during boot and did not, which is a
    /// defect worth failing rather than a service worth adding.
    Frozen,
}

/// Install `service` under `name`.
///
/// The name is `&'static str` on purpose: a service's name is part of the
/// boot's own code, not something read from a file or built at run time, and
/// requiring a `'static` string makes that a compile-time fact rather than a
/// convention.
///
/// Refused after [`freeze`], on a duplicate name, and when the table is full.
pub fn install(name: &'static str, service: Shared) -> Result<(), InstallError> {
    SERVICES.lock().install(name, service)
}

/// Stop accepting installations.
///
/// Called once by the boot, after the last service is installed and before
/// anything can look one up.  Idempotent: a second call is not an error,
/// because the state it asks for is the state the table is in.
pub fn freeze() {
    SERVICES.lock().freeze();
}

/// Whether the table has been frozen.
pub fn is_frozen() -> bool {
    SERVICES.lock().is_frozen()
}

/// How many services are installed.
pub fn installed() -> usize {
    SERVICES.lock().installed()
}

/// The service answering to `name`, or `None`.
///
/// The handle the caller keeps.  Using it afterwards is a lock on the service's
/// own mutex and a call through the trait, not another lookup: a caller that
/// resolved a name once cannot find a different service behind it later.
pub fn lookup(name: &str) -> Option<Shared> {
    SERVICES.lock().lookup(name)
}

/// Submit a request to the service answering to `name`, and drain what it
/// produces.
///
/// The one function that shows the whole model working end to end, and it
/// exists because every caller that holds a name would otherwise write it: look
/// up, submit, poll until the completion arrives, take it.  A request that
/// finishes in the call is answered from the call; one that does not is polled
/// for, bounded by `polls`.
///
/// The bound is the caller's because only the caller knows how long its service
/// is supposed to take.  A name that answers to nothing is `None`, which is a
/// different answer from a request that was accepted and never completed.
pub fn request(name: &str, request: Request, polls: usize) -> Option<Completion> {
    let service = lookup(name)?;
    let mut service = service.lock();
    if let Some(completion) = service.submit(request) {
        // Finished in the call: the caller does not wait for work that is
        // already done.
        return Some(completion);
    }
    for _ in 0..polls {
        service.poll();
        if let Some(completion) = service.take_completion() {
            return Some(completion);
        }
    }
    None
}

#[cfg(test)]
mod tests;
