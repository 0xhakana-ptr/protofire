//! devices/block/src/queue.rs
//!
//! The queued half of the block interface: a ticket, a request's state, and
//! the methods that let a caller be ahead of a device.
//!
//! ## Why this is a trait beside `BlockDevice` and not part of it
//!
//! Most of `BlockDevice` is safe methods a device must have: a name, a block
//! count, `read_blocks`, `write_blocks`.  An in-memory device and a device
//! behind a virtqueue both have those.
//!
//! The queue is different in one specific way:
//! [`QueuedBlockDevice::submit_read`] is `unsafe`,
//! because the caller's buffer has to stay put until the device is done with
//! it.  A device that copies during the submit does not need that promise, and
//! neither does any caller of one.  While the promise lived on `BlockDevice`,
//! every implementor carried an `unsafe` contract it did not use and every
//! caller of a depth-one device was handed a rule with nothing behind it.
//!
//! So the queue is its own trait.  A caller that wants to be ahead asks for
//! `Q: QueuedBlockDevice`, and the type system is what says whether the device
//! it holds can be.
//!
//! ## The three rules a queued device must keep
//!
//! - `submit` may refuse a run it cannot hold (`Busy`), rather than blocking or
//!   dropping it.
//! - `poll` answers for a ticket the device handed out, and answers an error
//!   for one it did not, an unknown ticket is a caller's bug and a hang would
//!   hide it.
//! - A request accepted is eventually completed.  Nothing enforces this; what
//!   makes it checkable is that a slot not freed is a slot the device cannot
//!   reuse.

use abi::Result;

use crate::block::BlockDevice;

/// A read a device has accepted but not yet completed.
///
/// The ticket is opaque, a device hands one back from
/// [`QueuedBlockDevice::submit_read`] and the caller gives it to
/// [`QueuedBlockDevice::poll`].  [`Ticket::DONE`] is the ticket a device
/// returns when it completed the read in place, which is what a device of
/// depth one does: the caller's buffer is already filled and there is nothing
/// left to wait for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket(u64);

impl Ticket {
    /// The ticket for a request that finished before its submit returned.
    pub const DONE: Ticket = Ticket(u64::MAX);

    /// A device's own name for a request it has queued.
    ///
    /// `id` is never `u64::MAX`: that value is what [`Ticket::DONE`] means, and
    /// a device that used it for a real request would be unable to say it had
    /// finished in place.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// The device's own name for the request.
    pub const fn id(self) -> u64 {
        self.0
    }

    /// Whether the request finished in place, before the submit returned.
    pub const fn is_done(self) -> bool {
        self.0 == u64::MAX
    }
}

/// How a submitted request is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    /// The device has not completed it yet.
    Pending,
    /// It finished; the answer is the request's own result.
    Done(Result<()>),
}

/// A block device whose requests a caller can have more than one of.
///
/// The supertrait is what makes this a *refinement* rather than a second
/// interface: every `QueuedBlockDevice` is a `BlockDevice`, so a caller can
/// read a block without knowing whether the device queues.
pub trait QueuedBlockDevice: BlockDevice {
    /// This device seen as a plain block device.
    ///
    /// `dyn QueuedBlockDevice` and `dyn BlockDevice` are different types, so a
    /// wrapper that holds the queued one and forwards `read_blocks` needs a way
    /// to say "the same device, seen plainly".  One method is cheaper than a
    /// second struct and keeps the queue and the device one object.
    fn as_block_device(&self) -> &dyn BlockDevice;

    /// The most requests this device can hold at once.
    ///
    /// One means the device finishes a request before its submit returns, so a
    /// caller has nothing to be ahead of.  A caller that wants to overlap asks
    /// this *before* it pipelines: a caller that pipelines without asking holds
    /// a queue open that the device does not have, and then pays for it with
    /// `Busy`.
    fn queue_depth(&self) -> u16 {
        1
    }

    /// Hand the device a read of one or more blocks, and name it with a ticket.
    ///
    /// `buffer.len()` is a whole number of blocks and the request covers them
    /// all: a run is one request, not one request per block.  A device that
    /// queues **may refuse** a run it cannot hold, `InvalidArgument`, refused
    /// rather than split behind the caller's back, so a caller that wants a
    /// run has to be prepared to fall back.  The waiting call,
    /// [`BlockDevice::read_blocks`], takes any size and splits it into runs the
    /// device can take.
    ///
    /// The default performs the read at once and answers [`Ticket::DONE`],
    /// which is what a device of depth one can do.  A device that queues
    /// returns a ticket whose [`poll`](Self::poll) answers when the device has
    /// the data, and refuses with `Busy` when its queue is full rather than
    /// blocking or dropping the request.
    ///
    /// # Safety
    ///
    /// `buffer` must stay live and must not move until a poll of the returned
    /// ticket answers [`RequestState::Done`], and no other read may name it at
    /// the same time.  A device that copies the data into its own memory
    /// during the submit (the default) is free of the constraint; a device
    /// that queues is not, and that is the price of not copying the DMA twice.
    unsafe fn submit_read(&self, lba: u64, buffer: &mut [u8]) -> Result<Ticket> {
        self.as_block_device().read_blocks(lba, buffer)?;
        Ok(Ticket::DONE)
    }

    /// Hand the device a write of one or more blocks, and name it with a
    /// ticket.
    ///
    /// This is **safe**, and the asymmetry with
    /// [`submit_read`](Self::submit_read) is the point: the data travels *into*
    /// the device, so a driver copies it out of the caller before this returns
    /// and nothing of the caller's has to outlive the ticket.
    fn submit_write(&self, lba: u64, data: &[u8]) -> Result<Ticket> {
        self.as_block_device().write_blocks(lba, data)?;
        Ok(Ticket::DONE)
    }

    /// Ask a device whether a submitted request has finished, and with what.
    ///
    /// A device of depth one always answers `Done`, because its submit already
    /// completed the request.  Polling a ticket the device does not know
    /// answers an error rather than waiting forever.
    fn poll(&self, _ticket: Ticket) -> RequestState {
        RequestState::Done(Ok(()))
    }
}
