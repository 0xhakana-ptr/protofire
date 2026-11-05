//! async_io/src/block.rs
//!
//! A block device behind the request/completion model: the first real service.
//!
//! ## Why this is here rather than in a driver
//!
//! It is not a driver.  There is no controller, no register, no interrupt: it
//! is a service over a byte slice, and its job is to show that the model
//! carries the shape a driver will have.  A driver's `submit` hands a command
//! to hardware and its `poll` reads a completion ring; this one copies into a
//! buffer and its `poll` returns the transfer it just did.  The trait does not
//! distinguish them, which is the claim being checked.
//!
//! ## What it models that a toy would not
//!
//! - **Transfers finish out of order.**  A device with a queue does not
//!   complete requests in submission order, and a queue that assumed it did
//!   would pass every test here while failing on real hardware.
//! - **The underwritten request is the one that waits.**  A request is accepted
//!   only if the queue has room for its completion; anything else is refused at
//!   `submit` rather than accepted and then dropped.
//! - **Cancel after completion says so.**  A device that already performed the
//!   transfer cannot un-perform it, and the completion still arrives.
//!
//! ## The host-only arm
//!
//! Everything here is a byte slice and a queue, so the whole service is
//! testable on a host.  The driver that replaces it is not; its gate is a boot
//! that drains the queue after a transfer.

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use abi::Error;

use crate::completion::Completion;
use crate::queue::CompletionQueue;
use crate::request::Request;
use crate::request::RequestId;
use crate::service::Service;

/// The sector size this service assumes, which is what every device this tree
/// has spoken to uses.
pub const SECTOR_SIZE: usize = 512;

/// What a transfer asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockOp {
    /// Read `count` sectors starting at `sector` into the caller's buffer.
    Read {
        /// First sector.
        sector: u64,
        /// How many sectors.
        count: usize,
    },
    /// Write `count` sectors from the caller's buffer starting at `sector`.
    Write {
        /// First sector.
        sector: u64,
        /// How many sectors.
        count: usize,
    },
}

/// One transfer the service has accepted and not finished.
struct Pending {
    id: RequestId,
    operation: BlockOp,
    /// The caller's buffer, as an address and a length the caller guarantees.
    ///
    /// A real driver would describe the transfer with a bus address and let the
    /// device write into it; this arm copies, so what it needs is the slice it
    /// was handed.  The address is kept rather than a `&mut [u8]` because the
    /// request outlives the call that submitted it — which is the same reason a
    /// driver keeps a physical address.
    buffer: usize,
    length: usize,
}

/// A block service over an in-memory device.
pub struct MemoryBlockService {
    /// The device's contents, one entry per sector's worth of bytes.
    device: Vec<u8>,
    /// Accepted transfers, in the order they will be performed.
    pending: VecDeque<Pending>,
    /// Where completions go.
    completions: CompletionQueue,
    /// How many transfers have been performed, for the tests.
    performed: u64,
}

impl MemoryBlockService {
    /// A device of `sectors` sectors, zeroed.
    pub fn new(sectors: usize, queue_capacity: usize) -> Self {
        Self {
            device: vec![0u8; sectors.saturating_mul(SECTOR_SIZE)],
            pending: VecDeque::new(),
            completions: CompletionQueue::new(queue_capacity),
            performed: 0,
        }
    }

    /// How many transfers this service has performed.
    pub fn performed(&self) -> u64 {
        self.performed
    }

    /// How many transfers are accepted and waiting.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Take one completion, if any is waiting.
    ///
    /// The queue is the service's, not the caller's: a block device is the one
    /// that knows a transfer finished, so it is the one that hands the news on.
    /// The tests below and the boot's check both read through this rather than
    /// reaching into the field.
    pub fn take_completion(&mut self) -> Option<Completion> {
        self.completions.pop()
    }

    /// The device's bytes, for a test that wants to check what a write did.
    pub fn bytes(&self) -> &[u8] {
        &self.device
    }

    /// How many sectors the device has.
    pub fn sectors(&self) -> usize {
        self.device.len() / SECTOR_SIZE
    }

    /// Whether a transfer's range is inside the device.
    fn range_is_valid(&self, sector: u64, count: usize) -> Option<usize> {
        if count == 0 {
            return None;
        }
        let start = usize::try_from(sector).ok()?.checked_mul(SECTOR_SIZE)?;
        let length = count.checked_mul(SECTOR_SIZE)?;
        let end = start.checked_add(length)?;
        if end > self.device.len() {
            return None;
        }
        Some(start)
    }
}

impl Service for MemoryBlockService {
    fn submit(&mut self, request: Request) -> Option<Completion> {
        // A block service's operation is the token's tag and its payload is the
        // two argument words: a buffer address and a byte count.  The queue
        // never inspects either.
        let Some(operation) = BlockOp::decode(request.id) else {
            return Some(Completion::err(request.id, Error::InvalidArgument));
        };

        let (sector, count) = match operation {
            BlockOp::Read { sector, count } | BlockOp::Write { sector, count } => (sector, count),
        };

        if self.range_is_valid(sector, count).is_none() {
            return Some(Completion::err(request.id, Error::InvalidArgument));
        }

        // A transfer that does not match its sector count is a caller error the
        // service can see before the device does any work.
        if request.length != count * SECTOR_SIZE {
            return Some(Completion::err(request.id, Error::InvalidArgument));
        }

        // A queue with no room for the completion would accept a transfer it
        // could not report.  Refusing at submission is the honest answer: the
        // caller learns now rather than after the device has done the work.
        if self.completions.len() >= self.completions.capacity() {
            return Some(Completion::err(request.id, Error::Busy));
        }

        self.pending.push_back(Pending {
            id: request.id,
            operation,
            buffer: request.argument as usize,
            length: request.length,
        });
        None
    }

    fn poll(&mut self) -> bool {
        // Perform exactly one transfer per poll, taking it from the back of the
        // queue: a device with a queue does not complete in submission order,
        // and a service that always took the front would make the out-of-order
        // test pass by never being out of order.
        let Some(pending) = self.pending.pop_back() else {
            return false;
        };

        match pending.operation {
            BlockOp::Read { sector, count } => {
                let offset = sector as usize * SECTOR_SIZE;
                let length = count * SECTOR_SIZE;
                // SAFETY: the caller handed this address and length to
                // `submit` as a writable buffer for this transfer, the range
                // was validated against the device before it was queued, and
                // the request is still outstanding, so the caller has not
                // reclaimed the buffer.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.device.as_ptr().add(offset),
                        pending.buffer as *mut u8,
                        length,
                    );
                }
            }
            BlockOp::Write { sector, count } => {
                let offset = sector as usize * SECTOR_SIZE;
                let length = count * SECTOR_SIZE;
                // SAFETY: as above, with the direction reversed — the caller
                // promised the buffer is readable for this transfer.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        pending.buffer as *const u8,
                        self.device.as_mut_ptr().add(offset),
                        length,
                    );
                }
            }
        }

        self.performed += 1;
        // The completion cannot be refused: `submit` checked there was room
        // before it accepted the transfer.
        let _ = self
            .completions
            .push(Completion::ok(pending.id, pending.length));
        true
    }

    fn cancel(&mut self, id: RequestId) -> bool {
        let Some(position) = self.pending.iter().position(|pending| pending.id == id) else {
            return false;
        };
        self.pending.remove(position);
        let _ = self.completions.push(Completion::err(id, Error::Busy));
        true
    }
}

impl BlockOp {
    /// The token this operation is submitted under.
    ///
    /// The tag is the operation and the low bits the sector range, so a test
    /// can name a transfer and the service can recover it without a side table.
    pub fn token(self, sequence: u64) -> RequestId {
        let (tag, sector, count) = match self {
            BlockOp::Read { sector, count } => (1u64, sector, count),
            BlockOp::Write { sector, count } => (2u64, sector, count),
        };
        RequestId::new(
            (tag << 56)
                | ((sequence & 0x00FF_FFFF) << 32)
                | ((sector & 0xFFFF) << 16)
                | (count as u64 & 0xFFFF),
        )
    }

    /// Recover the operation from a token [`Self::token`] produced.
    pub fn decode(id: RequestId) -> Option<Self> {
        let raw = id.get();
        let tag = raw >> 56;
        let sector = (raw >> 16) & 0xFFFF;
        let count = (raw & 0xFFFF) as usize;
        match tag {
            1 => Some(BlockOp::Read { sector, count }),
            2 => Some(BlockOp::Write { sector, count }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests;
