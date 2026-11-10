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
    /// request outlives the call that submitted it, which is the same reason a
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
                // SAFETY: as above, with the direction reversed, the caller
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
mod tests {
    //! The tests for this module.
    //!
    //! The blocking adapter: a future driven to completion by the executor, and
    //! what a pending one does.
    //!
    //! Extracted from the module so that a reader following the mechanism does
    //! not have to scroll past every case it has to satisfy; see
    //! `docs/fmts/testing.md` §1.

    use crate::block::BlockOp;
    use crate::block::MemoryBlockService;
    use crate::block::SECTOR_SIZE;
    use crate::request::Request;
    use crate::request::RequestId;
    use crate::service::Service;
    use alloc::vec;

    /// Submit a transfer over a caller-owned buffer.
    fn submit(
        service: &mut MemoryBlockService,
        operation: BlockOp,
        buffer: &mut [u8],
    ) -> RequestId {
        let id = operation.token(service.performed());
        let request = Request::with_arguments(id, buffer.as_mut_ptr() as u64, buffer.len());
        assert!(
            service.submit(request).is_none(),
            "the transfer was accepted and is pending"
        );
        id
    }

    /// A write reads back through the device's own bytes.
    ///
    /// This is the whole service in one test, and a driver's version of it is a
    /// boot that finds the bytes in the image on the host.
    #[test]
    fn a_write_reads_back() {
        let mut service = MemoryBlockService::new(8, 8);
        let mut source = vec![0xA5u8; SECTOR_SIZE];
        submit(
            &mut service,
            BlockOp::Write {
                sector: 2,
                count: 1,
            },
            &mut source,
        );
        assert!(service.poll());
        let done = service.completions.pop().expect("the write completed");
        assert!(done.is_ok());

        // The device's own copy holds what was written.
        let offset = 2 * SECTOR_SIZE;
        assert_eq!(&service.bytes()[offset..offset + SECTOR_SIZE], &source[..]);
    }

    /// A read brings back what the device holds.
    #[test]
    fn a_read_returns_the_device_contents() {
        let mut service = MemoryBlockService::new(4, 4);
        let mut source = vec![0x5Au8; SECTOR_SIZE];
        submit(
            &mut service,
            BlockOp::Write {
                sector: 1,
                count: 1,
            },
            &mut source,
        );
        assert!(service.poll());
        let _ = service.completions.pop();

        let mut destination = vec![0u8; SECTOR_SIZE];
        let id = submit(
            &mut service,
            BlockOp::Read {
                sector: 1,
                count: 1,
            },
            &mut destination,
        );
        assert!(service.poll());
        let done = service.completions.pop().expect("the read completed");
        assert_eq!(done.id, id);
        assert_eq!(destination, source);
    }

    /// Two transfers complete out of submission order, which is what a device
    /// with a queue does.
    #[test]
    fn transfers_finish_out_of_order() {
        let mut service = MemoryBlockService::new(8, 8);
        let mut first = vec![1u8; SECTOR_SIZE];
        let one = submit(
            &mut service,
            BlockOp::Read {
                sector: 0,
                count: 1,
            },
            &mut first,
        );
        let mut second = vec![2u8; SECTOR_SIZE];
        let two = submit(
            &mut service,
            BlockOp::Read {
                sector: 1,
                count: 1,
            },
            &mut second,
        );
        assert_eq!(service.pending(), 2);

        assert!(service.poll());
        let first_done = service.completions.pop().expect("one completion");
        assert_eq!(first_done.id, two, "the later submission completed first");
        assert!(service.poll());
        let second_done = service.completions.pop().expect("the other");
        assert_eq!(second_done.id, one);
    }

    /// A transfer past the end of the device is refused at submission, and
    /// nothing is queued.
    #[test]
    fn a_transfer_past_the_end_is_refused() {
        let mut service = MemoryBlockService::new(4, 4);
        let mut buffer = vec![0u8; SECTOR_SIZE * 2];
        let id = BlockOp::Read {
            sector: 3,
            count: 2,
        }
        .token(0);
        let done = service
            .submit(Request::with_arguments(
                id,
                buffer.as_mut_ptr() as u64,
                buffer.len(),
            ))
            .expect("refused in the call");
        assert!(!done.is_ok());
        assert_eq!(service.pending(), 0);
        assert_eq!(service.performed(), 0);
    }

    /// A length that disagrees with the sector count is refused before the
    /// device does any work.
    #[test]
    fn a_mismatched_length_is_refused() {
        let mut service = MemoryBlockService::new(8, 8);
        let mut buffer = vec![0u8; SECTOR_SIZE];
        let id = BlockOp::Read {
            sector: 0,
            count: 2,
        }
        .token(0);
        let done = service
            .submit(Request::with_arguments(
                id,
                buffer.as_mut_ptr() as u64,
                // One sector's worth, for a two-sector transfer.
                buffer.len(),
            ))
            .expect("refused in the call");
        assert!(!done.is_ok());
        assert_eq!(service.pending(), 0);
    }

    /// A queue with no room for the completion refuses the transfer rather than
    /// accepting work it cannot report.
    #[test]
    fn a_full_completion_queue_refuses_new_work() {
        let mut service = MemoryBlockService::new(8, 1);
        let mut buffer = vec![0u8; SECTOR_SIZE];
        submit(
            &mut service,
            BlockOp::Read {
                sector: 0,
                count: 1,
            },
            &mut buffer,
        );
        assert!(service.poll());
        // The completion is queued and not taken, so the queue is at its
        // capacity of one.
        let id = BlockOp::Read {
            sector: 1,
            count: 1,
        }
        .token(1);
        let done = service
            .submit(Request::with_arguments(
                id,
                buffer.as_mut_ptr() as u64,
                buffer.len(),
            ))
            .expect("refused in the call");
        assert!(!done.is_ok());
    }

    /// Cancelling a pending transfer completes it, and cancelling it again says
    /// so.
    #[test]
    fn cancelling_completes_and_is_not_repeatable() {
        let mut service = MemoryBlockService::new(8, 8);
        let mut buffer = vec![0u8; SECTOR_SIZE];
        let id = submit(
            &mut service,
            BlockOp::Read {
                sector: 0,
                count: 1,
            },
            &mut buffer,
        );
        assert!(service.cancel(id));
        let done = service
            .completions
            .pop()
            .expect("the cancellation completed");
        assert_eq!(done.id, id);
        assert!(!done.is_ok());
        assert!(!service.cancel(id), "it is not pending any more");
        assert_eq!(service.performed(), 0, "the transfer never happened");
    }

    /// Every accepted transfer is completed: after polling until quiet, the
    /// number performed equals the number accepted.
    #[test]
    fn every_accepted_transfer_completes() {
        let mut service = MemoryBlockService::new(16, 16);
        let mut buffers = vec![vec![0u8; SECTOR_SIZE]; 4];
        let accepted = 4;
        for (sector, buffer) in buffers.iter_mut().enumerate() {
            submit(
                &mut service,
                BlockOp::Read {
                    sector: sector as u64,
                    count: 1,
                },
                buffer,
            );
        }
        while service.poll() {}
        assert_eq!(service.performed(), accepted);
        let mut completed = 0;
        while service.completions.pop().is_some() {
            completed += 1;
        }
        assert_eq!(completed, accepted);
        assert_eq!(service.pending(), 0);
    }

    /// A zero-sector transfer is refused: it names no range.
    #[test]
    fn a_zero_sector_transfer_is_refused() {
        let mut service = MemoryBlockService::new(4, 4);
        let mut buffer = vec![0u8; SECTOR_SIZE];
        let id = BlockOp::Read {
            sector: 0,
            count: 0,
        }
        .token(0);
        let done = service
            .submit(Request::with_arguments(
                id,
                buffer.as_mut_ptr() as u64,
                buffer.len(),
            ))
            .expect("refused in the call");
        assert!(!done.is_ok());
    }

    /// A token that names no operation is refused rather than performed as
    /// something else.
    #[test]
    fn an_unknown_token_is_refused() {
        let mut service = MemoryBlockService::new(4, 4);
        let done = service
            .submit(Request::pending(RequestId::new(0)))
            .expect("refused in the call");
        assert!(!done.is_ok());
        assert_eq!(service.pending(), 0);
    }
}
