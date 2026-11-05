//! async_io/src/block/tests.rs
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
fn submit(service: &mut MemoryBlockService, operation: BlockOp, buffer: &mut [u8]) -> RequestId {
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
