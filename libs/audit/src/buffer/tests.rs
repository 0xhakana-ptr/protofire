//! libs/audit/src/buffer/tests.rs
//!
//! The audit ring: an event appended, the wrap when it fills, and the order a
//! reader sees.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::buffer::*;
use crate::types::AuditEventType;

fn sample_record(data: &[u8]) -> AuditRecord {
    let mut rec = AuditRecord::zeroed();
    rec.fill(0, 0, 42, AuditEventType::Syscall, 7, 1000, 0, data);
    rec
}

#[test]
fn emit_and_read_round_trip() {
    let buf = AuditBuffer::new();
    assert!(buf.is_empty());
    assert_eq!(buf.len(), 0);

    let rec = sample_record(b"hello");
    assert!(buf.emit(rec));
    assert_eq!(buf.len(), 1);

    let mut out = [AuditRecord::zeroed(); 10];
    let n = buf.read_events(&mut out);
    assert_eq!(n, 1);
    let data_slice = &out[0].data[..out[0].data_len as usize];
    assert_eq!(data_slice, b"hello");
    assert!(buf.is_empty());
}

#[test]
fn emit_rejects_full_buffer() {
    let buf = AuditBuffer::with_capacity(4);
    for i in 0..4 {
        assert!(buf.emit(sample_record(&[i as u8])));
    }
    // Fifth emit should fail.
    assert!(!buf.emit(sample_record(b"overflow")));
    assert_eq!(buf.len(), 4);
}

#[test]
fn read_events_drains_partial_batch() {
    let buf = AuditBuffer::new();
    for i in 0..10 {
        assert!(buf.emit(sample_record(&[i])));
    }
    assert_eq!(buf.len(), 10);

    let mut out = [AuditRecord::zeroed(); 3];
    let n = buf.read_events(&mut out);
    assert_eq!(n, 3);
    assert_eq!(buf.len(), 7);
}

#[test]
fn read_events_respects_output_capacity() {
    let buf = AuditBuffer::new();
    for i in 0..5 {
        assert!(buf.emit(sample_record(&[i])));
    }

    let mut out = [AuditRecord::zeroed(); 2];
    let n = buf.read_events(&mut out);
    assert_eq!(n, 2);
    assert_eq!(buf.len(), 3);
}

#[test]
fn sequence_numbers_are_monotonic() {
    let buf = AuditBuffer::new();
    assert!(buf.emit(sample_record(b"a")));
    assert!(buf.emit(sample_record(b"b")));

    let mut out = [AuditRecord::zeroed(); 10];
    let n = buf.read_events(&mut out);
    assert_eq!(n, 2);
    assert_eq!(out[0].sequence, 1);
    assert_eq!(out[1].sequence, 2);
}

#[test]
fn wrap_around_behaviour() {
    let buf = AuditBuffer::with_capacity(4);
    // Fill and drain to create a wraparound condition.
    for i in 0..4 {
        assert!(buf.emit(sample_record(&[i])));
    }
    let mut out = [AuditRecord::zeroed(); 4];
    assert_eq!(buf.read_events(&mut out), 4);

    // Now tail == head == 4; further emits should work.
    for i in 0..4 {
        assert!(buf.emit(sample_record(&[i])));
    }
    let n = buf.read_events(&mut out);
    assert_eq!(n, 4);
}

#[test]
fn peek_does_not_advance_until_commit() {
    let buf = AuditBuffer::new();
    buf.emit(sample_record(b"a"));
    buf.emit(sample_record(b"b"));
    buf.emit(sample_record(b"c"));
    assert_eq!(buf.len(), 3);

    let mut out = [AuditRecord::zeroed(); 10];
    let n = buf.peek_records(&mut out);
    assert_eq!(n, 3);
    // Peeking must not consume anything.
    assert_eq!(buf.len(), 3);

    // Committing only two of the three leaves one available.
    buf.commit_read(2);
    assert_eq!(buf.len(), 1);

    let n = buf.peek_records(&mut out);
    assert_eq!(n, 1);
    let data_slice = &out[0].data[..out[0].data_len as usize];
    assert_eq!(data_slice, b"c");

    buf.commit_read(1);
    assert!(buf.is_empty());
}

#[test]
fn commit_read_clamps_to_available() {
    let buf = AuditBuffer::new();
    buf.emit(sample_record(b"only"));
    assert_eq!(buf.len(), 1);

    // Committing more than is available must not overrun the buffer.
    buf.commit_read(100);
    assert!(buf.is_empty());
}
