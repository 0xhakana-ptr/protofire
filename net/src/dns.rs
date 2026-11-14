//! net/src/dns.rs
//!
//! DNS: the query a resolver sends and the answer it reads back.
//!
//! ## The layout
//!
//! ```text
//! header     id[2] flags[2] qdcount[2] ancount[2] nscount[2] arcount[2]
//! question   name… qtype[2] qclass[2]
//! answer     name… type[2] class[2] ttl[4] rdlength[2] rdata[…]
//! ```
//!
//! ## Why this is a parser and not a resolver
//!
//! A resolver needs a socket, a clock and a retry policy, and all three are the
//! caller's.  What is here is the two halves a resolver cannot do without: the
//! bytes a query is, and the address an answer carries.  A caller sends the
//! query, waits, and hands the reply back.
//!
//! That split is what lets every case below be a host test: a compressed name,
//! a name that is a pointer to itself, a record with no answer, a truncated
//! message.  A boot can only ever see the one answer its own network gave.
//!
//! ## Name compression, and the bound that makes it safe
//!
//! An answer may spell a name once and point at it from elsewhere: the top two
//! bits of a length byte are `11` and the rest is an offset from the message's
//! start.  A pointer can point *forward* or at itself, so a decoder that
//! followed every one would loop.  The rule here is the one every careful
//! decoder uses: a pointer may only point backwards, and the walk is bounded by
//! the message's own length.  A message that tries to loop is refused.
//!
//! ## What is not here
//!
//! DNSSEC validation, CNAME chains that cross a message boundary, and the
//! search-domain machinery a resolver applies before it asks.  Each is its own
//! decision, and none is needed by a stack whose lookups name one host.

use abi::Error;
use abi::Result;

use crate::address::Address;

/// The header every DNS message begins with.
pub const HEADER_LEN: usize = 12;

/// The long-lived resource-record type: an IPv4 address.
pub const TYPE_A: u16 = 1;

/// The long-lived resource-record type: an IPv6 address.
pub const TYPE_AAAA: u16 = 28;

/// The class the Internet uses.
pub const CLASS_IN: u16 = 1;

/// The response bit in the flags word.
pub const FLAGS_RESPONSE: u16 = 0x8000;

/// The recursion-desired bit, which this stack sets because it asks a server
/// to do the work rather than walking the tree itself.
pub const FLAGS_RECURSION_DESIRED: u16 = 0x0100;

/// The mask covering the response code.
pub const FLAGS_RCODE_MASK: u16 = 0x000F;

/// The response code meaning no such name.
pub const RCODE_NO_SUCH_NAME: u16 = 3;

/// A name is at most this many bytes on the wire, which is what bounds the
/// encoding a caller may hand in.
pub const MAX_NAME: usize = 255;

/// The most bytes a query for `name` can be.
pub const fn query_len(name: usize) -> usize {
    HEADER_LEN + (name + 2) + 4
}

/// Encode a hostname as the wire's sequence of length-prefixed labels.
///
/// `None` when the name cannot be one: empty, longer than [`MAX_NAME`], or
/// carrying a label longer than sixty-three bytes.  The last bound is not
/// arbitrary: the two top bits of a length byte are the compression flag's,
/// so a label of sixty-four or more would encode as a pointer.
///
/// The name is written without the trailing root label a longer encoding would
/// put there: the root is the zero-length label, and it is written exactly once
/// at the end.
pub fn encode_name(name: &str, into: &mut [u8]) -> Option<usize> {
    if name.is_empty() || name.len() > MAX_NAME {
        return None;
    }
    let mut written = 0;
    for label in name.split('.') {
        // An empty label is a leading or trailing dot, or two in a row; the
        // root's empty label is written by this function, not by the caller.
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if written + 1 + label.len() + 1 > into.len() {
            return None;
        }
        into[written] = label.len() as u8;
        written += 1;
        into[written..written + label.len()].copy_from_slice(label.as_bytes());
        written += label.len();
    }
    if written + 1 > into.len() {
        return None;
    }
    into[written] = 0;
    written += 1;
    Some(written)
}

/// Write a query asking `server` for `name`'s `kind` record.
///
/// `id` is the caller's: it is the one field that tells this answer from one
/// meant for a previous lookup, so a resolver draws it from its own generator
/// rather than reusing a constant.
///
/// `None` when the name will not encode or `into` is too small.
pub fn write_query(into: &mut [u8], id: u16, name: &str, kind: u16) -> Option<usize> {
    if into.len() < HEADER_LEN {
        return None;
    }
    into[..HEADER_LEN].fill(0);
    into[0..2].copy_from_slice(&id.to_be_bytes());
    into[2..4].copy_from_slice(&FLAGS_RECURSION_DESIRED.to_be_bytes());
    // One question, no answers, no authority, no additional.
    into[4..6].copy_from_slice(&1u16.to_be_bytes());
    let mut at = HEADER_LEN;
    at += encode_name(name, &mut into[at..])?;
    if at + 4 > into.len() {
        return None;
    }
    into[at..at + 2].copy_from_slice(&kind.to_be_bytes());
    into[at + 2..at + 4].copy_from_slice(&CLASS_IN.to_be_bytes());
    Some(at + 4)
}

/// What an answer turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// The name resolved.
    Address {
        /// The address, whose family the record type chose.
        address: Address,
        /// How many seconds the server says the answer may be kept.
        ttl: u32,
    },
    /// The server says the name does not exist.
    NoSuchName,
}

/// Read the first answer record of `kind` out of a response.
///
/// The header is checked before anything else: a message that is not a
/// response, one whose id is not `id`, and one whose response code is a
/// failure are each refused with the reason they name.  That id check is not
/// politeness, it is the whole protection a UDP resolver has: a datagram from
/// anywhere that happens to arrive on the port is not this lookup's answer.
///
/// A response with no record of `kind` is [`Error::NotFound`], which is
/// distinct from the server saying the name does not exist: the first is a
/// server that answered something else and the second is an answer.
pub fn parse_answer(response: &[u8], id: u16, kind: u16) -> Result<Answer> {
    if response.len() < HEADER_LEN {
        return Err(Error::InvalidArgument);
    }
    let answer_id = u16::from_be_bytes([response[0], response[1]]);
    let flags = u16::from_be_bytes([response[2], response[3]]);
    if flags & FLAGS_RESPONSE == 0 {
        return Err(Error::InvalidArgument);
    }
    if answer_id != id {
        return Err(Error::InvalidArgument);
    }
    match flags & FLAGS_RCODE_MASK {
        0 => {}
        RCODE_NO_SUCH_NAME => return Ok(Answer::NoSuchName),
        _ => return Err(Error::Unsupported),
    }
    let questions = u16::from_be_bytes([response[4], response[5]]) as usize;

    let answers = u16::from_be_bytes([response[6], response[7]]) as usize;

    // The question section, which the answer's names point back into.
    let mut at = HEADER_LEN;
    for _ in 0..questions {
        at = skip_name(response, at)?;

        at = at.checked_add(4).ok_or(Error::InvalidArgument)?;
        if at > response.len() {
            return Err(Error::InvalidArgument);
        }
    }

    for _ in 0..answers {
        at = skip_name(response, at)?;
        // type, class, ttl, rdlength.
        if at + 10 > response.len() {
            return Err(Error::InvalidArgument);
        }
        let record_type = u16::from_be_bytes([response[at], response[at + 1]]);
        let ttl = u32::from_be_bytes([
            response[at + 4],
            response[at + 5],
            response[at + 6],
            response[at + 7],
        ]);
        let length = u16::from_be_bytes([response[at + 8], response[at + 9]]) as usize;
        at += 10;
        let end = at.checked_add(length).ok_or(Error::InvalidArgument)?;
        if end > response.len() {
            return Err(Error::InvalidArgument);
        }
        if record_type == kind {
            let address = match (kind, length) {
                (TYPE_A, 4) => Address::V4([
                    response[at],
                    response[at + 1],
                    response[at + 2],
                    response[at + 3],
                ]),
                (TYPE_AAAA, 16) => {
                    let mut bytes = [0_u8; 16];
                    bytes.copy_from_slice(&response[at..at + 16]);
                    Address::V6(bytes)
                }
                // A record whose length is not its type's is a server that
                // disagreed with itself, which is not an answer.
                _ => return Err(Error::InvalidArgument),
            };
            return Ok(Answer::Address { address, ttl });
        }
        at = end;
    }

    Err(Error::NotFound)
}

/// Step past a name, following any compression pointers in the labels.
///
/// The pointer rule is the one that makes this terminate: a pointer must
/// address a byte *before* the one it was read from, so a message cannot
/// describe a loop.  It is checked here rather than trusted, because a reply
/// is a stranger's bytes.
///
/// The answer is the offset just past the name's last label in the message's
/// own sequence, which for a name ending in a pointer is two bytes past the
/// pointer.
fn skip_name(message: &[u8], start: usize) -> Result<usize> {
    let mut at = start;
    // Set only when a pointer is followed, and then to the offset just past
    // that pointer: the bytes after it belong to the record, not to the name,
    // and the name the pointer reaches is somewhere else entirely.
    let mut after_pointer: Option<usize> = None;
    // Each pointer must address a byte before the one it was read from, so a
    // message cannot describe a loop; the budget turns "cannot" into a check.
    let mut budget = message.len();
    loop {
        if budget == 0 {
            return Err(Error::InvalidArgument);
        }
        budget -= 1;
        let Some(&length) = message.get(at) else {
            return Err(Error::InvalidArgument);
        };
        match length & 0xC0 {
            0x00 => {
                if length == 0 {
                    // The root label ends the name, at the byte after it.
                    return Ok(after_pointer.unwrap_or(at + 1));
                }
                at += 1 + length as usize;
                if at > message.len() {
                    return Err(Error::InvalidArgument);
                }
            }
            0xC0 => {
                let Some(&low) = message.get(at + 1) else {
                    return Err(Error::InvalidArgument);
                };
                let target = (((length & 0x3F) as usize) << 8) | low as usize;
                if target >= at {
                    return Err(Error::InvalidArgument);
                }
                // The first pointer is the one that fixes where the record
                // resumes; a later one, reached through this, does not.
                after_pointer.get_or_insert(at + 2);
                at = target;
            }
            _ => return Err(Error::InvalidArgument),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Answer;
    use super::HEADER_LEN;
    use super::TYPE_A;
    use super::TYPE_AAAA;
    use super::parse_answer;
    use super::write_query;
    use crate::address::Address;
    use abi::Error;

    /// A query for one name is a header, the encoded name, and the type and
    /// class: the bytes a server reads.
    #[test]
    fn a_query_is_a_header_a_name_and_its_type() {
        let mut buffer = [0_u8; 64];
        let len = write_query(&mut buffer, 0x1234, "example.com", TYPE_A).expect("a query");
        assert_eq!(len, HEADER_LEN + 13 + 4);
        assert_eq!(&buffer[0..2], &[0x12, 0x34], "the id the caller chose");
        assert_eq!(buffer[2] & 0x01, 0x01, "recursion desired");
        assert_eq!(&buffer[4..6], &1u16.to_be_bytes(), "one question");
        // The encoded name: 7 "example", 3 "com", then the root.
        assert_eq!(buffer[HEADER_LEN], 7);
        assert_eq!(&buffer[HEADER_LEN + 1..HEADER_LEN + 8], b"example");
        assert_eq!(buffer[HEADER_LEN + 8], 3);
        assert_eq!(&buffer[HEADER_LEN + 9..HEADER_LEN + 12], b"com");
        assert_eq!(buffer[HEADER_LEN + 12], 0, "the root label");
        assert_eq!(&buffer[len - 4..len - 2], &TYPE_A.to_be_bytes());
        assert_eq!(&buffer[len - 2..len], &1u16.to_be_bytes(), "class IN");
    }

    /// A name that cannot be one is refused rather than encoded into
    /// something a server would have to guess at.
    #[test]
    fn a_name_that_cannot_be_one_is_refused() {
        let mut buffer = [0_u8; 512];
        assert!(write_query(&mut buffer, 1, "", TYPE_A).is_none(), "empty");
        assert!(
            write_query(&mut buffer, 1, "a..b", TYPE_A).is_none(),
            "an empty label"
        );
        assert!(
            write_query(&mut buffer, 1, ".leading", TYPE_A).is_none(),
            "a leading dot"
        );
        let long_label = "a".repeat(64);
        assert!(
            write_query(&mut buffer, 1, &long_label, TYPE_A).is_none(),
            "a label of sixty-four would encode as a pointer"
        );
        let long_name = "abcdefghi.".repeat(30);
        assert!(
            write_query(&mut buffer, 1, &long_name, TYPE_A).is_none(),
            "past the name limit"
        );
    }

    /// A response carrying an A record answers the address and the ttl, and
    /// one carrying an AAAA record answers the sixteen bytes.
    #[test]
    fn an_answer_carries_the_address_and_its_ttl() {
        // A response to question 0x1234 for "a.test", one answer.
        let response: &[u8] = &[
            0x12, 0x34, // id
            0x81, 0x80, // response, recursion available, no error
            0x00, 0x01, // one question
            0x00, 0x01, // one answer
            0x00, 0x00, 0x00, 0x00, // question: 1 "a", 4 "test", root, type A, class IN
            0x01, b'a', 0x04, b't', b'e', b's', b't', 0x00, 0x00, 0x01, 0x00, 0x01,
            // answer: a pointer to the question's name, type A, class IN,
            // ttl 300, rdlength 4, 10.0.2.7
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 10, 0, 2, 7,
        ];
        assert_eq!(
            parse_answer(response, 0x1234, TYPE_A),
            Ok(Answer::Address {
                address: Address::V4([10, 0, 2, 7]),
                ttl: 300,
            })
        );
    }

    /// A response for another lookup's id is refused: a datagram from anywhere
    /// that lands on the port is not this lookup's answer.
    #[test]
    fn an_answer_for_another_id_is_refused() {
        let response: &[u8] = &[
            0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            parse_answer(response, 0x4321, TYPE_A),
            Err(Error::InvalidArgument),
            "a different id"
        );
        assert_eq!(
            parse_answer(response, 0x1234, TYPE_A),
            Err(Error::NotFound),
            "no answers at all"
        );
    }

    /// A server that says the name does not exist says so, which is an answer
    /// and not a failure to match one.
    #[test]
    fn a_missing_name_is_an_answer() {
        let response: &[u8] = &[
            0x12, 0x34, 0x81, 0x83, // response, rcode 3
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            parse_answer(response, 0x1234, TYPE_A),
            Ok(Answer::NoSuchName)
        );
    }

    /// A name that points at itself, or forward, is refused rather than
    /// followed: that is the shape a decoder loops on.
    #[test]
    fn a_compression_pointer_that_does_not_point_backwards_is_refused() {
        // No question, one answer, and the answer's name is a pointer at
        // offset 12 that names offset 12: the one shape a decoder that
        // followed pointers blindly would loop on.
        let mut response = alloc::vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        response.extend_from_slice(&[0xC0, 0x0C]);
        response.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0, 0, 0, 10, 0x00, 0x04, 1, 2, 3, 4]);
        assert_eq!(
            parse_answer(&response, 0x1234, TYPE_A),
            Err(Error::InvalidArgument),
            "a self-pointer is refused"
        );
    }

    /// A truncated message refuses rather than reading past its end, which is
    /// what a stranger's bytes need.
    #[test]
    fn a_truncated_message_is_refused() {
        assert_eq!(
            parse_answer(&[0x12, 0x34], 0x1234, TYPE_A),
            Err(Error::InvalidArgument)
        );
        let mut response = alloc::vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        response.extend_from_slice(&[0x01, b'a', 0x00]);
        assert_eq!(
            parse_answer(&response, 0x1234, TYPE_A),
            Err(Error::InvalidArgument),
            "a name whose question runs out"
        );
    }

    /// An AAAA answer answers sixteen bytes, and a record whose length is not
    /// its type's is refused.
    #[test]
    fn an_aaaa_answer_and_a_wrong_length() {
        let address: [u8; 16] = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0, 0xff, 0xfe, 0x12, 0x34, 0x56,
        ];
        // One question, echoed: the answer's name points at it.
        let mut response = alloc::vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        response.extend_from_slice(&[0x01, b'a', 0x00, 0x00, 0x01, 0x00, 0x01]);
        response.extend_from_slice(&[0xC0, 0x0C]);
        // type AAAA, class IN, ttl 60, rdlength 16.
        response.extend_from_slice(&[0x00, 0x1C, 0x00, 0x01]);
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&[0x00, 0x10]);
        response.extend_from_slice(&address);
        assert_eq!(
            parse_answer(&response, 0x1234, TYPE_AAAA),
            Ok(Answer::Address {
                address: Address::V6(address),
                ttl: 60,
            })
        );

        // The record says AAAA and carries four bytes: a server that
        // disagreed with itself.  The rdlength is the field that says so,
        // two bytes before the data the record carries.
        let rdlength_at = response.len() - 16 - 2;
        response[rdlength_at..rdlength_at + 2].copy_from_slice(&4u16.to_be_bytes());
        assert_eq!(
            parse_answer(&response, 0x1234, TYPE_AAAA),
            Err(Error::InvalidArgument)
        );
    }
}
