//! net/src/tls/tests.rs
//!
//! The module's tests.
//!
//! A sibling file because the tests outgrew the module: a reader looking for
//! the mechanism should not scroll past them to find the end of it.

use super::CONTENT_APPLICATION_DATA;
use super::CONTENT_HANDSHAKE;
use super::GROUP_X25519;
use super::HANDSHAKE_CERTIFICATE;
use super::HANDSHAKE_CLIENT_HELLO;
use super::HANDSHAKE_ENCRYPTED_EXTENSIONS;
use super::HANDSHAKE_FINISHED;
use super::HANDSHAKE_SERVER_HELLO;
use super::Keys;
use super::LEGACY_VERSION;
use super::MAX_FRAGMENT;
use super::Offer;
use super::RECORD_HEADER_LEN;
use super::Schedule;
use super::Suite;
use super::Transcript;
use super::client_hello_body;
use super::finished_value;
use super::parse_server_hello;
use super::read_handshakes;
use super::read_plain;
use super::read_record;
use super::shared_secret;
use super::split_record;
use super::verify_finished;
use super::write_handshake;
use super::write_record;
use abi::Error;
use alloc::vec::Vec;

fn secret() -> [u8; 32] {
    let mut secret = [0_u8; 32];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(11).wrapping_add(5);
    }
    secret
}

/// A record round trips through the reader, for both suites.
///
/// Both, because the nonce and the AEAD are the two things they disagree
/// about and a round trip through one proves neither for the other.
#[test]
fn a_record_round_trips_for_both_suites() {
    for suite in [Suite::Aes128GcmSha256, Suite::ChaCha20Poly1305Sha256] {
        let mut writer = Keys::from_secret(&secret(), suite);
        let mut reader = Keys::from_secret(&secret(), suite);
        let record = write_record(CONTENT_HANDSHAKE, &mut writer, b"hello").expect("a record");
        assert_eq!(reader.sequence(), 0, "and the reader has not read one yet");
        let (plaintext, content_type, length) =
            read_record(&mut reader, &record).expect("a record");
        assert_eq!(plaintext, b"hello", "suite {suite:?}");
        assert_eq!(content_type, CONTENT_HANDSHAKE, "the inner type");
        assert_eq!(length, record.len());
        assert_eq!(writer.sequence(), 1);
        assert_eq!(reader.sequence(), 1);
    }
}

/// The outer type is `application_data` whatever the inner one is.
///
/// The camouflage [RFC 8446] added to TLS 1.2: a middlebox reading the wire
/// must not learn whether a record carries a handshake or a program's
/// bytes, and the test asserts the header says the one thing that is true
/// of both.
#[test]
fn the_outer_type_is_always_application_data() {
    let mut keys = Keys::from_secret(&secret(), Suite::Aes128GcmSha256);
    for inner in [CONTENT_HANDSHAKE, CONTENT_APPLICATION_DATA, 21] {
        let record = write_record(inner, &mut keys, b"x").expect("a record");
        assert_eq!(record[0], CONTENT_APPLICATION_DATA, "inner {inner}");
        assert_eq!(
            u16::from_be_bytes([record[1], record[2]]),
            LEGACY_VERSION,
            "and the legacy version is the constant"
        );
    }
}

/// The nonce's construction is the one [RFC 8446] states, byte for byte.
///
/// The test a round trip cannot replace: a nonce built wrongly on both
/// sides agrees with itself, and the peer's implementation would not.  The
/// sequence is exclusive-ored into the last eight bytes and the first four
/// are the IV's own.
#[test]
fn the_nonce_is_the_iv_with_the_sequence_exclusive_ored_in() {
    let mut keys = Keys::from_secret(&secret(), Suite::Aes128GcmSha256);
    let iv = keys.next_nonce();
    assert_eq!(&iv[..4], &keys.next_nonce()[..4], "the prefix never moves");
    // The IV's last eight bytes with one xored in, which is what the first
    // record's nonce is.
    let first = keys.next_nonce();
    let _ = write_record(CONTENT_APPLICATION_DATA, &mut keys, b"x").expect("a record");
    let second = keys.next_nonce();
    let mut expected = first;
    expected[11] ^= 1;
    assert_eq!(second, expected, "and the sequence is one, not two");
    assert_eq!(keys.sequence(), 1);
}

/// A record whose tag does not verify is refused, and the reader's counter
/// does not move.
///
/// The failure that makes a connection unrecoverable if it is mishandled:
/// the two sides' counters must agree exactly, so a record this side
/// refused must not advance its count.  A forged record would otherwise
/// desynchronise a connection with nothing on the wire to blame.
#[test]
fn a_failed_tag_is_refused_and_the_counter_does_not_move() {
    let mut writer = Keys::from_secret(&secret(), Suite::Aes128GcmSha256);
    let mut reader = Keys::from_secret(&secret(), Suite::Aes128GcmSha256);
    let record = write_record(CONTENT_HANDSHAKE, &mut writer, b"real").expect("a record");
    // A copy with one byte of the ciphertext altered, which still carries
    // the sequence number the real one does.
    let mut forged = record.clone();
    let at = forged.len() - 20;
    forged[at] ^= 0xFF;
    assert_eq!(
        read_record(&mut reader, &forged),
        Err(Error::PermissionDenied)
    );
    assert_eq!(reader.sequence(), 0, "and the counter did not move");

    // The **same** record, unaltered, still reads with the sequence the
    // forgery tried to spend.  A second `write_record` would carry the
    // writer's next sequence and be a different record, which is not what
    // this test is about.
    let (plaintext, _, _) = read_record(&mut reader, &record).expect("the real one");
    assert_eq!(plaintext, b"real");
    assert_eq!(reader.sequence(), 1);
}

/// A record larger than the fragment bound is refused rather than split.
#[test]
fn a_record_past_the_fragment_bound_is_refused() {
    let mut keys = Keys::from_secret(&secret(), Suite::Aes128GcmSha256);
    let large = alloc::vec![0_u8; MAX_FRAGMENT + 1];
    assert_eq!(
        write_record(CONTENT_APPLICATION_DATA, &mut keys, &large),
        Err(Error::InvalidArgument)
    );
    let exact = alloc::vec![0_u8; MAX_FRAGMENT];
    assert!(write_record(CONTENT_APPLICATION_DATA, &mut keys, &exact).is_ok());
}

/// A record that claims more bytes than the wire holds is refused.
///
/// Three refusals: a header shorter than five bytes, a length past the
/// wire, and a length past what a record may carry.
#[test]
fn a_truncated_record_is_refused() {
    let mut keys = Keys::from_secret(&secret(), Suite::Aes128GcmSha256);
    assert_eq!(
        read_record(&mut keys, &[23, 3, 3]),
        Err(Error::InvalidArgument)
    );

    let mut record = write_record(CONTENT_HANDSHAKE, &mut keys, b"x").expect("a record");
    let full = record.len();
    record.truncate(full - 1);
    assert_eq!(read_record(&mut keys, &record), Err(Error::InvalidArgument));

    // A length field that claims a record nothing could carry.
    let mut header = alloc::vec![23, 3, 3, 0, 0];
    header.extend_from_slice(&(MAX_FRAGMENT + 300).to_be_bytes()[..0]);
    let mut oversized = alloc::vec![23, 3, 3];
    oversized.extend_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(
        split_record(&oversized),
        Err(Error::InvalidArgument),
        "a length past one record"
    );
}

/// A cleartext record is read without keys, which is what a ClientHello is.
#[test]
fn a_cleartext_record_is_read_without_keys() {
    let mut wire = alloc::vec![CONTENT_HANDSHAKE, 3, 3, 0, 2];
    wire.extend_from_slice(b"CH");
    let (content, content_type, length) = read_plain(&wire).expect("a record");
    assert_eq!(content, b"CH");
    assert_eq!(content_type, CONTENT_HANDSHAKE);
    assert_eq!(length, wire.len());
    assert_eq!(RECORD_HEADER_LEN, 5);
}

/// The key schedule's ladder is [RFC 8446]'s, and each step moves the
/// answer.
///
/// The property a broken schedule breaks: two different transcript hashes
/// give two different secrets, and the two directions never collide.  A
/// schedule that derived one secret from nothing would give the same answer
/// for every handshake, which a test that only checked lengths would pass.
#[test]
fn the_schedule_moves_with_the_transcript() {
    let shared = [7_u8; 32];
    let one = Schedule::new(shared, [1_u8; 32], [2_u8; 32]);
    let two = Schedule::new(shared, [3_u8; 32], [2_u8; 32]);

    assert_ne!(
        one.client_handshake(),
        one.server_handshake(),
        "the two directions are two secrets"
    );
    assert_ne!(
        one.client_handshake(),
        two.client_handshake(),
        "and the transcript is in them"
    );
    assert_eq!(
        one.client_application(),
        Schedule::new(shared, [1_u8; 32], [2_u8; 32]).client_application(),
        "the same inputs give the same answer"
    );
    assert_ne!(
        one.client_application(),
        one.server_application(),
        "the application secrets differ by direction too"
    );
    assert_ne!(
        one.client_handshake(),
        one.client_application(),
        "and by phase"
    );
}

/// Two keys from one secret are two keys, and the finished keys differ from
/// the traffic secrets they come from.
#[test]
fn the_derived_keys_are_their_own() {
    let schedule = Schedule::new([7_u8; 32], [1_u8; 32], [2_u8; 32]);
    let client = Keys::from_secret(&schedule.client_handshake(), Suite::Aes128GcmSha256);
    let server = Keys::from_secret(&schedule.server_handshake(), Suite::Aes128GcmSha256);
    let mut writer = client.clone();
    let record = write_record(CONTENT_HANDSHAKE, &mut writer, b"x").expect("a record");
    let mut wrong = server;
    assert_eq!(
        read_record(&mut wrong, &record),
        Err(Error::PermissionDenied),
        "the other direction's keys do not open it"
    );

    assert_ne!(
        schedule.finished_key(true),
        schedule.server_handshake(),
        "the finished key is not the traffic secret"
    );
    assert_ne!(schedule.finished_key(true), schedule.finished_key(false));
}

/// A handshake message round trips, and its length covers its body only.
///
/// The field a reader believes: a length that disagreed with the body would
/// make the next message start in the wrong place, and a handshake is a
/// chain with no separators.
#[test]
fn a_handshake_message_round_trips() {
    let body = b"the body";
    let message = write_handshake(HANDSHAKE_CLIENT_HELLO, body);
    assert_eq!(message[0], HANDSHAKE_CLIENT_HELLO);
    assert_eq!(
        ((message[1] as usize) << 16) | ((message[2] as usize) << 8) | message[3] as usize,
        body.len()
    );
    let (parsed, used) = read_handshakes(&message).expect("a message");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].kind, HANDSHAKE_CLIENT_HELLO);
    assert_eq!(parsed[0].body, body);
    assert_eq!(used, message.len());
}

/// Several messages in one buffer are read in order, and a partial one is
/// left for the caller.
///
/// The property a handshake flight needs: messages arrive back to back with
/// no separators, and the last one may be cut by a segment boundary.  A
/// reader that refused the partial one would lose a connection to a TCP
/// segmentation choice.
#[test]
fn a_flight_is_read_and_a_partial_message_is_left() {
    let mut flight = write_handshake(HANDSHAKE_ENCRYPTED_EXTENSIONS, b"");
    flight.extend_from_slice(&write_handshake(HANDSHAKE_CERTIFICATE, b"cert"));
    flight.extend_from_slice(&write_handshake(HANDSHAKE_FINISHED, b"fin")[..3]);
    let (parsed, used) = read_handshakes(&flight).expect("a flight");
    assert_eq!(parsed.len(), 2, "the third is incomplete");
    assert_eq!(parsed[0].kind, HANDSHAKE_ENCRYPTED_EXTENSIONS);
    assert_eq!(parsed[1].body, b"cert");
    assert_eq!(used, flight.len() - 3, "and the partial one is left");
}

/// A ClientHello carries the suite and the key share this build offers, and
/// its length fields agree with what follows them.
///
/// Asserted by walking the body the way a server does: a writer that put a
/// length one byte off would build a hello no conforming server reads, and
/// a round trip through this module's own reader would not notice because
/// it never reads a hello.
#[test]
fn the_client_hello_carries_one_suite_and_one_share() {
    let (offer, _secret) = Offer::generate([9_u8; 32]);
    let body = client_hello_body(&offer, Some("example.test"));
    // legacy_version, then the random.
    assert_eq!(&body[..2], &LEGACY_VERSION.to_be_bytes());
    assert_eq!(&body[2..34], &[9_u8; 32]);
    assert_eq!(body[34], 0, "an empty session id");
    assert_eq!(u16::from_be_bytes([body[35], body[36]]), 2, "one suite");
    assert_eq!(
        u16::from_be_bytes([body[37], body[38]]),
        Suite::Aes128GcmSha256.code()
    );
    // Compression: one method, null.
    assert_eq!(body[39], 1);
    assert_eq!(body[40], 0);
    let extensions_len = u16::from_be_bytes([body[41], body[42]]) as usize;
    assert_eq!(
        extensions_len,
        body.len() - 43,
        "the extension block's length is what follows it"
    );
    // The first extension is supported_versions, which a server needs to
    // read the hello as TLS 1.3 at all.
    assert_eq!(u16::from_be_bytes([body[43], body[44]]), 0x002B);
    // And the name is in it, when one was named.
    assert!(
        body.windows(12).any(|window| window == b"example.test"),
        "the server name"
    );
}

/// A ServerHello is read, and a suite or a group this build does not serve
/// is refused rather than used.
///
/// The group refusal is the one that matters: a server that chose a group
/// the client never offered has chosen a key exchange nobody negotiated,
/// and deriving a secret from it would be a connection whose
/// confidentiality rests on that choice.
#[test]
fn a_server_hello_is_read_and_a_foreign_choice_refused() {
    let body = |suite: u16, group: u16| {
        let mut body = Vec::new();
        body.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
        body.extend_from_slice(&[4_u8; 32]);
        body.push(0);
        body.extend_from_slice(&suite.to_be_bytes());
        body.push(0);
        // One extension: key_share, one entry.
        body.extend_from_slice(&(40_u16).to_be_bytes());
        body.extend_from_slice(&0x0033_u16.to_be_bytes());
        body.extend_from_slice(&(36_u16).to_be_bytes());
        body.extend_from_slice(&group.to_be_bytes());
        body.extend_from_slice(&(32_u16).to_be_bytes());
        body.extend_from_slice(&[5_u8; 32]);
        body
    };

    let parsed = parse_server_hello(&body(0x1301, GROUP_X25519)).expect("a hello");
    assert_eq!(parsed.suite, Suite::Aes128GcmSha256);
    assert_eq!(parsed.share.group, GROUP_X25519);
    assert_eq!(parsed.share.key, [5_u8; 32]);
    assert_eq!(parsed.random, [4_u8; 32]);

    assert_eq!(
        parse_server_hello(&body(0x1302, GROUP_X25519)),
        Err(Error::Unsupported),
        "a suite this build does not serve"
    );
    assert_eq!(
        parse_server_hello(&body(0x1301, 0x0017)),
        Err(Error::Unsupported),
        "a group nobody offered"
    );
}

/// The shared secret round trips between two generated keys, and an
/// all-zero output is refused.
///
/// The refusal is [RFC 7748] §6.1's: a peer may choose a public key that
/// makes the output the point at infinity, and a shared secret of zeros is
/// one the peer knows and this side believes it chose.
#[test]
fn the_shared_secret_round_trips_and_a_zero_one_is_refused() {
    let (offer_a, secret_a) = Offer::generate([1_u8; 32]);
    let (offer_b, secret_b) = Offer::generate([2_u8; 32]);
    let one = shared_secret(&secret_a, &offer_b.key).expect("a secret");
    let two = shared_secret(&secret_b, &offer_a.key).expect("a secret");
    assert_eq!(one, two, "both sides compute the same secret");
    assert_ne!(one, [0_u8; 32]);

    assert_eq!(
        shared_secret(&secret_a, &[0_u8; 32]),
        Err(Error::PermissionDenied),
        "the point at infinity"
    );
}

/// A whole TLS 1.3 handshake between two endpoints, in memory, and then a
/// record each way.
///
/// The strongest evidence this tree can produce without a peer: both sides
/// derive the same handshake secrets from a real X25519 exchange and the
/// same transcript, each verifies the other's Finished, and the application
/// keys that follow carry a record in each direction.  A key schedule that
/// was wrong anywhere would give two sides different secrets and the
/// Finished check would fail; a record layer that was wrong would fail the
/// round trip.
#[test]
fn a_handshake_completes_and_carries_records_both_ways() {
    // The hello.  The client offers, the server answers.
    let (client_offer, client_secret) = Offer::generate([1_u8; 32]);
    let (server_offer, server_secret) = Offer::generate([2_u8; 32]);

    let client_hello = write_handshake(
        HANDSHAKE_CLIENT_HELLO,
        &client_hello_body(&client_offer, Some("example.test")),
    );
    let server_hello_body = {
        let mut body = Vec::new();
        body.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
        body.extend_from_slice(&server_offer.random);
        body.push(0);
        body.extend_from_slice(&Suite::Aes128GcmSha256.code().to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(40_u16).to_be_bytes());
        body.extend_from_slice(&0x0033_u16.to_be_bytes());
        body.extend_from_slice(&(36_u16).to_be_bytes());
        body.extend_from_slice(&GROUP_X25519.to_be_bytes());
        body.extend_from_slice(&(32_u16).to_be_bytes());
        body.extend_from_slice(&server_offer.key);
        body
    };
    let server_hello = write_handshake(HANDSHAKE_SERVER_HELLO, &server_hello_body);

    // Both sides build the transcript through the ServerHello, and the
    // shared secret.
    let mut client_transcript = Transcript::new();
    client_transcript.add(&client_hello);
    client_transcript.add(&server_hello);
    let mut server_transcript = client_transcript.clone();

    let client_shared = shared_secret(&client_secret, &server_offer.key).expect("a secret");
    let server_shared = shared_secret(&server_secret, &client_offer.key).expect("a secret");
    assert_eq!(client_shared, server_shared);

    let client_schedule = Schedule::new(client_shared, client_transcript.hash(), [0; 32]);
    let server_schedule = Schedule::new(server_shared, server_transcript.hash(), [0; 32]);
    assert_eq!(
        client_schedule.client_handshake(),
        server_schedule.client_handshake(),
        "both sides derive one client secret"
    );

    // The server's flight: its Finished, over the transcript so far.
    let server_hs_keys =
        Keys::from_secret(&server_schedule.server_handshake(), Suite::Aes128GcmSha256);
    let mut server_hs_keys = server_hs_keys;
    let mut client_hs_read =
        Keys::from_secret(&server_schedule.server_handshake(), Suite::Aes128GcmSha256);

    let server_finished = write_handshake(
        HANDSHAKE_FINISHED,
        &finished_value(
            &server_schedule.finished_key(true),
            &server_transcript.hash(),
        ),
    );
    let record =
        write_record(CONTENT_HANDSHAKE, &mut server_hs_keys, &server_finished).expect("a record");
    let (plaintext, content_type, _) = read_record(&mut client_hs_read, &record).expect("a record");
    assert_eq!(content_type, CONTENT_HANDSHAKE);
    let (messages, _) = read_handshakes(&plaintext).expect("a message");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].kind, HANDSHAKE_FINISHED);
    assert!(
        verify_finished(
            &client_schedule.finished_key(true),
            &client_transcript.hash(),
            &messages[0].body
        ),
        "the server's Finished verifies against the client's transcript"
    );

    // Both transcripts now cover it, and the application secrets follow.
    client_transcript.add(&server_finished);
    server_transcript.add(&server_finished);
    let client_app = Schedule::new(
        client_shared,
        client_transcript.hash(),
        client_transcript.hash(),
    );
    let server_app = Schedule::new(
        server_shared,
        server_transcript.hash(),
        server_transcript.hash(),
    );
    assert_eq!(
        client_app.client_application(),
        server_app.client_application()
    );

    // A record from the client to the server under the application keys.
    let mut client_write =
        Keys::from_secret(&client_app.client_application(), Suite::Aes128GcmSha256);
    let mut server_read =
        Keys::from_secret(&client_app.client_application(), Suite::Aes128GcmSha256);
    let record = write_record(CONTENT_APPLICATION_DATA, &mut client_write, b"hello server")
        .expect("a record");
    let (plaintext, content_type, _) = read_record(&mut server_read, &record).expect("a record");
    assert_eq!(plaintext, b"hello server");
    assert_eq!(content_type, CONTENT_APPLICATION_DATA);

    // And one the other way, under the server's application keys.
    let mut server_write =
        Keys::from_secret(&server_app.server_application(), Suite::Aes128GcmSha256);
    let mut client_read =
        Keys::from_secret(&server_app.server_application(), Suite::Aes128GcmSha256);
    let record = write_record(CONTENT_APPLICATION_DATA, &mut server_write, b"hello client")
        .expect("a record");
    let (plaintext, _, _) = read_record(&mut client_read, &record).expect("a record");
    assert_eq!(plaintext, b"hello client");
}

/// A forged Finished does not verify, and the check is the transcript's.
///
/// Two forgeries: a MAC under the wrong key, and one over a different
/// transcript.  The second is what makes Finished the proof the handshake
/// wanted, because it is the case an attacker who changed a message
/// produces.
#[test]
fn a_forged_finished_does_not_verify() {
    let mut transcript = Transcript::new();
    transcript.add(b"clienthello");
    let schedule = Schedule::new([7_u8; 32], transcript.hash(), [0; 32]);
    let key = schedule.finished_key(true);

    let good = finished_value(&key, &transcript.hash());
    assert!(verify_finished(&key, &transcript.hash(), &good));

    // The wrong key.
    assert!(!verify_finished(
        &schedule.finished_key(false),
        &transcript.hash(),
        &good
    ));

    // A different transcript.
    let mut other = Transcript::new();
    other.add(b"clienthello");
    other.add(b"tampered");
    assert!(!verify_finished(&key, &other.hash(), &good));

    assert!(!verify_finished(&key, &transcript.hash(), &good[..31]));
    let mut flipped = good;
    flipped[0] ^= 1;
    assert!(!verify_finished(&key, &transcript.hash(), &flipped));
}

/// A transcript hashes what it holds and moves when a byte moves.
#[test]
fn the_transcript_hashes_what_it_holds() {
    let mut transcript = Transcript::new();
    assert!(transcript.is_empty());
    assert_eq!(transcript.hash(), crypto::sha256::sha256(&[]));
    transcript.add(b"one");
    transcript.add(b"two");
    assert_eq!(transcript.len(), 6);
    let first = transcript.hash();
    transcript.add(b"three");
    assert_ne!(transcript.hash(), first);
    assert_eq!(Transcript::new().hash(), crypto::sha256::sha256(&[]));
}

/// A secret's length is the suite's, and a suite's code round trips.
#[test]
fn the_suites_states_are_the_wire_values() {
    assert_eq!(Suite::Aes128GcmSha256.code(), 0x1301);
    assert_eq!(Suite::ChaCha20Poly1305Sha256.code(), 0x1303);
    assert_eq!(Suite::from_code(0x1301), Some(Suite::Aes128GcmSha256));
    assert_eq!(
        Suite::from_code(0x1303),
        Some(Suite::ChaCha20Poly1305Sha256)
    );
    assert_eq!(Suite::from_code(0x1302), None, "TLS 1.2's suite");
    assert_eq!(Suite::Aes128GcmSha256.key_len(), 16);
    assert_eq!(Suite::ChaCha20Poly1305Sha256.key_len(), 32);
}
