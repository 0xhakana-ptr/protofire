//! net/src/ipsec/tests.rs
//!
//! The module's tests.
//!
//! A sibling file because the tests outgrew the module: a reader looking for
//! the mechanism should not scroll past them to find the end of it.

use super::Aead;
use super::Association;
use super::Outcome;
use super::REPLAY_WINDOW;
use super::Selector;
use super::Tables;
use abi::Error;
use alloc::vec::Vec;

const SP: [u8; 4] = [10, 0, 2, 15];
const PEER: [u8; 4] = [10, 0, 2, 2];
const SPI: u32 = 0x0000_0102;

fn sa_record(spi: u32, aead: Aead) -> abi::network::IpsecSaDef {
    let mut record = abi::network::IpsecSaDef {
        flags: 0,
        spi,
        mode: abi::network::IPSEC_MODE_TRANSPORT,
        proto: abi::network::IPSEC_PROTO_ESP,
        aead_algo: abi::network::IPSEC_AEAD_AES128_GCM,
        auth_algo: 0,
        enc_key_len: 16,
        auth_key_len: 0,
        enc_key: [0; 32],
        auth_key: [0; 32],
        salt: [0; 12],
        src_addr: SP,
        dst_addr: PEER,
        tunnel_src: [0; 4],
        tunnel_dst: [0; 4],
        lifetime_bytes: 0,
        lifetime_ticks: 0,
    };
    match aead {
        Aead::Aes128Gcm => {
            for (index, byte) in record.enc_key[..16].iter_mut().enumerate() {
                *byte = index as u8;
            }
            record.salt[..4].copy_from_slice(&[0xA0, 0xA1, 0xA2, 0xA3]);
        }
        Aead::ChaCha20Poly1305 => {
            record.aead_algo = abi::network::IPSEC_AEAD_CHACHA20_POLY1305;
            record.enc_key_len = 32;
            for (index, byte) in record.enc_key.iter_mut().enumerate() {
                *byte = index as u8;
            }
            record.salt[..4].copy_from_slice(&[0xB0, 0xB1, 0xB2, 0xB3]);
        }
    }
    record
}

fn sp_record(action: u32, direction: u32, sa_id: u32, protocol: u32) -> abi::network::IpsecSpDef {
    abi::network::IpsecSpDef {
        flags: 0,
        action,
        direction,
        protocol,
        src_addr: [0; 4],
        src_prefix: 0,
        dst_addr: [0; 4],
        dst_prefix: 0,
        src_port: 0,
        dst_port: 0,
        sa_id,
        reserved: 0,
    }
}

/// An association seals and opens, and the bytes come back whole.
///
/// Both algorithms, because the nonce's middle word is the one thing they
/// disagree about: an implementation that used the AES construction for
/// ChaCha would produce a packet the peer cannot open, and a round trip
/// against itself would not notice.
#[test]
fn an_association_round_trips_both_algorithms() {
    for aead in [Aead::Aes128Gcm, Aead::ChaCha20Poly1305] {
        let mut association =
            Association::from_record(&sa_record(SPI, aead)).expect("an association");
        let inner = b"the plaintext";
        let sealed = association
            .seal(inner, crate::ipv4::PROTOCOL_UDP)
            .expect("sealed");
        assert_eq!(&sealed[..4], &SPI.to_be_bytes(), "the SPI leads");
        assert_eq!(&sealed[4..8], &1_u32.to_be_bytes(), "the first sequence");
        assert!(
            sealed.len() > inner.len(),
            "the ciphertext and tag are there"
        );
        assert!(
            !sealed.windows(inner.len()).any(|window| window == inner),
            "and the plaintext is not in it"
        );

        let (opened, next) = association.open(&sealed).expect("opened");
        assert_eq!(opened, inner, "the bytes came back");
        assert_eq!(next, crate::ipv4::PROTOCOL_UDP);
    }
}

/// The nonce is the algorithm's, and the two constructions differ in the
/// middle word.
///
/// The round trip cannot catch this: a nonce derived wrongly on both sides
/// agrees with itself, so the test above passes whether the middle word is
/// zero or one.  This asserts the bytes, which is what a peer's
/// implementation checks against [RFC 7634]'s own text.
#[test]
fn the_nonce_is_each_algorithms_own() {
    let salt = [0xB0, 0xB1, 0xB2, 0xB3];
    let sequence = 0x0000_0005_u32;

    // RFC 4106: salt, thirty-two zero bits, the sequence number.
    assert_eq!(
        super::nonce(salt, Aead::Aes128Gcm, sequence),
        [
            0xB0, 0xB1, 0xB2, 0xB3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05
        ]
    );
    // RFC 7634: salt, thirty-two bits that are one, then the sequence.
    assert_eq!(
        super::nonce(salt, Aead::ChaCha20Poly1305, sequence),
        [
            0xB0, 0xB1, 0xB2, 0xB3, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05
        ]
    );
    // And they are different bytes, which is the property the round trip
    // could not see.
    assert_ne!(
        super::nonce(salt, Aead::Aes128Gcm, sequence),
        super::nonce(salt, Aead::ChaCha20Poly1305, sequence)
    );
}

/// The padding makes the plaintext a multiple of four, and its own length
/// says how much of it is padding.
///
/// Four lengths, one of which needs no padding, so the rule is asserted
/// where it is easy to get wrong: a reader that trusted the tag and not the
/// padding length would truncate every message by two bytes.
#[test]
fn the_padding_rounds_and_says_how_much_it_was() {
    let mut association =
        Association::from_record(&sa_record(SPI, Aead::Aes128Gcm)).expect("an association");
    for length in 0..8_usize {
        let inner: Vec<u8> = (0..length).map(|index| index as u8).collect();
        let sealed = association
            .seal(&inner, crate::ipv4::PROTOCOL_TCP)
            .expect("sealed");
        let (opened, next) = association.open(&sealed).expect("opened");
        assert_eq!(opened, inner, "length {length}");
        assert_eq!(next, crate::ipv4::PROTOCOL_TCP);
    }
}

/// Each send spends a sequence number, so two sends are two numbers.
#[test]
fn each_send_spends_a_sequence_number() {
    let mut association =
        Association::from_record(&sa_record(SPI, Aead::Aes128Gcm)).expect("an association");
    assert_eq!(association.next_sequence(), 1);
    let first = association.seal(b"a", 17).expect("sealed");
    assert_eq!(association.next_sequence(), 2);
    let second = association.seal(b"b", 17).expect("sealed");
    assert_eq!(&first[4..8], &1_u32.to_be_bytes());
    assert_eq!(&second[4..8], &2_u32.to_be_bytes());
}

/// A duplicate is refused and the window is not advanced by it.
///
/// The half a naive implementation gets wrong is the other one: the window
/// is consulted before the tag and advanced only after it verifies, so a
/// packet that failed its tag does not burn a sequence number.  That is
/// asserted separately, because it needs a payload the tag refuses.
#[test]
fn a_duplicate_is_refused() {
    let mut association =
        Association::from_record(&sa_record(SPI, Aead::Aes128Gcm)).expect("an association");
    let sealed = association.seal(b"once", 17).expect("sealed");
    association.open(&sealed).expect("the first");
    assert_eq!(
        association.open(&sealed),
        Err(Error::PermissionDenied),
        "the same sequence twice"
    );
    assert_eq!(association.replay_highest(), 1);
}

/// A packet that fails its tag does not mark its sequence as seen.
///
/// The attack this prevents: a stranger sends garbage with a high sequence
/// number, this machine rejects it, and the window has moved past every
/// packet the real peer is about to send.  The window only advances on a
/// packet that verified.
#[test]
fn a_failed_tag_does_not_advance_the_window() {
    let mut association =
        Association::from_record(&sa_record(SPI, Aead::Aes128Gcm)).expect("an association");
    let sealed = association.seal(b"real", 17).expect("sealed");

    // A copy of the packet with its ciphertext altered: same SPI, same
    // sequence, a tag that no longer verifies.
    let mut forged = sealed.clone();
    let at = forged.len() - super::TAG_LENGTH - 1;
    forged[at] ^= 0xFF;
    assert_eq!(
        association.open(&forged),
        Err(Error::PermissionDenied),
        "the tag failed"
    );
    assert_eq!(
        association.replay_highest(),
        0,
        "and the window did not move"
    );

    // The real packet still opens, with the sequence the forgery tried to
    // burn.
    let (opened, _) = association.open(&sealed).expect("the real one");
    assert_eq!(opened, b"real");
}

/// A sequence too far behind the window is refused, and one inside it is
/// accepted once.
///
/// The window's arithmetic: a packet `REPLAY_WINDOW` behind is too old,
/// one just inside is fresh, and the second copy of that one is a replay.
#[test]
fn the_window_refuses_what_is_behind_it() {
    let mut association =
        Association::from_record(&sa_record(SPI, Aead::Aes128Gcm)).expect("an association");

    // Seal `REPLAY_WINDOW + 4` packets and collect them, so the window can
    // be walked onto the highest one.
    let mut sealed = Vec::new();
    for index in 0..(REPLAY_WINDOW + 4) {
        sealed.push(association.seal(&[index as u8], 17).expect("sealed"));
    }
    let highest = sealed.len() as u32;

    // The highest arrives: the window slides onto it.
    association
        .open(&sealed[sealed.len() - 1])
        .expect("the newest");
    assert_eq!(association.replay_highest(), highest);

    // The oldest is behind the window: refused, and it was never opened so
    // its tag is irrelevant.
    assert_eq!(
        association.open(&sealed[0]),
        Err(Error::PermissionDenied),
        "too far behind"
    );

    // One just inside the window is accepted.
    let inside = sealed.len() - REPLAY_WINDOW as usize;
    association
        .open(&sealed[inside])
        .expect("inside the window");
    // And the same one again is a replay.
    assert_eq!(
        association.open(&sealed[inside]),
        Err(Error::PermissionDenied)
    );
}

/// An SPI that is not this association's is `NotFound`, not a decryption
/// failure.
///
/// The difference is what a receiver does next: an unknown SPI is a packet
/// for an association this machine does not have, and a wrong SPI on a
/// packet that otherwise parses is a peer that used the wrong one.
#[test]
fn a_packet_for_another_spi_is_not_found() {
    let mut association =
        Association::from_record(&sa_record(SPI, Aead::Aes128Gcm)).expect("an association");
    let sealed = association.seal(b"x", 17).expect("sealed");
    let mut other = sealed.clone();
    other[..4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    assert_eq!(association.open(&other), Err(Error::NotFound));
}

/// A record this build cannot use is refused, and ESP's two refusals are
/// `Unsupported` rather than `InvalidArgument`.
///
/// AH and tunnel mode are values the ABI names and this build does not do,
/// and the difference matters to a program: `Unsupported` says the machine
/// understood the request and will not, `InvalidArgument` says the request
/// was malformed.
#[test]
fn a_record_this_build_cannot_use_is_refused() {
    let good = sa_record(SPI, Aead::Aes128Gcm);
    assert!(Association::from_record(&good).is_ok());

    let mut ah = good;
    ah.proto = abi::network::IPSEC_PROTO_AH;
    assert_eq!(Association::from_record(&ah), Err(Error::Unsupported));

    let mut tunnel = good;
    tunnel.mode = abi::network::IPSEC_MODE_TUNNEL;
    assert_eq!(Association::from_record(&tunnel), Err(Error::Unsupported));

    let mut short_key = good;
    short_key.enc_key_len = 8;
    assert_eq!(
        Association::from_record(&short_key),
        Err(Error::InvalidArgument)
    );

    let mut unknown_aead = good;
    unknown_aead.aead_algo = 99;
    assert_eq!(
        Association::from_record(&unknown_aead),
        Err(Error::InvalidArgument)
    );
}

/// A policy's selector matches by prefix, protocol and port, and a port
/// rule does not match a packet with no ports.
#[test]
fn a_selector_matches_its_five_tuple() {
    let selector = Selector {
        protocol: crate::ipv4::PROTOCOL_TCP,
        source: [10, 0, 2, 0],
        source_length: 24,
        destination: [10, 0, 3, 0],
        destination_length: 24,
        source_port: 0,
        destination_port: 443,
    };
    assert!(selector.matches([10, 0, 2, 7], [10, 0, 3, 9], 6, Some((1000, 443))));
    // Another protocol.
    assert!(!selector.matches([10, 0, 2, 7], [10, 0, 3, 9], 17, Some((1000, 443))));
    // Another port.
    assert!(!selector.matches([10, 0, 2, 7], [10, 0, 3, 9], 6, Some((1000, 80))));
    // No ports at all, which a port name does not match.
    assert!(!selector.matches([10, 0, 2, 7], [10, 0, 3, 9], 6, None));
    // Outside the source prefix.
    assert!(!selector.matches([10, 0, 4, 7], [10, 0, 3, 9], 6, Some((1000, 443))));
}

/// The list is ordered and the first match decides.
///
/// The property a policy set is read as.  A broad discard written after a
/// narrow bypass is a bypass for the narrow case, and a lookup that took
/// the last match or the most specific one would make the order decorative.
#[test]
fn the_first_matching_policy_decides() {
    let mut tables = Tables::new();
    let association = tables
        .add_association(&sa_record(SPI, Aead::Aes128Gcm))
        .expect("an association");

    // A narrow bypass for one host, then a broad protect.
    let mut narrow = sp_record(
        abi::network::IPSEC_ACTION_BYPASS,
        abi::network::IPSEC_DIR_OUTBOUND,
        0,
        0,
    );
    narrow.dst_addr = PEER;
    narrow.dst_prefix = 32;
    tables.add_policy(&narrow).expect("narrow");

    let mut broad = sp_record(
        abi::network::IPSEC_ACTION_PROTECT,
        abi::network::IPSEC_DIR_OUTBOUND,
        association,
        0,
    );
    broad.dst_addr = [10, 0, 0, 0];
    broad.dst_prefix = 16;
    tables.add_policy(&broad).expect("broad");

    assert_eq!(
        tables.outbound(SP, PEER, 17, Some((1, 2))),
        Outcome::Bypass,
        "the narrow rule is first"
    );
    assert_eq!(
        tables.outbound(SP, [10, 0, 9, 9], 17, Some((1, 2))),
        Outcome::Protect(association),
        "the broad rule covers the rest"
    );
}

/// A packet nothing matches bypasses, and the inbound direction is a
/// different list from the outbound one.
#[test]
fn no_match_bypasses_and_directions_are_separate() {
    let mut tables = Tables::new();
    let association = tables
        .add_association(&sa_record(SPI, Aead::Aes128Gcm))
        .expect("an association");
    tables
        .add_policy(&sp_record(
            abi::network::IPSEC_ACTION_PROTECT,
            abi::network::IPSEC_DIR_OUTBOUND,
            association,
            0,
        ))
        .expect("a policy");

    assert_eq!(
        tables.outbound(SP, PEER, 17, None),
        Outcome::Protect(association)
    );
    assert_eq!(
        tables.inbound(SP, PEER, 17, None),
        Outcome::Bypass,
        "the policy is outbound only"
    );
}

/// A protect policy must name an association that exists, and a policy
/// naming one that does not is refused.
///
/// The reading that cannot send plaintext: a policy installed ahead of its
/// association would match a packet and have nothing to apply.
#[test]
fn a_protect_policy_needs_an_association() {
    let mut tables = Tables::new();
    assert_eq!(
        tables.add_policy(&sp_record(
            abi::network::IPSEC_ACTION_PROTECT,
            abi::network::IPSEC_DIR_OUTBOUND,
            42,
            0,
        )),
        Err(Error::NotFound)
    );
    // And a protect policy naming no association at all.
    assert_eq!(
        tables.add_policy(&sp_record(
            abi::network::IPSEC_ACTION_PROTECT,
            abi::network::IPSEC_DIR_OUTBOUND,
            0,
            0,
        )),
        Err(Error::InvalidArgument)
    );
    assert_eq!(tables.counts(), (0, 0));
}

/// Two associations cannot share an SPI, and removing one removes the
/// policies that named it.
///
/// The SPI is what names an association on the wire, so two with one SPI
/// would make an arriving packet belong to both.  And a policy whose
/// association is gone would match a packet and have nothing to apply,
/// which is the state the install refuses and the removal must not create.
#[test]
fn an_spi_has_one_association_and_removing_it_takes_its_policies() {
    let mut tables = Tables::new();
    tables
        .add_association(&sa_record(SPI, Aead::Aes128Gcm))
        .expect("the first");
    assert_eq!(
        tables.add_association(&sa_record(SPI, Aead::Aes128Gcm)),
        Err(Error::AlreadyExists)
    );
    assert_eq!(tables.counts().1, 1);

    let id = tables
        .add_policy(&sp_record(
            abi::network::IPSEC_ACTION_PROTECT,
            abi::network::IPSEC_DIR_BOTH,
            1,
            0,
        ))
        .expect("a policy");
    assert_eq!(tables.counts(), (1, 1));
    assert!(tables.remove_association(SPI));
    assert_eq!(tables.counts(), (0, 0), "the policy went with it");
    assert!(!tables.remove_association(SPI), "and it was there once");
    let _ = id;
}

/// The statistics count what happened, in the four categories.
#[test]
fn the_statistics_count_the_four_kinds() {
    let mut tables = Tables::new();
    assert_eq!(tables.statistics(), (0, 0, 0, 0));
    tables.note_sealed();
    tables.note_opened();
    tables.note_opened();
    tables.note_integrity_failure();
    tables.note_replay_drop();
    tables.note_replay_drop();
    assert_eq!(tables.statistics(), (1, 2, 1, 2));
}

/// A policy's direction word and its protocol are validated, and a word
/// nothing defines is refused rather than read as both.
#[test]
fn a_policy_that_names_nothing_is_refused() {
    let mut tables = Tables::new();
    let association = tables
        .add_association(&sa_record(SPI, Aead::Aes128Gcm))
        .expect("an association");

    let mut bad_direction = sp_record(
        abi::network::IPSEC_ACTION_BYPASS,
        abi::network::IPSEC_DIR_OUTBOUND,
        association,
        0,
    );
    bad_direction.direction = 9;
    assert_eq!(
        tables.add_policy(&bad_direction),
        Err(Error::InvalidArgument)
    );

    let mut long_prefix = sp_record(
        abi::network::IPSEC_ACTION_BYPASS,
        abi::network::IPSEC_DIR_OUTBOUND,
        association,
        0,
    );
    long_prefix.src_prefix = 33;
    assert_eq!(tables.add_policy(&long_prefix), Err(Error::InvalidArgument));

    let mut reserved = sp_record(
        abi::network::IPSEC_ACTION_BYPASS,
        abi::network::IPSEC_DIR_OUTBOUND,
        association,
        0,
    );
    reserved.reserved = 1;
    assert_eq!(tables.add_policy(&reserved), Err(Error::InvalidArgument));

    assert_eq!(tables.counts(), (0, 1), "nothing was installed");
}
