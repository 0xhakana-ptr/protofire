//! net/src/ipsec.rs
//!
//! IPsec's two databases and the encapsulation they decide: a policy that says
//! what happens to a packet, an association that says how, and [RFC 4303]'s ESP
//! header built with the AEAD this tree already has.
//!
//! ## The two databases, and why a policy names an association
//!
//! A **security policy** is the question "what happens to this packet": bypass
//! it, drop it, or protect it.  A **security association** is everything the
//! protection needs: a key, a salt, an SPI the peer will see, a sequence
//! counter, and the replay window that decides whether an arriving sequence has
//! been seen.  One policy names one association by id, which is what keeps the
//! two apart: two policies may protect with one association when they describe
//! one tunnel, and two associations may exist for one key during a rekey.
//!
//! The policy list is **ordered and the first match wins**, which is the
//! property a policy set is read as: a rule for one host written above a rule
//! for its subnet is a rule that says something about that host, and a lookup
//! that took the most specific match instead would make the order decorative.
//!
//! ## What ESP is, and what is deliberately not
//!
//! [RFC 4303]'s transport-mode ESP, one header: `SPI`, sequence number, the
//! encrypted `inner || pad || pad_len || next_header`, and the AEAD tag.  The
//! tag covers `SPI || sequence` as associated data, which is what stops a
//! replayed header from being accepted with a fresh one around it.
//!
//! **AH is not here.**  Its field is a protocol number the ABI names, and an
//! authentication header over a mutable IPv4 header needs the header's mutable
//! fields zeroed before the sum, which is a second encapsulation with its own
//! reader and writer.  A policy asking for it is refused rather than served
//! with ESP: the ABI's record has a protocol word and a caller that set it to
//! AH should learn that this build does not do it, not receive an ESP packet it
//! did not ask for.
//!
//! **Tunnel mode is not here either.**  It needs a second IP header around the
//! ESP one, and this stack's senders compose one header per packet.  A policy
//! asking for it is refused, for the same reason: a transport-mode packet sent
//! where a tunnel was asked for is a packet the peer's tunnel endpoint will
//! drop, and silence is worse than a refusal at the call.
//!
//! ## The replay window
//!
//! [RFC 4303] §3.4.3's algorithm, and the shape is the one thing worth
//! describing: a thirty-two bit sequence number, so the highest seen plus a
//! bitmap of the window's bits behind it.  A sequence ahead of the window is
//! fresh and slides it; one inside it is fresh only if its bit is clear; one
//! behind it is too old and is dropped without touching the bitmap.
//!
//! The window is **per association**, not per policy, because the sequence
//! number is the association's: two policies sharing one association share one
//! counter and one window, which is what a tunnel is.
//!
//! ## What this module does not do
//!
//! It does not **negotiate**.  IKE is the protocol that agrees a key, and it is
//! a different stack: the associations here arrive from a program through the
//! four `Ipsec*` calls, and nothing in this module speaks to a peer to get one.
//! It also does not **choose** which packets are protected on its own: the
//! lookup is a call the kernel makes with the packet's five-tuple, and what the
//! kernel does with the answer is the kernel's.
//!
//! [RFC 4303]: https://www.rfc-editor.org/rfc/rfc4303

use alloc::vec::Vec;

use abi::Error;
use abi::Result;

/// The largest number of policies a machine holds.
///
/// Bounded because the entries arrive from a program, and the previous tree's
/// number so a boot's configuration is what it was written against.
pub const POLICY_LIMIT: usize = 256;

/// The largest number of associations a machine holds.
pub const ASSOCIATION_LIMIT: usize = 256;

/// How many bits of the replay window are remembered.
///
/// [RFC 4303] requires at least thirty-two and recommends sixty-four, and this
/// is the recommendation: the encoder is a `u64`, so the window is one word and
/// sliding it is a shift.
pub const REPLAY_WINDOW: u32 = 64;

/// What a policy does with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Let it through untouched.
    Bypass,
    /// Drop it, silently, exactly as the packet filter's deny does.
    Discard,
    /// Encapsulate it in ESP under the association the policy names.
    Protect,
}

impl Action {
    /// The action a wire value names, or the error for one this build does not.
    pub fn from_wire(value: u32) -> Result<Self> {
        match value {
            abi::network::IPSEC_ACTION_BYPASS => Ok(Self::Bypass),
            abi::network::IPSEC_ACTION_DISCARD => Ok(Self::Discard),
            abi::network::IPSEC_ACTION_PROTECT => Ok(Self::Protect),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// The wire value this action is.
    pub fn to_wire(self) -> u32 {
        match self {
            Self::Bypass => abi::network::IPSEC_ACTION_BYPASS,
            Self::Discard => abi::network::IPSEC_ACTION_DISCARD,
            Self::Protect => abi::network::IPSEC_ACTION_PROTECT,
        }
    }
}

/// Which packets a policy is about.
///
/// The five-tuple a transport connection is, plus the protocol number, which is
/// what makes a UDP policy not match a TCP packet on the same ports.  A zero
/// protocol is any, and a zero prefix length is any address, which are the two
/// wildcards the ABI's record states with zeros.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selector {
    /// The IP protocol number, or zero for any.
    pub protocol: u8,
    /// The source prefix, its length, and the destination's.
    pub source: [u8; 4],
    pub source_length: u8,
    pub destination: [u8; 4],
    pub destination_length: u8,
    /// The two ports, zero for any.
    ///
    /// A policy about a port is a policy about a transport that has ports: an
    /// ICMP message has no ports, and a selector naming one does not match it,
    /// which is the same rule the packet filter's port rules follow.
    pub source_port: u16,
    pub destination_port: u16,
}

impl Selector {
    /// Whether this selector is about a packet's five-tuple.
    ///
    /// The addresses are compared by prefix, the protocol by number unless it
    /// is the wildcard, and the ports by value unless they are zero.  `ports`
    /// is `None` for a packet whose transport header carried none, and a
    /// selector naming a port does **not** match it: a policy written for TCP
    /// must not catch an ICMP message because the bytes it would read as ports
    /// were absent.
    pub fn matches(
        &self,
        source: [u8; 4],
        destination: [u8; 4],
        protocol: u8,
        ports: Option<(u16, u16)>,
    ) -> bool {
        if self.protocol != 0 && self.protocol != protocol {
            return false;
        }
        if !crate::route::prefix_bits(&self.source, &source, self.source_length as usize)
            || !crate::route::prefix_bits(
                &self.destination,
                &destination,
                self.destination_length as usize,
            )
        {
            return false;
        }
        let names_ports = self.source_port != 0 || self.destination_port != 0;
        if !names_ports {
            return true;
        }
        let Some((source_port, destination_port)) = ports else {
            return false;
        };
        (self.source_port == 0 || self.source_port == source_port)
            && (self.destination_port == 0 || self.destination_port == destination_port)
    }
}

/// One policy: what it is about, and what happens to a packet that matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// The id this policy was given.
    pub id: u32,
    /// The packets it is about.
    pub selector: Selector,
    /// What happens to them.
    pub action: Action,
    /// The association a `Protect` policy applies.
    pub association: Option<u32>,
    /// Whether it is about arriving packets, leaving ones, or both.
    ///
    /// The two directions are two lookups because a host usually protects one
    /// direction and accepts the other: an inbound policy and an outbound one
    /// are different rules about different packets, and one list consulted for
    /// both would make a policy an inbound one could not be written without
    /// also being an outbound one.
    pub outbound: bool,
    pub inbound: bool,
}

/// One association: everything ESP needs, and its own counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Association {
    /// The id a policy names.
    pub id: u32,
    /// The SPI the peer sees in every packet this association sends.
    pub spi: u32,
    /// The key and the salt the nonce is derived from.
    key: Vec<u8>,
    salt: [u8; 4],
    /// Which AEAD this association uses.
    pub aead: Aead,
    /// The next sequence number to send.
    next_sequence: u32,
    /// The highest sequence number accepted, and the window behind it.
    ///
    /// `replay_last` is zero before anything arrived, which is the state a
    /// fresh association is in and not a sequence number: ESP's sequence
    /// numbers start at one, so zero is never a sequence that arrived.
    replay_last: u32,
    replay_window: u64,
}

/// The AEAD an association uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aead {
    /// AES-128-GCM, [RFC 4106].
    Aes128Gcm,
    /// ChaCha20-Poly1305, [RFC 7634].
    ChaCha20Poly1305,
}

impl Aead {
    /// The algorithm a wire value names, or the error for one this build does
    /// not do.
    pub fn from_wire(value: u32) -> Result<Self> {
        match value {
            abi::network::IPSEC_AEAD_AES128_GCM => Ok(Self::Aes128Gcm),
            abi::network::IPSEC_AEAD_CHACHA20_POLY1305 => Ok(Self::ChaCha20Poly1305),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// How many key bytes this algorithm takes.
    pub fn key_length(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::ChaCha20Poly1305 => 32,
        }
    }
}

/// The AEAD tag's length, which both algorithms use.
pub const TAG_LENGTH: usize = 16;

/// The ESP header's length: the SPI and the sequence number.
pub const ESP_HEADER_LENGTH: usize = 8;

/// The nonce an ESP packet's AEAD uses ([RFC 4106] §3, [RFC 7634] §2).
///
/// Four bytes of salt and the sequence number, with the middle four bytes
/// carrying a constant: [RFC 4106] leaves them zero and [RFC 7634] puts a one
/// there, which is the difference between the two constructions and the reason
/// this takes the algorithm rather than a boolean.
///
/// [RFC 4106]: https://www.rfc-editor.org/rfc/rfc4106
/// [RFC 7634]: https://www.rfc-editor.org/rfc/rfc7634
fn nonce(salt: [u8; 4], aead: Aead, sequence: u32) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&salt);
    if aead == Aead::ChaCha20Poly1305 {
        nonce[4..8].copy_from_slice(&1_u32.to_be_bytes());
    }
    nonce[8..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

impl Association {
    /// An association from the record a program passed, or the error for one
    /// this build cannot use.
    ///
    /// Refused: a key whose length is not the algorithm's, a protocol that is
    /// not ESP, a mode that is not transport, and a reserved word that is not
    /// zero.  Each is a value this stack would otherwise have to guess about,
    /// and a guess in a key's length is a guess about which bytes are the key.
    pub fn from_record(record: &abi::network::IpsecSaDef) -> Result<Self> {
        if record.flags != 0 {
            return Err(Error::InvalidArgument);
        }
        // The ABI names AH and tunnel mode as values a caller may set, and this
        // build refuses both: a refusal here is a program learning what the
        // machine does, and an ESP packet sent where a tunnel was asked for is
        // a packet the peer's endpoint drops in silence.
        if record.proto != abi::network::IPSEC_PROTO_ESP {
            return Err(Error::Unsupported);
        }
        if record.mode != abi::network::IPSEC_MODE_TRANSPORT {
            return Err(Error::Unsupported);
        }
        let aead = Aead::from_wire(record.aead_algo)?;
        if record.enc_key_len as usize != aead.key_length() {
            return Err(Error::InvalidArgument);
        }
        if record.enc_key_len as usize > record.enc_key.len() {
            return Err(Error::InvalidArgument);
        }
        let mut salt = [0_u8; 4];
        salt.copy_from_slice(&record.salt[..4]);
        Ok(Self {
            id: 0,
            spi: record.spi,
            key: record.enc_key[..record.enc_key_len as usize].to_vec(),
            salt,
            aead,
            next_sequence: 0,
            replay_last: 0,
            replay_window: 0,
        })
    }

    /// The AEAD this association uses.
    pub fn aead(&self) -> Aead {
        self.aead
    }

    /// The next sequence number a send would use, without spending it.
    pub fn next_sequence(&self) -> u32 {
        self.next_sequence.wrapping_add(1)
    }

    /// Encapsulate `inner` into a complete ESP payload, spending a sequence
    /// number.
    ///
    /// The plaintext is `inner`, padding, the padding's length and the next
    /// header, in that order, padded so the whole is a multiple of four bytes:
    /// the padding is what makes the plaintext a whole number of blocks, and
    /// its own length is what lets a reader find where `inner` ended.  The next
    /// header is the protocol number that was inside, which is how the receiver
    /// knows what it decapsulated to.
    ///
    /// A **spent** sequence number is never reused: the counter increments even
    /// when the packet is lost, because a receiver's replay window is about
    /// what it *saw*, and a sender that reused a number would make two packets
    /// one number and the second one a replay.
    pub fn seal(&mut self, inner: &[u8], next_header: u8) -> Result<Vec<u8>> {
        let sequence = self.next_sequence();
        self.next_sequence = sequence;

        let pad_length = (4 - ((inner.len() + 2) % 4)) % 4;
        let mut plaintext = Vec::with_capacity(inner.len() + pad_length + 2);
        plaintext.extend_from_slice(inner);
        plaintext.extend(core::iter::repeat_n(0_u8, pad_length));
        plaintext.push(pad_length as u8);
        plaintext.push(next_header);

        let mut aad = [0_u8; ESP_HEADER_LENGTH];
        aad[..4].copy_from_slice(&self.spi.to_be_bytes());
        aad[4..].copy_from_slice(&sequence.to_be_bytes());
        let nonce = nonce(self.salt, self.aead, sequence);

        let (ciphertext, tag) = match self.aead {
            Aead::Aes128Gcm => {
                let mut key = [0_u8; 16];
                key.copy_from_slice(&self.key);
                crypto::gcm::aes128_gcm_encrypt(&key, &nonce, &aad, &plaintext)
            }
            Aead::ChaCha20Poly1305 => {
                let mut key = [0_u8; 32];
                key.copy_from_slice(&self.key);
                crypto::aead::chacha20_poly1305_encrypt(&key, &nonce, &aad, &plaintext)
            }
        };

        let mut payload = Vec::with_capacity(ESP_HEADER_LENGTH + ciphertext.len() + TAG_LENGTH);
        payload.extend_from_slice(&aad);
        payload.extend_from_slice(&ciphertext);
        payload.extend_from_slice(&tag);
        Ok(payload)
    }

    /// Decapsulate one ESP payload, answering the bytes inside and what they
    /// were.
    ///
    /// The order is the one that matters: the **replay window is consulted
    /// before the tag is verified**, so a duplicate costs a comparison rather
    /// than a decrypt.  But the window is only **advanced** after the tag
    /// verifies, which is the half a naive implementation gets wrong: a packet
    /// that failed its tag has not been seen, and marking its sequence as seen
    /// would let a stranger burn the window with packets this machine rejected.
    pub fn open(&mut self, payload: &[u8]) -> Result<(Vec<u8>, u8)> {
        if payload.len() < ESP_HEADER_LENGTH + TAG_LENGTH {
            return Err(Error::InvalidArgument);
        }
        if payload[..4] != self.spi.to_be_bytes() {
            return Err(Error::NotFound);
        }
        let sequence = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);

        // The window, asked but not yet advanced.
        if !self.would_accept(sequence) {
            return Err(Error::PermissionDenied);
        }

        let nonce = nonce(self.salt, self.aead, sequence);
        let aad = &payload[..ESP_HEADER_LENGTH];
        let ciphertext = &payload[ESP_HEADER_LENGTH..payload.len() - TAG_LENGTH];
        let mut tag = [0_u8; TAG_LENGTH];
        tag.copy_from_slice(&payload[payload.len() - TAG_LENGTH..]);

        let plaintext = match self.aead {
            Aead::Aes128Gcm => {
                let mut key = [0_u8; 16];
                key.copy_from_slice(&self.key);
                crypto::gcm::aes128_gcm_decrypt(&key, &nonce, aad, ciphertext, &tag)
            }
            Aead::ChaCha20Poly1305 => {
                let mut key = [0_u8; 32];
                key.copy_from_slice(&self.key);
                crypto::aead::chacha20_poly1305_decrypt(&key, &nonce, aad, ciphertext, &tag)
            }
        };

        // A failed tag is this machine's answer and not a caller's mistake:
        // `InvalidCredential` from the cipher becomes the integrity failure
        // ESP reports, and the sequence is **not** marked as seen.
        let plaintext = match plaintext {
            Ok(bytes) => bytes,
            Err(Error::InvalidCredential) => return Err(Error::PermissionDenied),
            Err(other) => return Err(other),
        };

        if plaintext.len() < 2 {
            return Err(Error::InvalidArgument);
        }
        let next_header = *plaintext.last().ok_or(Error::InvalidArgument)?;
        let pad_length = plaintext[plaintext.len() - 2] as usize;
        if pad_length + 2 > plaintext.len() {
            return Err(Error::InvalidArgument);
        }

        // The tag verified, so this sequence was really sent by the peer.
        self.accept(sequence);
        Ok((
            plaintext[..plaintext.len() - 2 - pad_length].to_vec(),
            next_header,
        ))
    }

    /// Whether the replay window would accept `sequence`.
    fn would_accept(&self, sequence: u32) -> bool {
        if sequence == 0 {
            return false;
        }
        if self.replay_last == 0 || sequence > self.replay_last {
            return true;
        }
        let behind = self.replay_last - sequence;
        if behind >= REPLAY_WINDOW {
            return false;
        }
        self.replay_window & (1_u64 << behind) == 0
    }

    /// Slide the window onto `sequence`.
    fn accept(&mut self, sequence: u32) {
        if self.replay_last == 0 || sequence > self.replay_last {
            let advance = if self.replay_last == 0 {
                // The first packet: everything before it is behind the window
                // and nothing is set but its own bit, which is the state a
                // fresh association reaches.
                REPLAY_WINDOW
            } else {
                sequence - self.replay_last
            };
            self.replay_window = if advance >= REPLAY_WINDOW {
                0
            } else {
                self.replay_window << advance
            };
            self.replay_window |= 1;
            self.replay_last = sequence;
        } else {
            let behind = self.replay_last - sequence;
            if behind < REPLAY_WINDOW {
                self.replay_window |= 1_u64 << behind;
            }
        }
    }

    /// The highest sequence number this association has accepted.
    pub fn replay_highest(&self) -> u32 {
        self.replay_last
    }
}

/// What a lookup decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Let it through.
    Bypass,
    /// Drop it.
    Discard,
    /// Encapsulate it under this association.
    Protect(u32),
}

/// The two databases, and the counters that say how much they did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tables {
    policies: Vec<Policy>,
    associations: Vec<Association>,
    /// The next id a policy or an association is given, shared so a policy's
    /// `association` field cannot name one by accident: the two id spaces are
    /// disjoint, and a policy naming an association that never existed is a
    /// lookup that answers nothing rather than one that finds the wrong table.
    next_id: u32,
    /// Packets ESP encapsulated, and packets it decapsulated.
    sealed: u64,
    opened: u64,
    /// Payloads whose tag did not verify, and sequences the window refused.
    ///
    /// Two counters and not one, because they are two failures: a tag that
    /// failed is a packet that was not the peer's, and a sequence the window
    /// refused is a packet that was the peer's and arrived twice.  A boot's
    /// line that added them would report a replay attack as a key mismatch.
    integrity_failures: u64,
    replay_drops: u64,
}

impl Tables {
    /// An empty pair of databases: no policy matches anything, and a lookup
    /// answers nothing for a packet, which is the state that makes every
    /// packet bypass.
    pub const fn new() -> Self {
        Self {
            policies: Vec::new(),
            associations: Vec::new(),
            next_id: 1,
            sealed: 0,
            opened: 0,
            integrity_failures: 0,
            replay_drops: 0,
        }
    }

    /// Install a policy from the record a program passed, answering its id.
    ///
    /// Appended, because the list is ordered and the order is the caller's: a
    /// policy that arrives first is consulted first, which is what makes a
    /// narrow rule written above a broad one decide.
    ///
    /// A `Protect` policy must name an association that exists **now**: a
    /// policy installed ahead of its association would be a lookup that matched
    /// and then had nothing to apply, and the packet would be either dropped or
    /// sent unprotected depending on which way the code leaned.  Refusing the
    /// install is the one reading that cannot send plaintext.
    pub fn add_policy(&mut self, record: &abi::network::IpsecSpDef) -> Result<u32> {
        if self.policies.len() >= POLICY_LIMIT {
            return Err(Error::Busy);
        }
        if record.flags != 0 || record.reserved != 0 {
            return Err(Error::InvalidArgument);
        }
        let action = Action::from_wire(record.action)?;
        if record.src_prefix > 32 || record.dst_prefix > 32 {
            return Err(Error::InvalidArgument);
        }
        for port in [record.src_port, record.dst_port] {
            if port > u16::MAX as u32 {
                return Err(Error::InvalidArgument);
            }
        }
        let (outbound, inbound) = match record.direction {
            abi::network::IPSEC_DIR_OUTBOUND => (true, false),
            abi::network::IPSEC_DIR_INBOUND => (false, true),
            abi::network::IPSEC_DIR_BOTH => (true, true),
            _ => return Err(Error::InvalidArgument),
        };
        let association = if action == Action::Protect {
            if record.sa_id == 0 {
                return Err(Error::InvalidArgument);
            }
            if !self.associations.iter().any(|held| held.id == record.sa_id) {
                return Err(Error::NotFound);
            }
            Some(record.sa_id)
        } else {
            None
        };
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.policies.push(Policy {
            id,
            selector: Selector {
                protocol: record.protocol as u8,
                source: record.src_addr,
                source_length: record.src_prefix as u8,
                destination: record.dst_addr,
                destination_length: record.dst_prefix as u8,
                source_port: record.src_port as u16,
                destination_port: record.dst_port as u16,
            },
            action,
            association,
            outbound,
            inbound,
        });
        Ok(id)
    }

    /// Remove a policy, answering whether one was there.
    pub fn remove_policy(&mut self, id: u32) -> bool {
        let before = self.policies.len();
        self.policies.retain(|policy| policy.id != id);
        self.policies.len() != before
    }

    /// Install an association from the record a program passed, answering its
    /// id.
    ///
    /// An SPI another association already holds is `AlreadyExists`: the SPI is
    /// what names an association **on the wire**, so two associations with one
    /// SPI would make an arriving packet belong to both.
    pub fn add_association(&mut self, record: &abi::network::IpsecSaDef) -> Result<u32> {
        if self.associations.len() >= ASSOCIATION_LIMIT {
            return Err(Error::Busy);
        }
        if self.associations.iter().any(|held| held.spi == record.spi) {
            return Err(Error::AlreadyExists);
        }
        let mut association = Association::from_record(record)?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        association.id = id;
        self.associations.push(association);
        Ok(id)
    }

    /// Remove an association by SPI, answering whether one was there.
    ///
    /// The ABI's call names an SPI rather than an id, because the SPI is what a
    /// manager has: it is in every packet on the wire, and an id is this
    /// machine's private number.  A policy that named the association is
    /// **removed with it**, because a policy whose association is gone would
    /// match a packet and have nothing to apply.
    pub fn remove_association(&mut self, spi: u32) -> bool {
        let Some(index) = self.associations.iter().position(|held| held.spi == spi) else {
            return false;
        };
        let id = self.associations[index].id;
        self.associations.remove(index);
        self.policies
            .retain(|policy| policy.association != Some(id));
        true
    }

    /// One association, by id.
    pub fn association(&self, id: u32) -> Option<&Association> {
        self.associations.iter().find(|held| held.id == id)
    }

    /// One association mutably, by id.
    pub fn association_mut(&mut self, id: u32) -> Option<&mut Association> {
        self.associations.iter_mut().find(|held| held.id == id)
    }

    /// One association, by the SPI a packet carries.
    pub fn by_spi(&self, spi: u32) -> Option<&Association> {
        self.associations.iter().find(|held| held.spi == spi)
    }

    /// One association mutably, by the SPI a packet carries.
    pub fn by_spi_mut(&mut self, spi: u32) -> Option<&mut Association> {
        self.associations.iter_mut().find(|held| held.spi == spi)
    }

    /// The policy a packet matches, walking the list in the order it was
    /// installed.
    fn matching(
        &self,
        outbound: bool,
        source: [u8; 4],
        destination: [u8; 4],
        protocol: u8,
        ports: Option<(u16, u16)>,
    ) -> Option<&Policy> {
        self.policies.iter().find(|policy| {
            let direction = if outbound {
                policy.outbound
            } else {
                policy.inbound
            };
            direction
                && policy
                    .selector
                    .matches(source, destination, protocol, ports)
        })
    }

    /// What a **leaving** packet should get.
    ///
    /// No match is [`Outcome::Bypass`], which is the state the previous tree's
    /// default action named and this one states outright: a machine with no
    /// policy sends plaintext, because a default of discard would make the
    /// stack stop working the moment this module arrived, and a default of
    /// protect has nothing to protect with.
    pub fn outbound(
        &self,
        source: [u8; 4],
        destination: [u8; 4],
        protocol: u8,
        ports: Option<(u16, u16)>,
    ) -> Outcome {
        match self.matching(true, source, destination, protocol, ports) {
            Some(policy) => match policy.action {
                Action::Bypass => Outcome::Bypass,
                Action::Discard => Outcome::Discard,
                Action::Protect => policy
                    .association
                    .map_or(Outcome::Discard, Outcome::Protect),
            },
            None => Outcome::Bypass,
        }
    }

    /// What an **arriving** packet should get.
    ///
    /// The answer for ESP is to protect with the association the packet's own
    /// SPI names, which is not the same reading as the outbound side: an
    /// inbound packet carries its SPI, and a policy that named a different one
    /// would be a policy about a packet this machine never sent.  So the SPI is
    /// what decides, and the policy list is consulted only to say whether the
    /// packet is meant to be protected at all.
    pub fn inbound(
        &self,
        source: [u8; 4],
        destination: [u8; 4],
        protocol: u8,
        ports: Option<(u16, u16)>,
    ) -> Outcome {
        match self.matching(false, source, destination, protocol, ports) {
            Some(policy) => match policy.action {
                Action::Bypass => Outcome::Bypass,
                Action::Discard => Outcome::Discard,
                Action::Protect => policy
                    .association
                    .map_or(Outcome::Discard, Outcome::Protect),
            },
            None => Outcome::Bypass,
        }
    }

    /// Count one sealed packet.
    pub fn note_sealed(&mut self) {
        self.sealed = self.sealed.saturating_add(1);
    }

    /// Count one opened packet.
    pub fn note_opened(&mut self) {
        self.opened = self.opened.saturating_add(1);
    }

    /// Count one payload whose tag failed.
    pub fn note_integrity_failure(&mut self) {
        self.integrity_failures = self.integrity_failures.saturating_add(1);
    }

    /// Count one sequence the window refused.
    pub fn note_replay_drop(&mut self) {
        self.replay_drops = self.replay_drops.saturating_add(1);
    }

    /// How many policies and associations are held.
    pub fn counts(&self) -> (usize, usize) {
        (self.policies.len(), self.associations.len())
    }

    /// The four counters, in the order the ABI's statistics record carries
    /// them: sealed, opened, integrity failures, replay drops.
    pub fn statistics(&self) -> (u64, u64, u64, u64) {
        (
            self.sealed,
            self.opened,
            self.integrity_failures,
            self.replay_drops,
        )
    }

    /// The policies, in the order they decide.
    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }
}

#[cfg(test)]
mod tests {
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

    fn sp_record(
        action: u32,
        direction: u32,
        sa_id: u32,
        protocol: u32,
    ) -> abi::network::IpsecSpDef {
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
}
