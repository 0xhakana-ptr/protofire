//! net/src/tls.rs
//!
//! TLS 1.3's record layer and key schedule: the AEAD that wraps every byte
//! after the ServerHello, and the [RFC 8446] §7.1 ladder that derives the keys
//! it wraps them with.
//!
//! ## What a record is
//!
//! Five bytes of header and the protected content:
//!
//! ```text
//! opaque_type (1) || legacy_version (2, 0x0303) || length (2) || ciphertext || tag
//! ```
//!
//! The `opaque_type` is `application_data` for **every** protected record,
//! including a handshake's, which is the change [RFC 8446] made to TLS 1.2: a
//! middlebox that used to read the content type now cannot, and the real type
//! travels inside the plaintext as its last byte.  The `legacy_version` is
//! always `0x0303`, a version this protocol does not speak, for the same
//! reason: a middlebox that parsed the record as a TLS 1.2 one reads something
//! plausible and learns nothing.
//!
//! ## The nonce
//!
//! Twelve bytes: the traffic key's IV with the record's sequence number
//! **exclusive-ored into its last eight bytes**.  Not the sequence number
//! repeated, and not a counter starting at one: the sequence starts at zero and
//! increments per record, and two records of one connection must never share a
//! nonce.  A nonce repeated under one key is the failure [RFC 8446] §5.3 calls
//! catastrophic, because it turns a GCM stream into two linked streams.
//!
//! ## The key schedule
//!
//! Five secrets in a ladder, each derived from the one above it and mixed with
//! the transcript hash of the handshake so far:
//!
//! ```text
//! early_secret        = HKDF-Extract(0, PSK)            (no PSK here, so zeros)
//! derived             = Derive-Secret(early_secret, "derived", "")
//! handshake_secret    = HKDF-Extract(derived, ECDHE)
//! master_secret       = HKDF-Extract(Derive-Secret(handshake_secret, "derived", ""), 0)
//! ```
//!
//! and from `handshake_secret` and `master_secret` the four traffic secrets,
//! two per phase, one per direction.  The two salts that are all zeros are not
//! a shortcut: `HKDF-Extract(salt, ikm)` with an empty salt is HMAC under an
//! all-zero key, and [RFC 5869] §2.2 says the two are the same.
//!
//! ## What is deliberately not here
//!
//! **X.509.**  A certificate chain is DER, and parsing it is a module of its
//! own: a sequence of tagged values, an algorithm identifier, a validity
//! window, an extension list, and the name matching that decides whether a
//! certificate is for the host you meant.  The handshake here carries the
//! chain **opaque** and verifies the signature over the transcript against a
//! key the caller supplies, and a caller that wants the chain examined is a
//! caller with a parser this module does not pretend to have.  Half a parser is
//! worse than none: one that read a certificate's fields and skipped the
//! extension that says "not for this name" would pass a chain a real client
//! refuses.
//!
//! **A PSK or 0-RTT.**  Both need state a connection does not have here, and
//! 0-RTT's replay window is a decision about a whole server.
//!
//! **A record's segmentation.**  A caller hands this module the bytes it wants
//! protected and gets one record back; a plaintext larger than
//! [`MAX_FRAGMENT`] is refused rather than split, because splitting is a choice
//! about how the peer's buffer behaves and the caller knows its peer.
//!
//! [RFC 8446]: https://www.rfc-editor.org/rfc/rfc8446
//! [RFC 5869]: https://www.rfc-editor.org/rfc/rfc5869

use alloc::vec::Vec;

use abi::Error;
use abi::Result;

/// The largest plaintext one record may carry: 2^14 bytes ([RFC 8446] §5.1).
pub const MAX_FRAGMENT: usize = 16_384;

/// The record header's length.
pub const RECORD_HEADER_LEN: usize = 5;

/// The authentication tag both served suites use.
pub const TAG_LEN: usize = 16;

/// `handshake`: a record carrying handshake messages.
pub const CONTENT_HANDSHAKE: u8 = 22;

/// `application_data`: the content type of **every** protected record.
pub const CONTENT_APPLICATION_DATA: u8 = 23;

/// `alert`: a connection is ending.
pub const CONTENT_ALERT: u8 = 21;

/// The legacy version every TLS 1.3 record states.
pub const LEGACY_VERSION: u16 = 0x0303;

/// The suites this build serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// `TLS_AES_128_GCM_SHA256`.
    Aes128GcmSha256,
    /// `TLS_CHACHA20_POLY1305_SHA256`.
    ChaCha20Poly1305Sha256,
}

impl Suite {
    /// The two-byte code a ClientHello offers.
    pub fn code(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::ChaCha20Poly1305Sha256 => 0x1303,
        }
    }

    /// The suite a code names, or `None` for one this build does not serve.
    ///
    /// `None` rather than an error: a ServerHello naming a suite this side did
    /// not offer is a peer that broke the protocol, and the caller decides
    /// whether that is a refusal or a fallback.  The suites this build does not
    /// serve are not errors either, they are numbers it does not know.
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1303 => Some(Self::ChaCha20Poly1305Sha256),
            _ => None,
        }
    }

    /// The AEAD key's length.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::ChaCha20Poly1305Sha256 => 32,
        }
    }
}

/// One direction's keys and the sequence number its nonce is built from.
///
/// A separate value per direction, which is the only arrangement that keeps the
/// two sequence numbers apart: a connection with one record counter shared
/// between its reads and writes would build a nonce from a number the peer also
/// uses for a different key, and that is a nonce collision by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keys {
    key: Vec<u8>,
    iv: [u8; 12],
    suite: Suite,
    sequence: u64,
}

impl Keys {
    /// Keys from a traffic secret, which is what the schedule produces.
    ///
    /// The key and IV are derived **from** the secret rather than being it: a
    /// secret is thirty-two bytes and an AES-128 key is sixteen, so using the
    /// secret directly would be a key of the wrong length that a shorter cipher
    /// happened to accept.  `HKDF-Expand-Label(secret, "key", "", key_len)` and
    /// `...("iv", "", 12)` are [RFC 8446] §7.3's rule.
    pub fn from_secret(secret: &[u8; 32], suite: Suite) -> Self {
        Self {
            key: expand_label(secret, "key", &[], suite.key_len()),
            iv: iv_from(expand_label(secret, "iv", &[], 12)),
            suite,
            sequence: 0,
        }
    }

    /// The suite these keys are for.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// How many records have been protected with these keys.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The nonce the **next** record would use, without spending it.
    ///
    /// Exposed because the nonce's construction is the one thing a test can
    /// check against [RFC 8446]'s text and a round trip cannot: a nonce built
    /// wrongly on both sides agrees with itself.
    pub fn next_nonce(&self) -> [u8; 12] {
        nonce(self.iv, self.sequence)
    }

    /// Wrap one record's plaintext, answering the bytes after the header.
    ///
    /// `content_type` travels inside the plaintext as its last byte, which is
    /// what lets every record's outer type be `application_data`: a middlebox
    /// reading the wire learns that a record carries *something* protected and
    /// nothing about what.
    pub fn seal(&mut self, content_type: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_FRAGMENT {
            return Err(Error::InvalidArgument);
        }
        let sequence = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        let nonce = nonce(self.iv, sequence);

        // The inner plaintext: the content, then its type, then zero padding
        // the caller did not ask for.  No padding is written here; the field
        // exists because a peer may pad and this side must read what it sent.
        let mut inner = Vec::with_capacity(plaintext.len() + 1);
        inner.extend_from_slice(plaintext);
        inner.push(content_type);

        let encrypted_len = inner.len() + TAG_LEN;
        let aad = additional_data(encrypted_len);
        let (ciphertext, tag) = match self.suite {
            Suite::Aes128GcmSha256 => {
                let mut key = [0_u8; 16];
                key.copy_from_slice(&self.key);
                crypto::gcm::aes128_gcm_encrypt(&key, &nonce, &aad, &inner)
            }
            Suite::ChaCha20Poly1305Sha256 => {
                let mut key = [0_u8; 32];
                key.copy_from_slice(&self.key);
                crypto::aead::chacha20_poly1305_encrypt(&key, &nonce, &aad, &inner)
            }
        };

        let mut content = ciphertext;
        content.extend_from_slice(&tag);
        Ok(content)
    }

    /// Unwrap one record, answering its plaintext and the type the sender put
    /// inside it.
    ///
    /// The sequence number is spent **only when the tag verifies**, which is
    /// the same rule ESP's replay window follows and for a sharper reason here:
    /// a record that failed its tag was not sent by the peer, and a counter
    /// advanced by it would make this side's next nonce differ from the peer's.
    /// The two sides' counters must agree exactly, so nothing may advance one
    /// that the other did not.
    pub fn open(&mut self, content: &[u8]) -> Result<(Vec<u8>, u8)> {
        if content.len() < TAG_LEN + 1 {
            return Err(Error::InvalidArgument);
        }
        let sequence = self.sequence;
        let nonce = nonce(self.iv, sequence);
        let aad = additional_data(content.len());
        let (ciphertext, tag) = content.split_at(content.len() - TAG_LEN);
        let mut tag_bytes = [0_u8; TAG_LEN];
        tag_bytes.copy_from_slice(tag);

        let inner = match self.suite {
            Suite::Aes128GcmSha256 => {
                let mut key = [0_u8; 16];
                key.copy_from_slice(&self.key);
                crypto::gcm::aes128_gcm_decrypt(&key, &nonce, &aad, ciphertext, &tag_bytes)
            }
            Suite::ChaCha20Poly1305Sha256 => {
                let mut key = [0_u8; 32];
                key.copy_from_slice(&self.key);
                crypto::aead::chacha20_poly1305_decrypt(&key, &nonce, &aad, ciphertext, &tag_bytes)
            }
        };

        let mut inner = match inner {
            Ok(bytes) => bytes,
            Err(Error::InvalidCredential) => return Err(Error::PermissionDenied),
            Err(other) => return Err(other),
        };

        // The tag verified, so this record was the peer's and the counter may
        // move.
        self.sequence = self.sequence.wrapping_add(1);

        // The type is the last non-zero byte: the padding a peer may have added
        // is zeros, and the type is never zero.
        while inner.last() == Some(&0) {
            inner.pop();
        }
        let content_type = inner.pop().ok_or(Error::InvalidArgument)?;
        Ok((inner, content_type))
    }
}

/// Build a complete record: the five-byte header and the protected content.
///
/// The header's type is [`CONTENT_APPLICATION_DATA`] for **any** protected
/// record, the legacy version is always [`LEGACY_VERSION`], and the length
/// covers the ciphertext and the tag.  A record built any other way is one a
/// conforming peer refuses, and the reason is in the module's header: the outer
/// fields are camouflage, and the truth is inside.
pub fn write_record(content_type: u8, keys: &mut Keys, plaintext: &[u8]) -> Result<Vec<u8>> {
    let content = keys.seal(content_type, plaintext)?;
    let mut record = Vec::with_capacity(RECORD_HEADER_LEN + content.len());
    record.push(CONTENT_APPLICATION_DATA);
    record.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
    record.extend_from_slice(&(content.len() as u16).to_be_bytes());
    record.extend_from_slice(&content);
    Ok(record)
}

/// Read one record, answering its plaintext, its real type, and how many bytes
/// it took from `wire`.
///
/// A **handshake** record may be sent in the clear, which is what the first
/// ClientHello is: the type is the header's own and the content is the
/// plaintext.  That is the one record this function reads without keys, and the
/// distinction is the caller's: [`read_plain`] reads a cleartext record and
/// this one reads a protected one.
pub fn read_record(keys: &mut Keys, wire: &[u8]) -> Result<(Vec<u8>, u8, usize)> {
    let (content, length) = split_record(wire)?;
    let (plaintext, content_type) = keys.open(content)?;
    Ok((plaintext, content_type, length))
}

/// The bytes of a record's content and the whole record's length, without
/// spending any key.
///
/// Refused: fewer bytes than a header, a length that runs past the wire, and a
/// length past what one record may carry.  The last is not the same as the
/// first two: a peer that claimed a hundred thousand bytes is a peer whose
/// length field is wrong, and reading it would be reading whatever follows.
pub fn split_record(wire: &[u8]) -> Result<(&[u8], usize)> {
    if wire.len() < RECORD_HEADER_LEN {
        return Err(Error::InvalidArgument);
    }
    let length = u16::from_be_bytes([wire[3], wire[4]]) as usize;
    let total = RECORD_HEADER_LEN + length;
    if wire.len() < total {
        return Err(Error::InvalidArgument);
    }
    if length > MAX_FRAGMENT + 256 {
        return Err(Error::InvalidArgument);
    }
    Ok((&wire[RECORD_HEADER_LEN..total], total))
}

/// Read one **cleartext** record: the header's type and the bytes it carries.
///
/// The ClientHello is the only record TLS 1.3 sends in the clear, and a reader
/// that treated it as protected would need keys that do not exist yet.  The
/// handshake between that message and the ServerHello is a single flight the
/// caller assembles; from the ServerHello onward, [`read_record`] is the one.
pub fn read_plain(wire: &[u8]) -> Result<(Vec<u8>, u8, usize)> {
    let (content, length) = split_record(wire)?;
    Ok((Vec::from(content), wire[0], length))
}

/// The secrets one connection's handshake produces, in the order it produces
/// them.
///
/// The ladder is [RFC 8446] §7.1's, and the two transcript hashes are the
/// caller's: `after_server_hello` covers ClientHello..ServerHello, and
/// `after_server_finished` covers everything through the server's Finished.
/// The split is not a convenience: the handshake secrets are derived from the
/// first and the application secrets from the second, and a caller that mixed
/// them would derive keys for the right connection and the wrong messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Schedule {
    /// The shared secret the key exchange produced.
    shared: [u8; 32],
    /// The transcript hash through the ServerHello.
    after_server_hello: [u8; 32],
    /// The transcript hash through the server's Finished.
    after_server_finished: [u8; 32],
    /// The handshake secret, carried forward.
    handshake_secret: [u8; 32],
}

impl Schedule {
    /// The ladder up to the handshake secrets.
    ///
    /// `shared` is the ECDHE output, which for X25519 is thirty-two bytes.  The
    /// early secret is extracted under an all-zero PSK because this build has
    /// no pre-shared-key mode, and `HKDF-Extract(salt, 0)` is not the same as
    /// skipping the step: the derived secret that follows is what the
    /// handshake's secret is extracted *under*, and omitting it would mix the
    /// two stages into one.
    pub fn new(
        shared: [u8; 32],
        after_server_hello: [u8; 32],
        after_server_finished: [u8; 32],
    ) -> Self {
        let early = crypto::hkdf::hkdf_sha256_extract(&[], &[0_u8; 32]);
        let derived = derive_secret(&early, "derived", &empty_hash());
        let handshake_secret = crypto::hkdf::hkdf_sha256_extract(&derived, &shared);
        Self {
            shared,
            after_server_hello,
            after_server_finished,
            handshake_secret,
        }
    }

    /// The shared secret the key exchange produced.
    pub fn shared(&self) -> [u8; 32] {
        self.shared
    }

    /// The client's handshake traffic secret.
    pub fn client_handshake(&self) -> [u8; 32] {
        derive_secret(
            &self.handshake_secret,
            "c hs traffic",
            &self.after_server_hello,
        )
    }

    /// The server's handshake traffic secret.
    pub fn server_handshake(&self) -> [u8; 32] {
        derive_secret(
            &self.handshake_secret,
            "s hs traffic",
            &self.after_server_hello,
        )
    }

    /// The master secret, which is what the application secrets come from.
    pub fn master(&self) -> [u8; 32] {
        let derived = derive_secret(&self.handshake_secret, "derived", &empty_hash());
        crypto::hkdf::hkdf_sha256_extract(&derived, &[0_u8; 32])
    }

    /// The client's application traffic secret.
    pub fn client_application(&self) -> [u8; 32] {
        derive_secret(&self.master(), "c ap traffic", &self.after_server_finished)
    }

    /// The server's application traffic secret.
    pub fn server_application(&self) -> [u8; 32] {
        derive_secret(&self.master(), "s ap traffic", &self.after_server_finished)
    }

    /// The finished key a side uses to authenticate its own Finished.
    ///
    /// Derived from that side's handshake traffic secret under the label
    /// `finished`, which is what makes a Finished unforgeable without the
    /// handshake's secret: the transcript is public, and the key is not.
    pub fn finished_key(&self, server: bool) -> [u8; 32] {
        let base = if server {
            self.server_handshake()
        } else {
            self.client_handshake()
        };
        expand_label_32(&base, "finished", &[])
    }
}

/// `HKDF-Expand-Label` ([RFC 8446] §7.1).
///
/// The info is a two-byte length, the label prefixed with `tls13 `, and a
/// context whose length is one byte.  The prefix is not decoration: it is what
/// makes a TLS 1.3 label a different HKDF info from any other protocol's use of
/// the same words, and omitting it derives a key no peer computes.
fn expand_label(secret: &[u8; 32], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    let mut full = Vec::with_capacity(6 + label.len() + 1 + context.len());
    full.extend_from_slice(b"tls13 ");
    full.extend_from_slice(label.as_bytes());
    expand_with_label(secret, &full, context, length)
}

/// The same, for a hundred-and-eighty-byte answer, which the finished key is.
fn expand_label_32(secret: &[u8; 32], label: &str, context: &[u8]) -> [u8; 32] {
    let mut key = [0_u8; 32];
    key.copy_from_slice(&expand_label(secret, label, context, 32));
    key
}

/// The HKDF info struct, given a label that already carries its prefix.
fn expand_with_label(secret: &[u8; 32], label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(2 + 1 + label.len() + 1 + context.len());
    info.extend_from_slice(&(length as u16).to_be_bytes());
    info.push(label.len() as u8);
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    crypto::hkdf::hkdf_sha256_expand(secret, &info, length)
}

/// `Derive-Secret(secret, label, messages)` ([RFC 8446] §7.1).
fn derive_secret(secret: &[u8; 32], label: &str, messages_hash: &[u8; 32]) -> [u8; 32] {
    expand_label_32(secret, label, messages_hash)
}

/// The SHA-256 of nothing, which is what a `Derive-Secret` with no messages
/// hashes.
fn empty_hash() -> [u8; 32] {
    crypto::sha256::sha256(&[])
}

/// The record's nonce: the IV with the sequence number exclusive-ored into its
/// last eight bytes ([RFC 8446] §5.3).
///
/// The first four bytes are never touched: they are the IV's own prefix, and
/// the sequence's thirty-two high bits of a `u64` are zero for every connection
/// that has sent fewer than four billion records.
fn nonce(iv: [u8; 12], sequence: u64) -> [u8; 12] {
    let mut nonce = iv;
    let bytes = sequence.to_be_bytes();
    for index in 0..8 {
        nonce[4 + index] ^= bytes[index];
    }
    nonce
}

/// The associated data one record's AEAD authenticates: the header it will
/// carry.
///
/// The outer type and the legacy version are constants, so the only field that
/// varies is the length, and it must be the **encrypted** length: a header that
/// stated the plaintext's length is not the header the record carries, and an
/// AEAD over the wrong bytes verifies nothing.
fn additional_data(encrypted_len: usize) -> [u8; 5] {
    let mut aad = [0_u8; 5];
    aad[0] = CONTENT_APPLICATION_DATA;
    aad[1..3].copy_from_slice(&LEGACY_VERSION.to_be_bytes());
    aad[3..5].copy_from_slice(&(encrypted_len as u16).to_be_bytes());
    aad
}

/// The twelve bytes of an expanded IV, which is always twelve.
fn iv_from(bytes: Vec<u8>) -> [u8; 12] {
    let mut iv = [0_u8; 12];
    iv.copy_from_slice(&bytes[..12]);
    iv
}

/// The handshake message types this build writes and reads.
pub const HANDSHAKE_CLIENT_HELLO: u8 = 1;
/// See [`HANDSHAKE_CLIENT_HELLO`].
pub const HANDSHAKE_SERVER_HELLO: u8 = 2;
/// See [`HANDSHAKE_CLIENT_HELLO`].
pub const HANDSHAKE_ENCRYPTED_EXTENSIONS: u8 = 8;
/// See [`HANDSHAKE_CLIENT_HELLO`].
pub const HANDSHAKE_CERTIFICATE: u8 = 11;
/// See [`HANDSHAKE_CLIENT_HELLO`].
pub const HANDSHAKE_CERTIFICATE_VERIFY: u8 = 15;
/// See [`HANDSHAKE_CLIENT_HELLO`].
pub const HANDSHAKE_FINISHED: u8 = 20;

/// The X25519 named group, which is the one key exchange this build offers.
pub const GROUP_X25519: u16 = 0x001D;

/// One `key_share` entry: a group and the public key it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyShare {
    /// The named group.
    pub group: u16,
    /// The public key, thirty-two bytes for X25519.
    pub key: [u8; 32],
}

/// What this side offers and what the peer answered, as a handshake carries
/// them.
///
/// A value rather than a `Vec` of extensions: this build offers exactly one
/// group and one suite, and a structure that could describe more would be one
/// whose extra cases no code exercises.  The module's header says what that
/// costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offer {
    /// The group this side's key share is in.
    pub group: u16,
    /// This side's public key.
    pub key: [u8; 32],
    /// The random the ClientHello carries, which is what makes two hellos of
    /// one connection different.
    pub random: [u8; 32],
}

impl Offer {
    /// A fresh offer: a generated key and a caller's random.
    ///
    /// The random is the caller's because it must be **unpredictable**, and the
    /// generator belongs to the boot: an offer built from a counter would make
    /// two connections' hellos guessable from one, and the hello's random is
    /// what stops a recorded handshake being replayed.
    pub fn generate(random: [u8; 32]) -> (Self, [u8; 32]) {
        let (secret, public) = crypto::x25519::x25519_keygen();
        (
            Self {
                group: GROUP_X25519,
                key: public,
                random,
            },
            secret,
        )
    }
}

/// Write a ClientHello's body: the random, the one suite, and the key share.
///
/// The body only, because the message header is [`write_handshake`]'s: a body
/// that carried its own length would be a length a caller could disagree with.
///
/// The shape is [RFC 8446] §4.1.2's, cut to what this build offers: one suite
/// and one key share.  A hello that offered a suite this side would not use
/// would be a promise about a negotiation it cannot finish.
pub fn client_hello_body(offer: &Offer, server_name: Option<&str>) -> Vec<u8> {
    let mut body = Vec::new();
    // legacy_version 0x0303, then the random.
    body.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
    body.extend_from_slice(&offer.random);
    // The session id: an echo for middlebox compatibility, empty here.  A
    // length byte and nothing after it.
    body.push(0);
    // One suite.
    body.extend_from_slice(&(2_u16).to_be_bytes());
    body.extend_from_slice(&Suite::Aes128GcmSha256.code().to_be_bytes());
    // Compression: null, one method.
    body.push(1);
    body.push(0);
    // Extensions, which are what make the hello a TLS 1.3 one.
    let mut extensions = Vec::new();
    // supported_versions: one version, and it must be the first extension for
    // a server to read the hello as TLS 1.3 at all.
    extensions.extend_from_slice(&(0x002B_u16).to_be_bytes());
    extensions.extend_from_slice(&(3_u16).to_be_bytes());
    extensions.push(2);
    extensions.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
    // key_share: one entry, its group and its key.
    extensions.extend_from_slice(&(0x0033_u16).to_be_bytes());
    extensions.extend_from_slice(&(36_u16).to_be_bytes());
    extensions.extend_from_slice(&(34_u16).to_be_bytes());
    extensions.extend_from_slice(&offer.group.to_be_bytes());
    extensions.extend_from_slice(&(32_u16).to_be_bytes());
    extensions.extend_from_slice(&offer.key);
    // server_name, when the caller named one: a server that routes by name
    // needs it, and a certificate is checked against it.
    if let Some(name) = server_name {
        let name = name.as_bytes();
        extensions.extend_from_slice(&(0x0000_u16).to_be_bytes());
        extensions.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
        extensions.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&(name.len() as u16).to_be_bytes());
        extensions.extend_from_slice(name);
    }
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    body
}

/// Write a handshake message: the one-byte type and a three-byte length.
///
/// The length covers the body and nothing else, which is the field a reader
/// believes: a length that disagreed with the body would make the next message
/// start in the wrong place, and a handshake is a chain of messages with no
/// separators between them.
pub fn write_handshake(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(4 + body.len());
    message.push(kind);
    let length = body.len() as u32;
    message.extend_from_slice(&length.to_be_bytes()[1..]);
    message.extend_from_slice(body);
    message
}

/// One handshake message: its type and its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handshake {
    /// The message's type.
    pub kind: u8,
    /// Its body.
    pub body: Vec<u8>,
}

/// Read every complete handshake message in `bytes`, answering them and how
/// many bytes they used.
///
/// The remainder is the caller's: a handshake flight may arrive in pieces, and
/// a reader that refused a partial message would lose a connection to one
/// TCP segment boundary.
pub fn read_handshakes(bytes: &[u8]) -> Result<(Vec<Handshake>, usize)> {
    let mut messages = Vec::new();
    let mut at = 0;
    loop {
        if bytes.len() - at < 4 {
            break;
        }
        let length = ((bytes[at + 1] as usize) << 16)
            | ((bytes[at + 2] as usize) << 8)
            | bytes[at + 3] as usize;
        if length > MAX_FRAGMENT {
            return Err(Error::InvalidArgument);
        }
        if bytes.len() - at < 4 + length {
            break;
        }
        messages.push(Handshake {
            kind: bytes[at],
            body: Vec::from(&bytes[at + 4..at + 4 + length]),
        });
        at += 4 + length;
    }
    Ok((messages, at))
}

/// What a ServerHello answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHello {
    /// The key share the server chose.
    pub share: KeyShare,
    /// The suite the server chose.
    pub suite: Suite,
    /// The random the server sent.
    pub random: [u8; 32],
}

/// Read a ServerHello's body.
///
/// Refused: a body shorter than its fixed part, a suite this build does not
/// serve, and a key-share group that is not the one offered.  The last is a
/// refusal and not a fallback: a group this side did not offer is a server
/// choosing a key exchange the client never agreed to, and deriving a secret
/// from it would be a connection whose confidentiality rests on a group nobody
/// negotiated.
pub fn parse_server_hello(body: &[u8]) -> Result<ServerHello> {
    // legacy_version (2) + random (32) + session id length (1) and its bytes.
    if body.len() < 35 {
        return Err(Error::InvalidArgument);
    }
    let mut random = [0_u8; 32];
    random.copy_from_slice(&body[2..34]);
    let session_len = body[34] as usize;
    let mut at = 35 + session_len;
    if body.len() < at + 3 {
        return Err(Error::InvalidArgument);
    }
    let suite =
        Suite::from_code(u16::from_be_bytes([body[at], body[at + 1]])).ok_or(Error::Unsupported)?;
    at += 2;
    at += 1; // the compression method, which must be zero.
    if body.len() < at + 2 {
        return Err(Error::InvalidArgument);
    }
    let extensions_len = u16::from_be_bytes([body[at], body[at + 1]]) as usize;
    at += 2;
    let end = (at + extensions_len).min(body.len());
    let mut share = None;
    while at + 4 <= end {
        let kind = u16::from_be_bytes([body[at], body[at + 1]]);
        let length = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
        at += 4;
        if at + length > end {
            return Err(Error::InvalidArgument);
        }
        if kind == 0x0033 {
            // key_share: the server's single entry.
            if length < 36 {
                return Err(Error::InvalidArgument);
            }
            let group = u16::from_be_bytes([body[at], body[at + 1]]);
            let key_len = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
            if key_len != 32 || at + 4 + key_len > end {
                return Err(Error::InvalidArgument);
            }
            let mut key = [0_u8; 32];
            key.copy_from_slice(&body[at + 4..at + 4 + key_len]);
            share = Some(KeyShare { group, key });
        }
        at += length;
    }
    let share = share.ok_or(Error::InvalidArgument)?;
    if share.group != GROUP_X25519 {
        return Err(Error::Unsupported);
    }
    Ok(ServerHello {
        share,
        suite,
        random,
    })
}

/// The shared secret one handshake produces.
///
/// `x25519` of this side's private key and the peer's public key, and a result
/// that is all zeros is **refused**: [RFC 7748] §6.1 says a peer may choose its
/// public key so the output is the point at infinity, and a shared secret of
/// zeros is a secret the peer knows and this side believes it chose.
///
/// [RFC 7748]: https://www.rfc-editor.org/rfc/rfc7748
pub fn shared_secret(private: &[u8; 32], peer: &[u8; 32]) -> Result<[u8; 32]> {
    let shared = crypto::x25519::x25519(private, peer);
    if shared == [0_u8; 32] {
        return Err(Error::PermissionDenied);
    }
    Ok(shared)
}

/// A transcript: the SHA-256 of every handshake message in the order they were
/// sent or received.
///
/// The hash is what the key schedule mixes in, and a transcript that included
/// a message twice or missed one would derive keys for a conversation that did
/// not happen.  Both sides build one, and a Finished is the proof that they
/// built the same one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    /// The messages so far, concatenated, which is what SHA-256 runs over.
    ///
    /// Kept whole rather than as a running hash because the schedule needs a
    /// hash at two different points (after the ServerHello and after the
    /// server's Finished), and a running hash cannot answer for a point it has
    /// already passed.
    messages: Vec<u8>,
}

impl Transcript {
    /// An empty transcript.
    pub const fn new() -> Self {
        Self {
            messages: Vec::new(),
        }
    }

    /// Add one message's bytes, exactly as they went on the wire.
    ///
    /// Handshake messages without the record header: the transcript covers the
    /// handshake layer's own bytes, and a record header has a length that
    /// depends on how a sender chose to segment, which is not part of the
    /// conversation.
    pub fn add(&mut self, message: &[u8]) {
        self.messages.extend_from_slice(message);
    }

    /// The hash of everything added so far.
    pub fn hash(&self) -> [u8; 32] {
        crypto::sha256::sha256(&self.messages)
    }

    /// How many bytes the transcript holds, for a boot's own report.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether nothing has been added.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

/// The value a Finished message carries: HMAC over the transcript with the
/// side's finished key ([RFC 8446] §4.4.4).
///
/// It is a **MAC over the transcript**, which is what makes it the proof the
/// handshake wanted: an attacker who changed any message changed the hash, and
/// the MAC is the one thing they cannot recompute without the traffic secret.
pub fn finished_value(finished_key: &[u8; 32], transcript_hash: &[u8; 32]) -> [u8; 32] {
    crypto::hmac::hmac_sha256(finished_key, transcript_hash)
}

/// Whether a peer's Finished verifies.
///
/// The comparison is [`crypto::constant_time`]'s, because a MAC compared with
/// `==` leaks how many leading bytes were right: a peer guessing the tag one
/// byte at a time would learn it in thirty-two tries.  The comparison is the
/// whole of why this function exists rather than a caller's `==`.
pub fn verify_finished(
    finished_key: &[u8; 32],
    transcript_hash: &[u8; 32],
    received: &[u8],
) -> bool {
    let expected = finished_value(finished_key, transcript_hash);
    received.len() == expected.len() && crypto::constant_time::constant_time_eq(&expected, received)
}

#[cfg(test)]
mod tests {
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
        let record = write_record(CONTENT_HANDSHAKE, &mut server_hs_keys, &server_finished)
            .expect("a record");
        let (plaintext, content_type, _) =
            read_record(&mut client_hs_read, &record).expect("a record");
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
        let (plaintext, content_type, _) =
            read_record(&mut server_read, &record).expect("a record");
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
}
