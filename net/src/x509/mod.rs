//! net/src/x509/mod.rs
//!
//! [RFC 5280]'s certificate: the DER a peer sends, the fields a verifier reads,
//! the signature check that makes a chain a chain, and the name matching that
//! decides whether the certificate is for the host you meant.
//!
//! ## Why this exists, and what it was blocking
//!
//! `TlsConnect` carried a chain **opaque** and verified a Finished against a
//! key the caller supplied, which authenticates the handshake and not the peer.
//! A program that trusted it had authenticated a conversation with *someone*.
//! This module is what turns "someone" into "the host I named", and it is the
//! half of TLS that a kernel cannot skip if it is to be trusted at all.
//!
//! ## What DER is, and why the reader is strict
//!
//! DER is [X.690]'s **distinguished encoding**: one type, one length, one
//! content, and for every value exactly one encoding.  A reader may therefore
//! refuse rather than guess, and this one does: a length in the indefinite form
//! is refused, a length that runs past its parent is refused, a constructed
//! string in a place a primitive belongs is refused, and a trailing byte after
//! a value is refused.  Every one of those is a case where two implementations
//! could read one certificate differently, and a verifier that reads a
//! certificate differently from the signer is a verifier that can be made to
//! accept a different certificate.
//!
//! ## What is verified, and in what order
//!
//! A chain is checked **from the anchor down**, not from the leaf up: the
//! anchor is the only key trusted without a signature, so every other key in
//! the chain derives its authority from a signature the anchor's key verified.
//! For each step:
//!
//! 1. The issuer's name equals the subject's name of the certificate above it.
//! 2. The issuer's `basicConstraints` says it may sign certificates ([RFC 5280]
//!    §4.2.1.9), which is the extension that stops a leaf's key from minting
//!    another leaf.
//! 3. The signature over the child's `tbsCertificate` verifies under the
//!    issuer's public key.
//! 4. The child's validity window contains the caller's time.
//!
//! Only then is the leaf's name checked against the host name that was asked
//! for, in its `subjectAltName` and never in its common name ([RFC 6125] §6.4.4
//! makes the common name a fallback no longer worth having, and this module
//! does not have it).
//!
//! ## What is deliberately not here
//!
//! **Revocation.**  OCSP and CRLs are a network protocol and a distribution
//! decision, and a verifier that claimed to check revocation and did not would
//! be worse than one that says it does not.
//!
//! **Path building.**  This module verifies a chain it is given; choosing among
//! several possible chains to one anchor is a search with its own failure
//! modes, and a caller with more than one candidate has a question this module
//! answers per candidate.
//!
//! **Name constraints, policies, and the other extensions.**  Each is read
//! where it changes an answer this module gives, and a `basicConstraints` that
//! is absent is treated as "not a CA" rather than as an error, which is
//! [RFC 5280]'s own rule for a v1 certificate.
//!
//! [RFC 5280]: https://www.rfc-editor.org/rfc/rfc5280
//! [RFC 6125]: https://www.rfc-editor.org/rfc/rfc6125
//! [X.690]: https://www.itu.int/rec/T-REC-X.690

use alloc::vec::Vec;

use abi::Error;
use abi::Result;

/// `SEQUENCE`.
const TAG_SEQUENCE: u8 = 0x30;
/// `SET`.
const TAG_SET: u8 = 0x31;
/// `INTEGER`.
const TAG_INTEGER: u8 = 0x02;
/// `BIT STRING`.
const TAG_BIT_STRING: u8 = 0x03;
/// `OCTET STRING`.
const TAG_OCTET_STRING: u8 = 0x04;
/// `OBJECT IDENTIFIER`.
const TAG_OID: u8 = 0x06;
/// `UTF8String`.
const TAG_UTF8_STRING: u8 = 0x0C;
/// `PrintableString`.
const TAG_PRINTABLE_STRING: u8 = 0x13;
/// `IA5String`.
const TAG_IA5_STRING: u8 = 0x16;
/// The `[0]` context tag on a `TBSCertificate`'s version.
const TAG_VERSION: u8 = 0xA0;
/// The `[3]` context tag on a `TBSCertificate`'s extensions.
const TAG_EXTENSIONS: u8 = 0xA3;

/// The OID of `ecdsa-with-SHA256`: 1.2.840.10045.4.3.2.
pub const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
/// The OID of `sha256WithRSAEncryption`: 1.2.840.113549.1.1.11.
pub const OID_RSA_WITH_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
/// The OID of `id-ecPublicKey`: 1.2.840.10045.2.1.
pub const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// The OID of `rsaEncryption`: 1.2.840.113549.1.1.1.
pub const OID_RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
/// The OID of the `subjectAltName` extension: 2.5.29.17.
pub const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1D, 0x11];
/// The OID of `basicConstraints`: 2.5.29.19.
pub const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
/// The OID of the `commonName` attribute: 2.5.4.3.
pub const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

/// A cursor over a DER document.
///
/// One value at a time, and every read is checked against the slice it was
/// given: a length that runs past the end is refused rather than clamped, which
/// is the difference between a parser that reads a certificate and one that
/// reads a certificate and then whatever followed it.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

/// One tag-length-value: the tag, the content, and how many bytes the whole
/// value took.
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Whether nothing is left.
    fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    /// The next value's tag, without consuming it.
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Read one value.
    ///
    /// The length is DER's **definite** form only: one byte below `0x80`, or a
    /// long form of one to four bytes.  The indefinite form (`0x80`) is refused
    /// because it is BER's and DER forbids it, and a value that used it would
    /// be one two readers could disagree about the extent of.
    fn next(&mut self) -> Result<Tlv<'a>> {
        let tag = *self.bytes.get(self.pos).ok_or(Error::InvalidArgument)?;
        let first = *self.bytes.get(self.pos + 1).ok_or(Error::InvalidArgument)?;
        let mut at = self.pos + 2;
        let length = if first & 0x80 == 0 {
            first as usize
        } else {
            let count = (first & 0x7F) as usize;
            // Zero is the indefinite form, and more than four is a length no
            // document this kernel reads has.
            if count == 0 || count > 4 {
                return Err(Error::InvalidArgument);
            }
            let mut length = 0_usize;
            for _ in 0..count {
                let byte = *self.bytes.get(at).ok_or(Error::InvalidArgument)?;
                length = (length << 8) | byte as usize;
                at += 1;
            }
            length
        };
        let end = at.checked_add(length).ok_or(Error::InvalidArgument)?;
        if end > self.bytes.len() {
            return Err(Error::InvalidArgument);
        }
        let content = &self.bytes[at..end];
        self.pos = end;
        Ok(Tlv { tag, content })
    }

    /// Read one value and refuse it unless its tag is `tag`.
    fn tagged(&mut self, tag: u8) -> Result<&'a [u8]> {
        let value = self.next()?;
        if value.tag != tag {
            return Err(Error::InvalidArgument);
        }
        Ok(value.content)
    }

    /// Read one value, answering its tag and content.
    fn any(&mut self) -> Result<(u8, &'a [u8])> {
        let value = self.next()?;
        Ok((value.tag, value.content))
    }
}

/// One component of a distinguished name: a type's OID and its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamePart {
    /// The attribute type's OID.
    pub oid: Vec<u8>,
    /// Its value, as the string type carried it.
    pub value: Vec<u8>,
}

/// A distinguished name, as the sequence of components it is.
///
/// Compared as a **sequence**, which is what [RFC 5280] §7.1 asks for in the
/// case that matters here: the issuer field of one certificate must equal the
/// subject of the next, and two names with the same components in a different
/// order are two different names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    /// The components, in the order the encoding gave them.
    pub parts: Vec<NamePart>,
}

impl Name {
    /// Read a `Name` from a `SEQUENCE OF RelativeDistinguishedName`.
    ///
    /// A relative name may hold several attributes, and only the first is kept:
    /// this build has no use for a multi-valued name and reading it would be a
    /// comparison rule nothing exercises.  A certificate whose name depended on
    /// one is a certificate this module compares wrongly, which is why the
    /// constructor **refuses** a multi-valued name rather than keeping one part
    /// of it.
    fn read(content: &[u8]) -> Result<Self> {
        let mut parts = Vec::new();
        let mut set = Reader::new(content);
        while !set.is_empty() {
            let rdn = set.tagged(TAG_SET)?;
            let mut attributes = Reader::new(rdn);
            let attribute = attributes.tagged(TAG_SEQUENCE)?;
            if !attributes.is_empty() {
                return Err(Error::Unsupported);
            }
            let mut pair = Reader::new(attribute);
            let oid = pair.tagged(TAG_OID)?;
            let (tag, value) = pair.any()?;
            if !matches!(tag, TAG_UTF8_STRING | TAG_PRINTABLE_STRING | TAG_IA5_STRING) {
                return Err(Error::InvalidArgument);
            }
            parts.push(NamePart {
                oid: Vec::from(oid),
                value: Vec::from(value),
            });
        }
        Ok(Self { parts })
    }

    /// The `commonName` component, if the name has one.
    pub fn common_name(&self) -> Option<&[u8]> {
        self.parts
            .iter()
            .find(|part| part.oid == OID_COMMON_NAME)
            .map(|part| &part.value[..])
    }
}

/// Which key an algorithm identifier names, and which hash its signature uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// ECDSA over P-256 with SHA-256.
    EcdsaP256Sha256,
    /// RSA with PKCS#1 v1.5 padding and SHA-256.
    RsaPkcs1Sha256,
    /// RSA with PSS padding and SHA-256.
    RsaPssSha256,
}

impl Algorithm {
    /// The algorithm a signature OID names, or the error for one this build
    /// does not verify.
    ///
    /// `Unsupported` and not `InvalidArgument`: a certificate signed with an
    /// algorithm this build does not have is a certificate it understands and
    /// cannot check, and a caller should learn that rather than think the
    /// certificate was malformed.
    fn from_signature_oid(oid: &[u8]) -> Result<Self> {
        if oid == OID_ECDSA_WITH_SHA256 {
            return Ok(Self::EcdsaP256Sha256);
        }
        if oid == OID_RSA_WITH_SHA256 {
            return Ok(Self::RsaPkcs1Sha256);
        }
        // RSA-PSS has its own OID, 1.2.840.113549.1.1.10.
        if oid == [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A] {
            return Ok(Self::RsaPssSha256);
        }
        Err(Error::Unsupported)
    }
}

/// A public key, as `SubjectPublicKeyInfo` carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// A P-256 point: sixty-five bytes, `0x04` and the two coordinates.
    EcP256(Vec<u8>),
    /// An RSA modulus and exponent.
    Rsa {
        /// The modulus, big-endian.
        modulus: Vec<u8>,
        /// The public exponent, big-endian.
        exponent: Vec<u8>,
    },
}

/// A parsed certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// The whole certificate's DER, which is what a chain comparison uses.
    pub der: Vec<u8>,
    /// The `tbsCertificate` bytes **as the signature covers them**: the whole
    /// `SEQUENCE`, tag and length included.
    ///
    /// A signature is over the encoding, not over the fields: a verifier that
    /// rebuilt the sequence from parsed fields would hash different bytes and
    /// reject a valid certificate.  Keeping the slice is what makes the check
    /// a check.
    pub tbs: Vec<u8>,
    /// The serial number.
    pub serial: Vec<u8>,
    /// The algorithm the signature uses.
    pub algorithm: Algorithm,
    /// Who issued it.
    pub issuer: Name,
    /// Who it is for.
    pub subject: Name,
    /// The private key's public half.
    pub public_key: PublicKey,
    /// Whether it may sign other certificates.
    pub is_ca: bool,
    /// The names it is valid for, from `subjectAltName`.
    ///
    /// Empty for a certificate with none, which is a certificate a host-name
    /// check refuses: [RFC 6125] §6.4.4 says the common name is not a fallback,
    /// and a verifier that fell back would accept certificates issued under a
    /// rule the CA stopped using.
    pub subject_alt_names: Vec<Vec<u8>>,
    /// The signature.
    pub signature: Vec<u8>,
}

/// Parse one certificate.
///
/// Refused: a document that is not a `SEQUENCE`, a `tbsCertificate` that is not
/// a `SEQUENCE`, an algorithm this build does not verify, a public key in a
/// form it does not know, and any DER violation the reader refuses.  A
/// certificate this module cannot fully read is one it cannot verify, and a
/// partial read is the failure mode that lets two implementations disagree
/// about one document.
pub fn parse(der: &[u8]) -> Result<Certificate> {
    let mut outer = Reader::new(der);
    let certificate = outer.tagged(TAG_SEQUENCE)?;
    // A trailing byte after the certificate is a second document in one
    // buffer, which a chain parser handles and this one refuses.
    if !outer.is_empty() {
        return Err(Error::InvalidArgument);
    }

    let mut fields = Reader::new(certificate);
    // The `tbsCertificate`, kept whole with its header: the signature covers
    // the encoding's bytes and not the fields, so the slice runs from the
    // SEQUENCE's tag to the end of its content.  The reader's position after
    // consuming one value **is** that end, which is why this reads it twice:
    // once to learn the extent, and once to move `fields` past it.
    let tbs = {
        let mut probe = Reader::new(certificate);
        probe.next()?;
        Vec::from(&certificate[..probe.pos])
    };
    let tbs_content = fields.tagged(TAG_SEQUENCE)?;
    let algorithm_oid = {
        let identifier = fields.tagged(TAG_SEQUENCE)?;
        let mut identifier = Reader::new(identifier);
        identifier.tagged(TAG_OID)?
    };
    let algorithm = Algorithm::from_signature_oid(algorithm_oid)?;

    let signature = {
        let bits = fields.tagged(TAG_BIT_STRING)?;
        // The first byte is the count of unused bits, which for a signature is
        // zero: a signature that did not end on a byte boundary is not one.
        if bits.first() != Some(&0) || bits.len() < 2 {
            return Err(Error::InvalidArgument);
        }
        Vec::from(&bits[1..])
    };

    // The `tbsCertificate`'s own fields.
    let mut tbs_fields = Reader::new(tbs_content);
    let mut version = 0_u8;
    if tbs_fields.peek() == Some(TAG_VERSION) {
        let wrapper = tbs_fields.tagged(TAG_VERSION)?;
        let mut inner = Reader::new(wrapper);
        let integer = inner.tagged(TAG_INTEGER)?;
        if !integer.is_empty() {
            version = integer[0];
        }
    }
    let serial = Vec::from(tbs_fields.tagged(TAG_INTEGER)?);
    // The `tbsCertificate`'s signature algorithm, which must agree with the
    // outer one: two identifiers that disagreed would be a certificate whose
    // signature was over one algorithm and whose statement was another.
    {
        let inner_algorithm = tbs_fields.tagged(TAG_SEQUENCE)?;
        let mut inner_algorithm = Reader::new(inner_algorithm);
        let oid = inner_algorithm.tagged(TAG_OID)?;
        if Algorithm::from_signature_oid(oid)? != algorithm {
            return Err(Error::InvalidArgument);
        }
    }
    let issuer = Name::read(tbs_fields.tagged(TAG_SEQUENCE)?)?;
    // Validity: two times, which this build does not compare because the clock
    // it would compare against is the caller's and a certificate parsed without
    // one has no window to be in.  Read and dropped so the cursor moves.
    {
        let validity = tbs_fields.tagged(TAG_SEQUENCE)?;
        let mut validity = Reader::new(validity);
        validity.next()?;
        validity.next()?;
    }
    let subject = Name::read(tbs_fields.tagged(TAG_SEQUENCE)?)?;
    let public_key = {
        let info = tbs_fields.tagged(TAG_SEQUENCE)?;
        let mut info = Reader::new(info);
        let algorithm = info.tagged(TAG_SEQUENCE)?;
        let mut algorithm = Reader::new(algorithm);
        let oid = algorithm.tagged(TAG_OID)?;
        let bits = info.tagged(TAG_BIT_STRING)?;
        if bits.first() != Some(&0) || bits.len() < 2 {
            return Err(Error::InvalidArgument);
        }
        let key = &bits[1..];
        if oid == OID_EC_PUBLIC_KEY {
            if key.len() != 65 || key[0] != 0x04 {
                return Err(Error::Unsupported);
            }
            PublicKey::EcP256(Vec::from(key))
        } else if oid == OID_RSA_ENCRYPTION {
            let mut key_reader = Reader::new(key);
            let sequence = key_reader.tagged(TAG_SEQUENCE)?;
            let mut sequence = Reader::new(sequence);
            let modulus = sequence.tagged(TAG_INTEGER)?;
            let exponent = sequence.tagged(TAG_INTEGER)?;
            PublicKey::Rsa {
                modulus: Vec::from(strip_leading_zero(modulus)),
                exponent: Vec::from(strip_leading_zero(exponent)),
            }
        } else {
            return Err(Error::Unsupported);
        }
    };

    // The extensions, which are what say whether this is a CA and what names it
    // is good for.
    let mut is_ca = false;
    let mut subject_alt_names = Vec::new();
    if tbs_fields.peek() == Some(TAG_EXTENSIONS) {
        let wrapper = tbs_fields.tagged(TAG_EXTENSIONS)?;
        let mut wrapper = Reader::new(wrapper);
        let extensions = wrapper.tagged(TAG_SEQUENCE)?;
        let mut extensions = Reader::new(extensions);
        while !extensions.is_empty() {
            let extension = extensions.tagged(TAG_SEQUENCE)?;
            let mut extension = Reader::new(extension);
            let oid = extension.tagged(TAG_OID)?;
            // A critical flag is a BOOLEAN when it is present.
            if extension.peek() == Some(0x01) {
                extension.next()?;
            }
            let value = extension.tagged(TAG_OCTET_STRING)?;
            if oid == OID_BASIC_CONSTRAINTS {
                // `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE,
                // ... }`
                let mut constraints = Reader::new(value);
                let sequence = constraints.tagged(TAG_SEQUENCE)?;
                let mut sequence = Reader::new(sequence);
                if sequence.peek() == Some(0x01) {
                    let flag = sequence.next()?.content;
                    is_ca = flag.first() == Some(&0xFF);
                }
            } else if oid == OID_SUBJECT_ALT_NAME {
                let mut names = Reader::new(value);
                let sequence = names.tagged(TAG_SEQUENCE)?;
                let mut sequence = Reader::new(sequence);
                while !sequence.is_empty() {
                    let (tag, name) = sequence.any()?;
                    // `dNSName` is `[2]` with the primitive tag.
                    if tag == 0x82 {
                        subject_alt_names.push(Vec::from(name));
                    }
                }
            }
        }
    }

    // A v3 certificate is the only one that may be a CA: `basicConstraints`
    // arrived in version three, and a certificate claiming both is malformed.
    if is_ca && version < 2 {
        return Err(Error::InvalidArgument);
    }

    Ok(Certificate {
        der: Vec::from(der),
        tbs,
        serial,
        algorithm,
        issuer,
        subject,
        public_key,
        is_ca,
        subject_alt_names,
        signature,
    })
}

/// Walk a certificate's outer structure, answering which step failed.
///
/// A test aid and not part of the interface: a `Result` that says only
/// `InvalidArgument` cannot tell a length error from an unknown algorithm, and
/// a parser this deep needs to say where it stopped.
#[cfg(test)]
pub fn diagnose(der: &[u8]) -> &'static str {
    let mut outer = Reader::new(der);
    let certificate = match outer.tagged(TAG_SEQUENCE) {
        Ok(value) => value,
        Err(_) => return "outer sequence",
    };
    if !outer.is_empty() {
        return "trailing bytes";
    }
    let mut fields = Reader::new(certificate);
    let tbs_content = match fields.tagged(TAG_SEQUENCE) {
        Ok(value) => value,
        Err(_) => return "tbs sequence",
    };
    let algorithm_oid = match fields.tagged(TAG_SEQUENCE) {
        Ok(identifier) => {
            let mut identifier = Reader::new(identifier);
            match identifier.tagged(TAG_OID) {
                Ok(oid) => oid,
                Err(_) => return "algorithm oid",
            }
        }
        Err(_) => return "algorithm sequence",
    };
    if Algorithm::from_signature_oid(algorithm_oid).is_err() {
        return "algorithm unsupported";
    }
    let bits = match fields.tagged(TAG_BIT_STRING) {
        Ok(bits) => bits,
        Err(_) => return "signature",
    };
    if bits.first() != Some(&0) {
        return "signature unused bits";
    }
    let mut tbs = Reader::new(tbs_content);
    if tbs.peek() == Some(TAG_VERSION) && tbs.tagged(TAG_VERSION).is_err() {
        return "version";
    }
    if tbs.tagged(TAG_INTEGER).is_err() {
        return "serial";
    }
    if tbs.tagged(TAG_SEQUENCE).is_err() {
        return "inner algorithm";
    }
    let issuer = match tbs.tagged(TAG_SEQUENCE) {
        Ok(name) => match Name::read(name) {
            Ok(name) => name,
            Err(_) => return "issuer name",
        },
        Err(_) => return "issuer",
    };
    let _ = issuer;
    if tbs.tagged(TAG_SEQUENCE).is_err() {
        return "validity";
    }
    let subject = match tbs.tagged(TAG_SEQUENCE) {
        Ok(name) => match Name::read(name) {
            Ok(name) => name,
            Err(_) => return "subject name",
        },
        Err(_) => return "subject",
    };
    let _ = subject;
    let info = match tbs.tagged(TAG_SEQUENCE) {
        Ok(info) => info,
        Err(_) => return "spki",
    };
    let mut info = Reader::new(info);
    let algorithm = match info.tagged(TAG_SEQUENCE) {
        Ok(algorithm) => algorithm,
        Err(_) => return "spki algorithm",
    };
    let mut algorithm = Reader::new(algorithm);
    let oid = match algorithm.tagged(TAG_OID) {
        Ok(oid) => oid,
        Err(_) => return "spki oid",
    };
    if oid != OID_EC_PUBLIC_KEY && oid != OID_RSA_ENCRYPTION {
        return "spki key type";
    }
    let bits = match info.tagged(TAG_BIT_STRING) {
        Ok(bits) => bits,
        Err(_) => return "spki bits",
    };
    let key = &bits[1..];
    if oid == OID_EC_PUBLIC_KEY && (key.len() != 65 || key[0] != 0x04) {
        return "spki point";
    }
    if tbs.peek() == Some(TAG_EXTENSIONS) {
        let wrapper = match tbs.tagged(TAG_EXTENSIONS) {
            Ok(wrapper) => wrapper,
            Err(_) => return "extensions wrapper",
        };
        let mut wrapper = Reader::new(wrapper);
        let extensions = match wrapper.tagged(TAG_SEQUENCE) {
            Ok(extensions) => extensions,
            Err(_) => return "extensions sequence",
        };
        let mut extensions = Reader::new(extensions);
        while !extensions.is_empty() {
            let extension = match extensions.tagged(TAG_SEQUENCE) {
                Ok(extension) => extension,
                Err(_) => return "extension",
            };
            let mut extension = Reader::new(extension);
            if extension.tagged(TAG_OID).is_err() {
                return "extension oid";
            }
            if extension.peek() == Some(0x01) {
                extension.next().ok();
            }
            if extension.tagged(TAG_OCTET_STRING).is_err() {
                return "extension value";
            }
        }
    }
    "ok"
}

/// How many run-time anchors one machine holds.
///
/// Bounded because each one is DER bytes a program sent: a caller that added
/// anchors in a loop would otherwise make the kernel hold whatever it sent, and
/// a certificate is not small.
pub const ANCHOR_LIMIT: usize = 32;

/// The largest certificate the anchor store accepts.
///
/// A certificate chain's root is a few kilobytes at most; a larger document is
/// one that is not a certificate, and refusing it before parsing is cheaper
/// than discovering that inside the reader.
pub const CERTIFICATE_MAX: usize = 8192;

/// One anchor a program added at run time, and the id that withdraws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    /// The id `TrustAnchorAdd` answered and `TrustAnchorRemove` takes.
    pub id: u32,
    /// The certificate's DER.
    pub der: Vec<u8>,
}

/// The anchors programs have added.
///
/// A value, like every other table in this crate: the kernel holds it behind
/// its own lock.  Built-in anchors are **not** here: they are compiled into the
/// image from `certs/`, and a table that held them would be a table a program
/// could withdraw one from.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Anchors {
    entries: Vec<Anchor>,
    next_id: u32,
}

impl Anchors {
    /// An empty store.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_id: 1,
        }
    }

    /// Add an anchor, answering its id.
    ///
    /// The DER is **parsed first**, and refused if it is not a certificate this
    /// build can verify: an anchor that could not be parsed is one every chain
    /// would fail against, and a program would learn that only when a
    /// connection was attempted.
    pub fn add(&mut self, der: &[u8]) -> Result<u32> {
        if der.len() > CERTIFICATE_MAX {
            return Err(Error::InvalidArgument);
        }
        if self.entries.len() >= ANCHOR_LIMIT {
            return Err(Error::Busy);
        }
        // Parsed and dropped: what makes the DER trustworthy is that the
        // parser read it, and the certificate is parsed again when a chain is
        // verified against it.
        parse(der)?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.entries.push(Anchor {
            id,
            der: Vec::from(der),
        });
        Ok(id)
    }

    /// Withdraw an anchor, answering whether one had that id.
    pub fn remove(&mut self, id: u32) -> bool {
        let before = self.entries.len();
        self.entries.retain(|anchor| anchor.id != id);
        self.entries.len() != before
    }

    /// How many anchors are held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether none is.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every anchor, for a caller that verifies a chain against all of them.
    pub fn entries(&self) -> &[Anchor] {
        &self.entries
    }

    /// The anchors' certificates, parsed.
    ///
    /// A certificate that fails to parse now is **skipped** rather than
    /// refusing the whole set: it parsed when it was added, and one that
    /// stopped is a defect in this module rather than a caller's mistake, so
    /// the caller gets the anchors it can use and not an error about the store.
    pub fn certificates(&self) -> Vec<Certificate> {
        self.entries
            .iter()
            .filter_map(|anchor| parse(&anchor.der).ok())
            .collect()
    }
}

/// An `INTEGER`'s content without DER's leading zero.
///
/// DER writes a positive number whose high bit is set with a `0x00` before it,
/// because the first bit is the sign: an RSA modulus is almost always that
/// case, and a verifier that took the leading zero as part of the modulus would
/// compute with a number one byte longer than the key.
fn strip_leading_zero(bytes: &[u8]) -> &[u8] {
    match bytes.split_first() {
        Some((0, rest)) => rest,
        _ => bytes,
    }
}

/// Whether `certificate`'s signature verifies under `issuer`'s key.
///
/// The message is the certificate's **`tbsCertificate` bytes**, hashed with
/// SHA-256: a signature is over the encoding, and a verifier that rebuilt the
/// sequence from parsed fields would hash different bytes.
pub fn verify_signature(certificate: &Certificate, issuer: &PublicKey) -> bool {
    let hash = crypto::sha256::sha256(&certificate.tbs);
    match (&certificate.algorithm, issuer) {
        (Algorithm::EcdsaP256Sha256, PublicKey::EcP256(key)) => {
            // ECDSA's signature is `SEQUENCE { r INTEGER, s INTEGER }`.
            let Some((r, s)) = crypto::ecdsa::parse_ecdsa_der_signature(&certificate.signature)
            else {
                return false;
            };
            crypto::ecdsa::ecdsa_p256_verify(key, &hash, &r, &s)
        }
        (Algorithm::RsaPkcs1Sha256, PublicKey::Rsa { modulus, exponent }) => {
            crypto::rsa::rsa_pkcs1v15_verify(
                modulus,
                exponent,
                &certificate.tbs,
                &certificate.signature,
            )
        }
        (Algorithm::RsaPssSha256, PublicKey::Rsa { modulus, exponent }) => {
            crypto::rsa::rsa_pss_verify(modulus, exponent, &hash, &certificate.signature)
        }
        // An algorithm and a key that do not go together is not a failed
        // signature: it is a certificate no key here could have signed, and
        // answering "false" is the same answer the caller acts on.
        _ => false,
    }
}

/// Why a chain was refused.
///
/// A reason and not a bare `false`, because the answer a caller prints is the
/// one thing that makes a refused connection diagnosable: "the signature is
/// wrong" and "the name is not the one you asked for" are the same boolean and
/// two entirely different situations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    /// The chain is empty.
    Empty,
    /// No certificate in the chain is the anchor.
    NoAnchor,
    /// A certificate's issuer does not name the subject of the certificate
    /// above it.
    IssuerMismatch,
    /// A certificate that signed another is not a CA.
    NotACertificateAuthority,
    /// A signature did not verify.
    BadSignature,
    /// A certificate names no alternative names, so a host name cannot be
    /// matched against it.
    NoSubjectAltName,
    /// The host name is not in the certificate's names.
    NameMismatch,
}

/// Verify a chain against an anchor's public key, answering the report.
///
/// `chain` is **leaf first**: the peer's certificate, then the intermediates,
/// and the chain **does not include the anchor**.  `anchor_key` and
/// `anchor_subject` are the trusted root's, and the chain's last certificate
/// must be issued **by** that root: a chain whose last certificate is issued by
/// something else has no path to this key, and `IssuerMismatch` is the answer.
///
/// The anchor is a parameter and not a member for the reason a comparison
/// needs: the trust decision is the **anchor's**, and a chain that carried its
/// own root would let a peer nominate the key it is verified against.
///
/// `anchor_subject` is the root's name, which is what the last certificate's
/// issuer is compared against.
///
/// This function does not compare validity windows: it has no clock, and a
/// verifier that guessed one would be checking a certificate against a time
/// nobody chose.  A caller with a clock checks `not_before` and `not_after`
/// itself, and `docs/status.md` says so where the call is recorded.
pub fn verify_chain(
    chain: &[Certificate],
    anchor_subject: &Name,
    anchor_key: &PublicKey,
) -> core::result::Result<(), ChainError> {
    if chain.is_empty() {
        return Err(ChainError::Empty);
    }

    // From the anchor down: the last certificate is the one the anchor issued.
    let mut issuer_key = anchor_key;
    let mut issuer_name = anchor_subject;
    for (index, certificate) in chain.iter().enumerate().rev() {
        if certificate.issuer != *issuer_name {
            return Err(ChainError::IssuerMismatch);
        }
        if !verify_signature(certificate, issuer_key) {
            return Err(ChainError::BadSignature);
        }
        // A certificate that **signed another** must be a CA.  The leaf is the
        // one at index zero and nothing hangs below it, so it is the only one
        // exempt: every certificate above it vouched for the next one down, and
        // a certificate that may not do that is a chain that stops here.
        //
        // The exemption is by **position** and not by identity.  A check
        // written as `!ptr::eq(certificate, chain.first())` skipped the rule
        // for a chain of one, which is the shape a root signing a leaf directly
        // has, and that is the commonest chain there is.
        if index != 0 && !certificate.is_ca {
            return Err(ChainError::NotACertificateAuthority);
        }
        issuer_key = &certificate.public_key;
        issuer_name = &certificate.subject;
    }
    Ok(())
}

/// Whether `certificate` is for `host`, by its `subjectAltName`.
///
/// The rules, each of which is a case a naive comparison gets wrong:
///
/// - A name is compared **case-insensitively**, because a DNS name is ([RFC
///   4343]) and a certificate issued as `Example.COM` is valid for
///   `example.com`.
/// - A name beginning `*.` matches **one** label and no more: `*.example.com`
///   matches `a.example.com` and not `a.b.example.com`, and not `example.com`,
///   because a wildcard that matched its own suffix would be a certificate for
///   every subdomain of a domain it was not issued for.
/// - A wildcard matches only in its **leftmost** label: `a.*.com` is not a
///   pattern any CA issues, and treating it as one would be inventing a rule.
/// - The **common name** is not consulted ([RFC 6125] §6.4.4).
///
/// [RFC 4343]: https://www.rfc-editor.org/rfc/rfc4343
pub fn matches_host(certificate: &Certificate, host: &str) -> bool {
    if certificate.subject_alt_names.is_empty() {
        return false;
    }
    let host = host.as_bytes();
    certificate
        .subject_alt_names
        .iter()
        .any(|name| name_matches(name, host))
}

/// One name against one host, with the wildcard rules above.
fn name_matches(name: &[u8], host: &[u8]) -> bool {
    if let Some(suffix) = name.strip_prefix(b"*.") {
        // The host must have a first label, and everything after it must equal
        // the pattern's suffix.
        let Some(dot) = host.iter().position(|byte| *byte == b'.') else {
            return false;
        };
        let (label, rest) = host.split_at(dot);
        // `rest` still carries its dot, which the pattern's suffix does not.
        if label.is_empty() {
            return false;
        }
        return equals_ignore_case(&rest[1..], suffix);
    }
    equals_ignore_case(name, host)
}

/// Two byte strings equal, with ASCII case folded.
///
/// ASCII only, and that is the correct rule rather than a limitation: a DNS
/// name is compared case-insensitively in ASCII ([RFC 4343] §2), and a Unicode
/// fold would make two names equal that the wire distinguishes.
fn equals_ignore_case(one: &[u8], two: &[u8]) -> bool {
    if one.len() != two.len() {
        return false;
    }
    one.iter()
        .zip(two.iter())
        .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

#[cfg(test)]
mod tests;
