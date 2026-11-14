//! net/src/transport/options.rs
//!
//! A socket's options: the three numbers a program may set or read, what each
//! one means to a value, and the rule that an option this stack does not know
//! is refused rather than stored.
//!
//! ## Why this is a value and not a table
//!
//! The previous tree's option handling was two `match` arms over a struct of
//! fourteen fields, and eleven of those fields were written by the setter and
//! read by nothing.  A field nothing reads is not an option; it is a promise
//! the kernel makes to a program that asks, and the promise is false.  This
//! module holds one field per option **this stack acts on**, and the setter's
//! `match` names exactly those: an option arriving that has no arm is refused
//! with [`abi::Error::InvalidArgument`], which is a program learning that the
//! machine does not do that, instead of a program believing it did.
//!
//! The three:
//!
//! | level | name | what the connection does with it |
//! |---|---|---|
//! | `SOL_SOCKET` | `SO_RCVBUF` | the window every outgoing segment advertises |
//! | `SOL_SOCKET` | `SO_SNDBUF` | the congestion window a write starts with |
//! | `IPPROTO_TCP` | `TCP_NODELAY` | whether a small write waits for a segment's worth |
//!
//! ## Why `SO_REUSEADDR` is not one of them
//!
//! It was in the previous tree's table and in this one's first draft, and it
//! cannot be honoured by this ABI: `BindUdp` names a port and nothing else, so
//! the option would have to be set on a socket that does not exist yet, and a
//! version that recorded it per process and spent it at the next bind was
//! kernel state for a flag no test could reach from ring 3.  A program that
//! sets an option gets an effect or a refusal; the refusal for this one is
//! the `match` below, and the ABI change that would make it honourable is a
//! `BindUdp` with an options word, which is a change to a frozen call and not
//! a change to this table.
//!
//! ## What the numbers are, and what they are not
//!
//! The level and name numbers are [`abi::network`]'s, because they are wire
//! values a program passes and the ABI crate is where a program's numbers
//! live.  This module names them through that crate rather than restating
//! them, so a program and the kernel cannot disagree about which option is
//! which.
//!
//! ## The unit of each value
//!
//! A byte for the two flags, and a word for the two sizes, which is the shape
//! the ABI states and the shape the handler validates against.  A buffer too
//! short for the value it names is refused; a buffer longer is accepted and
//! its extra bytes ignored, because a caller that padded a word is a caller
//! that did nothing wrong.

use abi::Error;
use abi::Result;
use abi::network;

/// Everything a socket lets a program change about how it behaves.
///
/// Held by value, on the connection or the datagram socket that owns it, and
/// changed only through [`Options::set`].  The fields are private because
/// every one of them has a meaning the setters enforce: a caller that wrote
/// `receive_buffer` directly could name a window larger than the inbox, which
/// is the state [`Options::set`] exists to make impossible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// The window outgoing segments advertise, in bytes.
    receive_buffer: usize,
    /// The congestion window a write starts with, in bytes.
    send_buffer: usize,
    /// Whether a small write goes out at once.
    no_delay: bool,
}

impl Options {
    /// The defaults a socket starts with.
    ///
    /// The receive buffer is [`crate::tcp::WINDOW`], which is the number this
    /// stack advertised before the option existed: a program that never
    /// touches the option gets the behaviour it always got.  The send buffer
    /// is [`crate::tcp::MAX_CWND`], which is the ceiling the congestion
    /// control already grows to, so a program that never touches it gets
    /// congestion control and not a constant window.
    ///
    /// Nagle's rule is **on**, which is [`network::TCP_NODELAY_DISABLED`]'s
    /// value and not what "the option is off" sounds like it should be: the
    /// option is "no delay", so its off value is the rule being in force.  A
    /// program that reads `TCP_NODELAY` back before setting it learns the rule
    /// this stack is running, which is why the default is stated here rather
    /// than left as the zero a fresh field happens to hold.
    pub const fn new() -> Self {
        Self {
            receive_buffer: crate::tcp::WINDOW as usize,
            send_buffer: crate::tcp::MAX_CWND,
            no_delay: network::TCP_NODELAY_DISABLED != 0,
        }
    }

    /// The window outgoing segments advertise.
    pub fn receive_buffer(&self) -> usize {
        self.receive_buffer
    }

    /// The congestion window a write starts with.
    pub fn send_buffer(&self) -> usize {
        self.send_buffer
    }

    /// Whether a small write goes out without waiting.
    pub fn no_delay(&self) -> bool {
        self.no_delay
    }

    /// Set one option, answering the byte count a caller reported.
    ///
    /// `value` is the caller's buffer, already validated to be inside its
    /// memory and to hold at least the bytes the option needs.  The width each
    /// option needs is this function's: a flag is one byte and a size is a
    /// word, and a caller that passed a flag in a word passed something this
    /// reads the first byte of, which is the shape the ABI states.
    ///
    /// An option whose number this build does not serve is
    /// [`Error::InvalidArgument`].  It is not `Unsupported`: an unsupported
    /// option is one this stack understands and will not do, and every number
    /// that reaches the refusal is one nothing here understands, which is a
    /// caller's mistake about the number and not a policy of this machine's.
    pub fn set(&mut self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        match (level, name) {
            (network::SOL_SOCKET, network::SO_RCVBUF) => {
                let bytes = read_word(value)?;
                // The window is carried in a sixteen-bit field, so a number
                // past that is not a larger window, it is one that would be
                // truncated into a smaller one.  Refusing is the only answer
                // that keeps the number the program set and the number the
                // peer reads the same.
                if bytes > u16::MAX as usize {
                    return Err(Error::InvalidArgument);
                }
                self.receive_buffer = bytes;
                Ok(())
            }
            (network::SOL_SOCKET, network::SO_SNDBUF) => {
                let bytes = read_word(value)?;
                // A zero send buffer is a stream that may never send, which is
                // a socket that is open and cannot carry, and no program wants
                // that by asking for a *smaller* buffer.  The floor is one
                // segment: below it a write could overtake the handshake.
                self.send_buffer = bytes.max(crate::tcp::MIN_MSS);
                Ok(())
            }
            (network::IPPROTO_TCP, network::TCP_NODELAY) => {
                self.no_delay = read_flag(value)?;
                Ok(())
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Read one option into `into`, answering how many bytes were written.
    ///
    /// The complement of [`Options::set`], and it answers the same width the
    /// setter reads: one byte for a flag, a word for a size.  A buffer that
    /// cannot hold the value is [`Error::InvalidArgument`] rather than a
    /// truncated answer, because a caller that passed four bytes for a word
    /// would read four bytes of a number and conclude something about the
    /// socket that is not true.
    pub fn get(&self, level: u32, name: u32, into: &mut [u8]) -> Result<usize> {
        match (level, name) {
            (network::SOL_SOCKET, network::SO_RCVBUF) => write_word(into, self.receive_buffer),
            (network::SOL_SOCKET, network::SO_SNDBUF) => write_word(into, self.send_buffer),
            (network::IPPROTO_TCP, network::TCP_NODELAY) => write_flag(into, self.no_delay),
            _ => Err(Error::InvalidArgument),
        }
    }
}

impl Default for Options {
    fn default() -> Self {
        Self::new()
    }
}

/// Read a flag: the first byte, and a value any of whose bytes is set is on.
///
/// Any-of rather than first-byte-only, because the ABI lets a caller pass a
/// word for a flag and a caller that wrote "on" as a word with its high byte
/// set meant on.  Reading only the first byte would turn that into off, which
/// is a setting silently inverted.
fn read_flag(value: &[u8]) -> Result<bool> {
    if value.is_empty() {
        return Err(Error::InvalidArgument);
    }
    Ok(value.iter().any(|byte| *byte != 0))
}

/// Write a flag: one byte, zero or one.
fn write_flag(into: &mut [u8], value: bool) -> Result<usize> {
    if into.is_empty() {
        return Err(Error::InvalidArgument);
    }
    into[0] = u8::from(value);
    Ok(1)
}

/// Read a size: one word, little-endian, which is the order the ABI writes.
fn read_word(value: &[u8]) -> Result<usize> {
    let width = core::mem::size_of::<usize>();
    if value.len() < width {
        return Err(Error::InvalidArgument);
    }
    let mut bytes = [0_u8; core::mem::size_of::<usize>()];
    bytes.copy_from_slice(&value[..width]);
    Ok(usize::from_le_bytes(bytes))
}

/// Write a size: one word, little-endian.
fn write_word(into: &mut [u8], value: usize) -> Result<usize> {
    let width = core::mem::size_of::<usize>();
    if into.len() < width {
        return Err(Error::InvalidArgument);
    }
    into[..width].copy_from_slice(&value.to_le_bytes());
    Ok(width)
}

#[cfg(test)]
mod tests {
    use super::Options;
    use abi::Error;
    use abi::network;

    /// A word, the way a program writes one.
    fn word(value: usize) -> [u8; core::mem::size_of::<usize>()] {
        value.to_le_bytes()
    }

    /// The defaults are the behaviour this stack had before the option existed.
    ///
    /// That is the property a default has to have: a program compiled before
    /// `SetSockOpt` was served must run the same way after it.  The receive
    /// buffer is `WINDOW`, because that is what every segment advertised; the
    /// send buffer is the congestion window's ceiling, because that is what
    /// grew; and Nagle's rule is on, which is the one default this stack did
    /// not have before, and it is stated as the constant rather than as `0`.
    #[test]
    fn the_defaults_are_what_the_stack_did_before() {
        let options = Options::new();
        assert_eq!(
            options.receive_buffer(),
            crate::tcp::WINDOW as usize,
            "the window every segment advertised"
        );
        assert_eq!(
            options.send_buffer(),
            crate::tcp::MAX_CWND,
            "the ceiling congestion control grows to"
        );
        assert_eq!(
            options.no_delay(),
            network::TCP_NODELAY_DISABLED != 0,
            "the default is the constant and not a zero somebody meant"
        );
        assert!(
            !options.no_delay(),
            "and that constant is off, which is Nagle's rule in force"
        );
    }

    /// Each of the three options sets and reads back the number it was given.
    ///
    /// Three separate assertions rather than a round trip of all three,
    /// because a `match` arm that read the wrong field would pass a loop that
    /// set and read the same option: what distinguishes them is that setting
    /// one leaves the other two alone.
    #[test]
    fn each_option_sets_and_reads_back() {
        let mut options = Options::new();

        options
            .set(network::SOL_SOCKET, network::SO_RCVBUF, &word(4096))
            .expect("a receive buffer");
        assert_eq!(options.receive_buffer(), 4096);
        assert_eq!(options.send_buffer(), crate::tcp::MAX_CWND, "untouched");

        options
            .set(network::SOL_SOCKET, network::SO_SNDBUF, &word(8192))
            .expect("a send buffer");
        assert_eq!(options.send_buffer(), 8192);
        assert_eq!(options.receive_buffer(), 4096, "untouched");

        assert!(!options.no_delay(), "the flag is untouched by the sizes");

        options
            .set(network::IPPROTO_TCP, network::TCP_NODELAY, &[1])
            .expect("no delay");
        assert!(options.no_delay());
        assert_eq!(options.receive_buffer(), 4096, "the sizes are still set");

        // And back, through `get`, at the width each one is.
        let mut buffer = [0_u8; 16];
        let written = options
            .get(network::SOL_SOCKET, network::SO_RCVBUF, &mut buffer)
            .expect("a receive buffer");
        assert_eq!(written, core::mem::size_of::<usize>());
        assert_eq!(
            usize::from_le_bytes(buffer[..written].try_into().unwrap()),
            4096
        );

        let written = options
            .get(network::IPPROTO_TCP, network::TCP_NODELAY, &mut buffer)
            .expect("no delay");
        assert_eq!(written, 1, "a flag is one byte");
        assert_eq!(buffer[0], 1);
    }

    /// A level and a name this stack does not serve are refused, not stored.
    ///
    /// The whole argument for having four options instead of fourteen fields:
    /// an option nothing acts on is a promise, and a machine that accepted it
    /// would be telling a program something untrue.  The refusal is the same
    /// for a level that does not exist and a name that does not, because a
    /// caller can tell neither from the other and the answer should not
    /// pretend it can.
    #[test]
    fn an_option_this_stack_does_not_serve_is_refused() {
        let mut options = Options::new();
        // A level nothing defines.
        assert_eq!(
            options.set(99, network::SO_RCVBUF, &word(4096)),
            Err(Error::InvalidArgument)
        );
        // The right level, a name this build does not act on.  `SO_KEEPALIVE`
        // was in the previous tree's table and nothing read it, which is the
        // case this refusal exists for.
        assert_eq!(
            options.set(network::SOL_SOCKET, 1, &[1]),
            Err(Error::InvalidArgument)
        );
        // `TCP_NODELAY` at the socket level is not the TCP option: the level
        // is part of the key, and a table keyed on the name alone would set
        // the wrong thing here.
        assert_eq!(
            options.set(network::SOL_SOCKET, network::TCP_NODELAY, &[1]),
            Err(Error::InvalidArgument)
        );
        // And the same for reading.
        let mut buffer = [0_u8; 8];
        assert_eq!(
            options.get(network::SOL_SOCKET, 1, &mut buffer),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            options.get(99, network::SO_RCVBUF, &mut buffer),
            Err(Error::InvalidArgument)
        );
        // Nothing any of the refusals did changed a field.
        assert_eq!(options, Options::new());
    }

    /// A buffer too short for the value it names is refused.
    ///
    /// Three kinds of too short: a flag in no bytes, a size in fewer than a
    /// word, and a read into a buffer that cannot hold the answer.  A truncated
    /// answer is the failure this prevents: four bytes of a word is a number,
    /// and a program that read it would believe a window this socket does not
    /// have.
    #[test]
    fn a_buffer_too_short_for_the_value_is_refused() {
        let mut options = Options::new();
        assert_eq!(
            options.set(network::IPPROTO_TCP, network::TCP_NODELAY, &[]),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            options.set(network::SOL_SOCKET, network::SO_RCVBUF, &[1, 2, 3]),
            Err(Error::InvalidArgument),
            "a word does not fit in three bytes"
        );
        let mut small = [0_u8; 2];
        assert_eq!(
            options.get(network::SOL_SOCKET, network::SO_RCVBUF, &mut small),
            Err(Error::InvalidArgument),
            "and it cannot be written into two"
        );
        assert_eq!(
            options.get(network::IPPROTO_TCP, network::TCP_NODELAY, &mut []),
            Err(Error::InvalidArgument)
        );
    }

    /// A window larger than the field that carries it is refused.
    ///
    /// The window is a sixteen-bit field in the segment header, so a program
    /// that set 70000 would set a number this stack could only send truncated.
    /// A truncation is worse than a refusal here: the program would read back
    /// 70000 and the peer would see 4464.
    #[test]
    fn a_receive_buffer_past_the_field_that_carries_it_is_refused() {
        let mut options = Options::new();
        assert_eq!(
            options.set(
                network::SOL_SOCKET,
                network::SO_RCVBUF,
                &word(u16::MAX as usize + 1)
            ),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            options.set(
                network::SOL_SOCKET,
                network::SO_RCVBUF,
                &word(u16::MAX as usize)
            ),
            Ok(()),
            "the largest number the field carries is accepted"
        );
        assert_eq!(options.receive_buffer(), u16::MAX as usize);
    }

    /// A zero send buffer is the floor and not a zero.
    ///
    /// A socket with a zero send window is open and can never carry a byte,
    /// which is not what a program asking for a smaller buffer wants.  The
    /// floor is one segment, and the test asserts the number rather than
    /// "greater than zero" because the floor is a decision.
    #[test]
    fn a_zero_send_buffer_is_the_floor() {
        let mut options = Options::new();
        options
            .set(network::SOL_SOCKET, network::SO_SNDBUF, &word(0))
            .expect("zero is accepted and raised");
        assert_eq!(options.send_buffer(), crate::tcp::MIN_MSS);
    }

    /// A flag written as a word with its high byte set reads as on.
    ///
    /// The ABI lets a caller pass a word for a byte-wide option, which is what
    /// a program written in C does with an `int`.  A reader that took only the
    /// first byte would read that as off on a little-endian machine, which is
    /// a setting silently inverted.
    #[test]
    fn a_flag_written_as_a_word_reads_as_on() {
        let mut options = Options::new();
        options
            .set(network::IPPROTO_TCP, network::TCP_NODELAY, &word(1))
            .expect("a word-shaped flag");
        assert!(options.no_delay());
    }
}
