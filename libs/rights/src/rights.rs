//! libs/rights/src/rights.rs
//!
//! What a handle may do: the rights carried by a handle-table entry.
//!
//! Two bit flags, and every layer names them — a device descriptor declares
//! which rights its device supports, the filesystem checks them before it
//! answers a read, the audit log opens its own file with one, and the handle
//! table stores them.  A set of flags that everyone needs is not a reason for
//! those layers to depend on each other, so they sit at the bottom, below
//! `device`, `fs`, `audit` and `process` alike.

/// Open for reading.
pub const HANDLE_RIGHT_READ: u32 = 1 << 0;

/// Open for writing.
pub const HANDLE_RIGHT_WRITE: u32 = 1 << 1;

#[cfg(test)]
mod tests {
    use super::HANDLE_RIGHT_READ;
    use super::HANDLE_RIGHT_WRITE;

    /// The rights are distinct bits.
    ///
    /// A filesystem checks `rights & HANDLE_RIGHT_READ != 0`, so two rights
    /// sharing a bit means a read-only handle is accepted for a write.  The
    /// constants are written by hand, which is exactly why this is checked: a
    /// copy-paste that gave both the same shift would compile and pass every
    /// other gate in the tree.
    #[test]
    fn the_rights_do_not_overlap() {
        assert_eq!(HANDLE_RIGHT_READ & HANDLE_RIGHT_WRITE, 0);
        assert_ne!(HANDLE_RIGHT_READ, 0);
        assert_ne!(HANDLE_RIGHT_WRITE, 0);
    }

    /// Each right is one bit, not a mask of several.
    #[test]
    fn each_right_is_a_single_bit() {
        assert_eq!(HANDLE_RIGHT_READ.count_ones(), 1);
        assert_eq!(HANDLE_RIGHT_WRITE.count_ones(), 1);
    }

    /// The values are the ones the wire format already uses.
    #[test]
    fn the_values_are_pinned() {
        assert_eq!(HANDLE_RIGHT_READ, 1);
        assert_eq!(HANDLE_RIGHT_WRITE, 2);
    }
}
