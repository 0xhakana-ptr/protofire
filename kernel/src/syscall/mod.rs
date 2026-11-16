//! kernel/src/syscall/mod.rs
//!
//! The syscall registry, in two pieces: the table from a number to the
//! function that serves it, and the handlers this boot can answer.
//!
//! | File | What it holds |
//! |---|---|
//! | [`table`] | the table, its descriptors, the installed registry, and the limits |
//! | [`handlers`] | the calls that answer at once: the filesystem's, memory's, time's, the MAC policy's, and the datagram and stream setups |
//! | this file | the re-exports a caller spells, and the tests |
//!
//! ## Why the table is here and not in the `syscall` crate
//!
//! Every slot names a subsystem, the filesystem, the network, the scheduler,
//! and the `syscall` crate must not know that any of them exist.  A table
//! there would have to import them, which is the edge
//! `scripts/check-layering.sh` refuses.  The crate keeps the numbering, the
//! context and the validators; where the handlers live is the kernel's
//! business, because the kernel is the only crate that may name them all.
//!
//! ## What is served today
//!
//! Thirty-one numbers, and the split between this table and `process.rs` is
//! the one that matters: a call that answers inside its own frame is a handler
//! here, and a call that must **park**, a pipe read, a datagram receive, an
//! accept, a sleep, is a branch in `process.rs`, because parking needs the
//! scheduler and a handler taking `&mut SyscallTable` cannot hold a trap frame.
//!
//! Every other number answers `Error::NotImplemented` rather than being
//! absent.  An absent slot would have to be a panic or a silent zero, and both
//! report a lie: this kernel does not serve that number, which is a fact the
//! caller can act on.
//!
//! ## Arguments, and what a pointer means here
//!
//! `SyscallContext` carries six words, and a word may be an address.  No
//! user-space caller reaches this registry, the boot's programs make their
//! calls through `process`, which validates a ring-3 address itself, so the
//! registry's only callers are the kernel's, and the two address-shaped
//! arguments arrive as borrows, [`Arguments::path`] and [`Arguments::buffer`],
//! rather than as integers a handler would have to turn back into pointers.
//!
//! That is deliberate.  A handler that does `from_raw_parts` on
//! `context.arg(1)` carries a promise it cannot show, the comment would say
//! "the caller promises this is valid", and nothing would check it.  Taking a
//! `&mut [u8]` moves the promise to the one place that can keep it: the code
//! that built the borrow.  When a program can call these, the entry path copies
//! its buffer into kernel memory and calls the same handler with the same
//! borrow, so the handler does not change and this module never gains an
//! `unsafe`.
//!
//! ## Descriptors
//!
//! A descriptor is an index into a fixed table of open nodes.  The table is
//! per boot because a handle table belongs to a process and the handle-table
//! half has not arrived; the scheduler and its processes are here, and this
//! module keeps only the number-to-handler mapping, which is the part that is
//! genuinely the kernel's.

pub mod handlers;
pub mod table;

pub use handlers::abi_info;
pub use handlers::accept_local;
pub use handlers::bind_local;
pub use handlers::bind_udp;
pub use handlers::brk;
pub use handlers::close;
pub use handlers::connect_local;
pub use handlers::connect_tcp;
pub use handlers::create_dir;
pub use handlers::create_dir_at;
pub use handlers::create_raw_socket;
pub use handlers::dccp_accept;
pub use handlers::dccp_bind;
pub use handlers::dccp_close;
pub use handlers::dccp_connect;
pub use handlers::dccp_listen;
pub use handlers::dccp_recv;
pub use handlers::dccp_send;
pub use handlers::fdatasync;
pub use handlers::filter_add_rule;
pub use handlers::filter_get_stats;
pub use handlers::filter_remove_rule;
pub use handlers::filter_set_default_action;
pub use handlers::fsync;
pub use handlers::get_host_name;
pub use handlers::get_peer_name;
pub use handlers::get_random;
pub use handlers::get_sock_name;
pub use handlers::get_sock_opt;
pub use handlers::get_time_of_day;
pub use handlers::ipsec_add_sa;
pub use handlers::ipsec_add_sp;
pub use handlers::ipsec_del_sa;
pub use handlers::ipsec_del_sp;
pub use handlers::ipsec_get_stats;
pub use handlers::ipv6_status;
pub use handlers::listen_tcp;
pub use handlers::mac_add_rule;
pub use handlers::mac_get_status;
pub use handlers::mac_set_mode;
pub use handlers::mmap;
pub use handlers::mrt_add_mfc;
pub use handlers::mrt_add_vif;
pub use handlers::mrt_del_mfc;
pub use handlers::mrt_del_vif;
pub use handlers::mrt_done;
pub use handlers::mrt_init;
pub use handlers::munmap;
pub use handlers::network_status;
pub use handlers::open;
pub use handlers::open_at;
pub use handlers::read;
pub use handlers::read_dir;
pub use handlers::read_dir_fd;
pub use handlers::reclaim_pages;
pub use handlers::remove_path;
pub use handlers::remove_path_at;
pub use handlers::rename;
pub use handlers::rename_at;
#[cfg(target_os = "none")]
pub use handlers::resolve_hostname;
pub use handlers::seek;
pub use handlers::send_raw_packet;
pub use handlers::send_to_udp;
pub use handlers::set_host_name;
pub use handlers::set_length;
pub use handlers::set_sock_opt;
pub use handlers::stat;
pub use handlers::stat_at;
pub use handlers::stat_fd;
pub use handlers::system_info;
pub use handlers::tls_connect;
pub use handlers::trust_anchor_add;
pub use handlers::trust_anchor_remove;
pub use handlers::write;
pub use table::Arguments;
pub use table::Dispatch;
pub use table::Handler;
pub use table::KernelHandler;
pub use table::MAX_DESCRIPTORS;
pub use table::PATH_MAX;
pub use table::READ_OFFSET_CURRENT;
pub use table::SyscallTable;
pub use table::accept_dccp;
pub use table::attach_local;
pub use table::attach_pipe;
pub use table::attach_tcp_stream;
pub use table::dccp_listener_port_for;
pub use table::has_registry;
pub use table::inherit;
pub use table::install;
pub use table::local_halves_for;
pub use table::local_name_for;
pub use table::open_descriptors;
pub use table::pipe_end;
pub use table::pipe_end_for;
pub use table::raw_socket_for;
pub use table::read_file;
pub use table::release_owned;
pub use table::serve;
pub use table::served_numbers;
pub use table::tcp_listener_for;
pub use table::tcp_stream_for;
pub use table::udp_socket_for;
