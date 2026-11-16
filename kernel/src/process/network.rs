//! kernel/src/process/network.rs
//!
//! The network calls: sockets, the filters, multicast forwarding, IPsec, DCCP,
//! TLS, and the trust anchors.
//!
//! One family of `serve`'s branches, moved out so the dispatcher reads as a
//! list of families.  `None` means this family does not serve `number` and
//! `serve` tries the next one; `Some(outcome)` is the call's answer and ends
//! the dispatch.

use super::NAME_MAX;
use super::copy_user_name;
use super::receive_datagram_answer;
use super::through_registry;
use super::write_ipv4_word;

pub(crate) fn serve_network(
    call: arch::CallFrame,
    frame: &mut arch::Context,
    number: usize,
    caller: Option<u32>,
) -> Option<arch::CallOutcome> {
    use arch::CallOutcome;
    use syscall::SyscallNumber;
    let _ = (&call, &*frame, number, caller);
    if number == SyscallNumber::SetSockOpt as usize || number == SyscallNumber::GetSockOpt as usize
    {
        let value = call.arguments[3];
        let length = call.arguments[4];
        if length == 0
            || length > abi::network::SOCK_OPT_MAX
            || !crate::address_space::is_user_range(value, length)
        {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The setter reads the
        // buffer and the getter writes it, each inside the length checked
        // above.
        let buffer = unsafe { core::slice::from_raw_parts_mut(value as *mut u8, length) };
        let outcome = through_registry(&mut context, None, None, Some(buffer));
        if let CallOutcome::Return(answer) = outcome {
            let refused = abi::syscall::is_error_status(answer);
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(if number == SyscallNumber::SetSockOpt as usize {
                " set socket option "
            } else {
                " read socket option "
            });
            arch::serial::write_u32(call.arguments[2] as u32);
            if refused {
                arch::serial::write_str(" refused\n");
            } else {
                arch::serial::write_str(" answered ");
                arch::serial::write_u32(answer as u32);
                arch::serial::write_str("\n");
            }
        }
        return Some(outcome);
    }

    // `TrustAnchorAdd` names a DER document, so its buffer is borrowed the way
    // every other record-shaped call's is.  `TrustAnchorRemove` names a word
    if number == SyscallNumber::TrustAnchorAdd as usize {
        let (record, length) = (call.arguments[0], call.arguments[1]);
        if length == 0
            || length > net::x509::CERTIFICATE_MAX
            || !crate::address_space::is_user_range(record, length)
        {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The handler copies the
        // document and reads nothing past the length checked above.
        let buffer = unsafe { core::slice::from_raw_parts_mut(record as *mut u8, length) };
        let outcome = through_registry(&mut context, None, None, Some(buffer));
        if let CallOutcome::Return(answer) = outcome {
            let refused = abi::syscall::is_error_status(answer);
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" trusted a root certificate, ");
            if refused {
                arch::serial::write_str("refused\n");
            } else {
                arch::serial::write_str("id ");
                arch::serial::write_u32(answer as u32);
                arch::serial::write_str("\n");
            }
        }
        return Some(outcome);
    }
    if number == SyscallNumber::TrustAnchorRemove as usize {
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        if let CallOutcome::Return(answer) = outcome {
            let refused = abi::syscall::is_error_status(answer);
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" withdrew a root certificate");
            arch::serial::write_str(if refused { ", refused\n" } else { "\n" });
        }
        return Some(outcome);
    }

    // `TlsConnect` names a host with a pointer and a length, so it is copied
    // the way a path is.  Its answer is a word: a refusal here, because the
    if number == SyscallNumber::TlsConnect as usize {
        let mut name_bytes = [0u8; NAME_MAX];
        let Ok(host) = copy_user_name(call.arguments[0], call.arguments[1], &mut name_bytes) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        };
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, Some(host), None, None);
        if let CallOutcome::Return(answer) = outcome {
            let refused = abi::syscall::is_error_status(answer);
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" asked for a tls connection, ");
            arch::serial::write_str(if refused { "refused\n" } else { "opened\n" });
        }
        return Some(outcome);
    }

    // The calls that name a host take a pointer and a length, so their string
    // is copied the way a path is and their answer is a word rather than a
    if number == SyscallNumber::SetHostName as usize
        || number == SyscallNumber::ResolveHostname as usize
        || number == SyscallNumber::BindLocal as usize
        || number == SyscallNumber::ConnectLocal as usize
    {
        let mut name_bytes = [0u8; NAME_MAX];
        let Ok(name) = copy_user_name(call.arguments[0], call.arguments[1], &mut name_bytes) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        };
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, Some(name), None, None);
        if let CallOutcome::Return(answer) = outcome {
            let refused = abi::syscall::is_error_status(answer);
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            if number == SyscallNumber::SetHostName as usize {
                arch::serial::write_str(" set the machine's name, ");
            } else if number == SyscallNumber::BindLocal as usize
                || number == SyscallNumber::ConnectLocal as usize
            {
                arch::serial::write_str(if number == SyscallNumber::BindLocal as usize {
                    " bound the local name, descriptor "
                } else {
                    " connected to the local name, descriptor "
                });
            } else {
                arch::serial::write_str(" resolved a name to ");
            }
            if refused {
                arch::serial::write_str("refused\n");
            } else {
                arch::serial::write_u32(answer as u32);
                arch::serial::write_str("\n");
            }
        }
        return Some(outcome);
    }

    // The packet filter's two buffer calls.  `FilterAddRule` names a record in
    // `a0` and its length in `a1`, and the record is read: the rule's every
    // field is a number the caller chose, and the handler is where they are
    // validated.  `FilterGetStats` names its output in `a0` and its length in
    // `a1`, and is written.  One branch because the two calls differ only in
    // which way the bytes move, which is the same reading the socket-option
    if number == SyscallNumber::FilterAddRule as usize
        || number == SyscallNumber::FilterGetStats as usize
    {
        let (record, length) = (call.arguments[0], call.arguments[1]);
        if length == 0
            || length > abi::network::FILTER_RULE_DEF_SIZE.max(abi::network::FILTER_STATS_SIZE)
            || !crate::address_space::is_user_range(record, length)
        {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The add reads a record
        // of the length it was given and the stats call writes one, each
        // inside the length checked above and each against the size the
        // handler itself states.
        let buffer = unsafe { core::slice::from_raw_parts_mut(record as *mut u8, length) };
        let outcome = through_registry(&mut context, None, None, Some(buffer));
        if let CallOutcome::Return(answer) = outcome {
            let refused = abi::syscall::is_error_status(answer);
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(if number == SyscallNumber::FilterAddRule as usize {
                " added a filter rule, id "
            } else {
                " read the filter's statistics, "
            });
            if refused {
                arch::serial::write_str("refused\n");
            } else {
                arch::serial::write_u32(answer as u32);
                arch::serial::write_str("\n");
            }
        }
        return Some(outcome);
    }

    // The multicast routing records.  `MrtAddVif` and `MrtAddMfc` name a
    // record and its length in `a0`/`a1`, and both are read: every field is a
    if number == SyscallNumber::MrtAddVif as usize || number == SyscallNumber::MrtAddMfc as usize {
        let (record, length) = (call.arguments[0], call.arguments[1]);
        if length == 0
            || length > abi::network::MRT_VIF_DEF_SIZE.max(abi::network::MRT_MFC_DEF_SIZE)
            || !crate::address_space::is_user_range(record, length)
        {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The handler reads a
        // record of the length it was given, against the size it states.
        let buffer = unsafe { core::slice::from_raw_parts_mut(record as *mut u8, length) };
        let outcome = through_registry(&mut context, None, None, Some(buffer));
        if let CallOutcome::Return(answer) = outcome {
            let refused = abi::syscall::is_error_status(answer);
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(if number == SyscallNumber::MrtAddVif as usize {
                " added a multicast interface, index "
            } else {
                " added a multicast route, "
            });
            if refused {
                arch::serial::write_str("refused\n");
            } else {
                arch::serial::write_u32(answer as u32);
                arch::serial::write_str("\n");
            }
        }
        return Some(outcome);
    }

    // DCCP's two buffer calls: `DccpSend` reads a buffer and `DccpRecv`
    // writes one, and the descriptor, the buffer address and the length are
    if number == SyscallNumber::DccpSend as usize || number == SyscallNumber::DccpRecv as usize {
        let buffer = call.arguments[1];
        let length = call.arguments[2];
        if length == 0
            || length > net::dccp::MAX_DATAGRAM.max(64 * 1024)
            || !crate::address_space::is_user_range(buffer, length)
        {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The send reads the
        // buffer and the receive writes it, each inside the length checked
        // above.
        let buffer = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) };
        let outcome = through_registry(&mut context, None, None, Some(buffer));
        if let CallOutcome::Return(answer) = outcome {
            let refused = abi::syscall::is_error_status(answer);
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(if number == SyscallNumber::DccpSend as usize {
                " sent a dccp datagram, "
            } else {
                " read a dccp datagram, "
            });
            arch::serial::write_u32(length as u32);
            arch::serial::write_str(if refused {
                " byte(s) asked, refused\n"
            } else {
                " byte(s) of room\n"
            });
        }
        return Some(outcome);
    }

    // DCCP's five calls that name words.  `DccpConnect` names an address and
    if number == SyscallNumber::DccpBind as usize
        || number == SyscallNumber::DccpListen as usize
        || number == SyscallNumber::DccpConnect as usize
        || number == SyscallNumber::DccpClose as usize
    {
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        if let CallOutcome::Return(answer) = outcome {
            let refused = abi::syscall::is_error_status(answer);
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(match number {
                n if n == SyscallNumber::DccpBind as usize => " bound a dccp port, descriptor ",
                n if n == SyscallNumber::DccpListen as usize => {
                    " listened on a dccp port, descriptor "
                }
                n if n == SyscallNumber::DccpConnect as usize => {
                    " connected with dccp, descriptor "
                }
                _ => " closed a dccp connection, ",
            });
            if refused {
                arch::serial::write_str("refused\n");
            } else {
                arch::serial::write_u32(answer as u32);
                arch::serial::write_str("\n");
            }
        }
        return Some(outcome);
    }

    // `DccpAccept` is a second accept, and it parks for the same reason
    // `AcceptLocal` does: the Request that answers it arrives on another CPU or
    // in an interrupt, and a handler cannot wait.  The wake is the one
    if number == SyscallNumber::DccpAccept as usize {
        let descriptor = call.arguments[0];
        let owner = crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS);
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(owner);
        let mut answer = through_registry(&mut context, None, None, None);
        if matches!(answer, CallOutcome::Return(value) if value == usize::MAX) {
            // Nothing was waiting.  The re-check asks the same handler again
            // under the scheduler's lock, and every answer but `usize::MAX` is
            // the call's answer.
            let port = crate::syscall::dccp_listener_port_for(descriptor, Some(owner));
            let retried = crate::scheduler::block_unless(frame, || {
                let port = port?;
                match crate::syscall::accept_dccp(port, owner) {
                    Ok(value) => Some(value),
                    Err(error) => Some(abi::syscall::encode_error(error)),
                }
            });
            answer = match retried {
                Some(value) => CallOutcome::Return(value),
                None => {
                    arch::serial::write_str(
                        "protofire: a program waits to accept a dccp request\n",
                    );
                    if !crate::scheduler::has_selectable() {
                        crate::scheduler::idle_until_woken();
                    }
                    return Some(crate::scheduler::switch_without_saving(frame));
                }
            };
        }
        if let CallOutcome::Return(value) = answer {
            let refused = abi::syscall::is_error_status(value);
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(owner);
            arch::serial::write_str(" accepted a dccp request as descriptor ");
            if refused {
                arch::serial::write_str("refused\n");
            } else {
                arch::serial::write_u32(value as u32);
                arch::serial::write_str("\n");
            }
        }
        return Some(answer);
    }

    // `DccpAccept` is the parking one, and it is handled with the other
    // accept below: a handler that cannot park does not hold a number whose
    // caller may have to wait.

    // The IPsec records: three calls take one and the other two name words.
    // `IpsecAddSp` and `IpsecAddSa` read a record, and `IpsecGetStats` writes
    // one, so all three take the buffer the trap path can validate; one branch
    if number == SyscallNumber::IpsecAddSp as usize
        || number == SyscallNumber::IpsecAddSa as usize
        || number == SyscallNumber::IpsecGetStats as usize
    {
        let (record, length) = (call.arguments[0], call.arguments[1]);
        if length == 0
            || length
                > abi::network::IPSEC_SP_DEF_SIZE
                    .max(abi::network::IPSEC_SA_DEF_SIZE)
                    .max(abi::network::IPSEC_STATS_SIZE)
            || !crate::address_space::is_user_range(record, length)
        {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The handlers read or
        // write one record, each against the size it states.
        let buffer = unsafe { core::slice::from_raw_parts_mut(record as *mut u8, length) };
        let outcome = through_registry(&mut context, None, None, Some(buffer));
        if let CallOutcome::Return(answer) = outcome {
            let refused = abi::syscall::is_error_status(answer);
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(match number {
                n if n == SyscallNumber::IpsecAddSp as usize => " added a security policy, id ",
                n if n == SyscallNumber::IpsecAddSa as usize => {
                    " added a security association, id "
                }
                _ => " read the ipsec statistics, ",
            });
            if refused {
                arch::serial::write_str("refused\n");
            } else {
                arch::serial::write_u32(answer as u32);
                arch::serial::write_str("\n");
            }
        }
        return Some(outcome);
    }

    if number == SyscallNumber::IpsecDelSp as usize || number == SyscallNumber::IpsecDelSa as usize
    {
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        if let CallOutcome::Return(answer) = outcome {
            let refused = abi::syscall::is_error_status(answer);
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(if number == SyscallNumber::IpsecDelSp as usize {
                " removed a security policy"
            } else {
                " removed a security association"
            });
            arch::serial::write_str(if refused { ", refused\n" } else { "\n" });
        }
        return Some(outcome);
    }

    // The four multicast calls that name words: the switch's two, and the two
    // removals.  Nothing here turns a word into a borrow, so the registry is
    if number == SyscallNumber::MrtInit as usize
        || number == SyscallNumber::MrtDone as usize
        || number == SyscallNumber::MrtDelVif as usize
        || number == SyscallNumber::MrtDelMfc as usize
    {
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        if let CallOutcome::Return(answer) = outcome {
            let refused = abi::syscall::is_error_status(answer);
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(match number {
                n if n == SyscallNumber::MrtInit as usize => " enabled multicast routing",
                n if n == SyscallNumber::MrtDone as usize => " disabled multicast routing",
                n if n == SyscallNumber::MrtDelVif as usize => " removed a multicast interface",
                _ => " removed a multicast route",
            });
            arch::serial::write_str(if refused { ", refused\n" } else { "\n" });
        }
        return Some(outcome);
    }

    // The filter's two calls that name no buffer: a rule by id, and the
    // default action.  Their arguments are words, so nothing here has to turn
    if number == SyscallNumber::FilterRemoveRule as usize
        || number == SyscallNumber::FilterSetDefaultAction as usize
    {
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        if let CallOutcome::Return(answer) = outcome {
            let refused = abi::syscall::is_error_status(answer);
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(if number == SyscallNumber::FilterRemoveRule as usize {
                " removed a filter rule, "
            } else {
                " set the filter's default action, "
            });
            if refused {
                arch::serial::write_str("refused\n");
            } else {
                arch::serial::write_u32(answer as u32);
                arch::serial::write_str("\n");
            }
        }
        return Some(outcome);
    }

    // `a0` is the clock or the selector), so the pair to validate is the second
    if number == SyscallNumber::GetTimeOfDay as usize
        || number == SyscallNumber::GetRandom as usize
        || number == SyscallNumber::SystemInfo as usize
        || number == SyscallNumber::AbiInfo as usize
        || number == SyscallNumber::NetworkStatus as usize
        || number == SyscallNumber::Ipv6Status as usize
        // The name and a socket's two ends are records too, and they park
        // nothing: what they report is a fact the kernel already holds.
        || number == SyscallNumber::GetHostName as usize
        || number == SyscallNumber::GetSockName as usize
        || number == SyscallNumber::GetPeerName as usize
    {
        // `GetRandom` names its buffer and its length in `a0`/`a1`.  `AbiInfo`
        // and `NetworkStatus` name the record in `a0` and its length in `a1`,
        // because neither has a selector to make room for.  `GetTimeOfDay`
        // and `SystemInfo` each have one, so their record and length are
        // `a1`/`a2`.  Reading the wrong pair here validates an address that
        // is not the buffer, and the refusal it produces looks exactly like
        // a machine that does not serve the call.
        let (record, length) = match number {
            n if n == SyscallNumber::GetRandom as usize => (call.arguments[0], call.arguments[1]),
            n if n == SyscallNumber::AbiInfo as usize => (call.arguments[0], call.arguments[1]),
            n if n == SyscallNumber::NetworkStatus as usize => {
                (call.arguments[0], call.arguments[1])
            }
            // The same shape as `NetworkStatus`: the record in `a0` and its
            // length in `a1`, because this call has no selector to make room
            // for either.
            n if n == SyscallNumber::Ipv6Status as usize => (call.arguments[0], call.arguments[1]),
            // A name is written where `NetworkStatus` writes its record: the
            // buffer in `a0` and its length in `a1`.
            n if n == SyscallNumber::GetHostName as usize => (call.arguments[0], call.arguments[1]),
            // A socket's ends name the descriptor first, so the record and its
            // length move to `a1` and `a2`: reading the wrong pair validates a
            // descriptor as an address, and the refusal that produces is
            // indistinguishable from a machine that does not serve the call.
            n if n == SyscallNumber::GetSockName as usize
                || n == SyscallNumber::GetPeerName as usize =>
            {
                (call.arguments[1], call.arguments[2])
            }
            _ => (call.arguments[1], call.arguments[2]),
        };
        if !crate::address_space::is_user_range(record, length) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The handlers write the
        // record and nothing past it, which is what their length check is for.
        let destination = unsafe { core::slice::from_raw_parts_mut(record as *mut u8, length) };
        let outcome = through_registry(&mut context, None, None, Some(destination));
        // A socket's own end prints what it answered, because it is the one of
        // these records whose content is a fact about a connection rather than
        // about the machine: the port and the address a program reads back are
        // the ones the kernel's table holds, and a handler that wrote zeros
        // would pass a check that only looked at the size.
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
            && (number == SyscallNumber::GetSockName as usize
                || number == SyscallNumber::GetPeerName as usize)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(if number == SyscallNumber::GetSockName as usize {
                " socket is "
            } else {
                " peer is "
            });
            write_ipv4_word(u32::from_be_bytes([
                destination[abi::network::SOCKADDR_IN_ADDRESS_OFFSET],
                destination[abi::network::SOCKADDR_IN_ADDRESS_OFFSET + 1],
                destination[abi::network::SOCKADDR_IN_ADDRESS_OFFSET + 2],
                destination[abi::network::SOCKADDR_IN_ADDRESS_OFFSET + 3],
            ]) as usize);
            arch::serial::write_str(":");
            arch::serial::write_u32(u16::from_be_bytes([
                destination[abi::network::SOCKADDR_IN_PORT_OFFSET],
                destination[abi::network::SOCKADDR_IN_PORT_OFFSET + 1],
            ]) as u32);
            arch::serial::write_str("\n");
        }
        // The evidence, printed by the kernel because a program has no way to
        // print one.  The line names the call and the first word of what it
        // answered, which is the part that cannot be a constant: a time's
        // seconds move, and a random call's first word is bytes the generator
        // produced.
        //
        // A refused call prints too.  Without that, a call the handler refused
        // is indistinguishable in the log from one the program never made
        // which is exactly the ambiguity the first boot of this group had, and
        // it cost a boot to find.
        if let CallOutcome::Return(answer) = outcome {
            let refused = abi::syscall::is_error_status(answer);
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(match number {
                n if n == SyscallNumber::GetTimeOfDay as usize => " read the clock, ",
                n if n == SyscallNumber::GetRandom as usize => " drew random bytes, ",
                n if n == SyscallNumber::SystemInfo as usize => " asked the system, ",
                n if n == SyscallNumber::NetworkStatus as usize => " asked the network, ",
                n if n == SyscallNumber::Ipv6Status as usize => " asked the ipv6 side, ",
                _ => " asked the ABI, ",
            });
            arch::serial::write_u32(length as u32);
            arch::serial::write_str(if refused {
                " byte(s) asked, refused\n"
            } else {
                " byte(s)\n"
            });
        }
        return Some(outcome);
    }

    // The datagram calls that answer at once: a bind, and a send.  The
    // receive is the branch below, because it parks, a handler that cannot
    // park does not hold a number whose caller may have to wait.
    // The raw socket's three calls, in one branch because two of them are
    // words and the third is the buffer `SendRawPacket` carries.  A raw call
    // is **not** a datagram call: the descriptor names a protocol rather than
    // a port, and `SendRawPacket`'s `a2` is the destination address's width
    // where `SendToUdp`'s is the buffer's pointer.  Sharing the datagram
    // branch, which the first version of this did, served a raw send with the
    if number == SyscallNumber::CreateRawSocket as usize
        || number == SyscallNumber::SendRawPacket as usize
    {
        let send_buffer = if number == SyscallNumber::SendRawPacket as usize {
            let buffer = call.arguments[3];
            let length = call.arguments[4];
            if !crate::address_space::is_user_range(buffer, length) {
                return Some(CallOutcome::Return(abi::syscall::encode_error(
                    abi::Error::InvalidArgument,
                )));
            }
            // SAFETY: the range is inside the user window and not empty,
            // which `is_user_range` checked, and the pages behind it are the
            // calling task's own mappings, installed on this CPU.  The handler
            // reads the bytes.
            Some(unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) })
        } else {
            None
        };
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, send_buffer);
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            if number == SyscallNumber::CreateRawSocket as usize {
                arch::serial::write_str(" made a raw socket for protocol ");
                arch::serial::write_u32(call.arguments[0] as u32);
                arch::serial::write_str(" as descriptor ");
                arch::serial::write_u32(answer as u32);
            } else {
                arch::serial::write_str(" sent a raw packet of ");
                arch::serial::write_u32(answer as u32);
                arch::serial::write_str(" byte(s)\n");
            }
            arch::serial::write_str("\n");
        }
        return Some(outcome);
    }
    if number == SyscallNumber::BindUdp as usize || number == SyscallNumber::SendToUdp as usize {
        // `SendToUdp` carries a buffer: `a2` the bytes, `a3` their length,
        // the same shape a file write is.  `BindUdp` names no address at
        // all, and its slots are the handler's to refuse.
        //
        // `SendRawPacket` carries one too, at `a3`/`a4`, because its `a1` and
        // `a2` are the destination's address and width: a raw send names a
        // family before it names its bytes.  `CreateRawSocket` takes no buffer
        // and shares the branch only because its arguments are words.
        let send_buffer = if number == SyscallNumber::SendToUdp as usize {
            let buffer = call.arguments[2];
            let length = call.arguments[3];
            if !crate::address_space::is_user_range(buffer, length) {
                return Some(CallOutcome::Return(abi::syscall::encode_error(
                    abi::Error::InvalidArgument,
                )));
            }
            // SAFETY: the range is inside the user window and not empty,
            // which `is_user_range` checked, and the pages behind it are the
            // calling task's own mappings, installed on this CPU.  The
            // handler reads the bytes; a copy-on-write page demoted by an
            // earlier write faults into the resolver like any other access.
            Some(unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) })
        } else {
            None
        };
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, send_buffer);
        // The evidence, printed by the kernel because a program has no way to
        // print one: the port bound and the descriptor it became, or the
        // datagram's own size beside the address and port it named.
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            if number == SyscallNumber::BindUdp as usize {
                arch::serial::write_str(" bound port ");
                arch::serial::write_u32(call.arguments[0] as u32);
                arch::serial::write_str(" as descriptor ");
                arch::serial::write_u32(answer as u32);
            } else {
                arch::serial::write_str(" sent ");
                arch::serial::write_u32(call.arguments[3] as u32);
                arch::serial::write_str(" byte(s) to ");
                write_ipv4_word(call.arguments[1]);
                arch::serial::write_str(" port ");
                arch::serial::write_u32(call.arguments[4] as u32);
            }
            arch::serial::write_str("\n");
        }
        return Some(outcome);
    }

    // The receive: one datagram from a bound socket, or a park until one
    // arrives.
    //
    // The park is the pipe reader's shape, and for the same reason: between
    // this call's own check and the park, a sender on another CPU can
    // deliver, and the wake that fact sends can fire into the gap.  The
    // re-check and the park are one critical section, so the delivery has
    // exactly two orders to find, the datagram first, and this call
    // answers it here, or the task parked first, and the delivery's wake
    // ends the wait.
    //
    // Before both, the card's ring is drained: a frame the card is holding
    if number == SyscallNumber::RecvFromUdp as usize {
        let descriptor = call.arguments[0];
        let buffer = call.arguments[1];
        let length = call.arguments[2];
        let sender_record = call.arguments[3];
        let sender_len = call.arguments[4];
        // `a5` is the flags word, and zero is what every caller before the
        // IPv6 side passed.  A bit this build does not define is refused
        // rather than ignored: a program that asked for a shape the kernel
        // silently dropped would read the record it did not get.
        let flags = call.arguments[5];
        if syscall::validate_known_flags(flags, abi::network::RECV_FROM_UDP_KNOWN_FLAGS).is_err() {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        // The record's required size follows the flag: a caller that set it is
        // asking for the sixteen-byte sender and gets refused if it passed a
        // record that cannot hold one.
        let record_size = if flags & abi::network::NETWORK_FLAG_IPV6 != 0 {
            abi::network::UDP_SENDER6_RECORD_SIZE
        } else {
            abi::network::UDP_SENDER_RECORD_SIZE
        };
        if !crate::address_space::is_user_range(buffer, length)
            || !crate::address_space::is_user_range(sender_record, sender_len)
            || sender_len < record_size
        {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let Some(socket) = crate::syscall::udp_socket_for(descriptor, caller) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        };
        // SAFETY: both ranges are inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind them are the calling
        // task's own mappings, installed on this CPU.  The receive writes the
        // buffer and the sender record and nothing past them, which is what
        // the record's length check is for.
        let destination = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) };
        let sender =
            unsafe { core::slice::from_raw_parts_mut(sender_record as *mut u8, sender_len) };

        crate::net::pump();
        let mut answer = receive_datagram_answer(&socket, destination, sender);
        if answer.is_none() {
            answer = crate::scheduler::block_unless(frame, || {
                receive_datagram_answer(&socket, destination, sender)
            });
        }
        return Some(match answer {
            None => {
                // Parked.  Resume something else; the frame was saved at the
                // call, so a wake returns here and the call is retried, and
                // the retry drains the card before it asks its question
                // again.
                arch::serial::write_str("protofire: a program blocks on a datagram socket\n");
                if !crate::scheduler::has_selectable() {
                    crate::scheduler::idle_until_woken();
                }
                crate::scheduler::switch_without_saving(frame)
            }
            Some(status) => {
                if !abi::syscall::is_error_status(status) {
                    // The sender the record now holds is the line's evidence:
                    // a receive that answered names where its datagram came
                    // from, which a caller can compare against the peer it
                    // expected.
                    let address = usize::from_le_bytes(
                        sender[..8].try_into().expect("the record's address word"),
                    );
                    let port = usize::from_le_bytes(
                        sender[8..16].try_into().expect("the record's port word"),
                    );
                    arch::serial::write_str("protofire: process ");
                    arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
                    arch::serial::write_str(" received ");
                    arch::serial::write_u32(status as u32);
                    arch::serial::write_str(" byte(s) from ");
                    write_ipv4_word(address);
                    arch::serial::write_str(" port ");
                    arch::serial::write_u32(port as u32);
                    arch::serial::write_str("\n");
                }
                CallOutcome::Return(status)
            }
        });
    }

    // A receive from a raw socket: a packet whose protocol number this side
    // named, or a park until one arrives.  The shape is the datagram
    // receiver's, and the two differences are the ones the call's arguments
    // state: there is no port to report, and the sender's record is sixteen
    // bytes for an IPv6 source and four for IPv4, which the record's own
    if number == SyscallNumber::RecvRawPacket as usize {
        let descriptor = call.arguments[0];
        let buffer = call.arguments[1];
        let length = call.arguments[2];
        let sender_record = call.arguments[3];
        // `a4` is the record's length and also the width of the source
        // address a program expects: four for IPv4 and sixteen for IPv6.  The
        // call has no flags word of its own, so the width is stated rather
        // than flagged, and a width that names neither family is refused.
        let sender_len = call.arguments[4];
        if sender_len != 4 && sender_len != 16 {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        if !crate::address_space::is_user_range(buffer, length)
            || !crate::address_space::is_user_range(sender_record, sender_len)
        {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let Some(socket) = crate::syscall::raw_socket_for(descriptor, caller) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        };
        // SAFETY: both ranges are inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind them are the calling
        // task's own mappings, installed on this CPU.  The receive writes the
        // buffer and the sender record and nothing past them.
        let destination = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) };
        let sender =
            unsafe { core::slice::from_raw_parts_mut(sender_record as *mut u8, sender_len) };

        // The card's ring is drained before the question is asked, the same
        // reason the datagram receive drains it: a frame the card is holding
        // is a packet in a queue rather than a wait that answers nothing.
        crate::net::pump();
        let ask = |socket: &alloc::sync::Arc<crate::net::RawSocket>,
                   destination: &mut [u8],
                   sender: &mut [u8]|
         -> Option<usize> {
            match socket.try_recv(destination) {
                Err(error) => Some(abi::syscall::encode_error(error)),
                Ok(None) => None,
                Ok(Some((source, count))) => {
                    match source {
                        net::address::Address::V4(bytes) => {
                            if sender.len() < 4 {
                                return Some(abi::syscall::encode_error(
                                    abi::Error::InvalidArgument,
                                ));
                            }
                            sender[..4].copy_from_slice(&bytes);
                        }
                        net::address::Address::V6(bytes) => {
                            if sender.len() < 16 {
                                return Some(abi::syscall::encode_error(
                                    abi::Error::InvalidArgument,
                                ));
                            }
                            sender[..16].copy_from_slice(&bytes);
                        }
                    }
                    Some(count)
                }
            }
        };
        let mut answer = ask(&socket, destination, sender);
        if answer.is_none() {
            answer = crate::scheduler::block_unless(frame, || ask(&socket, destination, sender));
        }
        return Some(match answer {
            None => {
                arch::serial::write_str("protofire: a program blocks on a raw socket\n");
                if !crate::scheduler::has_selectable() {
                    crate::scheduler::idle_until_woken();
                }
                crate::scheduler::switch_without_saving(frame)
            }
            Some(status) => {
                if !abi::syscall::is_error_status(status) {
                    arch::serial::write_str("protofire: process ");
                    arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
                    arch::serial::write_str(" received a raw packet, ");
                    arch::serial::write_u32(status as u32);
                    arch::serial::write_str(" byte(s)\n");
                }
                CallOutcome::Return(status)
            }
        });
    }

    // A read from a stream: the bytes the peer sent that this side has not
    // taken, or a park until some arrive.  The park is the pipe reader's
    // and the datagram receiver's shape, with the same re-check under the
    // scheduler's lock; the card's ring is drained first, so a frame the
    // card is holding is bytes in the stream's inbox rather than a wait
    // that answers nothing.
    //
    // End of file is the read that answers zero, and it comes from a stream
    // whose connection is gone, which an orderly close's last
    // acknowledgement leaves behind.  A read that never answered zero would
    if number == SyscallNumber::ListenTcp as usize || number == SyscallNumber::ConnectTcp as usize {
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            if number == SyscallNumber::ListenTcp as usize {
                arch::serial::write_str(" listening on port ");
                arch::serial::write_u32(call.arguments[0] as u32);
                arch::serial::write_str(" as descriptor ");
            } else {
                arch::serial::write_str(" connected to ");
                write_ipv4_word(call.arguments[0]);
                arch::serial::write_str(" port ");
                arch::serial::write_u32(call.arguments[1] as u32);
                arch::serial::write_str(" as stream ");
            }
            arch::serial::write_u32(answer as u32);
            arch::serial::write_str("\n");
        }
        return Some(outcome);
    }

    // The local accept: a connection from a name's queue, or a park until a
    // connect puts one there.  The handler answers `usize::MAX` for an empty
    // queue rather than parking itself, because it holds the registry's lock
    // and parking needs the scheduler; this branch is where the two meet.
    //
    // The wake is the connect's, which is a scheduler wake like the stream's,
    // and the re-check under the scheduler's lock is what closes the gap
    // between the `accept` above and the park: a connection made on another
    if number == SyscallNumber::AcceptLocal as usize {
        let descriptor = call.arguments[0];
        let owner = crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS);
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(owner);
        let mut answer = through_registry(&mut context, None, None, None);
        if matches!(answer, CallOutcome::Return(value) if value == usize::MAX) {
            // The queue was empty.  The re-check asks the same handler again
            // under the scheduler's lock; every answer but `usize::MAX` is the
            // call's answer.
            let name = crate::syscall::local_name_for(descriptor, Some(owner));
            let retried = crate::scheduler::block_unless(frame, || {
                let name = name.as_deref()?;
                match crate::local::accept(name.as_bytes()) {
                    Ok(Some(halves)) => Some(
                        crate::syscall::attach_local(halves, owner)
                            .unwrap_or_else(|| abi::syscall::encode_error(abi::Error::OutOfMemory)),
                    ),
                    // The queue is still empty, or the name went: the first is
                    // the park's own case and the second is an error this
                    // cannot answer from inside a re-check that must decide
                    // park or not.
                    Ok(None) => None,
                    Err(error) => Some(abi::syscall::encode_error(error)),
                }
            });
            answer = match retried {
                Some(value) => CallOutcome::Return(value),
                None => {
                    arch::serial::write_str(
                        "protofire: a program waits to accept a local connection\n",
                    );
                    if !crate::scheduler::has_selectable() {
                        crate::scheduler::idle_until_woken();
                    }
                    return Some(crate::scheduler::switch_without_saving(frame));
                }
            };
        }
        if let CallOutcome::Return(value) = answer
            && !abi::syscall::is_error_status(value)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(owner);
            arch::serial::write_str(" accepted a local connection as descriptor ");
            arch::serial::write_u32(value as u32);
            arch::serial::write_str("\n");
        }
        return Some(answer);
    }

    // The accept: one stream from a listener's pending list, or a park
    // until a client's SYN opens one.  The re-check under the scheduler's
    // lock is the same one every park here makes, and the SYN that fills
    // the list is what wakes it, the demux's own wake, which fires when a
    if number == SyscallNumber::AcceptTcp as usize {
        let descriptor = call.arguments[0];
        let Some(listener) = crate::syscall::tcp_listener_for(descriptor, caller) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        };
        crate::net::pump();
        let mut answer = crate::net::tcp_accept(listener);
        if answer == Ok(None) {
            match crate::scheduler::block_unless(frame, || match crate::net::tcp_accept(listener) {
                Ok(None) => None,
                other => Some(other),
            }) {
                Some(retried) => answer = retried,
                None => {
                    arch::serial::write_str("protofire: a program waits to accept a stream\n");
                    if !crate::scheduler::has_selectable() {
                        crate::scheduler::idle_until_woken();
                    }
                    return Some(crate::scheduler::switch_without_saving(frame));
                }
            }
        }
        return Some(match answer {
            Ok(Some(stream)) => {
                let owner =
                    crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS);
                match crate::syscall::attach_tcp_stream(stream, owner) {
                    Some(descriptor) => {
                        arch::serial::write_str("protofire: process ");
                        arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
                        arch::serial::write_str(" accepted a stream as descriptor ");
                        arch::serial::write_u32(descriptor as u32);
                        arch::serial::write_str("\n");
                        CallOutcome::Return(descriptor)
                    }
                    None => {
                        CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotImplemented))
                    }
                }
            }
            Ok(None) => CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotFound)),
            Err(error) => CallOutcome::Return(abi::syscall::encode_error(error)),
        });
    }

    None
}
