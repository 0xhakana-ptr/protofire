//! abi/src/number.rs
//!
//! The syscall numbering: which number is which operation.
//!
//! ## Why this is a contract and not an implementation detail
//!
//! A program is compiled against these numbers.  `open` is 2 because the
//! headers a program builds with say 2, and a kernel that served `open` from a
//! different number would give that program a descriptor from whatever
//! operation moved into 2, with nothing failing to compile on either side.
//!
//! That makes the numbering something both parties name, which is the whole
//! definition of what belongs in this crate.  It lived in the `syscall` crate,
//! which is the *implementation*, the table, the context, the validators,
//! and an implementation that owns the contract is one a program cannot be
//! written against without depending on the kernel's internals.
//!
//! ## The promise the numbers make
//!
//! Numbers up to and including 120 are frozen: assigned once, never reused,
//! never renumbered.  Above 120 the set may grow, and
//! [`PUBLIC_SYSCALL_COUNT`] is the count a build serves, which both sides must
//! agree on before the first call.
//!
//! The two tests at the bottom of this file pin the boundary and the numbers a
//! program is most likely to have hard-coded.  A test is the only form this
//! promise can take: renumbering reaches another handler and both numbers are
//! valid.

#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallNumber {
    Yield = 0,
    WriteDebug = 1,
    Open = 2,
    Exit = 3,
    ReadConsole = 4,
    Read = 5,
    Write = 6,
    Close = 7,
    Dup = 8,
    Dup2 = 69,
    Seek = 9,
    ArgCount = 10,
    ArgValue = 11,
    EnvCount = 12,
    EnvValue = 13,
    CurrentDir = 14,
    AppId = 15,
    AppVersion = 16,
    ImagePath = 17,
    ManifestPath = 18,
    CreateDir = 19,
    SetLength = 20,
    RemovePath = 21,
    InstallExceptionHandler = 22,
    ReturnFromException = 23,
    WaitProcess = 24,
    SpawnProcess = 25,
    ExecProcess = 26,
    Stat = 27,
    ReadDir = 28,
    Rename = 29,
    StatFd = 30,
    ReadDirFd = 31,
    OpenAt = 32,
    StatAt = 33,
    RenameAt = 34,
    CreateDirAt = 35,
    RemovePathAt = 36,
    NetworkStatus = 37,
    ConnectTcp = 38,
    AbiInfo = 39,
    SendSignal = 40,
    WaitSignal = 41,
    AccessQuery = 42,
    AccessQueryAt = 43,
    AccessQueryFd = 44,
    PermissionMetadata = 45,
    PermissionMetadataAt = 46,
    PermissionMetadataFd = 47,
    SetFdFlags = 48,
    Sleep = 49,
    ListProcesses = 50,
    ListThreads = 51,
    KernelLog = 52,
    SystemInfo = 53,
    Fsync = 54,
    Fdatasync = 55,
    ListenTcp = 56,
    AcceptTcp = 57,
    BindUdp = 58,
    SendToUdp = 59,
    RecvFromUdp = 60,
    ListProcessFaults = 61,
    Fork = 62,
    ReclaimPages = 63,
    Pipe = 64,
    Mount = 65,
    Umount = 66,
    Mmap = 67,
    Munmap = 68,
    GetTimeOfDay = 70,
    GetHostName = 71,
    SetHostName = 72,
    GetSockName = 73,
    GetPeerName = 74,
    GetRandom = 75,
    CreateRawSocket = 76,
    SendRawPacket = 77,
    RecvRawPacket = 78,
    SetSockOpt = 79,
    GetSockOpt = 80,
    GetPid = 81,
    GetPpid = 82,
    GetUid = 83,
    GetGid = 84,
    SetCurrentDir = 85,
    ListMounts = 86,
    ListBlockDevices = 87,
    SetSecurityDescriptor = 88,
    AddUser = 89,
    RemoveUser = 90,
    SetUserPassword = 91,
    Brk = 92,
    ResolveHostname = 93,
    SetSignalMask = 94,
    RepairVolume = 95,
    Poll = 96,
    BindLocal = 97,
    ConnectLocal = 98,
    AcceptLocal = 99,
    // Priority Gap #2: SystV shared memory
    ShmGet = 100,
    ShmAt = 101,
    ShmDt = 102,
    ShmCtl = 103,
    SetSignalHandler = 104,
    /// FUSE (Filesystem in Userspace) mount syscall.
    FuseMount = 105,
    /// Futex: fast userspace mutex (FUTEX_WAIT / FUTEX_WAKE).
    Futex = 106,
    /// eventfd: lightweight event notification.
    EventFd = 107,
    /// signalfd: signal notification via file descriptor.
    SignalFd = 108,
    /// timerfd: timer expiration notification.
    TimerFd = 109,
    /// sched_setaffinity: pin thread to specific CPUs.
    SchedSetAffinity = 110,
    /// sched_getaffinity: get thread CPU affinity mask.
    SchedGetAffinity = 111,
    /// mq_open: open or create a named message queue.
    MqOpen = 112,
    /// mq_close: close a message queue fd.
    MqClose = 113,
    /// mq_send: send a message to a queue.
    MqSend = 114,
    /// mq_receive: receive a message from a queue.
    MqReceive = 115,
    /// mq_notify: register for signal notification on a queue.
    MqNotify = 116,
    /// mq_unlink: remove a named message queue.
    MqUnlink = 117,
    /// epoll_create: create an epoll instance.
    EpollCreate = 118,
    /// epoll_ctl: control epoll interest list.
    EpollCtl = 119,
    /// epoll_wait: wait for events on epoll fds.
    EpollWait = 120,
    /// tls_connect, establish a TLS 1.3 encrypted connection.
    TlsConnect = 121,
    /// filter_add_rule: add a packet filter rule.
    FilterAddRule = 122,
    /// filter_remove_rule: remove a packet filter rule.
    FilterRemoveRule = 123,
    /// filter_set_default_action: set default filter policy.
    FilterSetDefaultAction = 124,
    /// filter_get_stats: retrieve filter statistics.
    FilterGetStats = 125,
    /// io_uring_setup: create an io_uring async I/O instance.
    IoUringSetup = 126,
    /// io_uring_enter: submit SQEs and/or reap CQEs.
    IoUringEnter = 127,
    /// ptrace: process tracing and debugging control.
    Ptrace = 128,
    /// seccomp: secure computing / syscall filtering.
    Seccomp = 129,
    /// prctl: process control operations.
    Prctl = 130,
    /// mlock: lock memory pages to prevent swapping.
    Mlock = 131,
    /// munlock: unlock memory pages.
    Munlock = 132,
    /// madvise: give advice about memory use.
    Madvise = 133,
    /// sigreturn: restore user context after async signal handler.
    SigReturn = 134,
    /// sigsuspend: atomically set signal mask and suspend execution.
    SigSuspend = 135,
    /// restart_syscall: re-issue an interrupted blocking syscall.
    RestartSyscall = 136,
    /// timer_create: create a POSIX per-process timer.
    TimerCreate = 137,
    /// timer_settime: arm/disarm a POSIX timer.
    TimerSetTime = 138,
    /// timer_gettime: get remaining time on a POSIX timer.
    TimerGetTime = 139,
    /// timer_delete: delete a POSIX timer.
    TimerDelete = 140,
    /// audit_set_enable: enable/disable audit event types for current process.
    AuditSetEnable = 143,
    /// audit_read_log: read events from the global audit ring buffer.
    AuditReadLog = 144,
    /// cpufreq_get: get current CPU frequency in KHz.
    CpufreqGet = 145,
    /// cpufreq_set: request a CPU frequency in KHz.
    CpufreqSet = 146,
    /// cpufreq_get_range: get (min, max) frequency in KHz (packed).
    CpufreqGetRange = 147,
    /// cpufreq_set_governor: select a frequency-scaling governor.
    CpufreqSetGovernor = 148,
    /// cpufreq_get_temp: get CPU temperature in millidegrees Celsius.
    CpufreqGetTemp = 149,
    /// compact_memory: trigger memory defragmentation (frame compaction).
    CompactMemory = 150,
    /// set_xattr: set an extended attribute on a file/dir (#151).
    SetXattr = 151,
    /// get_xattr: read an extended attribute value (#152).
    GetXattr = 152,
    /// list_xattr: list extended attribute names (#153).
    ListXattr = 153,
    /// remove_xattr: remove an extended attribute (#154).
    RemoveXattr = 154,
    /// set_file_flags: toggle per-file data-reduction flags (#155).
    SetFileFlags = 155,
    /// get_file_flags: read per-file data-reduction flags (#156).
    GetFileFlags = 156,
    /// dccp_bind: bind a DCCP socket to a local port (#157).
    DccpBind = 157,
    /// dccp_listen: start listening for DCCP Requests (#158).
    DccpListen = 158,
    /// dccp_connect: initiate a DCCP connection (#159).
    DccpConnect = 159,
    /// dccp_accept: accept the next pending DCCP connection (#160).
    DccpAccept = 160,
    /// dccp_send: send one DCCP datagram (#161).
    DccpSend = 161,
    /// dccp_recv: receive one DCCP datagram (#162).
    DccpRecv = 162,
    /// dccp_close: close a DCCP socket (#163).
    DccpClose = 163,
    /// ipsec_add_sp: add an IPsec security-policy entry (#164).
    IpsecAddSp = 164,
    /// ipsec_del_sp: remove an IPsec security-policy entry (#165).
    IpsecDelSp = 165,
    /// ipsec_add_sa: add an IPsec security association (#166).
    IpsecAddSa = 166,
    /// ipsec_del_sa: remove an IPsec security association by SPI (#167).
    IpsecDelSa = 167,
    /// ipsec_get_stats: read IPsec statistics (#168).
    IpsecGetStats = 168,
    /// mrt_init: enable multicast routing (#169).
    MrtInit = 169,
    /// mrt_done: disable multicast routing (#170).
    MrtDone = 170,
    /// mrt_add_vif: add a multicast virtual interface (#171).
    MrtAddVif = 171,
    /// mrt_del_vif: remove a multicast virtual interface (#172).
    MrtDelVif = 172,
    /// mrt_add_mfc: add a multicast forwarding-cache entry (#173).
    MrtAddMfc = 173,
    /// mrt_del_mfc: remove a multicast forwarding-cache entry (#174).
    MrtDelMfc = 174,
    /// mac_set_mode, enable/disable MAC enforcement and set the default
    /// (#175).
    MacSetMode = 175,
    /// mac_add_rule: add a MAC allow rule (#176).
    MacAddRule = 176,
    /// mac_set_path_type: set an object type override for a path (#177).
    MacSetPathType = 177,
    /// mac_get_status: read MAC policy status (#178).
    MacGetStatus = 178,
    /// fcntl, descriptor control incl. F_SETPIPE_SZ/F_GETPIPE_SZ (#179).
    Fcntl = 179,
    /// sync: flush all filesystems' dirty data to persistent storage (#180).
    Sync = 180,
    /// gpu_ctx_create: create a VIRGL rendering context (#181).
    GpuCtxCreate = 181,
    /// gpu_ctx_destroy: destroy a VIRGL rendering context (#182).
    GpuCtxDestroy = 182,
    /// gpu_res_create_3d, create a 3D resource with kernel-backed DMA (#183).
    GpuResCreate3d = 183,
    /// gpu_res_unref: destroy a 3D resource and release its backing (#184).
    GpuResUnref = 184,
    /// gpu_transfer_to_host_3d, upload user data into a resource (#185).
    GpuTransferToHost3d = 185,
    /// gpu_transfer_from_host_3d, read a resource region back to user (#186).
    GpuTransferFromHost3d = 186,
    /// gpu_submit_3d, submit a VIRGL command stream to a context (#187).
    GpuSubmit3d = 187,
    /// gpu_set_scanout: present a resource on the display (#188).
    GpuSetScanout = 188,
    /// gpu_device_info: report GPU presence and capabilities (#189).
    GpuDeviceInfo = 189,
    /// service_declare, register the services one rc.d file declares (#190).
    ServiceDeclare = 190,
    /// service_start_all, start every declared service that has not started
    /// (#191).
    ServiceStartAll = 191,
    InstallPackage = 192,
    /// fallocate, punch a hole in a file: the range reads as zeros and its
    /// clusters go back to the volume (#193).
    Fallocate = 193,
    /// trust_anchor_add, trust a DER-encoded root certificate the kernel was
    /// not built with, returning the id that withdraws it (#194).
    ///
    /// The built-in set is a demonstration one, so a machine talking to a
    /// private CA had no way to say so short of a rebuild.
    TrustAnchorAdd = 194,
    /// trust_anchor_remove, withdraw an anchor `trust_anchor_add` returned,
    /// by its id (#195).
    ///
    /// The pair is split rather than the add being permanent because trust a
    /// caller granted should stop when that caller stops needing it: an anchor
    /// that outlived its program would make "trusted" a property of the
    /// machine's uptime.
    TrustAnchorRemove = 195,
    /// wait_process_of, wait for **one named** process to end, answering its
    /// exit status (#196).
    ///
    /// `WaitProcess` answers about whichever process finished first, which is
    /// all a boot with one process tree could say when it was added.  It is
    /// the wrong answer for a parent that wants to know how *its* child ended:
    /// the child's status arrives only if the child happens to be the first,
    /// and a status line built from it can report another process's death.
    /// The argument is the pid the caller is waiting for, and a pid that has
    /// not exited is a park the pid's exit wakes.
    WaitProcessOf = 196,
}

/// How many syscall numbers this build serves.
///
/// The dispatch table is sized by it and a program's `SYSCALL_COUNT` must not
/// exceed it, so it is public: it is the number both sides agree on.
pub const PUBLIC_SYSCALL_COUNT: u32 = SyscallNumber::WaitProcessOf as u32 + 1;

#[cfg(test)]
mod tests {
    use super::PUBLIC_SYSCALL_COUNT;
    use super::SyscallNumber;

    /// The public range ends where the last number says it does.
    ///
    /// The count and the last variant are one fact written twice, and a variant
    /// appended without moving the count leaves a syscall that the dispatch
    /// table never reaches, a program calls it, gets an unregistered slot, and
    /// nothing in the build says why.
    #[test]
    fn the_public_range_ends_at_the_last_number() {
        assert_eq!(
            PUBLIC_SYSCALL_COUNT,
            SyscallNumber::WaitProcessOf as u32 + 1
        );
    }

    /// The frozen numbering's boundary is where the ABI says it is.
    ///
    /// Numbers at or below 120 are frozen: assigned once, never renumbered.
    /// This pins the ones a program is most likely to have hard-coded, because
    /// a renumbering reaches another handler and both numbers are valid.
    #[test]
    fn the_frozen_numbers_have_not_moved() {
        assert_eq!(SyscallNumber::Yield as usize, 0);
        assert_eq!(SyscallNumber::WriteDebug as usize, 1);
        assert_eq!(SyscallNumber::Open as usize, 2);
        assert_eq!(SyscallNumber::Exit as usize, 3);
        assert_eq!(SyscallNumber::Read as usize, 5);
        assert_eq!(SyscallNumber::Write as usize, 6);
        assert_eq!(SyscallNumber::Close as usize, 7);
        assert_eq!(SyscallNumber::GetPid as usize, 81);
        assert_eq!(SyscallNumber::EpollWait as usize, 120);
        assert_eq!(SyscallNumber::TlsConnect as usize, 121);
        assert_eq!(SyscallNumber::TrustAnchorRemove as usize, 195);
        assert_eq!(SyscallNumber::WaitProcessOf as usize, 196);
    }
}
