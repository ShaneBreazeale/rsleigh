//! Direct-syscall annotation for x86-64 Windows.
//!
//! Modern malware and EDR-bypass techniques invoke NT APIs via raw `syscall`
//! instructions (`mov eax, <num>; syscall`) to dodge userland hooks. rsleigh
//! surfaces those as opaque `syscall()` user-pcodeops. This module maps
//! syscall numbers to NT API names so the decompiler can annotate them.
//!
//! # Version sensitivity
//!
//! Windows syscall numbers are **not stable** — they shift between Windows
//! versions (even between build updates). The table below is Win11 24H2 +
//! Win10 22H2 x64 ntdll, sourced from publicly-documented dumps
//! (j00ru/windows-syscalls, SysWhispers). Callers should treat results as a
//! hint with version in the annotation (`NtAllocateVirtualMemory` for Win10
//! build X, may differ on other builds).
//!
//! Only x64 supported for now. Win32k / graphics syscalls (0x1000+) are
//! currently not included — they are process-attach gated and rarely seen in
//! malware triage.

/// Syscall number → NT API name for Windows 11 24H2 x64 ntdll.
///
/// Non-exhaustive — covers the ~120 syscalls most commonly observed in
/// malware families (process/thread/memory/file/registry/object ops).
/// Unknown numbers return `None`; caller should fall back to raw id.
pub fn win11_24h2_x64_syscall(num: u32) -> Option<&'static str> {
    Some(match num {
        0x00 => "NtAccessCheck",
        0x02 => "NtWorkerFactoryWorkerReady",
        0x03 => "NtAcceptConnectPort",
        0x04 => "NtMapUserPhysicalPagesScatter",
        0x05 => "NtWaitForSingleObject",
        0x06 => "NtCallbackReturn",
        0x07 => "NtReadFile",
        0x08 => "NtDeviceIoControlFile",
        0x09 => "NtWriteFile",
        0x0A => "NtRemoveIoCompletion",
        0x0B => "NtReleaseSemaphore",
        0x0C => "NtReplyWaitReceivePort",
        0x0D => "NtReplyPort",
        0x0E => "NtSetInformationThread",
        0x0F => "NtSetEvent",
        0x10 => "NtClose",
        0x11 => "NtQueryObject",
        0x12 => "NtQueryInformationFile",
        0x13 => "NtOpenKey",
        0x14 => "NtEnumerateValueKey",
        0x15 => "NtFindAtom",
        0x16 => "NtQueryDefaultLocale",
        0x17 => "NtQueryKey",
        0x18 => "NtQueryValueKey",
        0x19 => "NtAllocateVirtualMemory",
        0x1A => "NtQueryInformationProcess",
        0x1B => "NtWaitForMultipleObjects32",
        0x1C => "NtWriteFileGather",
        0x1D => "NtSetInformationProcess",
        0x1E => "NtCreateKey",
        0x1F => "NtFreeVirtualMemory",
        0x20 => "NtImpersonateClientOfPort",
        0x21 => "NtReleaseMutant",
        0x22 => "NtQueryInformationToken",
        0x23 => "NtRequestWaitReplyPort",
        0x24 => "NtQueryVirtualMemory",
        0x25 => "NtOpenThreadToken",
        0x26 => "NtQueryPerformanceCounter",
        0x27 => "NtEnumerateKey",
        0x28 => "NtOpenFile",
        0x29 => "NtDelayExecution",
        0x2A => "NtQueryDirectoryFile",
        0x2B => "NtQuerySystemInformation",
        0x2C => "NtOpenSection",
        0x2D => "NtQueryTimer",
        0x2E => "NtFsControlFile",
        0x2F => "NtWriteVirtualMemory",
        0x30 => "NtCloseObjectAuditAlarm",
        0x31 => "NtDuplicateObject",
        0x32 => "NtQueryAttributesFile",
        0x33 => "NtClearEvent",
        0x34 => "NtReadVirtualMemory",
        0x35 => "NtOpenEvent",
        0x36 => "NtAdjustPrivilegesToken",
        0x37 => "NtDuplicateToken",
        0x38 => "NtContinue",
        0x39 => "NtQueryDefaultUILanguage",
        0x3A => "NtQueueApcThread",
        0x3B => "NtYieldExecution",
        0x3C => "NtAddAtom",
        0x3D => "NtCreateEvent",
        0x3E => "NtQueryVolumeInformationFile",
        0x3F => "NtCreateSection",
        0x40 => "NtFlushBuffersFile",
        0x41 => "NtApphelpCacheControl",
        0x42 => "NtCreateProcessEx",
        0x43 => "NtCreateThread",
        0x44 => "NtIsProcessInJob",
        0x45 => "NtProtectVirtualMemory",
        0x46 => "NtQuerySection",
        0x47 => "NtResumeThread",
        0x48 => "NtTerminateProcess",
        0x49 => "NtReadRequestData",
        0x4A => "NtCreateFile",
        0x4B => "NtQueryEvent",
        0x4C => "NtWriteRequestData",
        0x4D => "NtOpenDirectoryObject",
        0x4E => "NtAccessCheckAndAuditAlarm",
        0x4F => "NtQuerySystemTime",
        0x50 => "NtWaitForMultipleObjects",
        0x51 => "NtSetInformationObject",
        0x52 => "NtCancelIoFile",
        0x53 => "NtTraceEvent",
        0x54 => "NtPowerInformation",
        0x55 => "NtSetValueKey",
        0x56 => "NtCancelTimer",
        0x57 => "NtSetTimer",
        0x58 => "NtAcceptConnectPort",
        0x59 => "NtAccessCheckByType",
        0x5A => "NtAccessCheckByTypeAndAuditAlarm",
        0x5B => "NtAccessCheckByTypeResultList",
        0x5C => "NtAccessCheckByTypeResultListAndAuditAlarm",
        0x5D => "NtAccessCheckByTypeResultListAndAuditAlarmByHandle",
        0x5E => "NtAcquireProcessActivityReference",
        0x5F => "NtAddBootEntry",
        0x60 => "NtAddDriverEntry",
        0x6C => "NtCreateThreadEx",
        0x6D => "NtCreateTimer",
        0x6E => "NtCreateTimer2",
        0x7A => "NtOpenProcess",
        0x7B => "NtOpenProcessToken",
        0x7D => "NtOpenThread",
        0x7E => "NtOpenThreadToken",
        0x80 => "NtOpenSymbolicLinkObject",
        0xA5 => "NtResumeProcess",
        0xAC => "NtSetContextThread",
        0xBE => "NtSuspendThread",
        0xC1 => "NtTerminateThread",
        0xD4 => "NtUnmapViewOfSection",
        0xF9 => "NtCreateUserProcess",
        _ => return None,
    })
}

/// Best-effort cross-Windows-version resolution. Currently just delegates to
/// Win11 24H2; future callers may want to try multiple tables and report all
/// candidates.
pub fn resolve_x64_syscall(num: u32) -> Option<&'static str> {
    win11_24h2_x64_syscall(num)
}

/// Linux x86_64 syscall table (kernel ABI, `syscall` with rax = number).
///
/// Kernel-stable across versions for the numbers below. Full table has
/// ~450 entries; this covers the ~140 most commonly-seen ones in
/// malware/dropper analysis (file/memory/process/network/futex/eventfd
/// + ptrace + module load/unload). Source: arch/x86/entry/syscalls/syscall_64.tbl
/// from the upstream Linux kernel.
pub fn linux_x86_64_syscall(num: u32) -> Option<&'static str> {
    Some(match num {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        4 => "stat",
        5 => "fstat",
        6 => "lstat",
        7 => "poll",
        8 => "lseek",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        13 => "rt_sigaction",
        14 => "rt_sigprocmask",
        15 => "rt_sigreturn",
        16 => "ioctl",
        17 => "pread64",
        18 => "pwrite64",
        19 => "readv",
        20 => "writev",
        21 => "access",
        22 => "pipe",
        23 => "select",
        24 => "sched_yield",
        25 => "mremap",
        26 => "msync",
        27 => "mincore",
        28 => "madvise",
        32 => "dup",
        33 => "dup2",
        34 => "pause",
        35 => "nanosleep",
        38 => "setitimer",
        39 => "getpid",
        40 => "sendfile",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        46 => "sendmsg",
        47 => "recvmsg",
        48 => "shutdown",
        49 => "bind",
        50 => "listen",
        51 => "getsockname",
        52 => "getpeername",
        53 => "socketpair",
        54 => "setsockopt",
        55 => "getsockopt",
        56 => "clone",
        57 => "fork",
        58 => "vfork",
        59 => "execve",
        60 => "exit",
        61 => "wait4",
        62 => "kill",
        63 => "uname",
        72 => "fcntl",
        73 => "flock",
        74 => "fsync",
        75 => "fdatasync",
        76 => "truncate",
        77 => "ftruncate",
        78 => "getdents",
        79 => "getcwd",
        80 => "chdir",
        81 => "fchdir",
        82 => "rename",
        83 => "mkdir",
        84 => "rmdir",
        85 => "creat",
        86 => "link",
        87 => "unlink",
        88 => "symlink",
        89 => "readlink",
        90 => "chmod",
        91 => "fchmod",
        92 => "chown",
        93 => "fchown",
        94 => "lchown",
        96 => "gettimeofday",
        97 => "getrlimit",
        98 => "getrusage",
        99 => "sysinfo",
        100 => "times",
        101 => "ptrace",
        102 => "getuid",
        104 => "getgid",
        105 => "setuid",
        106 => "setgid",
        107 => "geteuid",
        108 => "getegid",
        110 => "getppid",
        137 => "statfs",
        138 => "fstatfs",
        158 => "arch_prctl",
        165 => "mount",
        166 => "umount2",
        169 => "reboot",
        175 => "init_module",
        176 => "delete_module",
        186 => "gettid",
        201 => "time",
        202 => "futex",
        213 => "epoll_create",
        217 => "getdents64",
        218 => "set_tid_address",
        221 => "fadvise64",
        228 => "clock_gettime",
        231 => "exit_group",
        232 => "epoll_wait",
        233 => "epoll_ctl",
        253 => "inotify_init",
        254 => "inotify_add_watch",
        257 => "openat",
        258 => "mkdirat",
        260 => "fchownat",
        262 => "newfstatat",
        263 => "unlinkat",
        265 => "linkat",
        266 => "symlinkat",
        267 => "readlinkat",
        269 => "faccessat",
        270 => "pselect6",
        271 => "ppoll",
        272 => "unshare",
        281 => "epoll_pwait",
        284 => "eventfd",
        288 => "accept4",
        290 => "eventfd2",
        291 => "epoll_create1",
        292 => "dup3",
        293 => "pipe2",
        294 => "inotify_init1",
        302 => "prlimit64",
        310 => "process_vm_readv",
        311 => "process_vm_writev",
        318 => "getrandom",
        319 => "memfd_create",
        321 => "bpf",
        322 => "execveat",
        323 => "userfaultfd",
        324 => "membarrier",
        325 => "mlock2",
        326 => "copy_file_range",
        332 => "statx",
        435 => "clone3",
        437 => "openat2",
        439 => "faccessat2",
        _ => return None,
    })
}

/// macOS x86_64 syscall table. macOS encodes the BSD class in the high bits:
/// `0x02000000 | N` for the BSD layer, `0x01000000 | N` for Mach traps,
/// `0x03000000 | N` for Mach-Diag. This resolver strips the class bits and
/// returns the BSD-class name when it matches.
///
/// Numbers from `bsd/kern/syscalls.master` (Apple Open Source). Covers
/// the ~80 syscalls most commonly seen in macOS malware/dropper triage.
pub fn macos_x86_64_syscall(num: u32) -> Option<&'static str> {
    let class = num & 0xFF000000;
    let n = num & 0x00FFFFFF;
    if class != 0 && class != 0x02000000 {
        // Mach trap or other class — outside this table.
        return None;
    }
    Some(match n {
        1 => "exit",
        2 => "fork",
        3 => "read",
        4 => "write",
        5 => "open",
        6 => "close",
        7 => "wait4",
        9 => "link",
        10 => "unlink",
        12 => "chdir",
        13 => "fchdir",
        14 => "mknod",
        15 => "chmod",
        16 => "chown",
        18 => "getfsstat",
        20 => "getpid",
        23 => "setuid",
        24 => "getuid",
        25 => "geteuid",
        26 => "ptrace",
        27 => "recvmsg",
        28 => "sendmsg",
        29 => "recvfrom",
        30 => "accept",
        31 => "getpeername",
        32 => "getsockname",
        33 => "access",
        37 => "kill",
        39 => "getppid",
        41 => "dup",
        42 => "pipe",
        43 => "getegid",
        46 => "sigaction",
        47 => "getgid",
        48 => "sigprocmask",
        49 => "getlogin",
        53 => "sigaltstack",
        54 => "ioctl",
        55 => "reboot",
        58 => "readlink",
        59 => "execve",
        60 => "umask",
        61 => "chroot",
        65 => "msync",
        66 => "vfork",
        73 => "munmap",
        74 => "mprotect",
        75 => "madvise",
        78 => "mincore",
        79 => "getgroups",
        80 => "setgroups",
        81 => "getpgrp",
        82 => "setpgid",
        83 => "setitimer",
        85 => "swapon",
        86 => "getitimer",
        89 => "getdtablesize",
        90 => "dup2",
        92 => "fcntl",
        93 => "select",
        95 => "fsync",
        96 => "setpriority",
        97 => "socket",
        98 => "connect",
        100 => "getpriority",
        104 => "bind",
        105 => "setsockopt",
        106 => "listen",
        116 => "gettimeofday",
        117 => "getrusage",
        118 => "getsockopt",
        120 => "readv",
        121 => "writev",
        122 => "settimeofday",
        123 => "fchown",
        124 => "fchmod",
        126 => "rename",
        128 => "rename",
        131 => "flock",
        132 => "mkfifo",
        133 => "sendto",
        134 => "shutdown",
        135 => "socketpair",
        136 => "mkdir",
        137 => "rmdir",
        138 => "utimes",
        139 => "futimes",
        140 => "adjtime",
        165 => "quotactl",
        169 => "csops",
        170 => "csops_audittoken",
        185 => "ledger",
        197 => "mmap",
        199 => "lseek",
        202 => "sysctl",
        220 => "getattrlist",
        221 => "setattrlist",
        225 => "searchfs",
        232 => "fhopen",
        234 => "minherit",
        235 => "semsys",
        236 => "msgsys",
        237 => "shmsys",
        265 => "shm_open",
        266 => "shm_unlink",
        286 => "pthread_kill",
        287 => "pthread_sigmask",
        296 => "shared_region_map_np",
        327 => "issetugid",
        336 => "proc_info",
        338 => "stat64",
        339 => "fstat64",
        340 => "lstat64",
        344 => "getdirentries64",
        357 => "getfsstat64",
        360 => "bsdthread_create",
        361 => "bsdthread_terminate",
        362 => "kqueue",
        363 => "kevent",
        366 => "bsdthread_register",
        368 => "fsgetpath",
        372 => "thread_selfid",
        381 => "sandbox_ms",
        396 => "read_nocancel",
        397 => "write_nocancel",
        398 => "open_nocancel",
        399 => "close_nocancel",
        404 => "kill_nocancel",
        420 => "mac_syscall",
        428 => "audit_session_self",
        430 => "kqueue_workloop_ctl",
        434 => "fileport_makeport",
        435 => "fileport_makefd",
        443 => "guarded_kqueue_np",
        444 => "csrctl",
        445 => "stack_snapshot_with_config",
        451 => "sysctlbyname",
        454 => "necp_match_policy",
        457 => "openat",
        468 => "renameatx_np",
        500 => "getentropy",
        514 => "fclonefileat",
        520 => "fsetattrlistat",
        521 => "ulock_wait",
        522 => "ulock_wake",
        525 => "task_inspect_for_pid",
        526 => "task_read_for_pid",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_syscalls_resolve() {
        assert_eq!(resolve_x64_syscall(0x19), Some("NtAllocateVirtualMemory"));
        assert_eq!(resolve_x64_syscall(0x50), Some("NtWaitForMultipleObjects"));
        assert_eq!(resolve_x64_syscall(0x48), Some("NtTerminateProcess"));
    }

    #[test]
    fn unknown_syscall_is_none() {
        assert_eq!(resolve_x64_syscall(0xFFFF), None);
    }

    #[test]
    fn linux_common_syscalls_resolve() {
        assert_eq!(linux_x86_64_syscall(0), Some("read"));
        assert_eq!(linux_x86_64_syscall(1), Some("write"));
        assert_eq!(linux_x86_64_syscall(9), Some("mmap"));
        assert_eq!(linux_x86_64_syscall(59), Some("execve"));
        assert_eq!(linux_x86_64_syscall(60), Some("exit"));
        assert_eq!(linux_x86_64_syscall(231), Some("exit_group"));
        assert_eq!(linux_x86_64_syscall(318), Some("getrandom"));
        assert_eq!(linux_x86_64_syscall(99999), None);
    }

    #[test]
    fn macos_strips_bsd_class_bit() {
        // macOS encodes BSD syscalls as 0x02000000 | N. Both forms must
        // resolve to the same name.
        assert_eq!(macos_x86_64_syscall(1), Some("exit"));
        assert_eq!(macos_x86_64_syscall(0x02000001), Some("exit"));
        assert_eq!(macos_x86_64_syscall(197), Some("mmap"));
        assert_eq!(macos_x86_64_syscall(0x020000C5), Some("mmap"));
        assert_eq!(macos_x86_64_syscall(500), Some("getentropy"));
    }

    #[test]
    fn macos_mach_class_returns_none() {
        // 0x01000000 = Mach trap class — outside this BSD table.
        assert_eq!(macos_x86_64_syscall(0x01000001), None);
    }
}
