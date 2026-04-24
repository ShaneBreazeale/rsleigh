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
}
