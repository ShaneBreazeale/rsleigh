use rsleigh_decompile::peb_walk::djb2a_api;

fn main() {
    let hashes: &[u32] = &[
        0x3e003875, 0xcba985ff, 0xe91aad51, 0x1687a330, 0x17ea484f, 0x19fbbf49,
        0x2eeeae15, 0x33bfa5f6, 0x3eb9f90d, 0x3ef073da, 0x411b83a2, 0x4c05c8e3,
        0x4d9faf9f, 0x66a720a5, 0x687c0d79, 0x713f7ed4, 0x89ecab1a, 0x8be68952,
        0x8e5b39d1, 0x8e650d75, 0x90c612ce, 0x9210eadc, 0x97cf1bff, 0x9b554176,
        0xa3e21f99, 0xa6572adc, 0xaadfab0b, 0xb67acbef, 0xbcc2e5bf, 0xc28047cd,
        0xc76b4e42, 0xcd363694, 0xd94ef14b, 0xdd82c128, 0xf0146ce2, 0xf43a35ad,
    ];

    let modules = [
        "kernel32.dll", "ntdll.dll", "ws2_32.dll", "advapi32.dll", "user32.dll",
        "wininet.dll", "winhttp.dll", "crypt32.dll", "bcrypt.dll", "psapi.dll",
        "shell32.dll", "secur32.dll", "kernelbase.dll", "msvcrt.dll", "dbghelp.dll",
        "iphlpapi.dll", "shlwapi.dll",
    ];

    let apis = [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "NtSetInformationThread", "OutputDebugStringA", "OutputDebugStringW",
        "DebugActiveProcess", "DebugActiveProcessStop",
        "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualProtect",
        "VirtualProtectEx", "VirtualQuery", "VirtualLock", "VirtualUnlock",
        "HeapAlloc", "HeapFree", "HeapCreate", "GetProcessHeap", "RtlAllocateHeap",
        "WriteProcessMemory", "ReadProcessMemory",
        "NtAllocateVirtualMemory", "NtFreeVirtualMemory", "NtProtectVirtualMemory",
        "NtWriteVirtualMemory", "NtReadVirtualMemory", "NtMapViewOfSection",
        "NtUnmapViewOfSection", "NtCreateSection",
        "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW",
        "LoadLibraryA", "LoadLibraryW", "FreeLibrary",
        "LdrLoadDll", "LdrGetProcedureAddress", "LdrFindResourceEx_U",
        "GetCurrentProcess", "GetCurrentProcessId", "GetCurrentThread",
        "GetCurrentThreadId", "GetThreadContext", "SetThreadContext",
        "CreateThread", "ExitThread", "TerminateThread", "ResumeThread",
        "SuspendThread", "OpenThread", "OpenProcess",
        "CreateRemoteThread", "CreateRemoteThreadEx", "QueueUserAPC",
        "RtlCreateUserThread", "RtlExitUserThread", "TerminateProcess", "ExitProcess",
        "GetExitCodeThread", "Sleep", "SleepEx", "WaitForSingleObject",
        "WaitForMultipleObjects", "GetTickCount", "GetTickCount64",
        "RtlAddFunctionTable", "RtlLookupFunctionEntry", "RtlVirtualUnwind",
        "RtlUnwindEx", "AddVectoredExceptionHandler", "RemoveVectoredExceptionHandler",
        "SetUnhandledExceptionFilter", "RaiseException", "RtlRaiseException",
        "RtlInstallFunctionTableCallback",
        "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
        "GetFileSize", "SetFilePointer", "DeleteFileA", "DeleteFileW",
        "EnterCriticalSection", "LeaveCriticalSection", "InitializeCriticalSection",
        "DeleteCriticalSection", "CreateMutexA", "CreateMutexW", "ReleaseMutex",
        "CreateEventA", "CreateEventW", "SetEvent", "ResetEvent",
        "GetLastError", "SetLastError",
        "GetVersionExA", "GetVersionExW", "RtlGetVersion",
        "GetSystemInfo", "GetNativeSystemInfo", "IsWow64Process",
        "QueryPerformanceCounter", "QueryPerformanceFrequency",
        "OpenProcessToken", "GetTokenInformation", "AdjustTokenPrivileges",
        "memcpy", "memset", "memmove", "memcmp", "strlen", "strcpy", "strcat",
        "BCryptOpenAlgorithmProvider", "BCryptCloseAlgorithmProvider",
        "BCryptGenerateSymmetricKey", "BCryptDestroyKey",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptHashData",
        "BCryptCreateHash", "BCryptFinishHash", "BCryptDestroyHash",
        "BCryptGenRandom",
        // anti-VM / anti-sandbox
        "GetTickCount", "QueryPerformanceCounter", "GetCursorPos",
        "GetSystemFirmwareTable", "GlobalMemoryStatusEx", "GetUserNameA",
        "GetComputerNameA", "GetVolumeInformationA",
        // hash extras
        "ntdll", "kernel32", "user32", "kernelbase",
        "NtClose", "NtDelayExecution", "NtWaitForSingleObject",
        "NtSetContextThread", "NtGetContextThread", "NtTerminateProcess",
        "NtTerminateThread", "NtSuspendThread", "NtResumeThread",
        "NtOpenProcess", "NtOpenThread", "NtQuerySystemInformation",
        "NtQueryObject", "NtCreateThreadEx", "NtQueueApcThread",
        "NtRaiseException", "NtContinue", "NtAccessCheck",
        "GetCommandLineA", "GetCommandLineW",
        "GetModuleFileNameA", "GetModuleFileNameW",
        "GetSystemTime", "GetLocalTime", "GetSystemTimeAsFileTime",
        "GetSystemTimePreciseAsFileTime",
        "RtlGetCurrentPeb", "RtlGetCurrentTeb",
    ];

    let mut found: std::collections::HashMap<u32, &str> = std::collections::HashMap::new();
    for n in apis.iter().chain(modules.iter()) {
        found.insert(djb2a_api(n), *n);
    }

    let mut unresolved = Vec::new();
    for &h in hashes {
        match found.get(&h) {
            Some(name) => println!("{:#010x} -> {}", h, name),
            None => {
                unresolved.push(h);
                println!("{:#010x} -> ??", h);
            }
        }
    }
    println!("\n{} of {} unresolved", unresolved.len(), hashes.len());
}
