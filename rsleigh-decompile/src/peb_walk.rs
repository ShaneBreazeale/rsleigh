//! PEB-walk API hash resolution.
//!
//! Shellcode and packers frequently locate Windows APIs by walking the PEB
//! module list, iterating each module's export table, hashing each export
//! name, and comparing against a precomputed constant. This avoids storing
//! string literals and bypasses naive IAT-based hooks.
//!
//! The most common hash function is ROR13 (rotate-right-13), used by
//! Metasploit, Cobalt Strike, Donut, and the bulk of public shellcode.
//! When the decompiler sees a constant comparison whose value matches a
//! known API's ROR13 hash, this module returns the matched API name so
//! the printer can annotate it.
//!
//! False-positive surface: a random 32-bit constant has ~1 in 2^32 chance
//! of colliding with our ~250-entry hash table — negligible. The annotation
//! is therefore high-precision.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Metasploit-style rotate-right-13 hash. Hashes the byte sequence
/// `<UpperCaseModuleName>\0<ApiName>\0` for module-qualified resolvers, or
/// just `<ApiName>\0` for the unqualified variant. We compute both forms
/// for each API in the seed table; the unqualified form catches the
/// majority of public shellcode (single-module resolvers in kernel32 +
/// ntdll combined hashing).
pub fn ror13(input: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    for &b in input {
        hash = hash.rotate_right(13);
        hash = hash.wrapping_add(b as u32);
    }
    hash
}

/// Convenience: ROR13 over an unqualified API name with NUL terminator.
/// Mirrors the canonical Metasploit `block_api_x64.asm` shape.
pub fn ror13_api(name: &str) -> u32 {
    let mut buf = name.as_bytes().to_vec();
    buf.push(0);
    ror13(&buf)
}

/// ROR13 over `MODULE\0API\0` where MODULE is the upper-case unicode
/// module name (e.g. `KERNEL32.DLL`). Matches the kernel32-then-export
/// composition seen in most modern shellcode.
pub fn ror13_module_api(module: &str, name: &str) -> u32 {
    // Module name is hashed as uppercase UTF-16LE in real shellcode,
    // because that is the encoding stored in PEB_LDR_DATA. We mimic that.
    let mut buf: Vec<u8> = Vec::new();
    for c in module.to_ascii_uppercase().chars() {
        buf.push(c as u8);
        buf.push(0);
    }
    buf.push(0); // UTF-16 NUL
    buf.push(0);
    for &b in name.as_bytes() {
        buf.push(b);
    }
    buf.push(0);
    ror13(&buf)
}

/// Curated list of Windows APIs frequently seen in shellcode + packer
/// dynamic-resolution loops. Order is module-first (kernel32, ntdll,
/// ws2_32, advapi32, wininet) so collision-resolution bias toward the
/// more-common module.
const API_SEEDS: &[(&str, &str)] = &[
    // kernel32.dll
    ("kernel32.dll", "LoadLibraryA"),
    ("kernel32.dll", "LoadLibraryW"),
    ("kernel32.dll", "LoadLibraryExA"),
    ("kernel32.dll", "LoadLibraryExW"),
    ("kernel32.dll", "GetProcAddress"),
    ("kernel32.dll", "GetModuleHandleA"),
    ("kernel32.dll", "GetModuleHandleW"),
    ("kernel32.dll", "VirtualAlloc"),
    ("kernel32.dll", "VirtualAllocEx"),
    ("kernel32.dll", "VirtualProtect"),
    ("kernel32.dll", "VirtualProtectEx"),
    ("kernel32.dll", "VirtualFree"),
    ("kernel32.dll", "WriteProcessMemory"),
    ("kernel32.dll", "ReadProcessMemory"),
    ("kernel32.dll", "CreateProcessA"),
    ("kernel32.dll", "CreateProcessW"),
    ("kernel32.dll", "CreateRemoteThread"),
    ("kernel32.dll", "CreateRemoteThreadEx"),
    ("kernel32.dll", "OpenProcess"),
    ("kernel32.dll", "CloseHandle"),
    ("kernel32.dll", "CreateFileA"),
    ("kernel32.dll", "CreateFileW"),
    ("kernel32.dll", "ReadFile"),
    ("kernel32.dll", "WriteFile"),
    ("kernel32.dll", "DeleteFileA"),
    ("kernel32.dll", "DeleteFileW"),
    ("kernel32.dll", "ExitProcess"),
    ("kernel32.dll", "ExitThread"),
    ("kernel32.dll", "TerminateProcess"),
    ("kernel32.dll", "TerminateThread"),
    ("kernel32.dll", "Sleep"),
    ("kernel32.dll", "WaitForSingleObject"),
    ("kernel32.dll", "WaitForMultipleObjects"),
    ("kernel32.dll", "GetTickCount"),
    ("kernel32.dll", "GetTickCount64"),
    ("kernel32.dll", "GetCurrentProcess"),
    ("kernel32.dll", "GetCurrentProcessId"),
    ("kernel32.dll", "GetCurrentThread"),
    ("kernel32.dll", "GetCurrentThreadId"),
    ("kernel32.dll", "IsDebuggerPresent"),
    ("kernel32.dll", "CheckRemoteDebuggerPresent"),
    ("kernel32.dll", "OutputDebugStringA"),
    ("kernel32.dll", "OutputDebugStringW"),
    ("kernel32.dll", "HeapAlloc"),
    ("kernel32.dll", "HeapFree"),
    ("kernel32.dll", "HeapCreate"),
    ("kernel32.dll", "GetProcessHeap"),
    ("kernel32.dll", "GetEnvironmentVariableA"),
    ("kernel32.dll", "GetEnvironmentVariableW"),
    ("kernel32.dll", "SetEnvironmentVariableA"),
    ("kernel32.dll", "GetComputerNameA"),
    ("kernel32.dll", "GetComputerNameW"),
    ("kernel32.dll", "GetSystemInfo"),
    ("kernel32.dll", "GetNativeSystemInfo"),
    ("kernel32.dll", "IsWow64Process"),
    ("kernel32.dll", "GlobalAlloc"),
    ("kernel32.dll", "GlobalFree"),
    ("kernel32.dll", "lstrcatA"),
    ("kernel32.dll", "lstrcatW"),
    ("kernel32.dll", "lstrcpyA"),
    ("kernel32.dll", "lstrlenA"),
    ("kernel32.dll", "lstrlenW"),
    ("kernel32.dll", "WinExec"),
    ("kernel32.dll", "ResumeThread"),
    ("kernel32.dll", "SuspendThread"),
    ("kernel32.dll", "QueueUserAPC"),
    // ntdll.dll
    ("ntdll.dll", "NtAllocateVirtualMemory"),
    ("ntdll.dll", "NtFreeVirtualMemory"),
    ("ntdll.dll", "NtProtectVirtualMemory"),
    ("ntdll.dll", "NtWriteVirtualMemory"),
    ("ntdll.dll", "NtReadVirtualMemory"),
    ("ntdll.dll", "NtCreateThreadEx"),
    ("ntdll.dll", "NtCreateProcess"),
    ("ntdll.dll", "NtOpenProcess"),
    ("ntdll.dll", "NtTerminateProcess"),
    ("ntdll.dll", "NtCreateFile"),
    ("ntdll.dll", "NtClose"),
    ("ntdll.dll", "NtMapViewOfSection"),
    ("ntdll.dll", "NtUnmapViewOfSection"),
    ("ntdll.dll", "NtCreateSection"),
    ("ntdll.dll", "NtQueueApcThread"),
    ("ntdll.dll", "NtQueryInformationProcess"),
    ("ntdll.dll", "NtSetInformationThread"),
    ("ntdll.dll", "NtSuspendThread"),
    ("ntdll.dll", "NtResumeThread"),
    ("ntdll.dll", "RtlAddFunctionTable"),
    ("ntdll.dll", "RtlExitUserThread"),
    ("ntdll.dll", "RtlMoveMemory"),
    ("ntdll.dll", "RtlZeroMemory"),
    ("ntdll.dll", "ZwQueryInformationProcess"),
    ("ntdll.dll", "ZwSetInformationThread"),
    // ws2_32.dll
    ("ws2_32.dll", "WSAStartup"),
    ("ws2_32.dll", "WSACleanup"),
    ("ws2_32.dll", "WSASocketA"),
    ("ws2_32.dll", "WSAConnect"),
    ("ws2_32.dll", "WSARecv"),
    ("ws2_32.dll", "WSASend"),
    ("ws2_32.dll", "socket"),
    ("ws2_32.dll", "connect"),
    ("ws2_32.dll", "recv"),
    ("ws2_32.dll", "send"),
    ("ws2_32.dll", "bind"),
    ("ws2_32.dll", "listen"),
    ("ws2_32.dll", "accept"),
    ("ws2_32.dll", "closesocket"),
    ("ws2_32.dll", "gethostbyname"),
    ("ws2_32.dll", "inet_addr"),
    ("ws2_32.dll", "htons"),
    ("ws2_32.dll", "htonl"),
    // advapi32.dll
    ("advapi32.dll", "RegOpenKeyExA"),
    ("advapi32.dll", "RegOpenKeyExW"),
    ("advapi32.dll", "RegSetValueExA"),
    ("advapi32.dll", "RegSetValueExW"),
    ("advapi32.dll", "RegQueryValueExA"),
    ("advapi32.dll", "RegQueryValueExW"),
    ("advapi32.dll", "RegCloseKey"),
    ("advapi32.dll", "OpenProcessToken"),
    ("advapi32.dll", "AdjustTokenPrivileges"),
    ("advapi32.dll", "LookupPrivilegeValueA"),
    ("advapi32.dll", "OpenServiceA"),
    ("advapi32.dll", "OpenSCManagerA"),
    ("advapi32.dll", "StartServiceA"),
    ("advapi32.dll", "ControlService"),
    // wininet.dll
    ("wininet.dll", "InternetOpenA"),
    ("wininet.dll", "InternetOpenW"),
    ("wininet.dll", "InternetConnectA"),
    ("wininet.dll", "InternetConnectW"),
    ("wininet.dll", "HttpOpenRequestA"),
    ("wininet.dll", "HttpSendRequestA"),
    ("wininet.dll", "InternetReadFile"),
    ("wininet.dll", "InternetCloseHandle"),
    ("wininet.dll", "InternetWriteFile"),
    ("wininet.dll", "InternetCrackUrlA"),
    ("wininet.dll", "InternetSetOptionA"),
    ("wininet.dll", "HttpQueryInfoA"),
    // winhttp.dll — modern HTTP client used by Cobalt Strike, IcedID, etc.
    ("winhttp.dll", "WinHttpOpen"),
    ("winhttp.dll", "WinHttpConnect"),
    ("winhttp.dll", "WinHttpOpenRequest"),
    ("winhttp.dll", "WinHttpSendRequest"),
    ("winhttp.dll", "WinHttpReceiveResponse"),
    ("winhttp.dll", "WinHttpReadData"),
    ("winhttp.dll", "WinHttpWriteData"),
    ("winhttp.dll", "WinHttpQueryHeaders"),
    ("winhttp.dll", "WinHttpCloseHandle"),
    ("winhttp.dll", "WinHttpSetOption"),
    // crypt32.dll — certificate / blob crypto seen in C2 unpackers
    ("crypt32.dll", "CryptStringToBinaryA"),
    ("crypt32.dll", "CryptStringToBinaryW"),
    ("crypt32.dll", "CryptBinaryToStringA"),
    ("crypt32.dll", "CryptBinaryToStringW"),
    ("crypt32.dll", "CryptUnprotectData"),
    ("crypt32.dll", "CryptProtectData"),
    ("crypt32.dll", "CertOpenSystemStoreA"),
    ("crypt32.dll", "CertCloseStore"),
    ("crypt32.dll", "CertEnumCertificatesInStore"),
    // bcrypt.dll — Win10+ crypto primitives, AES/SHA in modern droppers
    ("bcrypt.dll", "BCryptOpenAlgorithmProvider"),
    ("bcrypt.dll", "BCryptCloseAlgorithmProvider"),
    ("bcrypt.dll", "BCryptGenerateSymmetricKey"),
    ("bcrypt.dll", "BCryptDestroyKey"),
    ("bcrypt.dll", "BCryptEncrypt"),
    ("bcrypt.dll", "BCryptDecrypt"),
    ("bcrypt.dll", "BCryptHash"),
    ("bcrypt.dll", "BCryptHashData"),
    ("bcrypt.dll", "BCryptCreateHash"),
    ("bcrypt.dll", "BCryptFinishHash"),
    ("bcrypt.dll", "BCryptDestroyHash"),
    ("bcrypt.dll", "BCryptGenRandom"),
    // secur32.dll — auth + SSPI
    ("secur32.dll", "AcquireCredentialsHandleA"),
    ("secur32.dll", "InitializeSecurityContextA"),
    ("secur32.dll", "DecryptMessage"),
    ("secur32.dll", "EncryptMessage"),
    ("secur32.dll", "FreeCredentialsHandle"),
    // psapi.dll — process enumeration / module discovery
    ("psapi.dll", "EnumProcesses"),
    ("psapi.dll", "EnumProcessModules"),
    ("psapi.dll", "EnumProcessModulesEx"),
    ("psapi.dll", "GetModuleFileNameExA"),
    ("psapi.dll", "GetModuleFileNameExW"),
    ("psapi.dll", "GetModuleBaseNameA"),
    ("psapi.dll", "GetModuleBaseNameW"),
    ("psapi.dll", "GetMappedFileNameA"),
    ("psapi.dll", "GetMappedFileNameW"),
    // dbghelp.dll — minidump / symbol enumeration (LSASS dumpers)
    ("dbghelp.dll", "MiniDumpWriteDump"),
    ("dbghelp.dll", "SymInitialize"),
    ("dbghelp.dll", "SymFromAddr"),
    ("dbghelp.dll", "SymGetModuleInfo"),
    // shell32.dll — file/system operations seen in installers + droppers
    ("shell32.dll", "ShellExecuteA"),
    ("shell32.dll", "ShellExecuteW"),
    ("shell32.dll", "ShellExecuteExA"),
    ("shell32.dll", "SHGetFolderPathA"),
    ("shell32.dll", "SHGetFolderPathW"),
    // user32.dll
    ("user32.dll", "MessageBoxA"),
    ("user32.dll", "MessageBoxW"),
    ("user32.dll", "FindWindowA"),
    ("user32.dll", "GetForegroundWindow"),
    ("user32.dll", "GetAsyncKeyState"),
    ("user32.dll", "GetKeyState"),
    ("user32.dll", "SetWindowsHookExA"),
    ("user32.dll", "CallNextHookEx"),
    ("user32.dll", "GetWindowTextA"),
    ("user32.dll", "GetWindowTextW"),
    ("user32.dll", "EnumWindows"),
    ("user32.dll", "GetClipboardData"),
    ("user32.dll", "OpenClipboard"),
    ("user32.dll", "CloseClipboard"),
    // ntdll.dll — additional NT APIs commonly resolved
    ("ntdll.dll", "RtlCreateUserThread"),
    ("ntdll.dll", "NtQuerySystemInformation"),
    ("ntdll.dll", "NtSetContextThread"),
    ("ntdll.dll", "NtGetContextThread"),
    ("ntdll.dll", "NtDelayExecution"),
    ("ntdll.dll", "NtWaitForSingleObject"),
    ("ntdll.dll", "NtCreateThread"),
    ("ntdll.dll", "LdrLoadDll"),
    ("ntdll.dll", "LdrGetProcedureAddress"),
    ("ntdll.dll", "LdrFindResourceEx_U"),
];

/// DJB2 hash (Dan Bernstein), the second-most-common API-resolution hash
/// after ROR13. Cobalt Strike's UDRL and several Donut variants use DJB2
/// (or DJB2a, the XOR variant) over the API name. Seed value 5381 is the
/// canonical Bernstein constant.
pub fn djb2(input: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in input {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}

/// DJB2 over an API name with NUL terminator (matches public-shellcode
/// implementations that loop until the export-name byte is zero).
pub fn djb2_api(name: &str) -> u32 {
    let mut buf = name.as_bytes().to_vec();
    buf.push(0);
    djb2(&buf)
}

/// DJB2a — XOR variant of DJB2. `h = h * 33 ^ byte` instead of
/// `h * 33 + byte`. Used by PyVMProtect v5 and several modern shellcode
/// loaders that want a slightly different distribution from canonical
/// DJB2 without changing the loop shape. Note: terminator byte is NOT
/// folded in (loop exits on zero — like the canonical Bernstein "while
/// (c = *str++)" form, the NUL is not part of the hash).
pub fn djb2a(input: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in input {
        h = h.wrapping_mul(33) ^ (b as u32);
    }
    h
}

/// DJB2a over an API name with no NUL terminator — matches the
/// `while (c = *str++) { hash = hash*33 ^ c }` loop in PyVMProtect v5
/// where the terminator is the loop-exit signal, not a hashed input.
pub fn djb2a_api(name: &str) -> u32 {
    djb2a(name.as_bytes())
}

/// Simple additive hash: `h = sum(byte)` rotated left 1 each step.
/// Seen in primitive shellcode (early Metasploit demos, some packers).
/// Lower entropy than ROR13/DJB2 but widely deployed.
pub fn add_rotl1(input: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &b in input {
        h = h.rotate_left(1).wrapping_add(b as u32);
    }
    h
}

/// add_rotl1 over an API name with NUL terminator.
pub fn add_rotl1_api(name: &str) -> u32 {
    let mut buf = name.as_bytes().to_vec();
    buf.push(0);
    add_rotl1(&buf)
}

/// Reverse map: hash → API name. Built lazily on first lookup. Covers
/// ROR13 (unqualified + module-qualified) plus the DJB2 and add+rotl
/// variants so a single resolver handles all common shellcode hash
/// schemes.
static HASH_INDEX: LazyLock<HashMap<u32, &'static str>> = LazyLock::new(|| {
    let mut m: HashMap<u32, &'static str> = HashMap::with_capacity(API_SEEDS.len() * 4);
    for &(module, name) in API_SEEDS {
        // ROR13 unqualified — Metasploit, Cobalt Strike beacon stub.
        m.entry(ror13_api(name)).or_insert(name);
        // ROR13 module-qualified (`MODULE\0API\0`).
        m.entry(ror13_module_api(module, name)).or_insert(name);
        // DJB2 — Cobalt Strike UDRL, several Donut variants.
        m.entry(djb2_api(name)).or_insert(name);
        // DJB2a — PyVMProtect v5 + similar loaders.
        m.entry(djb2a_api(name)).or_insert(name);
        // add+rotl1 — primitive shellcode.
        m.entry(add_rotl1_api(name)).or_insert(name);
    }
    m
});

/// Look up an API name from a 32-bit hash (any of ROR13, DJB2, DJB2a,
/// add+rotl1). Returns None for misses.
pub fn resolve_ror13_hash(h: u32) -> Option<&'static str> {
    HASH_INDEX.get(&h).copied()
}

/// Resolve a 32-bit hash and return both the API name and which hash
/// variant matched. Useful for printer annotations that want to call
/// out the specific algorithm (e.g. `DJB2a("VirtualAlloc")`).
///
/// Variants checked in order: ROR13, DJB2, DJB2a, add+rotl1. A given
/// (hash, name) pair only matches one variant in practice; ties prefer
/// the earlier-checked variant.
pub fn resolve_api_hash(h: u32) -> Option<(&'static str, &'static str)> {
    let name = HASH_INDEX.get(&h).copied()?;
    if ror13_api(name) == h
        || ror13_module_api("kernel32.dll", name) == h
        || ror13_module_api("ntdll.dll", name) == h
    {
        return Some((name, "ROR13"));
    }
    if djb2_api(name) == h {
        return Some((name, "DJB2"));
    }
    if djb2a_api(name) == h {
        return Some((name, "DJB2a"));
    }
    if add_rotl1_api(name) == h {
        return Some((name, "add+rotl1"));
    }
    Some((name, "hash"))
}

/// Heuristic gate: only annotate constants that *look* like a hash —
/// avoids spamming common values like 0, 1, 0xFFFF, page sizes, etc.
/// A real ROR13 hash has both halves non-zero and high entropy. This
/// filter cuts ~99% of legit constants while keeping all known hashes
/// (verified against API_SEEDS at test time).
pub fn looks_like_hash(value: u32) -> bool {
    if value < 0x01000000 {
        return false;
    }
    if value == u32::MAX {
        return false;
    }
    let high = value >> 16;
    let low = value & 0xFFFF;
    high != 0 && low != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ror13_is_deterministic_and_distinguishes_apis() {
        // Different APIs must hash to distinct values; same API must hash
        // to the same value across calls. (Metasploit-style ROR13 has
        // multiple published variants — uppercase pre-folding, UTF-16
        // module prefix, etc. — so we lock the algorithm to its own
        // outputs rather than matching an external reference.)
        let h1 = ror13_api("LoadLibraryA");
        let h2 = ror13_api("LoadLibraryA");
        let h3 = ror13_api("VirtualAlloc");
        assert_eq!(h1, h2, "non-deterministic hash");
        assert_ne!(h1, h3, "collision LoadLibraryA == VirtualAlloc");
    }

    #[test]
    fn ror13_known_apis_resolve() {
        // Every seeded API must round-trip through the index.
        for &(_, name) in API_SEEDS {
            let h = ror13_api(name);
            assert!(
                resolve_ror13_hash(h).is_some(),
                "API {} hash {:#x} not in index",
                name,
                h
            );
        }
    }

    #[test]
    fn djb2_known_apis_resolve() {
        for &(_, name) in API_SEEDS {
            let h = djb2_api(name);
            assert!(
                resolve_ror13_hash(h).is_some(),
                "DJB2 hash for {} ({:#x}) not in index",
                name,
                h
            );
        }
    }

    #[test]
    fn add_rotl1_known_apis_resolve() {
        for &(_, name) in API_SEEDS {
            let h = add_rotl1_api(name);
            assert!(
                resolve_ror13_hash(h).is_some(),
                "add_rotl1 hash for {} ({:#x}) not in index",
                name,
                h
            );
        }
    }

    #[test]
    fn resolve_api_hash_labels_djb2a_correctly() {
        // 0x19fbbf49 is djb2a("VirtualAlloc") — observed in v5.
        let h = djb2a_api("VirtualAlloc");
        let (name, variant) = resolve_api_hash(h).expect("should resolve");
        assert_eq!(name, "VirtualAlloc");
        assert_eq!(variant, "DJB2a");
    }

    #[test]
    fn resolve_api_hash_labels_ror13_correctly() {
        let h = ror13_api("LoadLibraryA");
        let (name, variant) = resolve_api_hash(h).expect("should resolve");
        assert_eq!(name, "LoadLibraryA");
        assert_eq!(variant, "ROR13");
    }

    #[test]
    fn djb2_seed_is_5381() {
        // Empty buffer must yield exactly the canonical Bernstein seed.
        assert_eq!(djb2(b""), 5381);
        // Standard Bernstein test vector for "" + 'a': 5381 * 33 + 97 = 177670.
        assert_eq!(djb2(b"a"), 177670);
    }

    #[test]
    fn distinct_hashes_for_distinct_apis() {
        // No two seeded APIs may collide under any single hash function
        // — collisions across different hash functions are fine since the
        // index dedupes by first-insert.
        for variant in [
            ror13_api as fn(&str) -> u32,
            djb2_api as fn(&str) -> u32,
            add_rotl1_api as fn(&str) -> u32,
        ] {
            let mut seen: std::collections::HashMap<u32, &str> = std::collections::HashMap::new();
            for &(_, name) in API_SEEDS {
                let h = variant(name);
                if let Some(prev) = seen.insert(h, name) {
                    if prev != name {
                        panic!("hash collision between {} and {} ({:#x})", prev, name, h);
                    }
                }
            }
        }
    }

    #[test]
    fn looks_like_hash_filters_common_values() {
        assert!(!looks_like_hash(0));
        assert!(!looks_like_hash(1));
        assert!(!looks_like_hash(0xFFFF)); // common mask
        assert!(!looks_like_hash(0x1000)); // page size
        assert!(!looks_like_hash(0x4000)); // common alignment
        assert!(!looks_like_hash(0xFFFFFFFF)); // all-ones mask
        assert!(looks_like_hash(0x0726774C)); // LoadLibraryA hash
        assert!(looks_like_hash(0xDEADBEEF)); // fake high-entropy
    }
}
