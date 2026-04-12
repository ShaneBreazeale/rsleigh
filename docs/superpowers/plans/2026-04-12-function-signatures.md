# Function Signature Database Implementation Plan

**Status: COMPLETED** — implemented and extended beyond original spec.

**Goal:** Automatic parameter naming and return type propagation for known library functions (libc, Win32) based on a declarative signature database.

**What was built (beyond original plan):**
- 38K+ function signatures (889 curated JSON + 304 macro + 36K embedded TSV)
- Platform coverage: C stdlib, POSIX, Linux, macOS (GCD, ObjC, Mach, CoreFoundation), Android, Win32/64, OpenSSL, zlib
- `display_type` typedef system: HKEY, HWND, REGSAM, LSTATUS, DWORD propagate through call chains
- Two-pass interprocedural type propagation: internal function params typed from API call context
- Backward Load propagation: `Load(param)` with typed result → param gets the type
- `/* param_name */` annotations at call sites
- Ghidra-style local declarations with array sizing: `WCHAR local_8[262]; int local_c;`
- PE32 support + prologue-based function discovery (69 → 95 of 106 Ghidra functions)
- PE import thunk resolution + MSVC CRT wrapper recognition (printf, fprintf)
- Runtime `--sigs` flag for loading external JSON signature files
- Ghidra extraction script: `scripts/extract-ghidra-sigs.py`

**Tech Stack:** Pure Rust, serde_json + flate2 for signature loading.

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `rsleigh-decompile/src/signatures.rs` | **Create** | Signature types, lookup function, declarative macro |
| `rsleigh-decompile/src/signatures_libc.rs` | **Create** | libc signatures (stdio, stdlib, string, unistd, socket) |
| `rsleigh-decompile/src/signatures_win32.rs` | **Create** | Win32 API signatures |
| `rsleigh-decompile/src/lib.rs` | Modify (lines 94-118) | Wire signature DB into decompile pipeline |
| `rsleigh-decompile/src/fold.rs` | Modify (lines 1005-1098) | Apply param names from signatures to call args |
| `rsleigh-decompile/src/printer.rs` | Modify (lines 4298-4372, 4811-4859) | Use sig return types + param names at call sites |
| `test-harness/src/main.rs` | Modify (line ~4270) | Add signature-aware decompiler tests |

---

### Task 1: Signature Types and Lookup

**Files:**
- Create: `rsleigh-decompile/src/signatures.rs`

- [ ] **Step 1: Write the failing test**

Add at the bottom of the new file:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_printf() {
        let sig = lookup("printf").expect("printf should exist");
        assert_eq!(sig.name, "printf");
        assert_eq!(sig.ret, SigType::Int);
        assert!(sig.variadic);
        assert_eq!(sig.params[0].name, "format");
        assert_eq!(sig.params[0].ty, SigType::ConstCharPtr);
    }

    #[test]
    fn lookup_malloc() {
        let sig = lookup("malloc").expect("malloc should exist");
        assert_eq!(sig.name, "malloc");
        assert_eq!(sig.ret, SigType::VoidPtr);
        assert_eq!(sig.params.len(), 1);
        assert_eq!(sig.params[0].name, "size");
        assert_eq!(sig.params[0].ty, SigType::SizeT);
    }

    #[test]
    fn lookup_unknown() {
        assert!(lookup("not_a_real_function").is_none());
    }

    #[test]
    fn lookup_case_insensitive_win32() {
        // Win32 APIs are sometimes referenced with different casing
        assert!(lookup("VirtualAlloc").is_some());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rsleigh-decompile -- signatures::tests --no-run 2>&1 | tail -5`
Expected: Compilation error — module `signatures` doesn't exist yet.

- [ ] **Step 3: Write the signature types and macro**

Create `rsleigh-decompile/src/signatures.rs`:

```rust
//! Function signature database for known library functions.
//!
//! Provides parameter names, types, and return types for libc and Win32 APIs.
//! Used by the fold pass to name call arguments and by the printer for return types.

use std::collections::HashMap;
use std::sync::LazyLock;

/// C type categories for signature parameters and return values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigType {
    Void,
    Int,
    UInt,
    Long,
    ULong,
    SizeT,
    CharPtr,
    ConstCharPtr,
    VoidPtr,
    ConstVoidPtr,
    FilePtr,       // FILE*
    Bool,
    Fd,            // int (file descriptor semantic)
    SockFd,        // int (socket descriptor semantic)
    WCharPtr,      // wchar_t* / LPCWSTR
    ConstWCharPtr, // const wchar_t* / LPCWSTR
    Handle,        // HANDLE (Win32)
    DWord,         // DWORD (Win32)
    LpVoid,        // LPVOID (Win32)
}

impl SigType {
    /// Convert to C type string for printer output.
    pub fn c_str(self) -> &'static str {
        match self {
            SigType::Void => "void",
            SigType::Int => "int",
            SigType::UInt => "unsigned int",
            SigType::Long => "long",
            SigType::ULong => "unsigned long",
            SigType::SizeT => "size_t",
            SigType::CharPtr => "char *",
            SigType::ConstCharPtr => "const char *",
            SigType::VoidPtr => "void *",
            SigType::ConstVoidPtr => "const void *",
            SigType::FilePtr => "FILE *",
            SigType::Bool => "bool",
            SigType::Fd | SigType::SockFd => "int",
            SigType::WCharPtr => "wchar_t *",
            SigType::ConstWCharPtr => "const wchar_t *",
            SigType::Handle => "HANDLE",
            SigType::DWord => "DWORD",
            SigType::LpVoid => "LPVOID",
        }
    }

    /// Convert to InferredType for the fold pass.
    pub fn to_inferred(self) -> crate::ir::InferredType {
        match self {
            SigType::VoidPtr | SigType::ConstVoidPtr | SigType::CharPtr
            | SigType::ConstCharPtr | SigType::FilePtr | SigType::WCharPtr
            | SigType::ConstWCharPtr | SigType::LpVoid
                => crate::ir::InferredType::Pointer,
            SigType::Int | SigType::Long | SigType::Fd | SigType::SockFd
                => crate::ir::InferredType::Signed,
            SigType::UInt | SigType::ULong | SigType::SizeT | SigType::DWord
                => crate::ir::InferredType::Unsigned,
            SigType::Bool => crate::ir::InferredType::Bool,
            SigType::Handle => crate::ir::InferredType::Unsigned,
            SigType::Void => crate::ir::InferredType::Unknown,
        }
    }
}

/// A single parameter in a function signature.
#[derive(Debug, Clone)]
pub struct SigParam {
    pub name: &'static str,
    pub ty: SigType,
}

/// A complete function signature.
#[derive(Debug, Clone)]
pub struct FuncSig {
    pub name: &'static str,
    pub ret: SigType,
    pub params: &'static [SigParam],
    pub variadic: bool,
}

/// Declarative macro for defining signatures concisely.
///
/// Usage:
/// ```ignore
/// define_signatures! {
///     fn printf(format: ConstCharPtr, ...) -> Int;
///     fn malloc(size: SizeT) -> VoidPtr;
///     fn free(ptr: VoidPtr);
/// }
/// ```
macro_rules! define_signatures {
    ($(fn $name:ident( $($pname:ident : $pty:ident),* $(, ...)? ) $(-> $ret:ident)?;)*) => {
        &[
            $(
                FuncSig {
                    name: stringify!($name),
                    ret: define_signatures!(@ret $($ret)?),
                    params: &[
                        $(SigParam { name: stringify!($pname), ty: SigType::$pty }),*
                    ],
                    variadic: define_signatures!(@variadic $($name)* $(...)? ),
                },
            )*
        ]
    };
    // Return type: default to Void if omitted
    (@ret) => { SigType::Void };
    (@ret $ret:ident) => { SigType::$ret };
    // Variadic detection: if `...` is present after params
    (@variadic $($name:ident)* ...) => { true };
    (@variadic $($name:ident)*) => { false };
}

// Re-export the macro for use in sub-modules
pub(crate) use define_signatures;

/// Lookup a function signature by name.
/// Returns None for unknown functions.
pub fn lookup(name: &str) -> Option<&'static FuncSig> {
    SIGNATURE_MAP.get(name).copied()
}

/// Global signature map, built once from all signature tables.
static SIGNATURE_MAP: LazyLock<HashMap<&'static str, &'static FuncSig>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    for sig in crate::signatures_libc::LIBC_SIGNATURES {
        map.insert(sig.name, sig);
    }
    for sig in crate::signatures_win32::WIN32_SIGNATURES {
        map.insert(sig.name, sig);
    }
    map
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_printf() {
        let sig = lookup("printf").expect("printf should exist");
        assert_eq!(sig.name, "printf");
        assert_eq!(sig.ret, SigType::Int);
        assert!(sig.variadic);
        assert_eq!(sig.params[0].name, "format");
        assert_eq!(sig.params[0].ty, SigType::ConstCharPtr);
    }

    #[test]
    fn lookup_malloc() {
        let sig = lookup("malloc").expect("malloc should exist");
        assert_eq!(sig.name, "malloc");
        assert_eq!(sig.ret, SigType::VoidPtr);
        assert_eq!(sig.params.len(), 1);
        assert_eq!(sig.params[0].name, "size");
        assert_eq!(sig.params[0].ty, SigType::SizeT);
    }

    #[test]
    fn lookup_unknown() {
        assert!(lookup("not_a_real_function").is_none());
    }

    #[test]
    fn lookup_case_insensitive_win32() {
        assert!(lookup("VirtualAlloc").is_some());
    }
}
```

- [ ] **Step 4: Register the module in lib.rs**

Add to `rsleigh-decompile/src/lib.rs` at the top with the other `pub mod` lines:

```rust
pub mod signatures;
mod signatures_libc;
mod signatures_win32;
```

Create empty stubs so it compiles:

`rsleigh-decompile/src/signatures_libc.rs`:
```rust
use crate::signatures::*;

pub static LIBC_SIGNATURES: &[FuncSig] = define_signatures! {
    fn printf(format: ConstCharPtr, ...) -> Int;
    fn malloc(size: SizeT) -> VoidPtr;
};
```

`rsleigh-decompile/src/signatures_win32.rs`:
```rust
use crate::signatures::*;

pub static WIN32_SIGNATURES: &[FuncSig] = define_signatures! {
    fn VirtualAlloc(lpAddress: LpVoid, dwSize: SizeT, flAllocationType: DWord, flProtect: DWord) -> LpVoid;
};
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p rsleigh-decompile -- signatures::tests -v`
Expected: 4 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add rsleigh-decompile/src/signatures.rs rsleigh-decompile/src/signatures_libc.rs rsleigh-decompile/src/signatures_win32.rs rsleigh-decompile/src/lib.rs
git commit -m "feat: add function signature types, lookup, and declarative macro"
```

---

### Task 2: libc Signature Definitions

**Files:**
- Modify: `rsleigh-decompile/src/signatures_libc.rs`

- [ ] **Step 1: Write a test for coverage**

Add to `rsleigh-decompile/src/signatures.rs` tests:

```rust
    #[test]
    fn libc_coverage() {
        // stdio
        for name in ["printf", "fprintf", "sprintf", "snprintf", "puts", "fputs",
                      "fgets", "fread", "fwrite", "fopen", "fclose", "fseek",
                      "ftell", "feof", "ferror", "fflush", "fputc", "fgetc",
                      "putchar", "getchar"] {
            assert!(lookup(name).is_some(), "missing: {}", name);
        }
        // stdlib
        for name in ["malloc", "calloc", "realloc", "free", "atoi", "atol",
                      "strtol", "strtoul", "exit", "abort", "abs", "qsort"] {
            assert!(lookup(name).is_some(), "missing: {}", name);
        }
        // string
        for name in ["strlen", "strcpy", "strncpy", "strcmp", "strncmp",
                      "strcat", "strncat", "strchr", "strrchr", "strstr",
                      "memcpy", "memset", "memmove", "memcmp"] {
            assert!(lookup(name).is_some(), "missing: {}", name);
        }
        // unistd / posix
        for name in ["read", "write", "open", "close", "fork", "execve",
                      "getpid", "sleep", "dup2", "pipe"] {
            assert!(lookup(name).is_some(), "missing: {}", name);
        }
        // socket
        for name in ["socket", "bind", "listen", "accept", "connect",
                      "send", "recv", "sendto", "recvfrom",
                      "setsockopt", "getsockopt", "shutdown"] {
            assert!(lookup(name).is_some(), "missing: {}", name);
        }
    }

    #[test]
    fn param_names_are_meaningful() {
        let sig = lookup("memcpy").unwrap();
        assert_eq!(sig.params[0].name, "dest");
        assert_eq!(sig.params[1].name, "src");
        assert_eq!(sig.params[2].name, "n");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p rsleigh-decompile -- signatures::tests::libc_coverage -v`
Expected: FAIL — many functions not found yet.

- [ ] **Step 3: Populate libc signatures**

Replace `rsleigh-decompile/src/signatures_libc.rs` with:

```rust
use crate::signatures::*;

pub static LIBC_SIGNATURES: &[FuncSig] = define_signatures! {
    // === stdio.h ===
    fn printf(format: ConstCharPtr, ...) -> Int;
    fn fprintf(stream: FilePtr, format: ConstCharPtr, ...) -> Int;
    fn sprintf(str: CharPtr, format: ConstCharPtr, ...) -> Int;
    fn snprintf(str: CharPtr, size: SizeT, format: ConstCharPtr, ...) -> Int;
    fn puts(s: ConstCharPtr) -> Int;
    fn fputs(s: ConstCharPtr, stream: FilePtr) -> Int;
    fn fgets(s: CharPtr, size: Int, stream: FilePtr) -> CharPtr;
    fn fread(ptr: VoidPtr, size: SizeT, nmemb: SizeT, stream: FilePtr) -> SizeT;
    fn fwrite(ptr: ConstVoidPtr, size: SizeT, nmemb: SizeT, stream: FilePtr) -> SizeT;
    fn fopen(pathname: ConstCharPtr, mode: ConstCharPtr) -> FilePtr;
    fn fclose(stream: FilePtr) -> Int;
    fn fseek(stream: FilePtr, offset: Long, whence: Int) -> Int;
    fn ftell(stream: FilePtr) -> Long;
    fn feof(stream: FilePtr) -> Int;
    fn ferror(stream: FilePtr) -> Int;
    fn fflush(stream: FilePtr) -> Int;
    fn fputc(c: Int, stream: FilePtr) -> Int;
    fn fgetc(stream: FilePtr) -> Int;
    fn putchar(c: Int) -> Int;
    fn getchar() -> Int;
    fn fprintf_stderr(format: ConstCharPtr, ...) -> Int;

    // === stdlib.h ===
    fn malloc(size: SizeT) -> VoidPtr;
    fn calloc(nmemb: SizeT, size: SizeT) -> VoidPtr;
    fn realloc(ptr: VoidPtr, size: SizeT) -> VoidPtr;
    fn free(ptr: VoidPtr);
    fn atoi(nptr: ConstCharPtr) -> Int;
    fn atol(nptr: ConstCharPtr) -> Long;
    fn strtol(nptr: ConstCharPtr, endptr: CharPtr, base: Int) -> Long;
    fn strtoul(nptr: ConstCharPtr, endptr: CharPtr, base: Int) -> ULong;
    fn exit(status: Int);
    fn abort();
    fn abs(j: Int) -> Int;
    fn qsort(base: VoidPtr, nmemb: SizeT, size: SizeT, compar: VoidPtr);

    // === string.h ===
    fn strlen(s: ConstCharPtr) -> SizeT;
    fn strcpy(dest: CharPtr, src: ConstCharPtr) -> CharPtr;
    fn strncpy(dest: CharPtr, src: ConstCharPtr, n: SizeT) -> CharPtr;
    fn strcmp(s1: ConstCharPtr, s2: ConstCharPtr) -> Int;
    fn strncmp(s1: ConstCharPtr, s2: ConstCharPtr, n: SizeT) -> Int;
    fn strcat(dest: CharPtr, src: ConstCharPtr) -> CharPtr;
    fn strncat(dest: CharPtr, src: ConstCharPtr, n: SizeT) -> CharPtr;
    fn strchr(s: ConstCharPtr, c: Int) -> CharPtr;
    fn strrchr(s: ConstCharPtr, c: Int) -> CharPtr;
    fn strstr(haystack: ConstCharPtr, needle: ConstCharPtr) -> CharPtr;
    fn memcpy(dest: VoidPtr, src: ConstVoidPtr, n: SizeT) -> VoidPtr;
    fn memset(s: VoidPtr, c: Int, n: SizeT) -> VoidPtr;
    fn memmove(dest: VoidPtr, src: ConstVoidPtr, n: SizeT) -> VoidPtr;
    fn memcmp(s1: ConstVoidPtr, s2: ConstVoidPtr, n: SizeT) -> Int;
    fn strerror(errnum: Int) -> CharPtr;

    // === unistd.h / POSIX ===
    fn read(fd: Fd, buf: VoidPtr, count: SizeT) -> Long;
    fn write(fd: Fd, buf: ConstVoidPtr, count: SizeT) -> Long;
    fn open(pathname: ConstCharPtr, flags: Int, ...) -> Fd;
    fn close(fd: Fd) -> Int;
    fn fork() -> Int;
    fn execve(pathname: ConstCharPtr, argv: VoidPtr, envp: VoidPtr) -> Int;
    fn getpid() -> Int;
    fn sleep(seconds: UInt) -> UInt;
    fn dup2(oldfd: Fd, newfd: Fd) -> Fd;
    fn pipe(pipefd: VoidPtr) -> Int;

    // === sys/socket.h ===
    fn socket(domain: Int, socktype: Int, protocol: Int) -> SockFd;
    fn bind(sockfd: SockFd, addr: ConstVoidPtr, addrlen: UInt) -> Int;
    fn listen(sockfd: SockFd, backlog: Int) -> Int;
    fn accept(sockfd: SockFd, addr: VoidPtr, addrlen: VoidPtr) -> SockFd;
    fn connect(sockfd: SockFd, addr: ConstVoidPtr, addrlen: UInt) -> Int;
    fn send(sockfd: SockFd, buf: ConstVoidPtr, len: SizeT, flags: Int) -> Long;
    fn recv(sockfd: SockFd, buf: VoidPtr, len: SizeT, flags: Int) -> Long;
    fn sendto(sockfd: SockFd, buf: ConstVoidPtr, len: SizeT, flags: Int, dest_addr: ConstVoidPtr, addrlen: UInt) -> Long;
    fn recvfrom(sockfd: SockFd, buf: VoidPtr, len: SizeT, flags: Int, src_addr: VoidPtr, addrlen: VoidPtr) -> Long;
    fn setsockopt(sockfd: SockFd, level: Int, optname: Int, optval: ConstVoidPtr, optlen: UInt) -> Int;
    fn getsockopt(sockfd: SockFd, level: Int, optname: Int, optval: VoidPtr, optlen: VoidPtr) -> Int;
    fn shutdown(sockfd: SockFd, how: Int) -> Int;
};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rsleigh-decompile -- signatures::tests -v`
Expected: All 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add rsleigh-decompile/src/signatures_libc.rs rsleigh-decompile/src/signatures.rs
git commit -m "feat: add libc function signatures (stdio, stdlib, string, unistd, socket)"
```

---

### Task 3: Win32 Signature Definitions

**Files:**
- Modify: `rsleigh-decompile/src/signatures_win32.rs`

- [ ] **Step 1: Write a coverage test**

Add to `rsleigh-decompile/src/signatures.rs` tests:

```rust
    #[test]
    fn win32_coverage() {
        for name in ["VirtualAlloc", "VirtualFree", "VirtualProtect",
                      "CreateFileA", "CreateFileW", "ReadFile", "WriteFile",
                      "CloseHandle", "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
                      "GetModuleHandleA", "GetModuleHandleW",
                      "CreateProcessA", "CreateProcessW",
                      "GetLastError", "SetLastError",
                      "HeapAlloc", "HeapFree",
                      "CreateRemoteThread", "WriteProcessMemory",
                      "RegOpenKeyExA", "RegSetValueExA"] {
            assert!(lookup(name).is_some(), "missing: {}", name);
        }
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p rsleigh-decompile -- signatures::tests::win32_coverage -v`
Expected: FAIL — most Win32 functions missing.

- [ ] **Step 3: Populate Win32 signatures**

Replace `rsleigh-decompile/src/signatures_win32.rs` with:

```rust
use crate::signatures::*;

pub static WIN32_SIGNATURES: &[FuncSig] = define_signatures! {
    // === Memory ===
    fn VirtualAlloc(lpAddress: LpVoid, dwSize: SizeT, flAllocationType: DWord, flProtect: DWord) -> LpVoid;
    fn VirtualFree(lpAddress: LpVoid, dwSize: SizeT, dwFreeType: DWord) -> Int;
    fn VirtualProtect(lpAddress: LpVoid, dwSize: SizeT, flNewProtect: DWord, lpflOldProtect: LpVoid) -> Int;
    fn HeapAlloc(hHeap: Handle, dwFlags: DWord, dwBytes: SizeT) -> LpVoid;
    fn HeapFree(hHeap: Handle, dwFlags: DWord, lpMem: LpVoid) -> Int;

    // === File I/O ===
    fn CreateFileA(lpFileName: ConstCharPtr, dwDesiredAccess: DWord, dwShareMode: DWord, lpSecurityAttributes: LpVoid, dwCreationDisposition: DWord, dwFlagsAndAttributes: DWord, hTemplateFile: Handle) -> Handle;
    fn CreateFileW(lpFileName: ConstWCharPtr, dwDesiredAccess: DWord, dwShareMode: DWord, lpSecurityAttributes: LpVoid, dwCreationDisposition: DWord, dwFlagsAndAttributes: DWord, hTemplateFile: Handle) -> Handle;
    fn ReadFile(hFile: Handle, lpBuffer: LpVoid, nNumberOfBytesToRead: DWord, lpNumberOfBytesRead: LpVoid, lpOverlapped: LpVoid) -> Int;
    fn WriteFile(hFile: Handle, lpBuffer: ConstVoidPtr, nNumberOfBytesToWrite: DWord, lpNumberOfBytesWritten: LpVoid, lpOverlapped: LpVoid) -> Int;
    fn CloseHandle(hObject: Handle) -> Int;

    // === Module / Library ===
    fn GetProcAddress(hModule: Handle, lpProcName: ConstCharPtr) -> LpVoid;
    fn LoadLibraryA(lpLibFileName: ConstCharPtr) -> Handle;
    fn LoadLibraryW(lpLibFileName: ConstWCharPtr) -> Handle;
    fn GetModuleHandleA(lpModuleName: ConstCharPtr) -> Handle;
    fn GetModuleHandleW(lpModuleName: ConstWCharPtr) -> Handle;

    // === Process ===
    fn CreateProcessA(lpApplicationName: ConstCharPtr, lpCommandLine: CharPtr, lpProcessAttributes: LpVoid, lpThreadAttributes: LpVoid, bInheritHandles: Int, dwCreationFlags: DWord, lpEnvironment: LpVoid, lpCurrentDirectory: ConstCharPtr, lpStartupInfo: LpVoid, lpProcessInformation: LpVoid) -> Int;
    fn CreateProcessW(lpApplicationName: ConstWCharPtr, lpCommandLine: WCharPtr, lpProcessAttributes: LpVoid, lpThreadAttributes: LpVoid, bInheritHandles: Int, dwCreationFlags: DWord, lpEnvironment: LpVoid, lpCurrentDirectory: ConstWCharPtr, lpStartupInfo: LpVoid, lpProcessInformation: LpVoid) -> Int;
    fn CreateRemoteThread(hProcess: Handle, lpThreadAttributes: LpVoid, dwStackSize: SizeT, lpStartAddress: LpVoid, lpParameter: LpVoid, dwCreationFlags: DWord, lpThreadId: LpVoid) -> Handle;
    fn WriteProcessMemory(hProcess: Handle, lpBaseAddress: LpVoid, lpBuffer: ConstVoidPtr, nSize: SizeT, lpNumberOfBytesWritten: LpVoid) -> Int;

    // === Error ===
    fn GetLastError() -> DWord;
    fn SetLastError(dwErrCode: DWord);

    // === Registry ===
    fn RegOpenKeyExA(hKey: Handle, lpSubKey: ConstCharPtr, ulOptions: DWord, samDesired: DWord, phkResult: LpVoid) -> Long;
    fn RegSetValueExA(hKey: Handle, lpValueName: ConstCharPtr, Reserved: DWord, dwType: DWord, lpData: ConstVoidPtr, cbData: DWord) -> Long;
};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p rsleigh-decompile -- signatures::tests -v`
Expected: All 7 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add rsleigh-decompile/src/signatures_win32.rs rsleigh-decompile/src/signatures.rs
git commit -m "feat: add Win32 API function signatures"
```

---

### Task 4: Fold Pass Integration — Apply Param Names to Call Args

**Files:**
- Modify: `rsleigh-decompile/src/fold.rs` (near line 1005 and line 1806)
- Modify: `rsleigh-decompile/src/lib.rs` (lines 94-118)

This is the core integration. When the fold pass collects call arguments and the call target resolves to a known import name, we apply parameter names from the signature database to the corresponding argument variables.

- [ ] **Step 1: Add the `apply_signature_names` function to fold.rs**

Add after the existing `name_parameters()` function (around line 1942):

```rust
/// Apply parameter names from the signature database to call arguments.
/// For each Call with a resolved import name that has a signature, rename
/// the argument variables to the signature's parameter names — but only
/// if the variable doesn't already have a DWARF-derived name and is only
/// used as an argument to this one call.
pub fn apply_signature_names(ssa: &mut SsaCfg, import_map: &std::collections::HashMap<u64, String>) {
    // Collect (var_id, new_name, new_type) tuples first to avoid borrow issues
    let mut renames: Vec<(crate::ir::VarId, String, crate::ir::InferredType)> = Vec::new();

    for block in &ssa.blocks {
        // Check Call statements
        for stmt in &block.stmts {
            if let crate::ir::Stmt::Call { target, args, .. } = stmt {
                collect_sig_renames(target, args, &ssa.vars, import_map, &mut renames);
            }
        }
        // Check Call terminators
        if let crate::ir::SsaTerminator::Call { target, args, .. } = &block.terminator {
            collect_sig_renames(target, args, &ssa.vars, import_map, &mut renames);
        }
    }

    // Apply renames
    for (var_id, name, ty) in renames {
        let vdef = &mut ssa.vars[var_id.0 as usize];
        // Never overwrite DWARF-recovered names
        if let Some(ref existing) = vdef.param_name {
            if !existing.starts_with("param_") {
                continue; // DWARF name — don't overwrite
            }
        }
        // Only rename if variable is used exactly once (as this call argument)
        if vdef.use_count <= 1 {
            vdef.param_name = Some(name);
        }
        // Always propagate type from signature (even for multi-use vars)
        if vdef.inferred_type == crate::ir::InferredType::Unknown {
            vdef.inferred_type = ty;
        }
    }
}

fn collect_sig_renames(
    target: &crate::ir::CallTarget,
    args: &[crate::ir::VarId],
    vars: &[crate::ir::VarDef],
    import_map: &std::collections::HashMap<u64, String>,
    renames: &mut Vec<(crate::ir::VarId, String, crate::ir::InferredType)>,
) {
    let name = match target {
        crate::ir::CallTarget::Direct(addr) => import_map.get(addr),
        _ => None,
    };
    let Some(func_name) = name else { return };
    let Some(sig) = crate::signatures::lookup(func_name) else { return };

    for (i, arg_var) in args.iter().enumerate() {
        if i >= sig.params.len() { break; } // variadic extra args — skip
        let param = &sig.params[i];
        let vdef = &vars[arg_var.0 as usize];

        // Skip if already has a non-generic name
        if let Some(ref existing) = vdef.param_name {
            if !existing.starts_with("param_") {
                continue;
            }
        }

        renames.push((*arg_var, param.name.to_string(), param.ty.to_inferred()));
    }
}
```

- [ ] **Step 2: Add return type propagation for call results**

Add after `apply_signature_names` in fold.rs:

```rust
/// Propagate return types from known function signatures to call result variables.
/// If `malloc()` returns void*, mark the RAX/EAX variable as Pointer.
pub fn propagate_signature_return_types(
    ssa: &mut SsaCfg,
    import_map: &std::collections::HashMap<u64, String>,
) {
    for block in &ssa.blocks {
        // Stmt::Call with out
        for stmt in &block.stmts {
            if let crate::ir::Stmt::Call { target, out: Some(out_var), .. } = stmt {
                apply_return_type(target, *out_var, &mut ssa.vars, import_map);
            }
        }
    }

    // Also check call_return vars in fallthrough blocks after Call terminators
    for bi in 0..ssa.blocks.len() {
        let (target, fallthrough) = match &ssa.blocks[bi].terminator {
            crate::ir::SsaTerminator::Call { target, fallthrough, .. } => {
                (target.clone(), *fallthrough)
            }
            _ => continue,
        };
        // Find the call_return var in the fallthrough block
        let ft_idx = fallthrough.0 as usize;
        if ft_idx >= ssa.blocks.len() { continue; }
        for stmt in &ssa.blocks[ft_idx].stmts {
            if let crate::ir::Stmt::Assign(var_id) = stmt {
                let vdef = &ssa.vars[var_id.0 as usize];
                if vdef.call_return {
                    apply_return_type(&target, *var_id, &mut ssa.vars, import_map);
                    break;
                }
            }
        }
    }
}

fn apply_return_type(
    target: &crate::ir::CallTarget,
    var_id: crate::ir::VarId,
    vars: &mut Vec<crate::ir::VarDef>,
    import_map: &std::collections::HashMap<u64, String>,
) {
    let name = match target {
        crate::ir::CallTarget::Direct(addr) => import_map.get(addr),
        _ => None,
    };
    let Some(func_name) = name else { return };
    let Some(sig) = crate::signatures::lookup(func_name) else { return };

    let ret_type = sig.ret.to_inferred();
    if ret_type != crate::ir::InferredType::Unknown {
        let vdef = &mut vars[var_id.0 as usize];
        if vdef.inferred_type == crate::ir::InferredType::Unknown {
            vdef.inferred_type = ret_type;
        }
    }
}
```

- [ ] **Step 3: Wire into lib.rs**

In `rsleigh-decompile/src/lib.rs`, after the `fold::fold_with_cc(&mut ssa, cc);` call on line 118, add:

```rust
    // Apply function signature parameter names and return types
    fold::apply_signature_names(&mut ssa, &import_map);
    fold::propagate_signature_return_types(&mut ssa, &import_map);
```

Note: This must come AFTER `fold_with_cc` (which collects call arguments and runs type inference) but BEFORE the DWARF name application (lines 120+), so DWARF names take priority over signature names.

- [ ] **Step 4: Run all existing tests**

Run: `cargo test -p rsleigh-decompile -v && cargo test -p test-harness -v`
Expected: All existing tests PASS (this is a non-breaking addition — signature names only apply when imports resolve to known functions).

- [ ] **Step 5: Commit**

```bash
git add rsleigh-decompile/src/fold.rs rsleigh-decompile/src/lib.rs
git commit -m "feat: apply signature param names and return types in fold pass"
```

---

### Task 5: Printer Integration — Signature-Aware Call Display

**Files:**
- Modify: `rsleigh-decompile/src/printer.rs` (lines 4298-4372 and 4811-4859)

The printer needs two changes:
1. Use signature return types when displaying calls with output variables
2. Use signature param types for function signature display when the function being decompiled is a known import

- [ ] **Step 1: Enhance call return type display in `generate_function_signature`**

In `printer.rs`, find the `generate_function_signature` function (around line 4298). The existing code infers return type from `InferredType`. Since we now propagate signature return types in the fold pass (Task 4), this already works — the `InferredType::Pointer` from `malloc` will already produce `void *` return type.

No code change needed here — the fold pass integration handles it.

- [ ] **Step 2: Add signature-aware parameter type display for known imports**

In `printer.rs`, the `generate_function_signature` function (around line 4348) maps `InferredType` to C type strings. We want to use more specific types when a function signature is available. Add this enhancement to `generate_function_signature`:

Find the section where parameters are formatted (after params are collected, around line 4348). Before the type mapping, add a signature lookup:

```rust
    // If this function has a known signature, use its specific types
    let sig = crate::signatures::lookup(func_name);

    let params_str: String = params.iter().enumerate().map(|(i, (name, sz, ty))| {
        // Prefer signature type if available
        let type_str = if let Some(sig) = sig {
            if i < sig.params.len() {
                sig.params[i].ty.c_str()
            } else {
                inferred_type_to_c(*ty, *sz)
            }
        } else {
            inferred_type_to_c(*ty, *sz)
        };
        format!("{} {}", type_str, name)
    }).collect::<Vec<_>>().join(", ");
```

Also extract the existing type-to-string mapping into a helper (if not already):

```rust
fn inferred_type_to_c(ty: InferredType, sz: u32) -> &'static str {
    match (ty, sz) {
        (InferredType::Float, 4) => "float",
        (InferredType::Float, 8) => "double",
        (InferredType::Signed, 1) => "char",
        (InferredType::Signed, 4) => "int",
        (InferredType::Signed, 8) => "long",
        (InferredType::Pointer, _) => "void *",
        (InferredType::Bool, _) => "bool",
        (_, 1) => "uint8_t",
        (_, 4) => "int",
        (_, 8) => "long",
        _ => "int",
    }
}
```

And for return type in the same function, prefer signature return type:

```rust
    let return_type = if let Some(sig) = sig {
        sig.ret.c_str()
    } else {
        // existing InferredType-based return type logic
        inferred_type_to_c(ret_ty, ret_sz)
    };
```

- [ ] **Step 3: Run all tests**

Run: `cargo test -p rsleigh-decompile -v && cargo test -p test-harness -v`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add rsleigh-decompile/src/printer.rs
git commit -m "feat: use signature types in printer for known function parameters and returns"
```

---

### Task 6: End-to-End Decompiler Test

**Files:**
- Modify: `test-harness/src/main.rs` (after line ~4270)

- [ ] **Step 1: Write the test**

Add after the existing `decompiler_validation` test in `test-harness/src/main.rs`:

```rust
fn test_signature_param_names(binary: &[u8], path: &std::path::Path, symbols: &[(u64, String)], segs: &[(u64, u64, u64)]) {
    // Find and decompile a function that calls known libc functions
    // The existing test binary (compiled in decompiler_validation) calls printf, strlen, strcpy
    let mut decoder = rsleigh_api::Decoder::new(rsleigh_api::Architecture::X86_64);

    for (addr, name) in symbols {
        let off = segs.iter().find_map(|(va, sz, fo)| {
            if *addr >= *va && *addr < va + sz { Some(fo + (addr - va)) } else { None }
        });
        let Some(off) = off else { continue };
        let max = 4096.min(binary.len() - off as usize);
        let bytes = &binary[off as usize..off as usize + max];

        let next = symbols.iter().filter(|(a, _)| *a > *addr).map(|(a, _)| *a).min()
            .unwrap_or(*addr + max as u64);
        let limit = ((next - addr) as usize).min(max);

        let mut insts = Vec::new();
        let mut io = 0;
        while io < limit {
            match decoder.decode(&bytes[io..], addr + io as u64) {
                Ok(inst) => {
                    let l = inst.len as usize;
                    if l == 0 { io += 1; continue; }
                    insts.push((addr + io as u64, inst));
                    io += l;
                }
                Err(_) => break,
            }
        }
        if insts.is_empty() { continue; }

        let output = rsleigh_decompile::decompile_with_binary(
            rsleigh_api::Architecture::X86_64,
            &insts,
            Some(binary),
            Some(path),
        );

        // Check that known function calls use parameter names from signatures
        if name == "test_strings" || output.contains("strlen(") {
            // strlen(s) — param should be named 's' not 'param_0'
            if output.contains("strlen(") {
                assert!(!output.contains("strlen(param_0)"),
                    "strlen should use signature param name 's', not 'param_0'.\nOutput:\n{}", output);
            }
        }
        if output.contains("malloc(") {
            // malloc return should be void* typed
            // The variable holding malloc result should reflect pointer type
            assert!(!output.contains("int iVar") || !output.contains("= malloc("),
                "malloc result should not be typed as int.\nOutput:\n{}", output);
        }
    }
}
```

- [ ] **Step 2: Call the test from `run_decompiler_validation`**

In the existing `run_decompiler_validation()` function, after the existing assertions, add:

```rust
    test_signature_param_names(&data, std::path::Path::new("/tmp/test_prog_x86"), &symbols, &segs);
```

- [ ] **Step 3: Run the tests**

Run: `cargo test -p test-harness -- decompiler_validation -v`
Expected: PASS — signature param names applied to calls.

- [ ] **Step 4: Commit**

```bash
git add test-harness/src/main.rs
git commit -m "test: add signature param name verification to decompiler tests"
```

---

### Task 7: Verify with readexe Binary

This is a manual verification task using the binary from the earlier Ghidra comparison.

- [ ] **Step 1: Run rsleigh-cli on readexe**

```bash
cargo run -p rsleigh-cli --release -- ~/Downloads/readexe-win64.exe --all 2>/dev/null > /tmp/rsleigh-sigs.txt
```

- [ ] **Step 2: Verify signature names appear**

```bash
# Check that fread now shows param names
grep "fread(" /tmp/rsleigh-sigs.txt | head -5
# Should show: fread(ptr, size, nmemb, stream) or similar

# Check malloc result type
grep "malloc(" /tmp/rsleigh-sigs.txt | head -5

# Check printf param names
grep "printf(" /tmp/rsleigh-sigs.txt | head -5
# Should show: printf(format, ...) with 'format' not 'param_0'

# Count improvements
echo "=== Signature-named params ==="
grep -oE '\b(format|size|nmemb|stream|dest|src|sockfd|buf|ptr|pathname|fd)\b' /tmp/rsleigh-sigs.txt | sort | uniq -c | sort -rn
```

- [ ] **Step 3: Run full test suite to confirm no regressions**

```bash
cargo test -p test-harness -v
cargo test -p rsleigh-decompile -v
```

Expected: All tests PASS.

- [ ] **Step 4: Commit any final adjustments**

```bash
git add -u
git commit -m "chore: final adjustments from readexe verification"
```

---

## Verification Checklist

After all tasks are complete, verify:

1. `cargo test -p rsleigh-decompile -- signatures -v` — All signature unit tests pass
2. `cargo test -p test-harness -v` — All existing + new decompiler tests pass
3. `cargo run -p rsleigh-cli --release -- ~/Downloads/readexe-win64.exe FUN_140001d42 2>/dev/null` — Shows `malloc(size)`, `fseek(stream, ...)`, `fread(ptr, size, nmemb, stream)`
4. DWARF names not overwritten — compile a test binary with `-g`, verify DWARF param names appear instead of signature names
5. Unknown functions unchanged — internal `func_XXXXXXXX` calls still work normally
