//! Function signature database for known library functions.
//!
//! Maps function names (e.g. "printf", "malloc", "VirtualAlloc") to their
//! C signatures so the decompiler can emit correct parameter names, types,
//! and variadic markers.

use std::collections::HashMap;
use std::sync::LazyLock;

use crate::ir::InferredType;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// C type categories for function parameters and return values.
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
    FilePtr,
    Bool,
    Fd,
    SockFd,
    WCharPtr,
    ConstWCharPtr,
    Handle,
    DWord,
    LpVoid,
}

impl SigType {
    /// Returns the C type string for display.
    pub fn c_str(&self) -> &'static str {
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
            SigType::Fd => "int",
            SigType::SockFd => "int",
            SigType::WCharPtr => "wchar_t *",
            SigType::ConstWCharPtr => "const wchar_t *",
            SigType::Handle => "HANDLE",
            SigType::DWord => "DWORD",
            SigType::LpVoid => "LPVOID",
        }
    }

    /// Maps to the decompiler's internal type system.
    pub fn to_inferred(&self) -> InferredType {
        match self {
            SigType::Void => InferredType::Unknown,
            SigType::Bool => InferredType::Bool,
            SigType::Int | SigType::Long | SigType::Fd | SigType::SockFd => InferredType::Signed,
            SigType::UInt | SigType::ULong | SigType::SizeT | SigType::DWord | SigType::Handle => {
                InferredType::Unsigned
            }
            SigType::CharPtr
            | SigType::ConstCharPtr
            | SigType::VoidPtr
            | SigType::ConstVoidPtr
            | SigType::FilePtr
            | SigType::WCharPtr
            | SigType::ConstWCharPtr
            | SigType::LpVoid => InferredType::Pointer,
        }
    }
}

// ---------------------------------------------------------------------------
// Signature structs
// ---------------------------------------------------------------------------

/// A single function parameter.
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

// ---------------------------------------------------------------------------
// Declarative macro for concise signature definitions
// ---------------------------------------------------------------------------

/// Define a table of function signatures.
///
/// ```ignore
/// define_signatures! {
///     fn printf(format: ConstCharPtr, ...) -> Int;
///     fn malloc(size: SizeT) -> VoidPtr;
///     fn free(ptr: VoidPtr);
/// }
/// ```
#[macro_export]
macro_rules! define_signatures {
    // Entry point: collect all function definitions into a slice.
    ( $( fn $name:ident ( $($params:tt)* ) $(-> $ret:ident)? ; )* ) => {
        &[
            $(
                $crate::signatures::FuncSig {
                    name: stringify!($name),
                    ret: $crate::define_signatures!(@ret $($ret)?),
                    params: $crate::define_signatures!(@params $($params)*),
                    variadic: $crate::define_signatures!(@variadic $($params)*),
                }
            ),*
        ]
    };

    // --- Return type: present or default to Void ---
    (@ret $ret:ident) => { $crate::signatures::SigType::$ret };
    (@ret) => { $crate::signatures::SigType::Void };

    // --- Variadic detection ---
    // Empty params: not variadic
    (@variadic) => { false };
    // Single `...`: variadic
    (@variadic ...) => { true };
    // Params ending with `, ...`: variadic
    (@variadic $($name:ident : $ty:ident),+ , ...) => { true };
    // Params without `...`: not variadic
    (@variadic $($name:ident : $ty:ident),+) => { false };

    // --- Parameter extraction ---
    // Empty params
    (@params) => { &[] };
    // Just `...` — no named params
    (@params ...) => { &[] };
    // Named params followed by `, ...`
    (@params $($name:ident : $ty:ident),+ , ...) => {
        &[
            $( $crate::signatures::SigParam { name: stringify!($name), ty: $crate::signatures::SigType::$ty } ),+
        ]
    };
    // Named params only
    (@params $($name:ident : $ty:ident),+) => {
        &[
            $( $crate::signatures::SigParam { name: stringify!($name), ty: $crate::signatures::SigType::$ty } ),+
        ]
    };
}

// ---------------------------------------------------------------------------
// Global lookup
// ---------------------------------------------------------------------------

static SIGNATURE_MAP: LazyLock<HashMap<&'static str, &'static FuncSig>> = LazyLock::new(|| {
    let mut map = HashMap::new();
    // Load compiled-in macro signatures
    for sig in crate::signatures_libc::LIBC_SIGNATURES {
        map.insert(sig.name, sig);
    }
    for sig in crate::signatures_win32::WIN32_SIGNATURES {
        map.insert(sig.name, sig);
    }
    // Load embedded compressed signature database (36K+ sigs, ~320KB gzipped)
    load_embedded_tsv(&mut map);
    // Load curated JSON signatures (overrides TSV where present — hand-tuned types)
    load_embedded_json(&mut map);
    map
});

/// Look up a function signature by exact name.
/// Checks runtime-loaded signatures first (--sigs), then the built-in database.
pub fn lookup(name: &str) -> Option<&'static FuncSig> {
    // Check runtime-loaded sigs first (they may override builtins)
    if let Some(rt) = RUNTIME_SIGS.get() {
        if let Some(sig) = rt.get(name) {
            return Some(sig);
        }
    }
    SIGNATURE_MAP.get(name).copied()
}

// ---------------------------------------------------------------------------
// Embedded compressed signature database (TSV + gzip)
// ---------------------------------------------------------------------------

/// Decompress and parse the embedded signature database.
/// Format: gzipped TSV with columns: name, ret_type_code, params (name:type,...), variadic (0/1)
/// Type codes: v=void, i=int, u=uint, l=long, U=ulong, z=size_t, b=bool,
///             s=char*, W=wchar_t*, p=void*, F=FILE*
fn load_embedded_tsv(map: &mut HashMap<&'static str, &'static FuncSig>) {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let compressed = include_bytes!("../data/signatures.tsv.gz");
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut text = String::new();
    if decoder.read_to_string(&mut text).is_err() {
        return;
    }

    for line in text.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 4 { continue; }

        let name = parts[0];
        if map.contains_key(name) { continue; } // macro sigs take priority

        let ret = tsv_type_code(parts[1]);

        let params: Vec<SigParam> = if parts[2].is_empty() {
            Vec::new()
        } else {
            parts[2].split(',').map(|p| {
                let mut it = p.splitn(2, ':');
                let pname = it.next().unwrap_or("arg");
                let ptype = tsv_type_code(it.next().unwrap_or("i"));
                SigParam { name: leak_str(pname), ty: ptype }
            }).collect()
        };

        let variadic = parts[3] == "1";

        let sig = FuncSig {
            name: leak_str(name),
            ret,
            params: Box::leak(params.into_boxed_slice()),
            variadic,
        };
        let sig_ref: &'static FuncSig = Box::leak(Box::new(sig));
        map.insert(sig_ref.name, sig_ref);
    }
}

/// Load curated JSON signatures (supplements TSV with hand-written entries).
fn load_embedded_json(map: &mut HashMap<&'static str, &'static FuncSig>) {
    let json_str = include_str!("../data/signatures.json");
    let Ok(entries) = serde_json::from_str::<Vec<JsonSigEntry>>(json_str) else { return };
    for entry in &entries {
        if map.contains_key(entry.name.as_str()) { continue; }
        let params: Vec<SigParam> = entry.params.iter().map(|p| {
            SigParam {
                name: leak_str(&clean_param_name(&p.name)),
                ty: ghidra_type_to_sigtype(&p.ty),
            }
        }).collect();
        let sig = FuncSig {
            name: leak_str(&entry.name),
            ret: ghidra_type_to_sigtype(&entry.ret),
            params: Box::leak(params.into_boxed_slice()),
            variadic: entry.variadic,
        };
        let sig_ref: &'static FuncSig = Box::leak(Box::new(sig));
        map.insert(sig_ref.name, sig_ref);
    }
}

fn tsv_type_code(code: &str) -> SigType {
    match code {
        "v" => SigType::Void,
        "i" => SigType::Int,
        "u" => SigType::UInt,
        "l" => SigType::Long,
        "U" => SigType::ULong,
        "z" => SigType::SizeT,
        "b" => SigType::Bool,
        "s" => SigType::CharPtr,
        "W" => SigType::WCharPtr,
        "p" => SigType::VoidPtr,
        "F" => SigType::FilePtr,
        _ => SigType::Int,
    }
}

// ---------------------------------------------------------------------------
// Runtime-loaded signatures (from JSON files)
// ---------------------------------------------------------------------------

/// Owned version of FuncSig for runtime-loaded signatures.
/// Stored in a leaked Box so we can return &'static references.
struct RuntimeSigStore {
    map: HashMap<String, &'static FuncSig>,
    // Keep the backing storage alive (leaked Vecs/Strings)
    _storage: Vec<Box<dyn std::any::Any + Send + Sync>>,
}

impl RuntimeSigStore {
    fn get(&self, name: &str) -> Option<&'static FuncSig> {
        self.map.get(name).copied()
    }
}

static RUNTIME_SIGS: std::sync::OnceLock<RuntimeSigStore> = std::sync::OnceLock::new();

/// Address-based learned type store for interprocedural propagation.
/// Populated by two-pass decompilation: first pass learns types, second pass uses them.
static LEARNED_SIGS: std::sync::OnceLock<std::sync::Mutex<HashMap<u64, &'static FuncSig>>> = std::sync::OnceLock::new();

/// Register learned function types from the first decompilation pass.
/// These are used by the second pass to type internal function parameters.
pub fn register_learned_types(types: &[crate::LearnedFuncType]) {
    let store = LEARNED_SIGS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let mut map = store.lock().unwrap();
    for lt in types {
        if lt.param_types.iter().all(|t| t.is_none()) && lt.return_type.is_none() {
            continue;
        }
        let params: Vec<SigParam> = lt.param_types.iter().enumerate().map(|(i, dt)| {
            SigParam {
                name: leak_str(&format!("param_{}", i)),
                ty: match dt {
                    Some(s) => c_str_to_sigtype(s),
                    None => SigType::Int,
                },
            }
        }).collect();
        let ret = match lt.return_type {
            Some(s) => c_str_to_sigtype(s),
            None => SigType::Void,
        };
        let sig = FuncSig {
            name: leak_str(&format!("func_{:x}", lt.addr)),
            ret,
            params: Box::leak(params.into_boxed_slice()),
            variadic: false,
        };
        map.insert(lt.addr, Box::leak(Box::new(sig)));
    }
}

/// Look up a learned signature by function address.
pub fn lookup_addr(addr: u64) -> Option<&'static FuncSig> {
    let store = LEARNED_SIGS.get()?;
    let map = store.lock().ok()?;
    map.get(&addr).copied()
}

/// Map C type display string back to SigType.
fn c_str_to_sigtype(s: &str) -> SigType {
    match s {
        "void" => SigType::Void,
        "int" => SigType::Int,
        "unsigned int" => SigType::UInt,
        "long" => SigType::Long,
        "unsigned long" => SigType::ULong,
        "size_t" => SigType::SizeT,
        "char *" => SigType::CharPtr,
        "const char *" => SigType::ConstCharPtr,
        "void *" => SigType::VoidPtr,
        "const void *" => SigType::ConstVoidPtr,
        "FILE *" => SigType::FilePtr,
        "bool" => SigType::Bool,
        "wchar_t *" => SigType::WCharPtr,
        "const wchar_t *" => SigType::ConstWCharPtr,
        "HANDLE" => SigType::Handle,
        "DWORD" => SigType::DWord,
        "LPVOID" => SigType::LpVoid,
        _ => SigType::Int,
    }
}

/// Load additional signatures from a Ghidra-exported JSON file.
///
/// The JSON format is an array of objects:
/// ```json
/// [{"name": "printf", "ret": "int", "params": [{"name": "format", "type": "char *"}], "variadic": true}, ...]
/// ```
///
/// Call this once at startup before decompilation begins. Subsequent calls are ignored.
/// Returns the number of signatures loaded.
pub fn load_json(json_str: &str) -> Result<usize, String> {
    let entries: Vec<JsonSigEntry> = serde_json::from_str(json_str)
        .map_err(|e| format!("failed to parse signature JSON: {}", e))?;

    let mut map = HashMap::new();
    let mut storage: Vec<Box<dyn std::any::Any + Send + Sync>> = Vec::new();

    for entry in &entries {
        let params: Vec<SigParam> = entry.params.iter().map(|p| {
            SigParam {
                name: leak_str(&clean_param_name(&p.name)),
                ty: ghidra_type_to_sigtype(&p.ty),
            }
        }).collect();
        let params_ref: &'static [SigParam] = Box::leak(params.into_boxed_slice());

        let sig = FuncSig {
            name: leak_str(&entry.name),
            ret: ghidra_type_to_sigtype(&entry.ret),
            params: params_ref,
            variadic: entry.variadic,
        };
        let sig_ref: &'static FuncSig = Box::leak(Box::new(sig));
        map.insert(entry.name.clone(), sig_ref);
    }

    let count = map.len();
    storage.push(Box::new(())); // placeholder to keep _storage non-empty

    let _ = RUNTIME_SIGS.set(RuntimeSigStore { map, _storage: storage });
    Ok(count)
}

/// Load signatures from a JSON file path.
pub fn load_json_file(path: &std::path::Path) -> Result<usize, String> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read {}: {}", path.display(), e))?;
    load_json(&data)
}

fn leak_str(s: &str) -> &'static str {
    Box::leak(s.to_string().into_boxed_str())
}

fn clean_param_name(name: &str) -> String {
    let n = name.trim_start_matches('_');
    if n.is_empty() { return "arg".to_string(); }
    // Rust keywords
    match n {
        "type" | "fn" | "mod" | "self" | "super" | "use" | "in" | "ref" | "mut"
        | "loop" | "match" | "if" | "else" | "return" | "struct" | "enum"
        | "trait" | "impl" | "as" | "where" | "break" | "continue" | "for"
        | "while" | "pub" | "const" | "static" | "let" | "move" | "unsafe" => {
            format!("{}_", n)
        }
        _ => n.to_string(),
    }
}

/// Map Ghidra type strings to SigType.
fn ghidra_type_to_sigtype(ty: &str) -> SigType {
    let t = ty.trim();
    match t {
        "void" => SigType::Void,
        "int" => SigType::Int,
        "uint" | "unsigned int" => SigType::UInt,
        "long" => SigType::Long,
        "ulong" | "unsigned long" => SigType::ULong,
        "longlong" => SigType::Long,
        "ulonglong" => SigType::ULong,
        "short" | "ushort" | "char" | "uchar" | "unsigned char" | "byte" => SigType::Int,
        "size_t" => SigType::SizeT,
        "ssize_t" => SigType::Long,
        "bool" | "BOOL" => SigType::Bool,
        "HANDLE" => SigType::Handle,
        "DWORD" => SigType::DWord,
        "LPVOID" => SigType::LpVoid,
        "FILE *" => SigType::FilePtr,
        _ if t.ends_with(" *") || t.ends_with(" * *") => {
            if t.contains("char") && !t.contains("* *") {
                if t.contains("wchar") { SigType::WCharPtr } else { SigType::CharPtr }
            } else {
                SigType::VoidPtr
            }
        }
        _ => SigType::Int,
    }
}

#[derive(serde::Deserialize)]
struct JsonSigEntry {
    name: String,
    ret: String,
    params: Vec<JsonParam>,
    variadic: bool,
}

#[derive(serde::Deserialize)]
struct JsonParam {
    name: String,
    #[serde(rename = "type")]
    ty: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
        assert_eq!(sig.ret, SigType::VoidPtr);
        assert_eq!(sig.params.len(), 1);
        assert_eq!(sig.params[0].name, "size");
        assert_eq!(sig.params[0].ty, SigType::SizeT);
    }

    #[test]
    fn lookup_unknown() {
        assert!(lookup("this_function_does_not_exist_xyz").is_none());
    }

    #[test]
    fn lookup_win32() {
        let sig = lookup("VirtualAlloc").expect("VirtualAlloc should exist");
        assert_eq!(sig.name, "VirtualAlloc");
    }

    #[test]
    fn libc_coverage() {
        for name in ["printf", "fprintf", "sprintf", "snprintf", "puts", "fputs",
                      "fgets", "fread", "fwrite", "fopen", "fclose", "fseek",
                      "ftell", "feof", "ferror", "fflush", "fputc", "fgetc",
                      "putchar", "getchar",
                      "malloc", "calloc", "realloc", "free", "atoi", "atol",
                      "strtol", "strtoul", "exit", "abort", "abs", "qsort",
                      "strlen", "strcpy", "strncpy", "strcmp", "strncmp",
                      "strcat", "strncat", "strchr", "strrchr", "strstr",
                      "memcpy", "memset", "memmove", "memcmp", "strerror",
                      "read", "write", "open", "close", "fork", "execve",
                      "getpid", "sleep", "dup2", "pipe",
                      "socket", "bind", "listen", "accept", "connect",
                      "send", "recv", "sendto", "recvfrom",
                      "setsockopt", "getsockopt", "shutdown"] {
            assert!(lookup(name).is_some(), "missing libc sig: {}", name);
        }
    }

    #[test]
    fn win32_coverage() {
        for name in ["VirtualAlloc", "VirtualFree", "VirtualProtect",
                      "CreateFileA", "CreateFileW", "ReadFile", "WriteFile",
                      "CloseHandle", "GetProcAddress", "LoadLibraryA", "LoadLibraryW",
                      "GetModuleHandleA", "GetModuleHandleW",
                      "CreateProcessA", "CreateProcessW",
                      "CreateRemoteThread", "WriteProcessMemory",
                      "GetLastError", "SetLastError",
                      "HeapAlloc", "HeapFree",
                      "RegOpenKeyExA", "RegSetValueExA"] {
            assert!(lookup(name).is_some(), "missing win32 sig: {}", name);
        }
    }

    #[test]
    fn param_names_are_meaningful() {
        let sig = lookup("memcpy").unwrap();
        assert_eq!(sig.params[0].name, "dest");
        assert_eq!(sig.params[1].name, "src");
        assert_eq!(sig.params[2].name, "n");
    }

    #[test]
    fn embedded_json_loads() {
        // These are only in the JSON database, not the macro files
        for name in ["mmap", "pthread_create", "dlopen", "epoll_create",
                      "CreateToolhelp32Snapshot", "Process32First",
                      "WSAStartup", "InternetOpenA", "IsDebuggerPresent",
                      "NtQueryInformationProcess", "TlsAlloc"] {
            assert!(lookup(name).is_some(), "missing from embedded JSON: {}", name);
        }
    }

    #[test]
    fn total_signature_count() {
        // Should have 30K+ from macro + embedded TSV
        let count = SIGNATURE_MAP.len();
        assert!(count >= 30000, "expected 30000+ signatures, got {}", count);
    }
}
