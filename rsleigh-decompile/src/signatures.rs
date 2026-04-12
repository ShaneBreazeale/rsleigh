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
    for sig in crate::signatures_libc::LIBC_SIGNATURES {
        map.insert(sig.name, sig);
    }
    for sig in crate::signatures_win32::WIN32_SIGNATURES {
        map.insert(sig.name, sig);
    }
    map
});

/// Look up a function signature by exact name.
/// Checks runtime-loaded signatures first, then compiled-in ones.
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
}
