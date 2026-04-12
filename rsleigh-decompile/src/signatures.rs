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
pub fn lookup(name: &str) -> Option<&'static FuncSig> {
    SIGNATURE_MAP.get(name).copied()
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
}
