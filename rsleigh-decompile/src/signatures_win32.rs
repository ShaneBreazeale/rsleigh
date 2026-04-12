//! Win32 API function signatures.

use crate::signatures::*;

pub static WIN32_SIGNATURES: &[FuncSig] = crate::define_signatures! {
    fn VirtualAlloc(lpAddress: LpVoid, dwSize: SizeT, flAllocationType: DWord, flProtect: DWord) -> LpVoid;
};
