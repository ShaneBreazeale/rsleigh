//! POSIX / C standard library function signatures.

use crate::signatures::*;

pub static LIBC_SIGNATURES: &[FuncSig] = crate::define_signatures! {
    fn printf(format: ConstCharPtr, ...) -> Int;
    fn malloc(size: SizeT) -> VoidPtr;
};
