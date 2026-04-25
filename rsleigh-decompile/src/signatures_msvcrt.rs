//! MSVC C runtime (msvcrt / ucrtbase) signatures.
//!
//! Common functions emitted by the MSVC compiler/linker into Windows
//! binaries that don't appear in POSIX libc. Buffer-security cookie
//! helpers, debug runtime, parameter-validation hooks, and the
//! Microsoft-specific stdio/string variants.

use crate::signatures::*;

pub static MSVCRT_SIGNATURES: &[FuncSig] = crate::define_signatures! {
    // Buffer security cookie (MSVC /GS)
    fn __security_cookie() -> ULong;
    fn __security_check_cookie(cookie: ULong);
    fn __report_gsfailure();
    fn __security_init_cookie();

    // Parameter validation
    fn _invalid_parameter(expression: ConstWCharPtr, function: ConstWCharPtr, file: ConstWCharPtr, line: UInt, pReserved: VoidPtr);
    fn _invalid_parameter_noinfo();
    fn _invalid_parameter_noinfo_noreturn();
    fn _set_invalid_parameter_handler(pNew: VoidPtr) -> VoidPtr;

    // CRT debug runtime
    fn _CrtDbgReport(reportType: Int, filename: ConstCharPtr, linenumber: Int, moduleName: ConstCharPtr, format: ConstCharPtr, ...) -> Int;
    fn _CrtDbgReportW(reportType: Int, filename: ConstWCharPtr, linenumber: Int, moduleName: ConstWCharPtr, format: ConstWCharPtr, ...) -> Int;
    fn _CrtSetDbgFlag(newFlag: Int) -> Int;
    fn _CrtSetReportMode(reportType: Int, reportMode: Int) -> Int;
    fn _CrtCheckMemory() -> Int;
    fn _CrtDumpMemoryLeaks() -> Int;

    // exit / atexit
    fn _onexit(func: VoidPtr) -> VoidPtr;
    fn _exit(status: Int);
    fn _Exit(status: Int);
    fn _amsg_exit(rterrnum: Int);
    fn _cexit();
    fn _c_exit();
    fn quick_exit(status: Int);
    fn at_quick_exit(func: VoidPtr) -> Int;

    // stdio (UCRT common variants)
    fn __stdio_common_vfprintf(options: ULong, stream: FilePtr, format: ConstCharPtr, locale: VoidPtr, arglist: VoidPtr) -> Int;
    fn __stdio_common_vsprintf(options: ULong, buf: CharPtr, count: SizeT, format: ConstCharPtr, locale: VoidPtr, arglist: VoidPtr) -> Int;
    fn __stdio_common_vsprintf_s(options: ULong, buf: CharPtr, count: SizeT, format: ConstCharPtr, locale: VoidPtr, arglist: VoidPtr) -> Int;
    fn __stdio_common_vsnprintf_s(options: ULong, buf: CharPtr, count: SizeT, sizeOfBuffer: SizeT, format: ConstCharPtr, locale: VoidPtr, arglist: VoidPtr) -> Int;
    fn __stdio_common_vfwprintf(options: ULong, stream: FilePtr, format: ConstWCharPtr, locale: VoidPtr, arglist: VoidPtr) -> Int;
    fn __stdio_common_vswprintf(options: ULong, buf: WCharPtr, count: SizeT, format: ConstWCharPtr, locale: VoidPtr, arglist: VoidPtr) -> Int;

    // MSVC string/stdio variants
    fn _wfopen(filename: ConstWCharPtr, mode: ConstWCharPtr) -> FilePtr;
    fn _wfopen_s(stream: VoidPtr, filename: ConstWCharPtr, mode: ConstWCharPtr) -> Int;
    fn fopen_s(stream: VoidPtr, filename: ConstCharPtr, mode: ConstCharPtr) -> Int;
    fn _strdup(str: ConstCharPtr) -> CharPtr;
    fn _wcsdup(str: ConstWCharPtr) -> WCharPtr;
    fn _stricmp(a: ConstCharPtr, b: ConstCharPtr) -> Int;
    fn _strnicmp(a: ConstCharPtr, b: ConstCharPtr, n: SizeT) -> Int;
    fn _wcsicmp(a: ConstWCharPtr, b: ConstWCharPtr) -> Int;
    fn _wcsnicmp(a: ConstWCharPtr, b: ConstWCharPtr, n: SizeT) -> Int;
    fn strcpy_s(dest: CharPtr, dest_size: SizeT, src: ConstCharPtr) -> Int;
    fn strncpy_s(dest: CharPtr, dest_size: SizeT, src: ConstCharPtr, count: SizeT) -> Int;
    fn strcat_s(dest: CharPtr, dest_size: SizeT, src: ConstCharPtr) -> Int;
    fn wcscpy_s(dest: WCharPtr, dest_size: SizeT, src: ConstWCharPtr) -> Int;
    fn memcpy_s(dest: VoidPtr, dest_size: SizeT, src: ConstVoidPtr, count: SizeT) -> Int;
    fn memmove_s(dest: VoidPtr, dest_size: SizeT, src: ConstVoidPtr, count: SizeT) -> Int;

    // Heap (MSVC-specific)
    fn _malloc_dbg(size: SizeT, blockType: Int, filename: ConstCharPtr, linenumber: Int) -> VoidPtr;
    fn _free_dbg(userData: VoidPtr, blockType: Int);
    fn _aligned_malloc(size: SizeT, alignment: SizeT) -> VoidPtr;
    fn _aligned_free(memblock: VoidPtr);
    fn _msize(memblock: VoidPtr) -> SizeT;
    fn _expand(memblock: VoidPtr, size: SizeT) -> VoidPtr;
    fn _recalloc(memblock: VoidPtr, num: SizeT, size: SizeT) -> VoidPtr;

    // Locale/initialization
    fn _initterm(start: VoidPtr, end: VoidPtr);
    fn _initterm_e(start: VoidPtr, end: VoidPtr) -> Int;
    fn __dllonexit(func: VoidPtr, pbegin: VoidPtr, pend: VoidPtr) -> VoidPtr;
    fn _set_new_handler(handler: VoidPtr) -> VoidPtr;
    fn _set_new_mode(newhandlermode: Int) -> Int;
    fn _setmbcp(codepage: Int) -> Int;
    fn _configure_narrow_argv(mode: Int) -> Int;
    fn _configthreadlocale(per_thread_locale_type: Int) -> Int;

    // Environment
    fn _wgetenv(varname: ConstWCharPtr) -> WCharPtr;
    fn _putenv(envstring: ConstCharPtr) -> Int;
    fn _wputenv(envstring: ConstWCharPtr) -> Int;
    fn _dupenv_s(buffer: VoidPtr, numberOfElements: VoidPtr, varname: ConstCharPtr) -> Int;

    // _wpgmptr / __p* family (TLS-like CRT internals)
    fn __p__commode() -> VoidPtr;
    fn __p__fmode() -> VoidPtr;
    fn __p___argc() -> VoidPtr;
    fn __p___argv() -> VoidPtr;
    fn __p___wargv() -> VoidPtr;
    fn __p__environ() -> VoidPtr;
    fn __p__wenviron() -> VoidPtr;
};
