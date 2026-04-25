//! Itanium C++ ABI runtime signatures.
//!
//! Common across libstdc++, libc++ (after demangling), and any C++ binary
//! linked with one of those runtimes. Names are the unmangled symbol form
//! the linker emits (`__cxa_*`, `_Unwind_*`, `__dynamic_cast`, etc.).

use crate::signatures::*;

pub static CXXABI_SIGNATURES: &[FuncSig] = crate::define_signatures! {
    // Exception machinery
    fn __cxa_allocate_exception(thrown_size: SizeT) -> VoidPtr;
    fn __cxa_free_exception(thrown_object: VoidPtr);
    fn __cxa_throw(thrown_object: VoidPtr, type_info: VoidPtr, dest: VoidPtr);
    fn __cxa_rethrow();
    fn __cxa_begin_catch(exceptionObject: VoidPtr) -> VoidPtr;
    fn __cxa_end_catch();
    fn __cxa_get_exception_ptr(exceptionObject: VoidPtr) -> VoidPtr;
    fn __cxa_current_exception_type() -> VoidPtr;
    fn __cxa_call_unexpected(exceptionObject: VoidPtr);
    fn __cxa_call_terminate(exceptionObject: VoidPtr);
    fn __cxa_throw_bad_array_new_length();
    fn __cxa_bad_cast();
    fn __cxa_bad_typeid();
    fn __cxa_pure_virtual();
    fn __cxa_deleted_virtual();

    // Static initialization / finalization
    fn __cxa_atexit(func: VoidPtr, arg: VoidPtr, dso_handle: VoidPtr) -> Int;
    fn __cxa_finalize(dso_handle: VoidPtr);
    fn __cxa_thread_atexit(func: VoidPtr, obj: VoidPtr, dso_symbol: VoidPtr) -> Int;
    fn __cxa_guard_acquire(guard_object: VoidPtr) -> Int;
    fn __cxa_guard_release(guard_object: VoidPtr);
    fn __cxa_guard_abort(guard_object: VoidPtr);

    // RTTI / dynamic_cast
    fn __dynamic_cast(src_ptr: ConstVoidPtr, src_type: VoidPtr, dst_type: VoidPtr, src2dst_offset: Long) -> VoidPtr;

    // Demangling (libsupc++ / libcxxabi)
    fn __cxa_demangle(mangled_name: ConstCharPtr, output_buffer: CharPtr, length: VoidPtr, status: VoidPtr) -> CharPtr;

    // Vector new/delete (POSIX C++ runtime helpers)
    fn __cxa_vec_new(element_count: SizeT, element_size: SizeT, padding_size: SizeT, constructor: VoidPtr, destructor: VoidPtr) -> VoidPtr;
    fn __cxa_vec_new2(element_count: SizeT, element_size: SizeT, padding_size: SizeT, constructor: VoidPtr, destructor: VoidPtr, alloc: VoidPtr, dealloc: VoidPtr) -> VoidPtr;
    fn __cxa_vec_delete(array_address: VoidPtr, element_size: SizeT, padding_size: SizeT, destructor: VoidPtr);
    fn __cxa_vec_delete2(array_address: VoidPtr, element_size: SizeT, padding_size: SizeT, destructor: VoidPtr, dealloc: VoidPtr);
    fn __cxa_vec_ctor(array_address: VoidPtr, element_count: SizeT, element_size: SizeT, constructor: VoidPtr, destructor: VoidPtr) -> VoidPtr;
    fn __cxa_vec_dtor(array_address: VoidPtr, element_count: SizeT, element_size: SizeT, destructor: VoidPtr);

    // _Unwind_* — DWARF stack unwinding (libgcc_s / libunwind)
    fn _Unwind_RaiseException(exception_object: VoidPtr) -> Int;
    fn _Unwind_Resume(exception_object: VoidPtr);
    fn _Unwind_Resume_or_Rethrow(exception_object: VoidPtr) -> Int;
    fn _Unwind_DeleteException(exception_object: VoidPtr);
    fn _Unwind_GetGR(context: VoidPtr, index: Int) -> ULong;
    fn _Unwind_SetGR(context: VoidPtr, index: Int, value: ULong);
    fn _Unwind_GetIP(context: VoidPtr) -> ULong;
    fn _Unwind_SetIP(context: VoidPtr, new_value: ULong);
    fn _Unwind_GetIPInfo(context: VoidPtr, ip_before_insn: VoidPtr) -> ULong;
    fn _Unwind_GetRegionStart(context: VoidPtr) -> ULong;
    fn _Unwind_GetLanguageSpecificData(context: VoidPtr) -> VoidPtr;
    fn _Unwind_Backtrace(trace: VoidPtr, trace_argument: VoidPtr) -> Int;
    fn _Unwind_FindEnclosingFunction(pc: VoidPtr) -> VoidPtr;

    // operator new / delete (mangled names — caller demangles)
    fn _Znwm(size: SizeT) -> VoidPtr;       // operator new(unsigned long)
    fn _Znam(size: SizeT) -> VoidPtr;       // operator new[](unsigned long)
    fn _ZdlPv(ptr: VoidPtr);                // operator delete(void*)
    fn _ZdaPv(ptr: VoidPtr);                // operator delete[](void*)
    fn _ZdlPvm(ptr: VoidPtr, size: SizeT);  // operator delete(void*, unsigned long)
    fn _ZdaPvm(ptr: VoidPtr, size: SizeT);  // operator delete[](void*, unsigned long)
};
