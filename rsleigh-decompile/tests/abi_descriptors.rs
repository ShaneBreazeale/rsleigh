//! ABI descriptor table sanity checks.
//!
//! Audit P1 #2 introduces an explicit `Abi` descriptor (arg locations,
//! return locations, cleanup, shadow space) so per-architecture rules
//! stop being scattered magic numbers across passes.

use rsleigh_decompile::fold::{abi, CallingConv};

#[test]
fn return_registers_match_each_arch() {
    let rax = 0u64;
    let xmm0 = 4608u64;
    let aarch64_x0 = 16384u64;
    let aarch64_v0 = 20480u64;
    let arm32_r0 = 32u64;

    assert_eq!(abi(CallingConv::SysV).return_reg_int, Some(rax));
    assert_eq!(abi(CallingConv::SysV).return_reg_float, Some(xmm0));
    assert_eq!(abi(CallingConv::Win64).return_reg_int, Some(rax));
    assert_eq!(abi(CallingConv::Win64).return_reg_float, Some(xmm0));
    assert_eq!(abi(CallingConv::AArch64).return_reg_int, Some(aarch64_x0));
    assert_eq!(abi(CallingConv::AArch64).return_reg_float, Some(aarch64_v0));
    assert_eq!(abi(CallingConv::Arm32).return_reg_int, Some(arm32_r0));
    assert_eq!(abi(CallingConv::Cdecl32).return_reg_int, Some(rax));
    assert_eq!(abi(CallingConv::Stdcall32).return_reg_int, Some(rax));
    assert_eq!(abi(CallingConv::Thiscall32).return_reg_int, Some(rax));
    assert_eq!(abi(CallingConv::Fastcall32).return_reg_int, Some(rax));
    assert_eq!(abi(CallingConv::GoAmd64).return_reg_int, Some(rax));
}

#[test]
fn cleanup_flag_distinguishes_cdecl_from_stdcall() {
    // Same args, same return, only cleanup differs.
    let cdecl = abi(CallingConv::Cdecl32);
    let stdcall = abi(CallingConv::Stdcall32);
    assert_eq!(cdecl.return_reg_int, stdcall.return_reg_int);
    assert_eq!(cdecl.int_args, stdcall.int_args);
    assert_eq!(cdecl.shadow_space_bytes, stdcall.shadow_space_bytes);

    assert_eq!(cdecl.callee_cleanup_stack, false, "cdecl: caller cleans");
    assert_eq!(stdcall.callee_cleanup_stack, true, "stdcall: callee cleans");
}

#[test]
fn win64_has_shadow_space_others_dont() {
    assert_eq!(abi(CallingConv::Win64).shadow_space_bytes, 32);
    for cc in [
        CallingConv::SysV,
        CallingConv::Cdecl32,
        CallingConv::Stdcall32,
        CallingConv::Thiscall32,
        CallingConv::Fastcall32,
        CallingConv::AArch64,
        CallingConv::Arm32,
        CallingConv::GoAmd64,
    ] {
        assert_eq!(
            abi(cc).shadow_space_bytes,
            0,
            "{:?} should not allocate shadow space",
            cc
        );
    }
}

#[test]
fn callee_cleanup_set_for_x86_32_callee_cleans_only() {
    for cc in [
        CallingConv::SysV,
        CallingConv::Win64,
        CallingConv::Cdecl32,
        CallingConv::AArch64,
        CallingConv::Arm32,
        CallingConv::GoAmd64,
    ] {
        assert_eq!(
            abi(cc).callee_cleanup_stack,
            false,
            "{:?} unexpectedly marked callee_cleanup_stack",
            cc
        );
    }
    for cc in [
        CallingConv::Stdcall32,
        CallingConv::Thiscall32,
        CallingConv::Fastcall32,
    ] {
        assert!(
            abi(cc).callee_cleanup_stack,
            "{:?} must be marked callee_cleanup_stack",
            cc
        );
    }
}

#[test]
fn x86_64_arg_regs_differ_between_sysv_and_win64() {
    let sysv = abi(CallingConv::SysV).int_args;
    let win64 = abi(CallingConv::Win64).int_args;
    // RDI vs RCX is the canonical difference.
    assert_eq!(sysv[0], 56, "SysV first int arg = RDI (56)");
    assert_eq!(win64[0], 8, "Win64 first int arg = RCX (8)");
}

#[test]
fn thiscall_uses_ecx_only() {
    let a = abi(CallingConv::Thiscall32);
    assert_eq!(a.int_args, &[0x4u64], "thiscall: this in ECX (0x4)");
    assert!(a.callee_cleanup_stack);
    assert!(!a.allows_varargs, "thiscall is incompatible with varargs");
}

#[test]
fn fastcall_uses_ecx_then_edx() {
    let a = abi(CallingConv::Fastcall32);
    assert_eq!(a.int_args, &[0x4u64, 0x8u64], "fastcall: ECX, EDX");
    assert!(a.callee_cleanup_stack);
    assert!(!a.allows_varargs, "fastcall is incompatible with varargs");
}

#[test]
fn varargs_only_flagged_for_conventions_that_allow_it() {
    // cdecl + the 64-bit conventions support varargs; the callee-cleans
    // x86-32 conventions cannot since the callee can't know how many
    // bytes the caller pushed beyond the prototype.
    for cc in [
        CallingConv::SysV,
        CallingConv::Win64,
        CallingConv::Cdecl32,
        CallingConv::AArch64,
        CallingConv::Arm32,
    ] {
        assert!(abi(cc).allows_varargs, "{:?} should allow varargs", cc);
    }
    for cc in [
        CallingConv::Stdcall32,
        CallingConv::Thiscall32,
        CallingConv::Fastcall32,
        CallingConv::GoAmd64,
    ] {
        assert!(
            !abi(cc).allows_varargs,
            "{:?} should not allow varargs",
            cc
        );
    }
}
