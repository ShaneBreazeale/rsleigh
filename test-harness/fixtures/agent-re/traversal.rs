//! Original x86-32 traversal fixtures, Apache-2.0. Reuses seed.rs's minimal PE
//! and exported function starts; all ground truth is encoded below.
pub fn binary() -> Vec<u8> {
    let mut bytes = super::re_seed::binary();
    bytes[0x200..0x300].fill(0x90);
    for (offset, code) in [
        // 0x401000: push 17; call 0x401020; add esp,4; ret.
        // Returned value is helper(17) = 22. Call at 0x401002; ret at 0x40100a.
        (0x00, &b"\x6a\x11\xe8\x19\x00\x00\x00\x83\xc4\x04\xc3"[..]),
        // 0x401020: mov eax,[esp+4]; add eax,5; ret (at 0x401027).
        (0x20, &b"\x8b\x44\x24\x04\x83\xc0\x05\xc3"[..]),
        // 0x401040: sub esp,4; mov dword [esp],73; mov eax,[esp]; add esp,4; ret.
        // Store at 0x401043; load at 0x40104a; return at 0x401050.
        (
            0x40,
            &b"\x83\xec\x04\xc7\x04\x24\x49\x00\x00\x00\x8b\x04\x24\x83\xc4\x04\xc3"[..],
        ),
        // 0x401060: mov dword [0x500000],73; mov eax,[0x500000]; ret.
        // Store at 0x401060; load at 0x40106a; return at 0x40106f.
        (
            0x60,
            &b"\xc7\x05\x00\x00\x50\x00\x49\x00\x00\x00\xa1\x00\x00\x50\x00\xc3"[..],
        ),
        // 0x401080: call 0x401080; ret. Dependency recursion must stop explicitly.
        (0x80, &b"\xe8\xfb\xff\xff\xff\xc3"[..]),
    ] {
        bytes[0x200 + offset..0x200 + offset + code.len()].copy_from_slice(code);
    }
    bytes
}
