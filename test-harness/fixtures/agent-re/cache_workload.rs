//! Original x86-32 cache workload, Apache-2.0.
//! mov eax,0; repeat 900 times: add eax,1; NOP padding; ret.
//! The return is 900. The workload measures repeated card pages over one
//! function with many SSA definitions, not a different ISA or a larger output.
pub fn binary() -> Vec<u8> {
    let mut bytes = super::seed::binary();
    bytes.resize(0x1200, 0);
    let opt = 0x98;
    bytes[opt + 96..opt + 104].fill(0); // remove the seed export directory
    let section = opt + 0xe0;
    for offset in [8, 16] {
        bytes[section + offset..section + offset + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    }
    bytes[0x200..].fill(0x90);
    bytes[0x200..0x205].copy_from_slice(&[0xb8, 0, 0, 0, 0]);
    for index in 0..900 {
        bytes[0x205 + index * 3..0x208 + index * 3].copy_from_slice(&[0x83, 0xc0, 1]);
    }
    bytes[0x11ff] = 0xc3;
    bytes
}
