#!/usr/bin/env python3
"""
Generate P-code golden output from Ghidra for comparison with rsleigh.
Uses pyhidra (Python bindings to Ghidra's Java API).

Usage: GHIDRA_INSTALL_DIR=/opt/homebrew/share/ghidra_12.0.4_PUBLIC python3 scripts/dump_pcode.py
"""
import os
import struct
import tempfile
import json

os.environ.setdefault("GHIDRA_INSTALL_DIR", "/opt/homebrew/share/ghidra_12.0.4_PUBLIC")
os.environ["PATH"] = "/opt/homebrew/opt/openjdk/bin:" + os.environ.get("PATH", "")

import pyhidra
pyhidra.start()

import ghidra
from ghidra.program.model.lang import LanguageID
from ghidra.app.plugin.processors.sleigh import SleighLanguageProvider
from ghidra.program.model.address import AddressSpace

def dump_pcode_for_bytes(lang_id_str, instructions, base_addr=0x1000):
    """Decode instructions and dump P-code using Ghidra's SLEIGH engine."""
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import CodeUnit

    lang_id = LanguageID(lang_id_str)
    provider = SleighLanguageProvider()
    lang = provider.getLanguage(lang_id)

    results = []

    for name, bytez in instructions:
        # Create a minimal program context
        from ghidra.pcode.emulate import EmulateDisassemblerContext
        ctx = lang.getDefaultSpace()

        # Use the Sleigh decoder directly
        from ghidra.app.plugin.processors.sleigh import SleighInstructionPrototype

        addr_factory = lang.getAddressFactory()
        default_space = lang.getDefaultSpace()
        addr = default_space.getAddress(base_addr)

        from ghidra.program.model.mem import ByteMemBufferImpl
        buf = ByteMemBufferImpl(addr, bytes(bytez), not lang.isBigEndian())

        from ghidra.program.disassemble import Disassembler
        from ghidra.app.plugin.processors.sleigh import PcodeEmit

        # Parse the instruction
        try:
            proto = lang.parse(buf, lang.getDefaultContext(), False)
            inst_len = proto.getLength()
            mnemonic = proto.getMnemonic(None)

            # Get P-code ops
            pcode_ops = proto.getPcode(None, buf, 0, None, None)

            ops = []
            for op in pcode_ops:
                opname = op.getMnemonic()
                output = None
                if op.getOutput() is not None:
                    out = op.getOutput()
                    output = {
                        "space": out.getAddress().getAddressSpace().getName(),
                        "offset": out.getOffset(),
                        "size": out.getSize()
                    }
                inputs = []
                for i in range(op.getNumInputs()):
                    inp = op.getInput(i)
                    inputs.append({
                        "space": inp.getAddress().getAddressSpace().getName(),
                        "offset": inp.getOffset(),
                        "size": inp.getSize()
                    })
                ops.append({
                    "op": opname,
                    "output": output,
                    "inputs": inputs
                })

            results.append({
                "name": name,
                "bytes": list(bytez),
                "length": inst_len,
                "mnemonic": mnemonic,
                "pcode": ops
            })
        except Exception as e:
            results.append({
                "name": name,
                "bytes": list(bytez),
                "error": str(e)
            })

    return results

# x86-64 test instructions
x86_tests = [
    ("MOV RDI,RAX", [0x48, 0x89, 0xc7]),
    ("ADD RDI,RAX", [0x48, 0x01, 0xc7]),
    ("PUSH RAX", [0x50]),
    ("POP RAX", [0x58]),
    ("RET", [0xc3]),
    ("JZ rel8", [0x74, 0x05]),
    ("JMP rel8", [0xeb, 0x0a]),
    ("CALL RAX", [0xff, 0xd0]),
    ("MOV RAX,[RDI]", [0x48, 0x8b, 0x07]),
    ("CMP RDI,RAX", [0x48, 0x39, 0xc7]),
    ("SUB RDI,RAX", [0x48, 0x29, 0xc7]),
    ("XOR RDI,RAX", [0x48, 0x31, 0xc7]),
    ("NOP", [0x90]),
    ("LEA RAX,[RDI+0x10]", [0x48, 0x8d, 0x47, 0x10]),
    ("MOV [RDI],RAX", [0x48, 0x89, 0x07]),
    ("MOV RAX,1", [0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00]),
    ("TEST RAX,RAX", [0x48, 0x85, 0xc0]),
    ("INC RAX", [0x48, 0xff, 0xc0]),
    ("DEC RAX", [0x48, 0xff, 0xc8]),
    ("NOT RAX", [0x48, 0xf7, 0xd0]),
]

print("Dumping x86-64 P-code from Ghidra...")
results = dump_pcode_for_bytes("x86:LE:64:default", x86_tests)
print(json.dumps(results, indent=2))

# Save to file
with open("test-harness/ghidra_golden.json", "w") as f:
    json.dump(results, f, indent=2)
print(f"\nSaved {len(results)} results to test-harness/ghidra_golden.json")
