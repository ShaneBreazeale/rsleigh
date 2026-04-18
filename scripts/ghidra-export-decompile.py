#!/usr/bin/env python3
"""
Ghidra headless export script for decompiler output.
Usage: (called by analyzeHeadless as post-script)

In analyzeHeadless command:
  ... -postScript scripts/ghidra-export-decompile.py <output_json>
"""

import json
import sys
import os

# Ghidra script API (injected by analyzeHeadless)
# globalThis, currentProgram, etc. available

def export_decompile_results(program, output_file):
    """Export decompiled functions to JSON."""
    results = {}

    listing = program.getListing()
    decompiler = None

    try:
        from ghidra.app.decompiler import DecompilerFactory
        decompiler = DecompilerFactory.getDecompiler(program)
    except:
        print("ERROR: Could not initialize decompiler")
        return

    for func in program.getFunctionManager().getFunctions(True):
        try:
            # Get decompiled pseudocode
            dec_result = decompiler.decompileFunction(func, 30, None)
            if dec_result:
                pseudocode = dec_result.getDecompiledFunction().getC()
                results[func.getName()] = {
                    "address": hex(func.getEntryPoint().getOffset()),
                    "pseudocode": pseudocode,
                    "signature": func.getPrototypeString(),
                }
        except Exception as e:
            results[func.getName()] = {
                "address": hex(func.getEntryPoint().getOffset()),
                "error": str(e),
            }

    # Write results
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print("Exported {} functions to {}".format(len(results), output_file))

# Entry point for Ghidra script
if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else "ghidra_output.json"
    export_decompile_results(currentProgram, output)
