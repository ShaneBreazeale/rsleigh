#!/usr/bin/env python3
"""
Ghidra headless export script for decompiler output.
Usage: analyzeHeadless ... -postScript ghidra-export-decompile.py <output_json>

Uses DecompInterface (correct API as of Ghidra 10.x+).
"""

import json
import sys

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def export_decompile_results(program, output_file):
    results = {}

    decompiler = DecompInterface()
    decompiler.openProgram(program)
    monitor = ConsoleTaskMonitor()

    count = 0
    skipped = 0
    for func in program.getFunctionManager().getFunctions(True):
        try:
            if func.isThunk() or func.isExternal():
                skipped += 1
                continue
            dec_result = decompiler.decompileFunction(func, 30, monitor)
            if dec_result is not None and dec_result.decompileCompleted():
                pseudocode = dec_result.getDecompiledFunction().getC()
                results[func.getName()] = {
                    "address": hex(func.getEntryPoint().getOffset()),
                    "pseudocode": pseudocode,
                    "signature": func.getPrototypeString(False, True),
                }
                count += 1
            else:
                err = dec_result.getErrorMessage() if dec_result is not None else "no result"
                results[func.getName()] = {
                    "address": hex(func.getEntryPoint().getOffset()),
                    "error": err,
                }
        except Exception as e:
            results[func.getName()] = {
                "address": hex(func.getEntryPoint().getOffset()),
                "error": str(e),
            }

    decompiler.dispose()

    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print("Exported {} functions ({} skipped) to {}".format(count, skipped, output_file))


if __name__ == "__main__":
    args = getScriptArgs()  # Ghidra-provided
    output = args[0] if len(args) > 0 else "ghidra_output.json"
    export_decompile_results(currentProgram, output)
