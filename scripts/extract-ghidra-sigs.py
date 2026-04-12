#!/usr/bin/env python3
"""Extract function signatures from Ghidra's type library archives (.gdt).

Usage:
    # Set GHIDRA_HOME or pass path:
    python3 scripts/extract-ghidra-sigs.py /path/to/ghidra

    # Or with GHIDRA_HOME:
    export GHIDRA_HOME=~/ghidra_11.3.1_PUBLIC
    python3 scripts/extract-ghidra-sigs.py

Outputs JSON files to rsleigh-decompile/data/ that can be loaded with:
    rsleigh binary.exe --all --sigs rsleigh-decompile/data/ghidra_clib64.json

Requires: Java 17+ on PATH (for Ghidra headless analyzer)
"""

import json
import os
import subprocess
import sys
import tempfile

ARCHIVES = {
    "ghidra_clib64.json": "Ghidra/Features/Base/data/typeinfo/generic/generic_clib_64.gdt",
    "ghidra_win64.json": "Ghidra/Features/Base/data/typeinfo/win32/windows_vs12_64.gdt",
    "ghidra_macos.json": "Ghidra/Features/Base/data/typeinfo/mac_10.9/mac_osx.gdt",
}

GHIDRA_SCRIPT = r'''
from ghidra.program.model.data import FileDataTypeManager
from java.io import File
import json

def type_to_str(dt):
    if dt is None:
        return "void"
    cn = dt.__class__.__name__
    while "Typedef" in cn:
        dt = dt.getBaseDataType()
        if dt is None:
            return "void"
        cn = dt.__class__.__name__
    name = dt.getName()
    if "Pointer" in cn:
        pointed = dt.getDataType()
        if pointed:
            return type_to_str(pointed) + " *"
        return "void *"
    if "Array" in cn:
        return type_to_str(dt.getDataType()) + " *"
    return name

archive_path = getScriptArgs()[0]
output_path = getScriptArgs()[1]
print("Opening archive: " + archive_path)

dtm = FileDataTypeManager.openFileArchive(File(archive_path), False)

sigs = []
for dt in dtm.getAllDataTypes():
    cn = dt.__class__.__name__
    if "FunctionDefinition" in cn:
        name = dt.getName()
        ret = type_to_str(dt.getReturnType())
        params = []
        for arg in dt.getArguments():
            pname = arg.getName() if arg.getName() else "arg"
            ptype = type_to_str(arg.getDataType())
            params.append({"name": pname, "type": ptype})
        variadic = dt.hasVarArgs()
        sigs.append({
            "name": name,
            "ret": ret,
            "params": params,
            "variadic": variadic,
        })

dtm.close()

with open(output_path, "w") as f:
    json.dump(sigs, f, indent=2)

print("Exported %d signatures to %s" % (len(sigs), output_path))
'''


def find_ghidra(arg=None):
    """Find Ghidra installation directory."""
    candidates = [
        arg,
        os.environ.get("GHIDRA_HOME"),
        os.path.expanduser("~/ghidra_install/ghidra_11.3.1_PUBLIC"),
        os.path.expanduser("~/ghidra"),
        "/opt/ghidra",
    ]
    for c in candidates:
        if c and os.path.isfile(os.path.join(c, "support", "analyzeHeadless")):
            return c
    return None


def find_java():
    """Find Java and set JAVA_HOME if needed."""
    if os.environ.get("JAVA_HOME"):
        return
    # Homebrew locations (macOS)
    for ver in ["21", "17", "11"]:
        for base in [f"/opt/homebrew/Cellar/openjdk@{ver}", f"/usr/local/Cellar/openjdk@{ver}"]:
            if os.path.isdir(base):
                for entry in os.listdir(base):
                    jdk = os.path.join(base, entry, "libexec", "openjdk.jdk", "Contents", "Home")
                    if os.path.isdir(jdk):
                        os.environ["JAVA_HOME"] = jdk
                        os.environ["PATH"] = os.path.join(jdk, "bin") + ":" + os.environ.get("PATH", "")
                        print(f"  Found Java at {jdk}")
                        return
    # Try /usr/libexec/java_home (macOS)
    try:
        result = subprocess.run(["/usr/libexec/java_home"], capture_output=True, text=True)
        if result.returncode == 0:
            jdk = result.stdout.strip()
            os.environ["JAVA_HOME"] = jdk
            os.environ["PATH"] = os.path.join(jdk, "bin") + ":" + os.environ.get("PATH", "")
            return
    except FileNotFoundError:
        pass


def main():
    ghidra_home = find_ghidra(sys.argv[1] if len(sys.argv) > 1 else None)
    if not ghidra_home:
        print("Error: Cannot find Ghidra. Pass the path as an argument or set GHIDRA_HOME.")
        print("Usage: python3 scripts/extract-ghidra-sigs.py /path/to/ghidra")
        sys.exit(1)

    print(f"Using Ghidra at: {ghidra_home}")
    find_java()

    # Create output directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    out_dir = os.path.join(repo_root, "rsleigh-decompile", "data")
    os.makedirs(out_dir, exist_ok=True)

    # Write the Ghidra script to a temp file
    script_file = os.path.join(tempfile.gettempdir(), "extract_sigs.py")
    with open(script_file, "w") as f:
        f.write(GHIDRA_SCRIPT)

    # Create a tiny binary for Ghidra to "analyze" (it needs one to run scripts)
    tiny_c = os.path.join(tempfile.gettempdir(), "tiny.c")
    tiny_bin = os.path.join(tempfile.gettempdir(), "tiny_sig_extract")
    with open(tiny_c, "w") as f:
        f.write("int main(){return 0;}\n")
    subprocess.run(["cc", "-o", tiny_bin, tiny_c], capture_output=True)

    headless = os.path.join(ghidra_home, "support", "analyzeHeadless")
    project_dir = os.path.join(tempfile.gettempdir(), "ghidra_sig_extract")

    for out_name, gdt_rel_path in ARCHIVES.items():
        gdt_path = os.path.join(ghidra_home, gdt_rel_path)
        if not os.path.isfile(gdt_path):
            print(f"  Skipping {out_name}: {gdt_rel_path} not found")
            continue

        out_path = os.path.join(out_dir, out_name)
        print(f"\nExtracting {out_name}...")

        # Clean project dir
        subprocess.run(["rm", "-rf", project_dir], capture_output=True)

        result = subprocess.run(
            [headless, tempfile.gettempdir(), "ghidra_sig_extract",
             "-import", tiny_bin,
             "-postScript", script_file, gdt_path, out_path,
             "-deleteProject"],
            capture_output=True, text=True, timeout=120
        )

        # Check output
        for line in result.stdout.split("\n"):
            if "Exported" in line:
                print(f"  {line.strip()}")
                break
        else:
            print(f"  Warning: extraction may have failed")
            if result.returncode != 0:
                print(f"  stderr: {result.stderr[-200:]}")

    print(f"\nDone! Signature files saved to {out_dir}/")
    print("Load them with: rsleigh binary.exe --all --sigs rsleigh-decompile/data/ghidra_win64.json")


if __name__ == "__main__":
    main()
