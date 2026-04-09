#!/usr/bin/env python3
"""
Generate machine-readable Ghidra P-code fixtures for rsleigh differential tests.

This script uses Ghidra's headless analyzer instead of pyhidra/JPype because
the embedded JVM path is not reliable on this machine.

Usage:
  JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
    python3 scripts/dump_pcode.py
"""

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


REPO_ROOT = Path(__file__).resolve().parent.parent
GHIDRA_HOME = Path(
    os.environ.get("GHIDRA_INSTALL_DIR", "/opt/homebrew/share/ghidra_12.0.4_PUBLIC")
)
ANALYZE_HEADLESS = GHIDRA_HOME / "support" / "analyzeHeadless"
SCRIPT_PATH = REPO_ROOT / "scripts"

DEFAULT_JAVA_HOME = Path("/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home")

FIXTURES = [
    {
        "path": REPO_ROOT / "test-harness" / "ghidra_x86.json",
        "architecture": "x86-64",
        "language_id": "x86:LE:64:default",
        "instructions": [
            ("MOV RDI,RAX", [0x48, 0x89, 0xC7]),
            ("ADD RDI,RAX", [0x48, 0x01, 0xC7]),
            ("PUSH RAX", [0x50]),
            ("POP RAX", [0x58]),
            ("RET", [0xC3]),
        ],
    },
    {
        "path": REPO_ROOT / "test-harness" / "ghidra_aarch64.json",
        "architecture": "aarch64",
        "language_id": "AARCH64:LE:64:v8A",
        "instructions": [
            ("add x0,x0,x1", [0x00, 0x00, 0x01, 0x8B]),
            ("sub x0,x0,x1", [0x00, 0x00, 0x01, 0xCB]),
            ("mov x0,x1", [0xE0, 0x03, 0x01, 0xAA]),
            ("and x0,x0,x1", [0x00, 0x00, 0x01, 0x8A]),
            ("orr x0,x0,x1", [0x00, 0x00, 0x01, 0xAA]),
            ("eor x0,x0,x1", [0x00, 0x00, 0x01, 0xCA]),
            ("cmp x0,x1", [0x1F, 0x00, 0x01, 0xEB]),
            ("mul x0,x0,x1", [0x00, 0x7C, 0x01, 0x9B]),
            ("ldr x0,[x0]", [0x00, 0x00, 0x40, 0xF9]),
            ("str x0,[x0]", [0x00, 0x00, 0x00, 0xF9]),
            ("ret", [0xC0, 0x03, 0x5F, 0xD6]),
        ],
    },
]


HEADER_RE = re.compile(r"=== ([0-9a-fA-F]+): (.+) ===")
VAR_RE = re.compile(r"(?:out|in\d+)=\(([^,]+),0x([0-9a-fA-F]+),(\d+)\)")


def java_env():
    env = os.environ.copy()
    java_home = env.get("JAVA_HOME")
    if not java_home and DEFAULT_JAVA_HOME.exists():
        env["JAVA_HOME"] = str(DEFAULT_JAVA_HOME)
        env["PATH"] = f"{DEFAULT_JAVA_HOME / 'bin'}:{env.get('PATH', '')}"
    return env


def emit_binary(path: Path, instructions):
    data = bytearray()
    for _, bytes_ in instructions:
        data.extend(bytes_)
    path.write_bytes(data)


def strip_headless_prefix(line: str) -> Optional[str]:
    marker = "DumpPcode.java>"
    if marker not in line:
        return None
    payload = line.split(marker, 1)[1].strip()
    suffix = "(GhidraScript)"
    if payload.endswith(suffix):
        payload = payload[: -len(suffix)].rstrip()
    return payload


def parse_dump_output(stdout: str):
    cases = []
    current = None

    for raw_line in stdout.splitlines():
        line = strip_headless_prefix(raw_line)
        if not line:
            continue
        if line.startswith("Disassembling from") or line.startswith("Total:"):
            continue

        header = HEADER_RE.match(line)
        if header:
            if current is not None:
                cases.append(current)
            current = {"name": header.group(2), "pcode": []}
            continue

        if current is None:
            continue

        if line.startswith("bytes: "):
            current["bytes"] = [int(part, 16) for part in line[len("bytes: ") :].split()]
            continue
        if line.startswith("length: "):
            current["length"] = int(line[len("length: ") :])
            continue
        if line.startswith("pcode_ops: "):
            current["pcode_count"] = int(line[len("pcode_ops: ") :])
            continue

        if line and not line.startswith("="):
            parts = line.split()
            op = {"op": parts[0], "output": None, "inputs": []}
            for idx, match in enumerate(VAR_RE.finditer(line)):
                entry = {
                    "space": match.group(1),
                    "offset": int(match.group(2), 16),
                    "size": int(match.group(3)),
                }
                if idx == 0 and "out=" in line and line.index("out=") < line.index(match.group(0)):
                    pass
                if f"out={match.group(0)}" in line:
                    op["output"] = entry
                else:
                    op["inputs"].append(entry)
            # More reliable split than the check above.
            op["output"] = None
            op["inputs"] = []
            for token in parts[1:]:
                if token.startswith("out="):
                    op["output"] = parse_token_varnode(token[len("out=") :])
                elif token.startswith("in"):
                    _, value = token.split("=", 1)
                    op["inputs"].append(parse_token_varnode(value))
            current["pcode"].append(op)

    if current is not None:
        cases.append(current)

    return cases


def parse_token_varnode(token: str):
    token = token.strip()
    if not (token.startswith("(") and token.endswith(")")):
        raise ValueError(f"bad varnode token: {token}")
    space, offset, size = token[1:-1].split(",")
    return {"space": space, "offset": int(offset[2:], 16), "size": int(size)}


def run_fixture(fixture):
    with tempfile.TemporaryDirectory(prefix="rsleigh-ghidra-") as tempdir:
        tempdir = Path(tempdir)
        project_dir = tempdir / "project"
        binary_path = tempdir / f"{fixture['architecture']}.bin"
        project_dir.mkdir(parents=True, exist_ok=True)
        emit_binary(binary_path, fixture["instructions"])

        cmd = [
            str(ANALYZE_HEADLESS),
            str(project_dir),
            "proj",
            "-import",
            str(binary_path),
            "-processor",
            fixture["language_id"],
            "-scriptPath",
            str(SCRIPT_PATH),
            "-postScript",
            "DumpPcode.java",
            "-deleteProject",
            "-noanalysis",
        ]
        result = subprocess.run(cmd, env=java_env(), capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"headless ghidra failed for {fixture['architecture']}:\n"
                f"stdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}"
            )

    cases = parse_dump_output(result.stdout)
    if len(cases) != len(fixture["instructions"]):
        raise RuntimeError(
            f"{fixture['architecture']}: expected {len(fixture['instructions'])} cases, got {len(cases)}"
        )
    return {
        "fixture_version": 1,
        "architecture": fixture["architecture"],
        "cases": cases,
    }


def main():
    if not ANALYZE_HEADLESS.exists():
        raise SystemExit(f"missing analyzeHeadless at {ANALYZE_HEADLESS}")

    for fixture in FIXTURES:
        data = run_fixture(fixture)
        fixture["path"].write_text(json.dumps(data, indent=2) + "\n")
        print(f"wrote {fixture['architecture']} fixture to {fixture['path']}")


if __name__ == "__main__":
    main()
