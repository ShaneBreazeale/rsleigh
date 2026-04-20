#!/usr/bin/env python3
"""Extract Qt library function signatures as TSV for rsleigh.

Reads Qt5 shared objects, enumerates defined T/W symbols, demangles
with c++filt, maps demangled params to rsleigh type codes, and emits
TSV rows compatible with rsleigh-decompile/data/signatures.tsv.gz.

TSV columns: name<TAB>ret_code<TAB>params<TAB>variadic
Params:      pname:pcode,pname:pcode,...
Codes:       v=void i=int u=uint l=long U=ulong z=size_t b=bool
             s=char* W=wchar_t* p=void* F=FILE*
"""
import gzip
import os
import re
import subprocess
import sys

QT_LIBS = [
    "libQt5Core.so.5",
    "libQt5Gui.so.5",
    "libQt5Widgets.so.5",
    "libQt5Network.so.5",
    "libQt5DBus.so.5",
    "libQt5Svg.so.5",
    "libQt5XcbQpa.so.5",
    "libQt5X11Extras.so.5",
]


def demangled_symbols(sofile):
    """Yield (mangled, demangled) for each T/W defined symbol."""
    raw = subprocess.check_output(
        ["nm", "-D", "--defined-only", sofile], text=True, errors="replace"
    )
    mangled = []
    for line in raw.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        _, typ, name = parts
        if typ not in ("T", "W"):
            continue
        if not name.startswith("_Z"):
            continue
        # strip @@version suffix
        name = name.split("@", 1)[0]
        mangled.append(name)
    if not mangled:
        return
    # batch via c++filt
    proc = subprocess.run(
        ["c++filt", "-n"], input="\n".join(mangled), text=True,
        capture_output=True, check=True,
    )
    for m, d in zip(mangled, proc.stdout.splitlines()):
        yield m, d


# Map a C++ param type (demangled) to a single rsleigh TSV code.
def type_code(t):
    t = t.strip()
    if not t:
        return "v"
    # references/pointers -> pointer
    if t.endswith("*") or t.endswith("&"):
        # char* variants stay 's'
        base = t.rstrip("*& ").strip()
        if base in ("char", "const char", "char const", "signed char",
                    "const signed char", "unsigned char", "const unsigned char"):
            return "s"
        if base in ("wchar_t", "const wchar_t", "wchar_t const",
                    "QChar", "const QChar", "QChar const",
                    "ushort", "const ushort"):
            return "W"
        return "p"
    # strip cv
    t2 = re.sub(r"\b(const|volatile)\b", "", t).strip()
    if t2 in ("void",):
        return "v"
    if t2 in ("bool",):
        return "b"
    if t2 in ("int", "signed int", "short", "signed short", "short int",
              "signed", "signed char", "char"):
        return "i"
    if t2 in ("unsigned", "unsigned int", "unsigned short",
              "unsigned char", "uint", "uchar", "ushort"):
        return "u"
    if t2 in ("long", "long int", "signed long", "long long",
              "signed long long", "qint64", "qintptr", "qptrdiff", "qlonglong"):
        return "l"
    if t2 in ("unsigned long", "unsigned long int", "unsigned long long",
              "quint64", "quintptr", "qulonglong", "WId"):
        return "U"
    if t2 in ("size_t", "std::size_t"):
        return "z"
    if t2 in ("float", "double", "long double", "qreal"):
        return "i"  # decompiler lacks float param code; int is safest fallback
    # class/struct by value in Itanium ABI is passed via hidden pointer
    return "p"


def return_code(ret):
    ret = ret.strip()
    if not ret or ret == "void":
        return "v"
    return type_code(ret)


# Parse `Ret Qualified::Name(arg1, arg2, ...)` into (name, ret, [args]).
# Handles nested <> and (). Skips vtables, typeinfo, guard vars.
def parse_demangled(d):
    # Skip non-function symbols
    if d.startswith(("vtable for ", "typeinfo ", "typeinfo for ",
                     "typeinfo name for ", "VTT for ", "guard variable for ",
                     "construction vtable for ")):
        return None
    # Find top-level '(' that opens the param list — scan right-to-left
    depth_ang = 0
    paren_open = -1
    i = len(d) - 1
    while i >= 0:
        c = d[i]
        if c == ">":
            depth_ang += 1
        elif c == "<":
            depth_ang -= 1
        elif c == ")" and depth_ang == 0:
            # find matching (
            pd = 1
            j = i - 1
            while j >= 0 and pd > 0:
                if d[j] == ")":
                    pd += 1
                elif d[j] == "(":
                    pd -= 1
                j -= 1
            if pd == 0:
                paren_open = j + 1
                paren_close = i
                break
            return None
        i -= 1
    if paren_open < 0:
        return None
    before = d[:paren_open].rstrip()
    params_str = d[paren_open + 1:paren_close]
    # trailing qualifiers after ')': const, &, &&, noexcept
    # (ignored for our purposes)

    # Split ret vs name: scan before from right; name ends at last top-level
    # identifier boundary. Simple: last space at depth 0.
    depth = 0
    depth_p = 0
    split = -1
    for k in range(len(before) - 1, -1, -1):
        c = before[k]
        if c == ">":
            depth += 1
        elif c == "<":
            depth -= 1
        elif c == ")":
            depth_p += 1
        elif c == "(":
            depth_p -= 1
        elif c == " " and depth == 0 and depth_p == 0:
            split = k
            break
    if split >= 0:
        ret = before[:split].strip()
        name = before[split + 1:].strip()
    else:
        ret = ""
        name = before.strip()
    if not name:
        return None
    # Split params at top-level commas
    params = []
    depth = 0
    depth_p = 0
    start = 0
    for k, c in enumerate(params_str):
        if c == "<":
            depth += 1
        elif c == ">":
            depth -= 1
        elif c == "(":
            depth_p += 1
        elif c == ")":
            depth_p -= 1
        elif c == "," and depth == 0 and depth_p == 0:
            params.append(params_str[start:k])
            start = k + 1
    if params_str.strip():
        params.append(params_str[start:])
    params = [p.strip() for p in params if p.strip()]
    # void-only param list
    if params == ["void"]:
        params = []
    return name, ret, params


def sanitize_name(n):
    # TSV uses tab delimiter; name must not contain tabs or newlines.
    # Mangled is preferred (matches direct call-site lookup). We use mangled.
    return n.replace("\t", " ").replace("\n", " ")


def emit_row(mangled, demangled, seen):
    if mangled in seen:
        return None
    parsed = parse_demangled(demangled)
    if not parsed:
        return None
    _, ret, params = parsed
    ret_c = return_code(ret)
    param_parts = []
    for idx, p in enumerate(params):
        param_parts.append(f"arg{idx}:{type_code(p)}")
    row = f"{mangled}\t{ret_c}\t{','.join(param_parts)}\t0"
    seen.add(mangled)
    return row


def main():
    if len(sys.argv) < 3:
        print("usage: extract-qt-sigs.py <qt_lib_dir> <out.tsv.gz>", file=sys.stderr)
        sys.exit(1)
    qt_dir = sys.argv[1]
    out_path = sys.argv[2]

    seen = set()
    rows = []
    for lib in QT_LIBS:
        path = os.path.join(qt_dir, lib)
        if not os.path.exists(path):
            print(f"skip missing: {path}", file=sys.stderr)
            continue
        n_before = len(rows)
        for m, d in demangled_symbols(path):
            r = emit_row(m, d, seen)
            if r:
                rows.append(r)
        print(f"{lib}: +{len(rows) - n_before}", file=sys.stderr)

    body = ("\n".join(rows) + "\n").encode()
    with gzip.open(out_path, "wb", compresslevel=9) as fh:
        fh.write(body)
    print(f"wrote {len(rows)} sigs -> {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
