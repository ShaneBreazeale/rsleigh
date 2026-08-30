# CLI triage flags

Three high-level flags ship as a malware-triage front end on top of the
decompiler. Each works on PE32 / PE32+ / ELF / Mach-O where applicable
and is usable both interactively (human-readable output) and from
pipelines (`--json`).

For an LLM or coding-agent session, start with the bounded
[`--agent-brief`](agent-workflow.md#--agent-brief). It includes a capped subset
of file findings and a ranked function map. Run the flags below directly when
you need complete triage coverage rather than the brief's navigation budget.

| Flag | Purpose | JSON | Aux flag |
|------|---------|------|----------|
| `--ioc` | Indicators of compromise (URLs, IPs, paths, registry, mutexes, secrets) | yes | — |
| `--sigcheck` | Authenticode signature parse (signer, issuer, timestamp, chain) | yes | — |
| `--resources` | PE resource directory walk; payload extraction | yes | `--dump <DIR>` |

All three are independent of the decoder/decompiler pipeline. They walk file
structure and string runs without invoking the SSA passes, so they are suitable
as an inexpensive first pass even though work still scales with input size. Use
them before deciding which individual functions to inspect. Avoid whole-binary
pseudocode dumps in agent workflows.

---

## `--ioc` — Indicator-of-compromise extraction

```
rsleigh <binary> --ioc           # human-readable
rsleigh <binary> --ioc --json    # pipeline-ready
```

Scans ASCII (≥6 chars) and UTF-16LE (≥4 chars) string runs out of the
raw image and bins matches into seven categories:

- **URLs** — `http://`, `https://`, `ftp://`. PE security-blob DER tail
  bytes are trimmed off cert URLs (`http://...crl0E` → `http://...crl`).
- **IPv4** — octet-validated. Rejects `.NET`-version-style literals
  (`4.0.0.0`, `1.0.0.0`) by counting zero octets — real routable IPs
  almost never have ≥2 zero octets.
- **Domains** — TLD-anchored against a curated list. Pascal-case
  namespace tokens (`System.IO`, `MyApplication.app`) and tokens
  containing `/`, `\`, or `:` are rejected.
- **Paths** — Windows drive-letter paths (`C:\…`, uppercase only),
  `%ENVVAR%` paths (env-var name must be ≥2 uppercase chars to avoid
  `%s` / `%d` printf noise), Unix `/tmp`, `/var`, `/etc`, `/usr`,
  `/home`, `/root`, `/dev`, `/proc`. Each path is validated to contain
  only path-legal characters end to end.
- **Registry** — `HKEY_*`, `HKLM\`, `HKCU\`, `HKCR\` prefix matches.
- **Mutexes / named objects** — `Global\`, `Local\`, `Session\`,
  `BaseNamedObjects\`.
- **Secret-like strings** — `password=`, `bearer `, `api_key=`,
  `client_secret=`, `private_key=`, `ssh-rsa `, `-----BEGIN PRIVATE`.
  `.NET` assembly-identity strings are filtered out (otherwise every
  `PublicKeyToken=…` line lights up).

Output is `BTreeSet`-deduped and sorted within each category.

### Example

```
rsleigh ~/Downloads/sample.exe --ioc
```

```
=== IOCs from /Users/.../sample.exe ===

URLs (12)
  http://178.16.54.109/grab.exe
  http://178.16.54.109/xmr.exe
  ...

IPv4 (1)
  178.16.54.109

Paths (3)
  %APPDATA%\2353253532535.txt
  %TEMP%\d3333333333333333333.txt
  %s\%d%d.exe

Mutexes/Named Objects (2)
  Global\WixWaitForEventFail
  Global\WixWaitForEventSucceed

Total: 18 indicators
```

### `--json` schema

```json
{
  "binary":   "<path>",
  "urls":     ["..."],
  "ips":      ["..."],
  "domains":  ["..."],
  "paths":    ["..."],
  "registry": ["..."],
  "mutexes":  ["..."],
  "secrets":  ["..."]
}
```

### Known limitations

- `unicode.to`-style Go internal package paths can survive the domain
  filter when the second label happens to be a real TLD. Acceptable
  noise; rare in practice outside Go binaries.
- Truncated path runs (`/dev/nulH`, `/etc/locH` from Go binaries where
  the next byte after the path is one consistent uppercase letter)
  appear with a junk trailing char. Hard to fix textually without
  cutting real paths.

---

## `--sigcheck` — Authenticode signature parse

```
rsleigh <binary> --sigcheck             # human-readable
rsleigh <binary> --sigcheck --json      # pipeline-ready
```

Parses the PE Security data directory and surfaces the parts of an
Authenticode signature an analyst actually wants on first look:

- Signed yes/no (presence of a non-zero Security directory entry)
- `WIN_CERTIFICATE` header (size, revision, type)
- **Signer CN** — first non-CA-like Subject `commonName` in the chain
- **Issuer CN** — the CA-like CN immediately preceding the signer
- **Signing time** — UTCTime / GeneralizedTime decoded to
  `YYYY-MM-DD HH:MM:SS UTC`
- **Counter-signature timestamp signer** when present
- Full chain of CNs in DER scan order

### Implementation notes

Hand-rolled DER walker, no new ASN.1 / CMS dependency. Pattern-matches
three fixed OID prefixes:

| OID | Encoded prefix | Meaning |
|-----|----------------|---------|
| `2.5.4.3` | `06 03 55 04 03` | `commonName` |
| `1.2.840.113549.1.9.5` | `06 09 2A 86 48 86 F7 0D 01 09 05` | `signingTime` |
| `1.2.840.113549.1.9.6` | `06 09 2A 86 48 86 F7 0D 01 09 06` | `counterSignature` |

Strings decoded from the standard text tags: `0x13` `PrintableString`,
`0x0C` `UTF8String`, `0x16` `IA5String`, `0x14` `T61String`, `0x1E`
`BMPString` (UTF-16BE). Times handle both `UTCTime` (`YYMMDDHHMMSSZ`,
20YY heuristic for two-digit years <50) and `GeneralizedTime`
(`YYYYMMDDHHMMSSZ`).

The leaf-signer heuristic is: the first commonName in the chain that
does **not** match `" CA"` / `"Code Signing"` / `"Root"` /
`"Time(s)tamping"`. Intermediate / root certs almost always carry one
of those tokens; publisher leaf certs carry the company / product
name. The issuer is the most recent CA-like CN appearing **before**
the signer in scan order.

### Example

```
rsleigh ~/Downloads/ScreenConnect.ClientSetup.exe --sigcheck
```

```
=== Authenticode signature for /Users/.../ScreenConnect.ClientSetup.exe ===

  Cert blob size:  93984 bytes  (revision 0x0200, type 0x0002)
  Signer CN:       Connectwise, LLC
  Issuer CN:       DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1
  Signing time:    2025-04-08 18:37:56 UTC

  Cert chain CNs (6):
    [0] DigiCert Trusted Root G4
    [1] DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1
    [2] Connectwise, LLC
    [3] DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA
    [4] DigiCert Timestamp 2024
    [5] DigiCert Assured ID Root CA
```

For an unsigned PE / ELF / Mach-O:

```
=== Authenticode signature for /tmp/bed ===

UNSIGNED — no PE Security directory entry, or directory was empty.
```

### `--json` schema

```json
{
  "binary":              "<path>",
  "signed":              true,
  "signer_cn":           "Connectwise, LLC",
  "issuer_cn":           "DigiCert ...",
  "signing_time":        "2025-04-08 18:37:56 UTC",
  "timestamp_signer_cn": null,
  "all_cns":             ["...", "..."],
  "cert_blob_size":      93984,
  "win_cert_revision":   "0x0200",
  "win_cert_type":       "0x0002"
}
```

### Known limitations

- Cryptographic signature **validity** is not verified — `--sigcheck`
  only parses the structure and extracts the names. Pair with
  `signtool verify` / `osslsigncode verify` to confirm the signature
  hashes the binary correctly and chains to a trust anchor. Forged
  / mismatched signatures will still print signer info.
- Counter-signature timestamp signer extraction is best-effort and
  depends on OID order in the blob; it is `null` more often than the
  Microsoft / DigiCert chains print it.

---

## `--resources` — PE resource directory walk

```
rsleigh <binary> --resources                       # listing only
rsleigh <binary> --resources --json                # JSON
rsleigh <binary> --resources --dump /tmp/out       # extract every blob
```

Walks the three-level PE resource directory tree
(TYPE → NAME/ID → LANGUAGE → DATA_ENTRY) using only spec-defined
offsets — no `goblin` resource dependency. Surfaces every embedded
resource with the type-name decoded from the standard `RT_*` table.

Recognized type IDs:

| ID | Name | ID | Name |
|----|------|----|------|
|  1 | CURSOR        |  3 | ICON |
|  2 | BITMAP        |  4 | MENU |
|  5 | DIALOG        |  6 | STRING |
|  7 | FONTDIR       |  8 | FONT |
|  9 | ACCELERATOR   | 10 | RCDATA |
| 11 | MESSAGETABLE  | 12 | GROUP_CURSOR |
| 14 | GROUP_ICON    | 16 | VERSION |
| 17 | DLGINCLUDE    | 19 | PLUGPLAY |
| 20 | VXD           | 21 | ANICURSOR |
| 22 | ANIICON       | 23 | HTML |
| 24 | MANIFEST      | other | `TYPE_<n>` |

Named (non-numeric) types are read from the resource directory string
table and printed verbatim.

### Preview heuristics

For each resource, a one-line preview is printed. Magic-byte sniffs
fire first and produce a tagged annotation:

| Bytes | Preview |
|-------|---------|
| `MZ` | `[embedded PE/EXE, N bytes]` |
| `D0 CF 11 E0 A1 B1 1A E1` | `[OLE compound (likely MSI), N bytes]` |
| `MSCF` | `[CAB archive, N bytes]` |
| `89 PNG …` | `[PNG image, N bytes]` |
| `FF D8 FF` | `[JPEG image, N bytes]` |

If no magic matches, type-specific preview takes over:

- `RT_MANIFEST` — first 80 chars of the XML (control chars stripped)
- `RT_VERSION` — printable UTF-16LE run from `VS_VERSIONINFO`
- everything else — first 32 bytes hex + ASCII gutter

### `--dump <DIR>` extraction

Writes every resource blob to disk under
`<DIR>/<TYPE>_<id>_<lang>.bin`. Stable naming so the same input
always produces the same files. Useful for:

- Pulling embedded payloads out of installer bootstrappers and
  feeding them back through `rsleigh` for nested triage
- Feeding extracted CABs / MSIs into a downstream unpacker
- Recovering icons / manifests for visual inspection

### Example

```
rsleigh ~/Downloads/ScreenConnect.ClientSetup.exe --resources --dump /tmp/sc
```

```
=== Resources for /Users/.../ScreenConnect.ClientSetup.exe ===

6 entries

type           id                       lang       size  preview
------------------------------------------------------------------------------
FILES          SCREENCONNECT.CORE,...   0       550912  [embedded PE/EXE, 550912 bytes]
FILES          SCREENCONNECT.WINDOWS... 0      1729024  [embedded PE/EXE, 1729024 bytes]
FILES          SCREENCONNECT.WINDOWSI.. 0       109568  [embedded PE/EXE, 109568 bytes]
FILES          _ENTRYPOINT              0      3072792  [embedded PE/EXE, 3072792 bytes]
FILES          _RESOLVER                0         5632  [embedded PE/EXE, 5632 bytes]
MANIFEST       #1                       1033       392  <?xml version='1.0' encoding...

Resources dumped to /tmp/sc/
```

`file(1)` on the dumped blobs confirms five valid `.NET PE32`
assemblies plus an XML manifest.

### `--json` schema

```json
{
  "binary":         "<path>",
  "has_resources": true,
  "count":         6,
  "entries": [
    {
      "type":        "FILES",
      "type_id":     0,
      "id":          "_ENTRYPOINT",
      "id_raw":      0,
      "lang":        0,
      "rva":         "0x...",
      "file_offset": "0x...",
      "size":        3072792,
      "preview":    "[embedded PE/EXE, 3072792 bytes]"
    }
  ]
}
```

For binaries without a resource directory:

```json
{ "binary": "<path>", "has_resources": false }
```

### Known limitations

- Three-level walk only — does not recurse into multi-level directory
  structures beyond TYPE/NAME/LANGUAGE (no real-world PE uses deeper).
- No `RT_VERSION` field-by-field decode (no `FileVersion`,
  `ProductVersion` extraction yet); only a flattened printable preview.
- `--dump` filenames replace nothing; if a named ID contains a path
  separator (rare), the file write may fail. Sanitize the dump dir
  before re-running on different binaries.

---

## Recommended triage workflow

For an unknown PE binary picked up in incident response:

```bash
# 1. What is it, who signed it, when?
rsleigh sample.exe --sigcheck

# 2. Where does it reach out / what does it touch?
rsleigh sample.exe --ioc

# 3. Does it carry embedded payloads we should pull out?
rsleigh sample.exe --resources --dump /tmp/sample-rsrc

# 4. If yes — recurse. Each extracted blob is a fresh sample.
for blob in /tmp/sample-rsrc/*.bin; do
  rsleigh "$blob" --sigcheck --json
done

# 5. Decompile the suspicious ones.
rsleigh sample.exe --vulnscan
rsleigh sample.exe 0x401000 --disasm
```

For pipeline ingestion, add `--json` where the flag documents a JSON form and
pipe it into `jq` or your enrichment layer. For IOC and vulnerability findings
that must share one evidence vocabulary, prefer `--findings-ndjson` and the
[shared schema](findings-ndjson.md). Preserve stderr separately from stdout.

## See also

- `docs/features.md` — broader analysis catalog
- `docs/decompiler-passes.md` — pipeline internals
- `docs/architectures.md` — supported architectures and binary formats
- `docs/TESTING.md` — running the test harness and benchmarks
