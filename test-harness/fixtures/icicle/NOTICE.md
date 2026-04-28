# Icicle `.ins` corpus — third-party fixture

The `*.ins` files in this directory are vendored from the upstream
`icicle-emu/icicle-emu` repository:

  https://github.com/icicle-emu/icicle-emu/tree/master/icicle-test/tests

They are dual-licensed under Apache-2.0 and MIT (see `LICENSE-APACHE`
and `LICENSE-MIT` in this directory).

  Copyright (c) Cyber Security Research Centre Limited 2023.

`x64_smoke.ins` is a small original fixture authored locally to exercise
rsleigh's `.ins` parser; it is not vendored.

## Why
We use these as a ground-truth oracle for rsleigh's SLEIGH-generated
decoders. Decode-only validation (bytes → instruction length + disasm
string) only — semantics execution is intentionally deferred since
rsleigh is a decompiler, not an emulator.

## Updating
To refresh from upstream:

```sh
for arch in x64 mips aarch64; do
  curl -sL "https://raw.githubusercontent.com/icicle-emu/icicle-emu/master/icicle-test/tests/${arch}.ins" \
    -o "test-harness/fixtures/icicle/${arch}.ins"
done
```

Note the upstream files mix decode and semantics tests in the same DSL
(see `icicle-test/README.md` upstream). rsleigh's `icicle_ins` parser
accepts both shapes; `check_cases_decode_report` exercises only the
decode path.
