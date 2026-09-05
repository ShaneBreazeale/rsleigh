# rsleigh documentation

rsleigh is a Rust reverse engineering framework with a shell-friendly CLI and
an embeddable decoder/lifter. It runs without a JVM. Its agent workflow turns
binaries into bounded navigation maps, focused evidence, and reusable files.

## Start here

1. [Install rsleigh](../README.md#installation).
2. Read the [agent quickstart](agent-workflow.md#start-a-session) for the first
   commands to run and the checks to make before interpreting output.
3. Use the [command guide](cli-reference.md) to choose a mode by question and
   input type.
4. Use [output formats and validation](output-formats.md) when writing a script
   or passing artifacts to an LLM.

For a target-analysis workspace, merge the [agent contract](AGENTS-rsleigh.md)
into its existing instructions. The contract is deliberately short; follow its
links for details instead of loading all documentation into every model turn.

## Find the right reference

| Question | Read |
|---|---|
| How should an agent investigate a binary? | [Agent workflow](agent-workflow.md) |
| Which command and flags answer this question? | [CLI command guide](cli-reference.md) |
| Is this output JSON, NDJSON, or text? How do I detect failure? | [Output formats](output-formats.md) |
| Why is output empty, incomplete, or unexpected? | [Troubleshooting](troubleshooting.md) |
| Does my architecture support this analysis stage? | [Architecture matrix](architectures.md) |
| How do I extract IOCs, signatures, and resources? | [CLI triage](cli-triage.md) |
| What does a finding's confidence or severity mean? | [Findings NDJSON](findings-ndjson.md) |
| How do I build and use solver-assisted analysis? | [SMT backend](smt-backend.md) · [SMT candidate records](smt-candidates.md) |
| What specialized analysis is available? | [Feature catalog](features.md) · [PE64 SEH pipeline](pe64-seh-pipeline.md) |
| How has this been used on real targets? | [Sony camera and TP-Link router firmware](showcase/firmware-investigations.md) · [PyVMProtect case study](showcase/crackme3-pyvmprotect.md) |
| How do I embed the decoder? | [Rust API example](../README.md#embed-in-rust) |
| How do the decompiler and tests work? | [Decompiler passes](decompiler-passes.md) · [Testing](TESTING.md) |

## Reading outputs correctly

Decoded instructions and coherent P-code are the closest evidence to the
binary. Function discovery, names, inferred types, pseudocode, and pattern
matches have additional assumptions. Check the architecture matrix at the
stage you use; successful decoding does not establish complete lifting.

A capped map is a starting point, not an exhaustive result. A solver's
`Reachable` result is relative to its model, not proof of a runtime bug.
`NotReachable` can also reflect analysis filters; inspect `filter_reasons`.

## Current reference versus project history

The guides linked above describe the current source checkout. Record the
installed package version or source revision with an analysis; a release or
Context7 index can lag `master`. The CLI currently prints usage when invoked
without arguments and does not implement conventional `--help` / `--version`
flags. See [CLI conventions](cli-reference.md#invocation-conventions).

[The engineering audit](audit-gpt-5.5.md) and the design specifications and
plans under `superpowers/` are historical development material. They can explain
why a change was made, but are not the current command or support contract.

For documentation lookup tools, the repository also provides
[llms.txt](../llms.txt) and [Context7 configuration](../context7.json).
