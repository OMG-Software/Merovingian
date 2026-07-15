# Coding rules

This file has moved. The authoritative, explained security coding rules for Merovingian —
every rule below plus the module-specific ones from each `src/*/AGENTS.md` file, each with a
"why" and a CWE/vulnerability-class reference where one applies — now live in
[`docs/security-coding-rules.md`](../docs/security-coding-rules.md).

Style-only conventions (member naming, include ordering, quoting) live in
[`docs/coding-rules.md`](../docs/coding-rules.md).

`scripts/reject-unsafe.sh` still enforces the automatable subset of these rules (banned raw
`new`/`delete`/`malloc`/`free`/`calloc`/`realloc`, unjustified `shared_ptr`) as a pre-commit
gate, independent of this file.
