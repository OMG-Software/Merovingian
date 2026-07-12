# Coding Rules

Style-only conventions (member naming, include ordering, quoting) live in
[`docs/coding-rules.md`](../docs/coding-rules.md) — this file is security-only,
so every entry below cites the CWE or named vulnerability class it prevents.

## Mandatory rules

- Security defects block release.
- RAII everywhere (CWE-401 Missing Release of Memory, CWE-459 Incomplete Cleanup).
- References preferred over pointers (CWE-476 NULL Pointer Dereference).
- No raw owning pointers (CWE-401 Missing Release of Memory, CWE-416 Use After Free).
- No naked `new` or `delete` (CWE-415 Double Free, CWE-416 Use After Free).
- No manual `malloc` or `free` outside reviewed low-level wrappers (CWE-415 Double Free, CWE-416 Use After Free, CWE-401 Missing Release of Memory).
- No unchecked narrowing conversions (CWE-197 Numeric Truncation Error).
- No logging secrets (CWE-532 Insertion of Sensitive Information into Log File).
- No logging access tokens, refresh tokens, signing keys, device keys, encrypted payloads, authorization headers, or plaintext message content (CWE-532 Insertion of Sensitive Information into Log File).
- No parser without fuzz coverage (CWE-20 Improper Input Validation).
- No protocol feature without tests (correctness gate for CWE-20 Improper Input Validation and CWE-863 Incorrect Authorization surfaces reachable through protocol handling).
- No dependency without review (CWE-1104 Use of Unmaintained Third Party Components / supply-chain risk).
- Warnings are errors (compiler diagnostics catch instances of the above classes at build time; treating them as non-fatal reintroduces the same bug classes).

## Ownership policy

- Prefer values.
- Prefer references for required access.
- Use `std::span` and `std::string_view` for bounded non-owning access.
- Use `not_null<T*>` only for unavoidable interop.
- `std::shared_ptr` requires justification.

## Logging rules

- Prefer `LOG_*` and `LOGF_*` macros.
- Log lines must be structured and bounded.
- Logging must not allocate unbounded attacker-controlled memory.
- Logging paths must not bypass redaction requirements.

## Security-over-performance rule

Performance work must not bypass:

- validation
- bounds checks
- authorization
- signature verification
- redaction
- logging controls
- policy enforcement
