# Coding Rules

## Mandatory rules

- Security defects block release.
- RAII everywhere.
- References preferred over pointers.
- No raw owning pointers.
- No naked `new` or `delete`.
- No manual `malloc` or `free` outside reviewed low-level wrappers.
- No unchecked narrowing conversions.
- Member variables must use `m_` prefix.
- Local project includes use `""`.
- Third-party includes use `<>`.
- Standard library includes use `<>`.
- Include ordering must be:
  1. local project includes
  2. third-party includes
  3. standard library includes
- No logging secrets.
- No logging access tokens, refresh tokens, signing keys, device keys, encrypted payloads, authorization headers, or plaintext message content.
- No parser without fuzz coverage.
- No protocol feature without tests.
- No dependency without review.
- Warnings are errors.

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
